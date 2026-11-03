"""
=============================================================================
CHRONOS-ZK: SINTETIZADOR Y EXPORTADOR DE BINARIOS OFICIALES IDEN3 (.R1CS v1)
Modulo: tools/generate_binary_r1cs.py
Proposito: Empaqueta circuitos R1CS al formato binario estandar Iden3 v1
           (Little-Endian, Magic 'r1cs', Secciones 1 Header, 2 Constraints y
           3 Wire2LabelId) exactamente como los emite `circom --r1cs`.
=============================================================================
"""

import os
import struct
import sys
from smt_verifier.bn254_field import BN254_PRIME
from smt_verifier.r1cs_to_z3 import R1CSCircuitModel, get_fixture_model


def encode_lc_binary(terms: list, prime: int) -> bytes:
    """
    Serializa una combinacion lineal R1CS al formato binario de la Seccion 2:
      - n_terms: u32 LE
      - Para cada termino: wire_id (u32 LE) + coeff_mod_p (32 bytes LE)
    """
    consolidated = {}
    for wire_id, coeff in terms:
        w = int(wire_id)
        c = int(coeff) % prime
        consolidated[w] = (consolidated.get(w, 0) + c) % prime

    non_zero = [(w, c) for w, c in sorted(consolidated.items()) if c != 0]
    buf = bytearray(struct.pack("<I", len(non_zero)))
    for w, c in non_zero:
        buf.extend(struct.pack("<I", w))
        buf.extend(int(c).to_bytes(32, byteorder="little", signed=False))
    return bytes(buf)


def write_iden3_binary_r1cs(model: R1CSCircuitModel, output_path: str):
    """
    Escribe un objeto R1CSCircuitModel como archivo binario `.r1cs` Iden3 v1.
    """
    prime = int(model.prime)
    n_wires = int(model.num_variables)
    n_pub_out = len(model.output_signals)
    n_pub_in = len(model.public_inputs)
    n_prv_in = max(0, n_wires - 1 - n_pub_out - n_pub_in)
    n_labels = n_wires
    m_constraints = len(model.constraints)

    # 1. Construir Seccion 1 (Header: 64 bytes para field_size = 32)
    field_size = 32
    prime_bytes = prime.to_bytes(field_size, byteorder="little", signed=False)
    sec1_payload = (
        struct.pack("<I", field_size)
        + prime_bytes
        + struct.pack("<IIIIQI", n_wires, n_pub_out, n_pub_in, n_prv_in, n_labels, m_constraints)
    )

    # 2. Construir Seccion 2 (Constraints)
    sec2_chunks = []
    for c in model.constraints:
        sec2_chunks.append(encode_lc_binary(c.get("A", []), prime))
        sec2_chunks.append(encode_lc_binary(c.get("B", []), prime))
        sec2_chunks.append(encode_lc_binary(c.get("C", []), prime))
    sec2_payload = b"".join(sec2_chunks)

    # 3. Construir Seccion 3 (Wire2LabelId Map: n_wires * u64 LE)
    sec3_payload = b"".join(struct.pack("<Q", i) for i in range(n_wires))

    # 4. Ensamblar archivo completo con cabecera 'r1cs', version 1, 3 secciones
    file_bytes = bytearray()
    file_bytes.extend(struct.pack("<4sII", b"r1cs", 1, 3))

    # Seccion 1
    file_bytes.extend(struct.pack("<IQ", 1, len(sec1_payload)))
    file_bytes.extend(sec1_payload)

    # Seccion 2
    file_bytes.extend(struct.pack("<IQ", 2, len(sec2_payload)))
    file_bytes.extend(sec2_payload)

    # Seccion 3
    file_bytes.extend(struct.pack("<IQ", 3, len(sec3_payload)))
    file_bytes.extend(sec3_payload)

    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(file_bytes)

    print(
        f"[+] Binario Iden3 .r1cs v1 generado: {output_path} "
        f"({len(file_bytes)} bytes | Wires: {n_wires} | Constraints: {m_constraints})"
    )


def build_canonical_binary_fixtures():
    """
    Genera los 4 fixtures binarios `.r1cs` canonicos con el layout de cables
    estandar de Iden3 (0: ONE, 1..n_out: outputs, n_out+1..n_out+n_pub: public_inputs).
    """
    # 1. IsZero Vulnerable (0: ONE, 1: out, 2: in, 3: inv)
    iszero_vuln = R1CSCircuitModel(
        name="iszero_vulnerable",
        prime=BN254_PRIME,
        num_variables=4,
        public_inputs=[2],
        output_signals=[1],
        private_inputs=[3],
        constraints=[
            {"A": [(2, 1)], "B": [(3, 1)], "C": [(0, 1), (1, -1)]},
        ],
    )
    write_iden3_binary_r1cs(iszero_vuln, os.path.join("circuits", "vulnerable", "iszero_vulnerable.r1cs"))

    # 2. IsZero Secure (0: ONE, 1: out, 2: in, 3: inv)
    iszero_sec = R1CSCircuitModel(
        name="iszero_secure",
        prime=BN254_PRIME,
        num_variables=4,
        public_inputs=[2],
        output_signals=[1],
        private_inputs=[3],
        constraints=[
            {"A": [(2, 1)], "B": [(3, 1)], "C": [(0, 1), (1, -1)]},
            {"A": [(2, 1)], "B": [(1, 1)], "C": []},
        ],
    )
    write_iden3_binary_r1cs(iszero_sec, os.path.join("circuits", "secure", "iszero_secure.r1cs"))

    # 3. Merkle Vulnerable (0: ONE, 1: root, 2: leaf, 3..5: pathElements, 6..8: pathIndices)
    merkle_vuln = get_fixture_model("merkle_vulnerable")
    # En `_build_merkle_fixture`, leaf=1 y root=2; intercambiamos los cables 1 y 2 para que
    # cumpla estrictamente el orden contiguo de la Seccion 1 de Iden3 (1: out=root, 2..5: pub=leaf,pe)
    def remap_merkle_wires(m: R1CSCircuitModel) -> R1CSCircuitModel:
        swap = {1: 2, 2: 1}
        new_constraints = []
        for c in m.constraints:
            new_c = {}
            for k in ("A", "B", "C"):
                new_c[k] = [(swap.get(w, w), coeff) for w, coeff in c.get(k, [])]
            new_constraints.append(new_c)
        return R1CSCircuitModel(
            name=m.name,
            prime=m.prime,
            num_variables=m.num_variables,
            public_inputs=[2, 3, 4, 5],
            output_signals=[1],
            private_inputs=m.private_inputs,
            constraints=new_constraints,
        )

    write_iden3_binary_r1cs(
        remap_merkle_wires(merkle_vuln),
        os.path.join("circuits", "vulnerable", "merkle_malleable.r1cs"),
    )

    merkle_sec = get_fixture_model("merkle_secure")
    write_iden3_binary_r1cs(
        remap_merkle_wires(merkle_sec),
        os.path.join("circuits", "secure", "merkle_secure.r1cs"),
    )


if __name__ == "__main__":
    if len(sys.argv) == 3:
        in_json = sys.argv[1]
        out_r1cs = sys.argv[2]
        circuit_model = R1CSCircuitModel.from_json(in_json)
        write_iden3_binary_r1cs(circuit_model, out_r1cs)
    else:
        build_canonical_binary_fixtures()