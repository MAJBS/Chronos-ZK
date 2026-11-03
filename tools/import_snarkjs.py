"""
=============================================================================
CHRONOS-ZK: IMPORTADOR Y NORMALIZADOR DE AST R1CS DESDE SNARKJS
Modulo: tools/import_snarkjs.py
Proposito: Traduccion exacta de archivos JSON exportados por SnarkJS
           (`snarkjs r1cs export json`) al contrato unificado Chronos-IR,
           con normalizacion simetrica de coeficientes en F_p.
=============================================================================
"""

import json
import sys
import os

BN254_PRIME_DEFAULT = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def canonical_coeff_str(coeff_val, prime: int) -> str:
    """
    Convierte un coeficiente de SnarkJS (en [0, p-1]) a su representacion entera
    simetrica con signo en [-(p-1)/2, (p-1)/2] como string decimal.
    Ejemplo: p - 1 -> "-1".
    """
    c = int(coeff_val) % prime
    if c > (prime // 2):
        return str(c - prime)
    return str(c)


def convert_snarkjs_to_chronos(snarkjs_file: str, output_file: str):
    print(f"[*] Leyendo AST R1CS de SnarkJS: {snarkjs_file}")
    with open(snarkjs_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    circuit_name = data.get("name", os.path.basename(snarkjs_file).replace(".json", ""))
    prime_int = int(data.get("prime", data.get("field_prime", BN254_PRIME_DEFAULT)))

    # Si el archivo ya esta en formato Chronos-IR, normalizar y reexportar
    if "r1cs_constraints" in data and "num_variables" in data:
        num_vars = int(data["num_variables"])
        public_inputs = [int(x) for x in data.get("public_inputs", [])]
        private_inputs = [int(x) for x in data.get("private_inputs", [])]
        output_signals = [int(x) for x in data.get("output_signals", [])]
        determined_signals = [int(x) for x in data.get("determined_signals", [0] + public_inputs)]
        suspicious_signals = [
            int(x)
            for x in data.get(
                "suspicious_signals",
                output_signals if output_signals else private_inputs,
            )
        ]

        normalized_constraints = []
        for c in data["r1cs_constraints"]:
            A = [[int(item[0]), canonical_coeff_str(item[1], prime_int)] for item in c.get("A", [])]
            B = [[int(item[0]), canonical_coeff_str(item[1], prime_int)] for item in c.get("B", [])]
            C = [[int(item[0]), canonical_coeff_str(item[1], prime_int)] for item in c.get("C", [])]
            normalized_constraints.append({"A": A, "B": B, "C": C})

        chronos_ir = {
            "name": circuit_name,
            "field_prime": str(prime_int),
            "num_variables": num_vars,
            "public_inputs": public_inputs,
            "private_inputs": private_inputs,
            "output_signals": output_signals,
            "determined_signals": determined_signals,
            "suspicious_signals": suspicious_signals,
            "r1cs_constraints": normalized_constraints,
        }
    else:
        # Layout estandar de SnarkJS R1CS:
        # 0: constante ONE
        # 1 .. nOutputs: seniales de salida (output_signals)
        # nOutputs + 1 .. nOutputs + nPubInputs: entradas publicas (public_inputs)
        # nOutputs + nPubInputs + 1 .. nOutputs + nPubInputs + nPrvInputs: entradas privadas
        n_vars = int(data["nVars"])
        n_outputs = int(data.get("nOutputs", 0))
        n_pub = int(data.get("nPubInputs", 0))
        n_prv = int(data.get("nPrvInputs", 0))

        output_signals = list(range(1, 1 + n_outputs))
        pub_start = 1 + n_outputs
        public_inputs = list(range(pub_start, pub_start + n_pub))
        prv_start = pub_start + n_pub
        private_inputs = list(range(prv_start, min(n_vars, prv_start + n_prv)))

        # Si el circuito no declaro nOutputs explicitos, las seniales posteriores a las
        # entradas publicas son candidatas a verificacion de unicidad
        suspicious_signals = (
            output_signals
            if output_signals
            else [i for i in range(1, n_vars) if i not in set(public_inputs)]
        )

        r1cs_constraints = []
        for c in data.get("constraints", []):
            A = [
                [int(k), canonical_coeff_str(v, prime_int)]
                for k, v in c[0].items()
                if (int(v) % prime_int) != 0
            ]
            B = [
                [int(k), canonical_coeff_str(v, prime_int)]
                for k, v in c[1].items()
                if (int(v) % prime_int) != 0
            ]
            C = [
                [int(k), canonical_coeff_str(v, prime_int)]
                for k, v in c[2].items()
                if (int(v) % prime_int) != 0
            ]
            r1cs_constraints.append({"A": A, "B": B, "C": C})

        chronos_ir = {
            "name": circuit_name,
            "field_prime": str(prime_int),
            "num_variables": n_vars,
            "public_inputs": public_inputs,
            "private_inputs": private_inputs,
            "output_signals": output_signals,
            "determined_signals": [0] + public_inputs,
            "suspicious_signals": suspicious_signals,
            "r1cs_constraints": r1cs_constraints,
        }

    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(chronos_ir, f, indent=2)

    print(f"[+] Traduccion exitosa. Contrato Chronos-IR exportado a: {output_file}")
    print(
        f"    Variables: {chronos_ir['num_variables']} | "
        f"Publicas: {len(chronos_ir['public_inputs'])} | "
        f"Salidas: {len(chronos_ir['output_signals'])} | "
        f"Restricciones: {len(chronos_ir['r1cs_constraints'])}"
    )


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python -m tools.import_snarkjs <snarkjs_output.json> <chronos_ir.json>")
        sys.exit(1)
    convert_snarkjs_to_chronos(sys.argv[1], sys.argv[2])