"""
=============================================================================
CHRONOS-ZK: TRADUCTOR R1CS A SMT VIA COCIENTE ALGEBRAICO EXACTO
Modulo: smt_verifier/r1cs_to_z3.py
Proposito: Transformacion diofantica certificada A(w)*B(w) == C(w) + k*p
           con soporte de subanillo directo (k = 0) y reduccion modular
           completa sobre F_p con Lema de Euclides para C == 0.
=============================================================================
"""

import json
import z3
from smt_verifier.bn254_field import BN254Field, BN254_PRIME, log_telemetry


class R1CSCircuitModel:
    def __init__(
        self,
        name: str,
        prime: int,
        num_variables: int,
        public_inputs: list,
        constraints: list,
        suspicious_signals: list = None,
        output_signals: list = None,
        private_inputs: list = None,
        determined_signals: list = None,
    ):
        self.name = name
        self.prime = int(prime)
        self.num_variables = int(num_variables)
        self.public_inputs = [int(x) for x in (public_inputs or [])]
        self.private_inputs = [int(x) for x in (private_inputs or [])]
        self.output_signals = [int(x) for x in (output_signals or [])]
        self.suspicious_signals = [int(x) for x in (suspicious_signals or [])]
        self.determined_signals = [int(x) for x in (determined_signals or [])]
        self.constraints = constraints or []

    @classmethod
    def from_json(cls, file_path: str):
        log_telemetry("AST_PARSE", f"Cargando contrato Chronos-IR desde: {file_path}")
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        name = data.get("name", "Imported_R1CS")
        prime = int(data.get("field_prime", BN254_PRIME))
        num_vars = int(data["num_variables"])
        public_inputs = data.get("public_inputs", [])
        private_inputs = data.get("private_inputs", [])
        outputs = data.get("output_signals", [])
        suspicious = data.get("suspicious_signals", [])
        determined = data.get("determined_signals", [])

        raw_constraints = data.get("r1cs_constraints", data.get("constraints", []))
        parsed_constraints = []
        for c in raw_constraints:
            a_raw = c.get("A", c.get("a", []))
            b_raw = c.get("B", c.get("b", []))
            c_raw = c.get("C", c.get("c", []))
            parsed_constraints.append({
                "A": [(int(item[0]), int(item[1])) for item in a_raw],
                "B": [(int(item[0]), int(item[1])) for item in b_raw],
                "C": [(int(item[0]), int(item[1])) for item in c_raw],
            })

        log_telemetry(
            "AST_PARSE",
            f"Contrato '{name}' cargado: {num_vars} seniales, {len(parsed_constraints)} restricciones R1CS.",
        )
        return cls(
            name=name,
            prime=prime,
            num_variables=num_vars,
            public_inputs=public_inputs,
            constraints=parsed_constraints,
            suspicious_signals=suspicious,
            output_signals=outputs,
            private_inputs=private_inputs,
            determined_signals=determined,
        )

    def instantiate_witness(self, prefix: str) -> dict:
        """Instancia el vector de testigo simbolico con w_0 = 1."""
        witness_map = {0: 1}
        for i in range(1, self.num_variables):
            witness_map[i] = BN254Field.field_var(f"{prefix}_w{i}")
        return witness_map

    def get_active_constraint_signals(self) -> set:
        """Devuelve el conjunto de IDs de seniales que participan en al menos una restriccion."""
        active = set()
        for c in self.constraints:
            for term_key in ("A", "B", "C"):
                for sig_id, coeff in c.get(term_key, []):
                    if (int(coeff) % self.prime) != 0 and int(sig_id) != 0:
                        active.add(int(sig_id))
        return active

    def build_system_assertions(
        self,
        witness_map: dict,
        prefix: str,
        allow_modular_wrap: bool = True,
    ) -> list:
        """
        Construye el sistema de aserciones Z3 para un testigo simbolico:
          - Si `allow_modular_wrap=False`, evalua el subanillo entero directo (k = 0)
            con w_i in [0, p-1], evitando variables existenciales de 254 bits en
            cascadas polinomiales profundas (toda solucion k = 0 es solucion exacta mod p).
          - Si `allow_modular_wrap=True`, construye la formulacion diofantica completa
            A(w)*B(w) == C(w) + k*p con cotas de intervalo exactas [k_min, k_max].
        """
        assertions = []
        p = self.prime

        # 1. Restricciones de Dominio: w_i in [0, p-1]
        for i in range(1, self.num_variables):
            assertions.append(BN254Field.domain_constraint(witness_map[i], p))

        # 2. Traduccion algebraica de cada restriccion R1CS
        for idx, c in enumerate(self.constraints):
            a_eval, a_min, a_max, a_const = BN254Field.eval_linear_combination_with_bounds(
                c.get("A", []), witness_map, p
            )
            b_eval, b_min, b_max, b_const = BN254Field.eval_linear_combination_with_bounds(
                c.get("B", []), witness_map, p
            )
            c_eval, c_min, c_max, c_const = BN254Field.eval_linear_combination_with_bounds(
                c.get("C", []), witness_map, p
            )

            c_is_zero = c_const and (c_eval == 0)

            if not allow_modular_wrap:
                # Subanillo directo (k = 0): A(w) * B(w) == C(w) en Z
                if c_is_zero:
                    assertions.append(a_eval * b_eval == 0)
                else:
                    assertions.append(a_eval * b_eval == c_eval)
                continue

            if c_is_zero:
                # LEMA DE EUCLIDES EN CUERPOS PRIMOS F_p:
                ka_min = BN254Field.ceil_div(a_min, p)
                ka_max = BN254Field.floor_div(a_max, p)
                kb_min = BN254Field.ceil_div(b_min, p)
                kb_max = BN254Field.floor_div(b_max, p)

                if ka_min == 0 and ka_max == 0 and kb_min == 0 and kb_max == 0:
                    if a_const and b_const:
                        if (a_eval * b_eval) % p != 0:
                            assertions.append(z3.BoolVal(False))
                    elif a_const:
                        if a_eval % p != 0:
                            assertions.append(b_eval == 0)
                    elif b_const:
                        if b_eval % p != 0:
                            assertions.append(a_eval == 0)
                    else:
                        assertions.append(a_eval * b_eval == 0)
                else:
                    conds = []
                    if not a_const:
                        if ka_min == 0 and ka_max == 0:
                            conds.append(a_eval == 0)
                        elif ka_min <= ka_max:
                            ka_var = z3.Int(f"{prefix}_ka_{idx}")
                            assertions.append(z3.And(ka_var >= ka_min, ka_var <= ka_max))
                            conds.append(a_eval == ka_var * p)
                    elif (a_eval % p) == 0:
                        conds.append(z3.BoolVal(True))

                    if not b_const:
                        if kb_min == 0 and kb_max == 0:
                            conds.append(b_eval == 0)
                        elif kb_min <= kb_max:
                            kb_var = z3.Int(f"{prefix}_kb_{idx}")
                            assertions.append(z3.And(kb_var >= kb_min, kb_var <= kb_max))
                            conds.append(b_eval == kb_var * p)
                    elif (b_eval % p) == 0:
                        conds.append(z3.BoolVal(True))

                    if conds:
                        assertions.append(z3.Or(conds) if len(conds) > 1 else conds[0])
                    else:
                        assertions.append(z3.BoolVal(False))
            else:
                corners = (
                    a_min * b_min,
                    a_min * b_max,
                    a_max * b_min,
                    a_max * b_max,
                )
                p_min = min(corners)
                p_max = max(corners)

                d_min = p_min - c_max
                d_max = p_max - c_min

                k_min = BN254Field.ceil_div(d_min, p)
                k_max = BN254Field.floor_div(d_max, p)

                lhs_expr = a_eval * b_eval

                if k_min > k_max:
                    assertions.append(z3.BoolVal(False))
                elif k_min == 0 and k_max == 0:
                    assertions.append(lhs_expr == c_eval)
                elif k_min == k_max:
                    assertions.append(lhs_expr == c_eval + (k_min * p))
                else:
                    k_var = z3.Int(f"{prefix}_k_{idx}")
                    assertions.append(z3.And(k_var >= k_min, k_var <= k_max))
                    assertions.append(lhs_expr == c_eval + (k_var * p))

        return assertions


# =============================================================================
# FIXTURES CANONICOS CERTIFICADOS (ISZERO, NUM2BITS, MERKLE)
# =============================================================================

def _build_merkle_fixture(secure: bool, levels: int = 3) -> R1CSCircuitModel:
    sig_id = 1
    leaf_id = sig_id
    sig_id += 1
    root_id = sig_id
    sig_id += 1

    path_elements = []
    for _ in range(levels):
        path_elements.append(sig_id)
        sig_id += 1

    path_indices = []
    for _ in range(levels):
        path_indices.append(sig_id)
        sig_id += 1

    constraints = []
    current_id = leaf_id

    for i in range(levels):
        s_id = path_indices[i]
        pe_id = path_elements[i]

        if secure:
            constraints.append({
                "A": [(s_id, 1)],
                "B": [(0, 1), (s_id, -1)],
                "C": [],
            })

        left_id = sig_id
        sig_id += 1
        right_id = sig_id
        sig_id += 1
        prod_id = sig_id
        sig_id += 1
        next_curr_id = root_id if (i == levels - 1) else sig_id
        if i < levels - 1:
            sig_id += 1

        constraints.append({
            "A": [(s_id, 1)],
            "B": [(pe_id, 1), (current_id, -1)],
            "C": [(left_id, 1), (current_id, -1)],
        })

        constraints.append({
            "A": [(s_id, 1)],
            "B": [(current_id, 1), (pe_id, -1)],
            "C": [(right_id, 1), (pe_id, -1)],
        })

        constraints.append({
            "A": [(left_id, 1)],
            "B": [(right_id, 1)],
            "C": [(prod_id, 1)],
        })

        constraints.append({
            "A": [(0, 1)],
            "B": [(prod_id, 1), (left_id, 1), (right_id, 1), (0, 7)],
            "C": [(next_curr_id, 1)],
        })

        current_id = next_curr_id

    name = "Merkle_Secure" if secure else "Merkle_Vulnerable"
    public_inputs = [leaf_id] + path_elements
    output_signals = [root_id]
    suspicious_signals = [root_id] if secure else (path_indices + [root_id])
    private_inputs = path_indices
    determined_signals = [0] + public_inputs + ([root_id] if secure else [])

    return R1CSCircuitModel(
        name=name,
        prime=BN254_PRIME,
        num_variables=sig_id,
        public_inputs=public_inputs,
        constraints=constraints,
        suspicious_signals=suspicious_signals,
        output_signals=output_signals,
        private_inputs=private_inputs,
        determined_signals=determined_signals,
    )


def get_fixture_model(fixture_name: str) -> R1CSCircuitModel:
    log_telemetry("FIXTURE", f"Cargando fixture canonico: {fixture_name}")
    norm_name = fixture_name.strip().lower()

    if norm_name in ("iszero_vulnerable", "iszero_underconstrained"):
        constraints = [
            {"A": [(1, 1)], "B": [(3, 1)], "C": [(0, 1), (2, -1)]}
        ]
        return R1CSCircuitModel(
            name="IsZero_Vulnerable",
            prime=BN254_PRIME,
            num_variables=4,
            public_inputs=[1],
            constraints=constraints,
            suspicious_signals=[2, 3],
            output_signals=[2],
            private_inputs=[3],
            determined_signals=[0, 1],
        )

    elif norm_name == "iszero_secure":
        constraints = [
            {"A": [(1, 1)], "B": [(3, 1)], "C": [(0, 1), (2, -1)]},
            {"A": [(1, 1)], "B": [(2, 1)], "C": []},
        ]
        return R1CSCircuitModel(
            name="IsZero_Secure",
            prime=BN254_PRIME,
            num_variables=4,
            public_inputs=[1],
            constraints=constraints,
            suspicious_signals=[2],
            output_signals=[2],
            private_inputs=[3],
            determined_signals=[0, 1, 2],
        )

    elif norm_name in ("num2bits_vulnerable", "num2bits_underconstrained"):
        lin_sum = [(2 + i, 1 << i) for i in range(8)]
        constraints = [{"A": [(0, 1)], "B": lin_sum, "C": [(1, 1)]}]
        return R1CSCircuitModel(
            name="Num2Bits_Vulnerable",
            prime=BN254_PRIME,
            num_variables=10,
            public_inputs=[1],
            constraints=constraints,
            suspicious_signals=list(range(2, 10)),
            output_signals=list(range(2, 10)),
            private_inputs=[],
            determined_signals=[0, 1],
        )

    elif norm_name == "num2bits_secure":
        lin_sum = [(2 + i, 1 << i) for i in range(8)]
        constraints = [{"A": [(0, 1)], "B": lin_sum, "C": [(1, 1)]}]
        for i in range(8):
            bit_idx = 2 + i
            constraints.append({
                "A": [(bit_idx, 1)],
                "B": [(0, 1), (bit_idx, -1)],
                "C": [],
            })
        return R1CSCircuitModel(
            name="Num2Bits_Secure",
            prime=BN254_PRIME,
            num_variables=10,
            public_inputs=[1],
            constraints=constraints,
            suspicious_signals=list(range(2, 10)),
            output_signals=list(range(2, 10)),
            private_inputs=[],
            determined_signals=[0, 1] + list(range(2, 10)),
        )

    elif norm_name in ("merkle_vulnerable", "merkle_malleable"):
        return _build_merkle_fixture(secure=False, levels=3)

    elif norm_name == "merkle_secure":
        return _build_merkle_fixture(secure=True, levels=3)

    else:
        raise ValueError(f"Fixture desconocido: {fixture_name}")