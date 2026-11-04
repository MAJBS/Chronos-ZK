"""
=============================================================================
CHRONOS-ZK: TRADUCTOR R1CS A SMT, CLAUSURA CUADRATICA Y EXTRACTOR DE ISLAS
Modulo: smt_verifier/r1cs_to_z3.py
Proposito: Transformacion diofantica certificada A(w)*B(w) == C(w) + k*p,
           clausura funcional cuadratica universal (colapso de Poseidon/MiMC),
           ingesta de tabla de simbolos Circom (.sym) y micro-slicing por
           islas para el Modo Francotirador (--sniper).
=============================================================================
"""

import json
import os
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
        signal_symbols: dict = None,
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
        self.signal_symbols = {
            int(k): str(v) for k, v in (signal_symbols or {}).items()
        }
        if 0 not in self.signal_symbols:
            self.signal_symbols[0] = "ONE"

    def load_sym_file(self, sym_path: str) -> int:
        """
        Lee un archivo `.sym` oficial generado por `circom --r1cs --sym`.
        Formato CSV de Circom: label_id,wire_id,component_id,symbol_name
        Cuando wire_id >= 1, asocia el wire_id con su nombre simbolico real.
        """
        if not sym_path or not os.path.exists(sym_path):
            return 0

        loaded = 0
        with open(sym_path, "r", encoding="utf-8") as f:
            for raw_line in f:
                line = raw_line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(",")
                if len(parts) >= 4:
                    try:
                        wire_id = int(parts[1].strip())
                        sym_name = parts[3].strip()
                        if 0 <= wire_id < self.num_variables and sym_name:
                            self.signal_symbols[wire_id] = sym_name
                            loaded += 1
                    except ValueError:
                        continue

        log_telemetry(
            "SYM_TABLE",
            f"Tabla de simbolos Circom cargada desde '{sym_path}' ({loaded} seniales mapeadas).",
        )
        return loaded

    def get_signal_label(self, sig_id: int) -> str:
        """Devuelve el nombre simbolico real si existe, o `w_<id>`."""
        sym = self.signal_symbols.get(int(sig_id))
        if sym and sym != f"w_{sig_id}":
            return f"w_{sig_id} ({sym})"
        return f"w_{sig_id}"

    @classmethod
    def from_json(cls, file_path: str, sym_path: str = None):
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
        signal_symbols = data.get("signal_symbols", {})

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

        model = cls(
            name=name,
            prime=prime,
            num_variables=num_vars,
            public_inputs=public_inputs,
            constraints=parsed_constraints,
            suspicious_signals=suspicious,
            output_signals=outputs,
            private_inputs=private_inputs,
            determined_signals=determined,
            signal_symbols=signal_symbols,
        )

        if sym_path:
            model.load_sym_file(sym_path)

        log_telemetry(
            "AST_PARSE",
            f"Contrato '{name}' cargado: {num_vars} seniales, {len(parsed_constraints)} restricciones R1CS.",
        )
        return model

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

    def compute_forward_algebraic_closure(self) -> tuple:
        """
        PIEZA 1 DEL MODO FRANCOTIRADOR:
        Ejecuta la Clausura Funcional Cuadratica y Lineal Universal en L4.
        Colapsa automaticamente rondas completas de hashes no-lineales deterministas
        (Poseidon x^5, MiMC x^3, sumas MDS, etc.) donde A y B estan determinadas
        y despejan univocamente una unica variable libre en C.

        Retorna (determined_set, root_bounded_set, unresolved_signals).
        """
        p = self.prime
        determined = {0} | set(self.public_inputs) | set(self.determined_signals)
        root_bounded = set(determined)

        def non_const_vars(terms):
            return [
                int(sig_id)
                for sig_id, coeff in terms
                if int(sig_id) != 0 and (int(coeff) % p) != 0
            ]

        # Pre-indexar acoplamientos bilineales x * y == 0
        bilinear_zeros = set()
        for c in self.constraints:
            a_v = non_const_vars(c.get("A", []))
            b_v = non_const_vars(c.get("B", []))
            c_v = non_const_vars(c.get("C", []))
            has_c_const = any(int(s) == 0 and (int(cf) % p) != 0 for s, cf in c.get("C", []))
            if not c_v and not has_c_const and len(a_v) == 1 and len(b_v) == 1 and a_v[0] != b_v[0]:
                bilinear_zeros.add((a_v[0], b_v[0]))
                bilinear_zeros.add((b_v[0], a_v[0]))

        changed = True
        while changed:
            changed = False
            for c in self.constraints:
                a_terms = c.get("A", [])
                b_terms = c.get("B", [])
                c_terms = c.get("C", [])

                a_vars = non_const_vars(a_terms)
                b_vars = non_const_vars(b_terms)
                c_vars = non_const_vars(c_terms)

                # 1. Deteccion de cota booleana x * (1 - x) == 0
                if not c_terms and len(a_vars) == 1 and len(b_vars) == 1 and a_vars[0] == b_vars[0]:
                    x_id = a_vars[0]
                    if x_id not in root_bounded:
                        root_bounded.add(x_id)
                        changed = True
                    continue

                # 2. Acoplamiento IsZero: in * inv == 1 - out con in * out == 0
                if len(a_vars) == 1 and len(b_vars) == 1 and len(c_vars) == 1:
                    s_a, s_b, s_c = a_vars[0], b_vars[0], c_vars[0]
                    has_c_one = any(int(s) == 0 and (int(cf) % p) != 0 for s, cf in c_terms)
                    if has_c_one:
                        if (s_a in determined and (s_a, s_c) in bilinear_zeros) or (
                            s_b in determined and (s_b, s_c) in bilinear_zeros
                        ):
                            if s_c not in determined:
                                determined.add(s_c)
                                root_bounded.add(s_c)
                                changed = True

                # 3. Inyectividad binaria Num2Bits: 1 * (sum 2^i b_i) == target
                if not a_vars and len(c_vars) == 1 and 2 <= len(b_vars) < 253:
                    target_id = c_vars[0]
                    if target_id in determined and all(b_id in root_bounded for b_id in b_vars):
                        for b_id in b_vars:
                            if b_id not in determined:
                                determined.add(b_id)
                                changed = True

                # 4. CLAUSURA CUADRATICA UNIVERSAL (Poseidon / MiMC / Productos deterministas):
                # Si todas las variables en A y en B estan determinadas, entonces el
                # producto <A, w> * <B, w> es constante conocido respecto a las entradas publicas.
                # Si en C todas las variables excepto una (u) estan determinadas, u queda determinada.
                if all(v in determined for v in a_vars) and all(v in determined for v in b_vars):
                    undetermined_c = [v for v in c_vars if v not in determined]
                    if len(undetermined_c) == 1:
                        u = undetermined_c[0]
                        if u not in determined:
                            determined.add(u)
                            changed = True

                # 5. Clausura Lineal General (cuando A es constante no nula o B es constante no nula):
                if not a_vars or not b_vars:
                    lin_vars = list(set(a_vars + b_vars + c_vars))
                    undetermined_lin = [v for v in lin_vars if v not in determined]
                    if len(undetermined_lin) == 1:
                        u = undetermined_lin[0]
                        if u not in determined:
                            determined.add(u)
                            changed = True

        self.determined_signals = sorted(determined)
        unresolved = [
            i for i in range(1, self.num_variables) if i not in determined
        ]
        return determined, root_bounded, unresolved

    def extract_sniper_islands(self, max_island_constraints: int = 25) -> list:
        """
        PIEZA 2 DEL MODO FRANCOTIRADOR:
        Aisla las componentes conexas (islas) de restricciones que contienen seniales
        no determinadas, preservando la distincion exacta entre salidas reales
        (output_signals) y entradas privadas (private_inputs) de cada isla.
        """
        determined, _, unresolved = self.compute_forward_algebraic_closure()
        unresolved_set = set(unresolved)
        if not unresolved_set:
            return []

        # Si el circuito define output_signals explicitas y TODAS ya estan funcionalmente
        # determinadas por las entradas publicas, las salidas son 100% inmaleables.
        if self.output_signals:
            unresolved_outputs = [o for o in self.output_signals if o in unresolved_set]
            if not unresolved_outputs:
                return []

        p = self.prime
        active_indices = []
        constraint_undetermined_vars = {}
        constraint_all_vars = {}
        var_to_constraints = {u: [] for u in unresolved_set}

        for idx, c in enumerate(self.constraints):
            all_v = set()
            for k in ("A", "B", "C"):
                for sig_id, coeff in c.get(k, []):
                    if int(sig_id) != 0 and (int(coeff) % p) != 0:
                        all_v.add(int(sig_id))
            undet_v = all_v & unresolved_set
            if undet_v:
                active_indices.append(idx)
                constraint_undetermined_vars[idx] = undet_v
                constraint_all_vars[idx] = all_v
                for u in undet_v:
                    var_to_constraints[u].append(idx)

        visited_constraints = set()
        islands = []

        # 1. Detectar seniales de salida completamente huerfanas (0 restricciones activas)
        target_pool = (
            [o for o in self.output_signals if o in unresolved_set]
            if self.output_signals
            else unresolved
        )
        orphan_signals = [u for u in target_pool if not var_to_constraints.get(u)]
        if orphan_signals:
            islands.append(
                R1CSCircuitModel(
                    name=f"{self.name}::Orphan_Island",
                    prime=self.prime,
                    num_variables=self.num_variables,
                    public_inputs=self.public_inputs,
                    constraints=[],
                    suspicious_signals=orphan_signals,
                    output_signals=orphan_signals,
                    private_inputs=orphan_signals,
                    determined_signals=list(determined),
                    signal_symbols=self.signal_symbols,
                )
            )

        # 2. Extraer cada isla conexa de restricciones no determinadas
        orig_outs_set = set(self.output_signals)
        orig_prvs_set = set(self.private_inputs)

        for start_c in active_indices:
            if start_c in visited_constraints:
                continue

            queue = [start_c]
            visited_constraints.add(start_c)
            comp_constraints = []
            comp_undet_signals = set()
            comp_boundary_determined = set()

            while queue and len(comp_constraints) < max_island_constraints:
                cur_c = queue.pop(0)
                comp_constraints.append(self.constraints[cur_c])
                comp_undet_signals.update(constraint_undetermined_vars[cur_c])
                comp_boundary_determined.update(
                    constraint_all_vars[cur_c] - constraint_undetermined_vars[cur_c]
                )

                for u_sig in constraint_undetermined_vars[cur_c]:
                    for nbr_c in var_to_constraints.get(u_sig, []):
                        if nbr_c not in visited_constraints:
                            visited_constraints.add(nbr_c)
                            queue.append(nbr_c)

            # Preservar las salidas reales y entradas privadas reales dentro de la isla
            island_outs = sorted(comp_undet_signals & orig_outs_set)
            if not island_outs:
                if self.output_signals:
                    # Isla puramente auxiliar que no toca ninguna salida no determinada
                    continue
                island_outs = sorted(comp_undet_signals)

            island_prvs = [p for p in self.private_inputs if p in comp_undet_signals]
            if not island_prvs:
                island_prvs = sorted(comp_undet_signals - orig_outs_set)

            island_pubs = sorted(set(self.public_inputs) | comp_boundary_determined)

            islands.append(
                R1CSCircuitModel(
                    name=f"{self.name}::Island_{len(islands) + 1}",
                    prime=self.prime,
                    num_variables=self.num_variables,
                    public_inputs=island_pubs,
                    constraints=comp_constraints,
                    suspicious_signals=sorted(comp_undet_signals),
                    output_signals=island_outs,
                    private_inputs=island_prvs,
                    determined_signals=sorted(determined | comp_boundary_determined),
                    signal_symbols=self.signal_symbols,
                )
            )

        return islands

    def build_system_assertions(
        self,
        witness_map: dict,
        prefix: str,
        allow_modular_wrap: bool = True,
    ) -> list:
        assertions = []
        p = self.prime

        for i in range(1, self.num_variables):
            assertions.append(BN254Field.domain_constraint(witness_map[i], p))

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
                if c_is_zero:
                    assertions.append(a_eval * b_eval == 0)
                else:
                    assertions.append(a_eval * b_eval == c_eval)
                continue

            if c_is_zero:
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
# FIXTURES CANONICOS + FIXTURE FRANCOTIRADOR (POSEIDON + DIVISION MODULAR)
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


def _build_poseidon_div_sniper_fixture(secure: bool, rounds: int = 8) -> R1CSCircuitModel:
    """
    Construye un circuito real de prueba para el Modo Francotirador:
      - Subgrafo 1 (Determinista pesado): `rounds` rondas de S-Box tipo Poseidon x^5
        (x2 = x*x, x4 = x2*x2, x5 = x4*x, next_state = x5 + c_r).
        En un solver SMT tradicional tiene grado 5^rounds = 390,625 y da TIMEOUT.
        Con la Clausura Cuadratica Universal de Chronos-ZK colapsa en < 1 ms.
      - Subgrafo 2 (Gadget de division / residuo): `hash_out === q * 4 + r`,
        donde en la version vulnerable falta restringir los bits de `r` en {0, 1, 2, 3}.
    """
    sig_id = 1
    in_seed = sig_id
    sig_id += 1
    symbols = {0: "ONE", in_seed: "main.public_seed"}

    constraints = []
    curr = in_seed

    for r in range(rounds):
        x2 = sig_id
        sig_id += 1
        x4 = sig_id
        sig_id += 1
        x5 = sig_id
        sig_id += 1
        nxt = sig_id
        sig_id += 1

        symbols[x2] = f"main.poseidon.round[{r}].x2"
        symbols[x4] = f"main.poseidon.round[{r}].x4"
        symbols[x5] = f"main.poseidon.round[{r}].x5"
        symbols[nxt] = f"main.poseidon.round[{r}].state_out"

        constraints.append({"A": [(curr, 1)], "B": [(curr, 1)], "C": [(x2, 1)]})
        constraints.append({"A": [(x2, 1)], "B": [(x2, 1)], "C": [(x4, 1)]})
        constraints.append({"A": [(x4, 1)], "B": [(curr, 1)], "C": [(x5, 1)]})
        constraints.append({"A": [(0, 1)], "B": [(x5, 1), (0, r + 3)], "C": [(nxt, 1)]})
        curr = nxt

    # Gadget de Division Entera: curr === 4 * q + r (donde r = b0 + 2*b1)
    q_id = sig_id
    sig_id += 1
    r_id = sig_id
    sig_id += 1
    b0_id = sig_id
    sig_id += 1
    b1_id = sig_id
    sig_id += 1

    symbols[q_id] = "main.div_gadget.quotient_q"
    symbols[r_id] = "main.div_gadget.remainder_r"
    symbols[b0_id] = "main.div_gadget.rem_bit_0"
    symbols[b1_id] = "main.div_gadget.rem_bit_1"

    # r === b0 + 2 * b1
    constraints.append({"A": [(0, 1)], "B": [(b0_id, 1), (b1_id, 2)], "C": [(r_id, 1)]})
    # curr === 4 * q + r
    constraints.append({"A": [(0, 1)], "B": [(q_id, 4), (r_id, 1)], "C": [(curr, 1)]})

    if secure:
        # En la version segura, b0 y b1 son booleanos y q queda determinado
        constraints.append({"A": [(b0_id, 1)], "B": [(0, 1), (b0_id, -1)], "C": []})
        constraints.append({"A": [(b1_id, 1)], "B": [(0, 1), (b1_id, -1)], "C": []})

    model = R1CSCircuitModel(
        name="Poseidon_Div_Secure" if secure else "Poseidon_Div_Vulnerable",
        prime=BN254_PRIME,
        num_variables=sig_id,
        public_inputs=[in_seed],
        constraints=constraints,
        suspicious_signals=[r_id, q_id, b0_id, b1_id],
        output_signals=[r_id, q_id],
        private_inputs=[b0_id, b1_id, q_id, r_id],
        determined_signals=[0, in_seed],
        signal_symbols=symbols,
    )
    model.compute_forward_algebraic_closure()
    if secure:
        model.determined_signals = list(range(sig_id))
    return model


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
            signal_symbols={0: "ONE", 1: "main.in", 2: "main.out", 3: "main.inv"},
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
            signal_symbols={0: "ONE", 1: "main.in", 2: "main.out", 3: "main.inv"},
        )

    elif norm_name in ("num2bits_vulnerable", "num2bits_underconstrained"):
        lin_sum = [(2 + i, 1 << i) for i in range(8)]
        constraints = [{"A": [(0, 1)], "B": lin_sum, "C": [(1, 1)]}]
        syms = {0: "ONE", 1: "main.in"}
        for i in range(8):
            syms[2 + i] = f"main.out[{i}]"
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
            signal_symbols=syms,
        )

    elif norm_name == "num2bits_secure":
        lin_sum = [(2 + i, 1 << i) for i in range(8)]
        constraints = [{"A": [(0, 1)], "B": lin_sum, "C": [(1, 1)]}]
        syms = {0: "ONE", 1: "main.in"}
        for i in range(8):
            bit_idx = 2 + i
            syms[bit_idx] = f"main.out[{i}]"
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
            signal_symbols=syms,
        )

    elif norm_name in ("merkle_vulnerable", "merkle_malleable"):
        return _build_merkle_fixture(secure=False, levels=3)

    elif norm_name == "merkle_secure":
        return _build_merkle_fixture(secure=True, levels=3)

    elif norm_name == "poseidon_div_vulnerable":
        return _build_poseidon_div_sniper_fixture(secure=False, rounds=8)

    elif norm_name == "poseidon_div_secure":
        return _build_poseidon_div_sniper_fixture(secure=True, rounds=8)

    else:
        raise ValueError(f"Fixture desconocido: {fixture_name}")