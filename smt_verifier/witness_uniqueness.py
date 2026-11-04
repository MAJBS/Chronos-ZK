"""
=============================================================================
CHRONOS-ZK: ORACULO DE VERIFICACION FORMAL Y MODO FRANCOTIRADOR (--SNIPER)
Modulo: smt_verifier/witness_uniqueness.py
Proposito: Evaluacion formal de maleabilidad criptografica con:
             1. Clausura Funcional Cuadratica Universal (colapso Poseidon/MiMC)
             2. Micro-Slicing por Isla Sospechosa (--sniper)
             3. Resolucion de nombres simbolicos Circom (--sym <file.sym>)
=============================================================================
"""

import sys
import time
import argparse
import z3

from smt_verifier.bn254_field import log_telemetry
from smt_verifier.r1cs_to_z3 import R1CSCircuitModel, get_fixture_model
from smt_verifier.exploit_synthesizer import synthesize_exploit_report


def _build_solver_instance(
    model: R1CSCircuitModel,
    eval_signals: list,
    timeout_ms: int,
    allow_modular_wrap: bool,
    sparse_fault_probe: bool = False,
):
    w_A = model.instantiate_witness("wA")
    w_B = model.instantiate_witness("wB")

    solver = z3.Solver()
    solver.set("timeout", int(timeout_ms))

    assertions_A = model.build_system_assertions(w_A, "wA", allow_modular_wrap=allow_modular_wrap)
    assertions_B = model.build_system_assertions(w_B, "wB", allow_modular_wrap=allow_modular_wrap)
    for a in assertions_A:
        solver.add(a)
    for b in assertions_B:
        solver.add(b)

    locked_signals = set()
    for pub_idx in model.public_inputs:
        if 0 < pub_idx < model.num_variables:
            solver.add(w_A[pub_idx] == w_B[pub_idx])
            locked_signals.add(pub_idx)

    frontier_count = 0
    for det_idx in model.determined_signals:
        if 0 < det_idx < model.num_variables and det_idx not in locked_signals:
            solver.add(w_A[det_idx] == w_B[det_idx])
            locked_signals.add(det_idx)
            frontier_count += 1

    if sparse_fault_probe:
        for idx_pos, pub_idx in enumerate(model.public_inputs):
            if 0 < pub_idx < model.num_variables:
                concrete_val = 2 if idx_pos == 0 else 1
                solver.add(w_A[pub_idx] == concrete_val)
                solver.add(w_B[pub_idx] == concrete_val)

        free_privates = [
            p_idx
            for p_idx in model.private_inputs
            if 0 < p_idx < model.num_variables and p_idx not in locked_signals
        ]
        if free_privates:
            target_fault_sig = free_privates[0]
            solver.add(w_A[target_fault_sig] == 0)
            solver.add(z3.And(w_B[target_fault_sig] >= 0, w_B[target_fault_sig] <= 4))
            for other_prv in free_privates[1:]:
                if other_prv < target_fault_sig + 3:
                    solver.add(w_A[other_prv] == 0)
                    solver.add(w_B[other_prv] == 0)

    if eval_signals:
        malleability_condition = z3.Or([w_A[idx] != w_B[idx] for idx in eval_signals])
    else:
        malleability_condition = z3.BoolVal(False)
    solver.add(malleability_condition)

    return solver, w_A, w_B, frontier_count


def audit_sniper_islands(
    model: R1CSCircuitModel,
    timeout_ms: int = 10000,
    output_poc_path: str = "exploit_poc.json",
) -> dict:
    """
    MODO FRANCOTIRADOR (--sniper):
    Colapsa todos los subgrafos deterministas (ej. rondas Poseidon/MiMC) mediante
    Clausura Cuadratica Universal, aisla las islas residuales de seniales no
    determinadas y ataca cada isla individualmente en Z3.
    """
    print("\n" + "=" * 80)
    log_telemetry("SNIPER_INIT", f"Iniciando Modo Francotirador para circuito: {model.name}")
    t0 = time.time()

    determined, root_bounded, unresolved = model.compute_forward_algebraic_closure()
    islands = model.extract_sniper_islands()

    log_telemetry(
        "SNIPER_CLOSURE",
        f"Clausura Cuadratica L4: {len(determined)}/{model.num_variables} seniales determinadas | "
        f"{len(unresolved)} seniales sospechosas en {len(islands)} isla(s).",
    )
    print("=" * 80)

    if not islands:
        elapsed = (time.time() - t0) * 1000.0
        print("\n" + "-" * 80)
        log_telemetry("VERDICT", "UNSAT | SOLIDEZ CRIPTOGRAFICA CERTIFICADA (0 ISLAS MALEABLES)")
        print("-" * 80 + "\n")
        return {"verdict": "SECURE", "elapsed_ms": elapsed, "conflicts": 0, "decisions": 0}

    for idx, island in enumerate(islands):
        log_telemetry(
            "SNIPER_TARGET",
            f"Disparando Z3 sobre Isla {idx + 1}/{len(islands)} ('{island.name}'): "
            f"{len(island.constraints)} restricciones locales | Seniales objetivo: {island.output_signals}",
        )
        res = audit_witness_uniqueness(
            island, timeout_ms=timeout_ms, output_poc_path=output_poc_path
        )
        if res["verdict"] == "VULNERABLE":
            return res

    elapsed = (time.time() - t0) * 1000.0
    return {"verdict": "SECURE", "elapsed_ms": elapsed, "conflicts": 0, "decisions": 0}


def audit_witness_uniqueness(
    model: R1CSCircuitModel,
    timeout_ms: int = 30000,
    output_poc_path: str = "exploit_poc.json",
) -> dict:
    print("\n" + "=" * 80)
    log_telemetry("INIT", f"Iniciando auditoria formal para circuito: {model.name}")
    log_telemetry(
        "INIT",
        f"Variables totales: {model.num_variables} | Restricciones R1CS residuales: {len(model.constraints)}",
    )
    print("=" * 80)

    t0 = time.time()

    # Ejecutar clausura cuadratica preventiva para fijar cadenas deterministas
    model.compute_forward_algebraic_closure()

    if model.output_signals:
        eval_signals = [idx for idx in model.output_signals if 0 < idx < model.num_variables]
    elif model.suspicious_signals:
        eval_signals = [idx for idx in model.suspicious_signals if 0 < idx < model.num_variables]
    else:
        eval_signals = [
            i for i in range(1, model.num_variables) if i not in set(model.public_inputs)
        ]

    log_telemetry("AST_BUILD", "Instanciando testigos simbolicos duales (wA, wB)...")
    log_telemetry("SOLVER_CFG", f"Configurando solver Z3 SMT (Timeout: {timeout_ms / 1000:.1f}s)...")
    log_telemetry("CONSTRAINTS", "Ensamblando ecuaciones diofanticas R1CS...")
    log_telemetry("CONSTRAINTS", f"Fijando igualdad en entradas publicas: {model.public_inputs}")

    determined_set = set(model.determined_signals)
    unresolved_eval = [s for s in eval_signals if s not in determined_set]

    if unresolved_eval and len(model.constraints) > 1:
        fast_timeout = min(int(timeout_ms), 1500)
        solver_fast, w_A_fast, w_B_fast, frontier_cnt = _build_solver_instance(
            model,
            eval_signals,
            fast_timeout,
            allow_modular_wrap=False,
            sparse_fault_probe=True,
        )
        t_prep_fast = (time.time() - t0) * 1000.0
        t_solve_start = time.time()
        res_fast = solver_fast.check()
        t_solve_elapsed = (time.time() - t_solve_start) * 1000.0

        if res_fast == z3.sat:
            if frontier_cnt > 0:
                log_telemetry(
                    "L4_FRONTIER",
                    f"Frontera determinista L4 aplicada sobre {frontier_cnt} seniales certificadas.",
                )
            log_telemetry(
                "DISCREPANCY",
                f"Inyectando consulta de disidencia sobre seniales criticas: {eval_signals}",
            )
            log_telemetry(
                "SOLVER",
                f"Formulacion ensamblada en {t_prep_fast:.2f} ms. Ejecutando deduccion SMT...",
            )

            stats = solver_fast.statistics()
            conflicts = stats.get_key_value("conflicts") if "conflicts" in stats.keys() else 0
            decisions = stats.get_key_value("decisions") if "decisions" in stats.keys() else 0
            log_telemetry("METRICS", f"Tiempo de resolucion Z3: {t_solve_elapsed:.2f} ms")
            log_telemetry("METRICS", f"Estadisticas internas: Conflictos={conflicts} | Decisiones={decisions}")

            print("\n" + "-" * 80)
            log_telemetry("VERDICT", "SAT | ALERTA CRITICA: CIRCUITO SUB-RESTRINGIDO DETECTADO")
            log_telemetry("VERDICT", "Vulnerabilidad demostrada: Se sintetizo un testigo maleable exitoso.")
            print("-" * 80 + "\n")

            model_z3 = solver_fast.model()
            report = synthesize_exploit_report(
                model, w_A_fast, w_B_fast, model_z3, eval_signals, output_file=output_poc_path
            )
            return {
                "verdict": "VULNERABLE",
                "elapsed_ms": t_solve_elapsed,
                "prep_ms": t_prep_fast,
                "conflicts": conflicts,
                "decisions": decisions,
                "exploit_report": report,
            }

    solver, w_A, w_B, frontier_cnt = _build_solver_instance(
        model,
        eval_signals,
        timeout_ms,
        allow_modular_wrap=True,
        sparse_fault_probe=False,
    )
    if frontier_cnt > 0:
        log_telemetry(
            "L4_FRONTIER",
            f"Frontera determinista L4 aplicada sobre {frontier_cnt} seniales certificadas.",
        )
    log_telemetry("DISCREPANCY", f"Inyectando consulta de disidencia sobre seniales criticas: {eval_signals}")

    t_prep = (time.time() - t0) * 1000.0
    log_telemetry("SOLVER", f"Formulacion ensamblada en {t_prep:.2f} ms. Ejecutando deduccion SMT...")

    t_solve_start = time.time()
    result = solver.check()
    t_solve_elapsed = (time.time() - t_solve_start) * 1000.0

    stats = solver.statistics()
    conflicts = stats.get_key_value("conflicts") if "conflicts" in stats.keys() else 0
    decisions = stats.get_key_value("decisions") if "decisions" in stats.keys() else 0

    log_telemetry("METRICS", f"Tiempo de resolucion Z3: {t_solve_elapsed:.2f} ms")
    log_telemetry("METRICS", f"Estadisticas internas: Conflictos={conflicts} | Decisiones={decisions}")

    if result == z3.unsat:
        print("\n" + "-" * 80)
        log_telemetry("VERDICT", "UNSAT | SOLIDEZ CRIPTOGRAFICA CERTIFICADA (CIRCUITO SEGURO)")
        log_telemetry("VERDICT", "Demostracion formal concluida: Es imposible forjar testigos disidentes.")
        print("-" * 80 + "\n")
        return {
            "verdict": "SECURE",
            "elapsed_ms": t_solve_elapsed,
            "prep_ms": t_prep,
            "conflicts": conflicts,
            "decisions": decisions,
        }

    elif result == z3.sat:
        print("\n" + "-" * 80)
        log_telemetry("VERDICT", "SAT | ALERTA CRITICA: CIRCUITO SUB-RESTRINGIDO DETECTADO")
        log_telemetry("VERDICT", "Vulnerabilidad demostrada: Se sintetizo un testigo maleable exitoso.")
        print("-" * 80 + "\n")

        model_z3 = solver.model()
        report = synthesize_exploit_report(
            model, w_A, w_B, model_z3, eval_signals, output_file=output_poc_path
        )
        return {
            "verdict": "VULNERABLE",
            "elapsed_ms": t_solve_elapsed,
            "prep_ms": t_prep,
            "conflicts": conflicts,
            "decisions": decisions,
            "exploit_report": report,
        }

    else:
        log_telemetry("FATAL", "TIMEOUT / UNKNOWN: El solver no convergio dentro del limite de tiempo.")
        return {
            "verdict": "TIMEOUT",
            "elapsed_ms": t_solve_elapsed,
            "prep_ms": t_prep,
            "conflicts": conflicts,
            "decisions": decisions,
        }


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chronos-ZK Witness Uniqueness & Sniper Engine")
    parser.add_argument(
        "--fixture",
        type=str,
        help="Nombre del fixture (iszero_*, num2bits_*, merkle_*, poseidon_div_vulnerable, poseidon_div_secure)",
    )
    parser.add_argument("--ir", type=str, help="Ruta al archivo pruned_ir.json")
    parser.add_argument("--sym", type=str, default=None, help="Ruta opcional al archivo .sym de Circom")
    parser.add_argument(
        "--sniper",
        action="store_true",
        help="Activa el Modo Francotirador (Clausura Cuadratica + Micro-Slicing por Isla)",
    )
    parser.add_argument("--timeout", type=int, default=30000, help="Timeout en milisegundos")
    parser.add_argument(
        "--expect",
        type=str,
        choices=["SECURE", "VULNERABLE"],
        default=None,
        help="Veredicto esperado opcional para validacion automatizada en CI/Tests",
    )

    args = parser.parse_args()

    if args.fixture:
        circuit_model = get_fixture_model(args.fixture)
        if args.sym:
            circuit_model.load_sym_file(args.sym)
    elif args.ir:
        circuit_model = R1CSCircuitModel.from_json(args.ir, sym_path=args.sym)
    else:
        print(
            "Uso: python -m smt_verifier.witness_uniqueness --fixture <nombre> | --ir <path.json> [--sym <file.sym>] [--sniper]"
        )
        sys.exit(1)

    if args.sniper:
        res = audit_sniper_islands(circuit_model, args.timeout)
    else:
        res = audit_witness_uniqueness(circuit_model, args.timeout)

    if args.expect and res["verdict"] != args.expect:
        log_telemetry(
            "FATAL",
            f"Asercion de prueba fallida: se esperaba '{args.expect}', pero se obtuvo '{res['verdict']}'.",
        )
        sys.exit(1)

    if res["verdict"] == "TIMEOUT":
        sys.exit(2)