"""
=============================================================================
CHRONOS-ZK: ESCANER MASIVO DE REPOSITORIOS PARA BUG BOUNTIES (--SNIPER)
Modulo: tools/bounty_scanner.py
Proposito: Recorre recursivamente cualquier directorio de circuitos (.r1cs,
           .circom, .json), ejecuta la poda coinductiva L4 y el Modo
           Francotirador por Islas en silencio (sin rebalsar la consola),
           imprime la Tabla Ejecutiva de Exploits Confirmados y exporta el
           reporte completo a `BOUNTY_SCAN_REPORT.md`.
=============================================================================
"""

import argparse
import contextlib
import io
import os
import subprocess
import time
from tabulate import tabulate

from smt_verifier.bn254_field import log_telemetry
from smt_verifier.r1cs_to_z3 import R1CSCircuitModel
from smt_verifier.witness_uniqueness import audit_sniper_islands


def discover_circuit_files(target_path: str) -> list:
    if os.path.isfile(target_path):
        return [target_path]

    found = []
    for root, dirs, files in os.walk(target_path):
        dirs[:] = [
            d
            for d in dirs
            if d not in (".git", ".venv", "venv", "target", "node_modules", "__pycache__")
        ]
        for fname in sorted(files):
            if fname.endswith((".r1cs", ".circom", ".snarkjs.json")):
                found.append(os.path.join(root, fname))
    return found


def scan_repository_targets(
    target_dir: str,
    use_gpu: bool = True,
    timeout_ms: int = 10000,
    report_path: str = "BOUNTY_SCAN_REPORT.md",
):
    print("\n" + "=" * 95)
    log_telemetry("BOUNTY_SCAN", f"Iniciando barrido Francotirador silencioso sobre: {target_dir}")
    print("=" * 95)

    targets = discover_circuit_files(target_dir)
    if not targets:
        log_telemetry("WARN", "No se encontraron archivos (.r1cs, .circom, .snarkjs.json) en la ruta.")
        return

    pruner_exe = os.path.join(
        "core_pruner",
        "target",
        "release",
        "core_pruner.exe" if os.name == "nt" else "core_pruner",
    )
    mode_flag = "--gpu" if use_gpu else "--cpu"
    tmp_ir = "bounty_scan_ir.tmp.json"

    all_rows = []
    vuln_rows = []
    secure_count = 0

    for idx, fpath in enumerate(targets, 1):
        rel_path = os.path.relpath(fpath)
        sym_candidate = os.path.splitext(fpath)[0] + ".sym"

        cmd = [pruner_exe, "--input", fpath, "--output", tmp_ir, mode_flag]
        if os.path.exists(sym_candidate):
            cmd.extend(["--sym", sym_candidate])

        t0 = time.perf_counter()
        proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
        if proc.returncode != 0 or not os.path.exists(tmp_ir):
            all_rows.append([idx, rel_path, "ERR", "-", "-", "-", "PARSE_ERROR"])
            continue

        with contextlib.redirect_stdout(io.StringIO()):
            model = R1CSCircuitModel.from_json(
                tmp_ir, sym_path=sym_candidate if os.path.exists(sym_candidate) else None
            )
            determined, _, _ = model.compute_forward_algebraic_closure()
            islands = model.extract_sniper_islands()
            res = audit_sniper_islands(model, timeout_ms=timeout_ms, output_poc_path="exploit_poc.json")

        total_ms = (time.perf_counter() - t0) * 1000.0
        verdict = res["verdict"]

        if verdict == "VULNERABLE":
            rep = res.get("exploit_report", {})
            divs = rep.get("divergent_signals", [])
            top_signal = "-"
            if divs:
                first_div = divs[0]
                top_signal = f"w_{first_div['signal_id']} ({first_div.get('symbol_name', '')})"
            verdict_str = f"SAT [EXPLOIT: {top_signal}]"
            row_data = [
                idx,
                rel_path,
                f"{len(model.constraints)}",
                f"{len(determined)}/{model.num_variables}",
                f"{len(islands)}",
                f"{total_ms:.1f} ms",
                verdict_str,
            ]
            all_rows.append(row_data)
            vuln_rows.append(row_data)
        elif verdict == "SECURE":
            secure_count += 1
            all_rows.append([
                idx,
                rel_path,
                f"{len(model.constraints)}",
                f"{len(determined)}/{model.num_variables}",
                f"{len(islands)}",
                f"{total_ms:.1f} ms",
                "UNSAT [SECURE]",
            ])
        else:
            all_rows.append([
                idx,
                rel_path,
                f"{len(model.constraints)}",
                f"{len(determined)}/{model.num_variables}",
                f"{len(islands)}",
                f"{total_ms:.1f} ms",
                "TIMEOUT / UNKNOWN",
            ])

        if len(targets) > 15 and (idx % 20 == 0 or idx == len(targets)):
            log_telemetry(
                "PROGRESS",
                f"Auditados {idx}/{len(targets)} circuitos | Seguros: {secure_count} | Exploits SAT: {len(vuln_rows)}",
            )

    if os.path.exists(tmp_ir):
        os.remove(tmp_ir)

    headers = [
        "#",
        "Circuit Target",
        "R1CS",
        "L4 Determined",
        "Islands",
        "Total Time",
        "Formal Sniper Verdict",
    ]

    print("\n" + "=" * 95)
    log_telemetry(
        "BOUNTY_REPORT",
        f"Barrido finalizado: {len(targets)} circuitos | {secure_count} SEGUROS | {len(vuln_rows)} EXPLOITS SAT",
    )
    print("=" * 95)

    # Si hay mas de 20 archivos, imprimir en consola SOLO la tabla compacta de Exploits encontrados
    # para nunca rebalsar la terminal, y guardar las dos tablas en BOUNTY_SCAN_REPORT.md.
    if len(targets) > 20 and vuln_rows:
        print("\n>>> RESUMEN COMPACTO DE OBJETIVOS VULNERABLES (SAT EXPLOITS DETECTADOS):")
        print(tabulate(vuln_rows, headers=headers, tablefmt="fancy_grid") + "\n")
    else:
        print("\n" + tabulate(all_rows, headers=headers, tablefmt="fancy_grid") + "\n")

    md_content = [
        f"# Chronos-ZK Sniper Bounty Scan Report (`{target_dir}`)",
        "",
        f"- **Total Circuits Audited:** {len(targets)}",
        f"- **Formally Certified Secure (`UNSAT`):** {secure_count}",
        f"- **Exploitable Under-Constrained (`SAT`):** {len(vuln_rows)}",
        "",
        "## 1. Confirmed Exploitable Targets (`SAT`)",
        "",
        tabulate(vuln_rows, headers=headers, tablefmt="github") if vuln_rows else "_No vulnerabilities detected._",
        "",
        "## 2. Full Repository Audit Table",
        "",
        tabulate(all_rows, headers=headers, tablefmt="github"),
        "",
    ]
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("\n".join(md_content))

    log_telemetry("REPORT_SAVED", f"Reporte completo guardado sin recortes en: {report_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Chronos-ZK Multi-Circuit Bug Bounty Scanner")
    parser.add_argument("target", type=str, help="Directorio o archivo de circuito a escanear")
    parser.add_argument("--cpu", action="store_true", help="Forzar modo CPU")
    parser.add_argument("--timeout", type=int, default=10000, help="Timeout Z3 por isla en ms")
    args = parser.parse_args()

    scan_repository_targets(args.target, use_gpu=not args.cpu, timeout_ms=args.timeout)