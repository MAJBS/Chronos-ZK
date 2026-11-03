"""
=============================================================================
CHRONOS-ZK: PAQUETE DE VERIFICACION FORMAL SMT Y SINTESIS DE EXPLOITS
Modulo: smt_verifier/__init__.py
Proposito: Exportacion canonica del motor algebraico BN254 y traductor R1CS
           (sin importar anticipadamente el entrypoint CLI witness_uniqueness
           para evitar RuntimeWarning en ejecuciones con `python -m`).
=============================================================================
"""

from smt_verifier.bn254_field import BN254_PRIME, BN254_HALF_PRIME, BN254Field, log_telemetry
from smt_verifier.r1cs_to_z3 import R1CSCircuitModel, get_fixture_model
from smt_verifier.exploit_synthesizer import synthesize_exploit_report, verify_witness_satisfies_r1cs

__all__ = [
    "BN254_PRIME",
    "BN254_HALF_PRIME",
    "BN254Field",
    "log_telemetry",
    "R1CSCircuitModel",
    "get_fixture_model",
    "synthesize_exploit_report",
    "verify_witness_satisfies_r1cs",
]