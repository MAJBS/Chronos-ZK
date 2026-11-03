#!/usr/bin/env bash
set -e

echo "==============================================================================="
echo "=== CHRONOS-ZK: AUDITOR FORMAL SMT DE CIRCUITOS CRIPTOGRAFICOS (POSIX)      ==="
echo "==============================================================================="

if [ -z "$1" ]; then
    echo "[ERROR] No se especifico el archivo de circuito."
    echo "Uso: ./audit_circuit.sh <circuito.circom|r1cs.json> [--gpu | --cpu]"
    exit 1
fi

TARGET_CIRCUIT="$1"
MODE="--cpu"
if [ "$2" == "--gpu" ]; then
    MODE="--gpu"
fi

echo "[*] Target: $TARGET_CIRCUIT"
echo "[*] Modo de aceleracion: $MODE"

# 1. Verificar y compilar el podador de Rust si no existe
if [ ! -f "core_pruner/target/release/core_pruner" ]; then
    echo "[*] Binario de Rust no detectado. Compilando core_pruner en release..."
    (cd core_pruner && cargo build --release)
fi

# 2. Si el modo es GPU, verificar binario CUDA
if [ "$MODE" == "--gpu" ]; then
    if [ ! -f "cuda_pruner/zk_megakernel" ]; then
        if command -v nvcc &> /dev/null; then
            echo "[*] Binario CUDA no detectado. Compilando zk_megakernel con NVCC..."
            (cd cuda_pruner && bash build_cuda.sh)
        else
            echo "[WARN] NVCC no disponible en este entorno; ejecutando con fallback a CPU L4."
            MODE="--cpu"
        fi
    fi
fi

# 3. Ejecutar la Poda Coinductiva L4
echo ""
echo "[*] FASE 1: Podando grafo de restricciones con Chronos-ZK ($MODE)..."
./core_pruner/target/release/core_pruner --input "$TARGET_CIRCUIT" --output pruned_ir.json "$MODE"

# 4. Ejecutar el Oraculo SMT en Z3
echo ""
echo "[*] FASE 2: Verificando unicidad de testigo formal en Z3 SMT Solver..."
python3 -m smt_verifier.witness_uniqueness --ir pruned_ir.json

echo ""
echo "==============================================================================="
echo "[EXITO] Auditoria formal finalizada sin excepciones de ejecucion."
echo "==============================================================================="