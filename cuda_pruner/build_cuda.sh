#!/usr/bin/env bash
set -e

echo "[TELEMETRIA] | COMPILER | Inicializando compilacion del Reactor CUDA ZK (Ampere sm_86) en POSIX..."

rm -f zk_megakernel

if ! command -v nvcc &> /dev/null; then
    echo "[FATAL] | COMPILER | nvcc no detectado en PATH. Instala CUDA Toolkit 12.x."
    exit 1
fi

echo "[TELEMETRIA] | NVCC | Compilando zk_megakernel.cu con optimizacion -O3 para arquitectura sm_86..."
nvcc -allow-unsupported-compiler -O3 -arch=sm_86 -use_fast_math -std=c++17 zk_megakernel.cu -o zk_megakernel

if [ ! -f "zk_megakernel" ]; then
    echo "[FATAL] | COMPILER | Error generando binario CUDA zk_megakernel."
    exit 1
fi

chmod +x zk_megakernel
echo "[TELEMETRIA] | VERDICT | Compilacion finalizada con exito. Binario: zk_megakernel"