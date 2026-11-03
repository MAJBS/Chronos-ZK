@echo off
setlocal enabledelayedexpansion

echo ===============================================================================
echo === CHRONOS-ZK: AUDITOR FORMAL SMT DE CIRCUITOS CRIPTOGRAFICOS              ===
echo ===============================================================================

if "%~1"=="" (
    echo [ERROR] No se especifico el archivo de circuito.
    echo Uso: .\audit_circuit.bat ^<circuito.circom^|r1cs.json^> [--gpu ^| --cpu]
    exit /b 1
)

set TARGET_CIRCUIT=%~1
set MODE=--cpu
if /I "%~2"=="--gpu" set MODE=--gpu
if /I "%~2"=="--cpu" set MODE=--cpu

echo [*] Target: %TARGET_CIRCUIT%
echo [*] Modo de aceleracion: %MODE%

REM 1. Verificar y compilar el podador de Rust si no existe
if not exist "core_pruner\target\release\core_pruner.exe" (
    echo [*] Binario de Rust no detectado. Compilando core_pruner en release...
    cd core_pruner
    cargo build --release
    if !ERRORLEVEL! NEQ 0 (
        cd ..
        echo [FATAL] Error compilando core_pruner en Rust.
        exit /b 1
    )
    cd ..
)

REM 2. Si el modo es GPU, verificar binario CUDA
if "%MODE%"=="--gpu" (
    if not exist "cuda_pruner\zk_megakernel.exe" (
        echo [*] Binario CUDA no detectado. Compilando zk_megakernel con NVCC sm_86...
        cd cuda_pruner
        call build_cuda.bat
        if !ERRORLEVEL! NEQ 0 (
            cd ..
            echo [FATAL] Error compilando zk_megakernel en CUDA.
            exit /b 1
        )
        cd ..
    )
)

REM 3. Ejecutar la Poda Coinductiva L4 (Genera pruned_ir.json pasando %MODE%)
echo.
echo [*] FASE 1: Podando grafo de restricciones con Chronos-ZK (%MODE%)...
.\core_pruner\target\release\core_pruner.exe --input "%TARGET_CIRCUIT%" --output pruned_ir.json %MODE%
if %ERRORLEVEL% NEQ 0 (
    echo [FATAL] Error en la poda coinductiva del circuito.
    exit /b 1
)

REM 4. Ejecutar el Oraculo SMT en Z3
echo.
echo [*] FASE 2: Verificando unicidad de testigo formal en Z3 SMT Solver...
python -m smt_verifier.witness_uniqueness --ir pruned_ir.json

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ===============================================================================
    echo [EXITO] Auditoria formal finalizada sin excepciones de ejecucion.
    echo ===============================================================================
    exit /b 0
) else (
    echo [FATAL] Error o timeout durante la ejecucion de Z3.
    exit /b 1
)