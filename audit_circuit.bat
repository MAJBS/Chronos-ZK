@echo off
setlocal enabledelayedexpansion

echo ===============================================================================
echo === CHRONOS-ZK: AUDITOR FORMAL SMT DE CIRCUITOS CRIPTOGRAFICOS              ===
echo ===============================================================================

if "%~1"=="" (
    echo [ERROR] No se especifico el archivo de circuito.
    echo Uso: .\audit_circuit.bat ^<circuito.circom^|r1cs^|json^> [--gpu ^| --cpu] [--sniper]
    exit /b 1
)

set TARGET_CIRCUIT=%~1
set MODE=--cpu
set SNIPER_FLAG=--sniper

for %%A in (%*) do (
    if /I "%%~A"=="--gpu" set MODE=--gpu
    if /I "%%~A"=="--cpu" set MODE=--cpu
    if /I "%%~A"=="--no-sniper" set SNIPER_FLAG=
)

REM Autodetectar archivo de simbolos .sym si existe junto al circuito
set SYM_CANDIDATE=%~dpn1.sym
set SYM_ARGS_RUST=
set SYM_ARGS_PY=
if exist "!SYM_CANDIDATE!" (
    set SYM_ARGS_RUST=--sym "!SYM_CANDIDATE!"
    set SYM_ARGS_PY=--sym "!SYM_CANDIDATE!"
)

echo [*] Target: %TARGET_CIRCUIT%
echo [*] Modo de aceleracion: %MODE% %SNIPER_FLAG%

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

echo.
echo [*] FASE 1: Podando grafo de restricciones con Chronos-ZK (%MODE%)...
.\core_pruner\target\release\core_pruner.exe --input "%TARGET_CIRCUIT%" --output pruned_ir.json %MODE% !SYM_ARGS_RUST!
if %ERRORLEVEL% NEQ 0 (
    echo [FATAL] Error en la poda coinductiva del circuito.
    exit /b 1
)

echo.
echo [*] FASE 2: Verificando unicidad de testigo formal en Z3 SMT Solver...
python -m smt_verifier.witness_uniqueness --ir pruned_ir.json !SYM_ARGS_PY! %SNIPER_FLAG%

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