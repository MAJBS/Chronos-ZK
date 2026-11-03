@echo off
setlocal enabledelayedexpansion

echo ===============================================================================
echo === CHRONOS-ZK: BATERIA DE REGRESION DE SOLIDEZ FORMAL COMPLETA (6/6)       ===
echo ===============================================================================

set TESTS_PASSED=0
set TOTAL_TESTS=6

REM Asegurar que las dependencias de Python esten listas
pip install -r smt_verifier\requirements.txt >nul 2>&1

echo.
echo --- [TEST 1/6] Auditando IsZero Vulnerable (Esperado: SAT / Exploit) ---
python -m smt_verifier.witness_uniqueness --fixture iszero_vulnerable --expect VULNERABLE
if !ERRORLEVEL! EQU 0 set /a TESTS_PASSED+=1

echo.
echo --- [TEST 2/6] Auditando IsZero Seguro (Esperado: UNSAT / Certificado) ---
python -m smt_verifier.witness_uniqueness --fixture iszero_secure --expect SECURE
if !ERRORLEVEL! EQU 0 set /a TESTS_PASSED+=1

echo.
echo --- [TEST 3/6] Auditando Num2Bits Vulnerable (Esperado: SAT / Exploit) ---
python -m smt_verifier.witness_uniqueness --fixture num2bits_vulnerable --expect VULNERABLE
if !ERRORLEVEL! EQU 0 set /a TESTS_PASSED+=1

echo.
echo --- [TEST 4/6] Auditando Num2Bits Seguro (Esperado: UNSAT / Certificado) ---
python -m smt_verifier.witness_uniqueness --fixture num2bits_secure --expect SECURE
if !ERRORLEVEL! EQU 0 set /a TESTS_PASSED+=1

echo.
echo --- [TEST 5/6] Auditando Pipeline Hibrido Rust + GPU + Z3 (IsZero y Merkle) ---
set PIPELINE_OK=1
.\core_pruner\target\release\core_pruner.exe --input circuits\vulnerable\iszero_underconstrained.circom --output pruned_ir.json --gpu >nul
python -m smt_verifier.witness_uniqueness --ir pruned_ir.json --expect VULNERABLE
if !ERRORLEVEL! NEQ 0 set PIPELINE_OK=0

.\core_pruner\target\release\core_pruner.exe --input circuits\vulnerable\merkle_malleable.circom --output pruned_ir.json --gpu >nul
python -m smt_verifier.witness_uniqueness --ir pruned_ir.json --expect VULNERABLE
if !ERRORLEVEL! NEQ 0 set PIPELINE_OK=0

.\core_pruner\target\release\core_pruner.exe --input circuits\secure\merkle_secure.circom --output pruned_ir.json --gpu >nul
python -m smt_verifier.witness_uniqueness --ir pruned_ir.json --expect SECURE
if !ERRORLEVEL! NEQ 0 set PIPELINE_OK=0

if !PIPELINE_OK! EQU 1 set /a TESTS_PASSED+=1

echo.
echo --- [TEST 6/6] Verificando Reactor CUDA Megakernel en GPU (50k R1CS) ---
cd cuda_pruner
.\zk_megakernel.exe --benchmark 50000
if !ERRORLEVEL! EQU 0 set /a TESTS_PASSED+=1
cd ..

echo.
echo ===============================================================================
echo [RESULTADOS]: !TESTS_PASSED! / !TOTAL_TESTS! Pruebas Pasadas Exitosamente.
if !TESTS_PASSED! EQU !TOTAL_TESTS! (
    echo [ESTADO]: SISTEMA 100%% CERTIFICADO Y LIBRE DE DEUDA TECNICA.
    echo ===============================================================================
    exit /b 0
) else (
    echo [ESTADO]: ADVERTENCIA: Algunas pruebas no convergieron.
    echo ===============================================================================
    exit /b 1
)