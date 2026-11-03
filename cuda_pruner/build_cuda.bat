@echo off
setlocal enabledelayedexpansion

echo [TELEMETRIA] ^| COMPILER ^| Inicializando compilacion del Reactor CUDA ZK (Ampere sm_86)...

REM 1. Priorizar Visual Studio 18 (2026) con toolset compatible 14.44 para CUDA 12.x
if not defined VSCMD_ARG_TGT_ARCH (
    for %%E in ("Community" "Professional" "Enterprise" "BuildTools") do (
        if not defined VSCMD_ARG_TGT_ARCH (
            if exist "C:\Program Files\Microsoft Visual Studio\18\%%~E\VC\Auxiliary\Build\vcvars64.bat" (
                call "C:\Program Files\Microsoft Visual Studio\18\%%~E\VC\Auxiliary\Build\vcvars64.bat" -vcvars_ver=14.44 >nul 2>&1
            )
        )
        if not defined VSCMD_ARG_TGT_ARCH (
            if exist "C:\Program Files\Microsoft Visual Studio\18\%%~E\VC\Auxiliary\Build\vcvars64.bat" (
                call "C:\Program Files\Microsoft Visual Studio\18\%%~E\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
            )
        )
    )
)

REM 2. Fallback a Visual Studio 2022 / 2019 si no se detecto VS 18
if not defined VSCMD_ARG_TGT_ARCH (
    for %%V in ("2022" "2019") do (
        for %%E in ("Community" "Professional" "Enterprise" "BuildTools") do (
            if not defined VSCMD_ARG_TGT_ARCH (
                if exist "C:\Program Files\Microsoft Visual Studio\%%~V\%%~E\VC\Auxiliary\Build\vcvars64.bat" (
                    call "C:\Program Files\Microsoft Visual Studio\%%~V\%%~E\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
                )
            )
            if not defined VSCMD_ARG_TGT_ARCH (
                if exist "C:\Program Files (x86)\Microsoft Visual Studio\%%~V\%%~E\VC\Auxiliary\Build\vcvars64.bat" (
                    call "C:\Program Files (x86)\Microsoft Visual Studio\%%~V\%%~E\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
                )
            )
        )
    )
)

if exist zk_megakernel.exe del /F /Q zk_megakernel.exe
if exist zk_megakernel.exe (
    echo [FATAL] ^| OS ^| zk_megakernel.exe esta bloqueado por otro proceso en Windows.
    exit /b 1
)

echo [TELEMETRIA] ^| NVCC ^| Compilando zk_megakernel.cu con optimizacion -O3 para arquitectura sm_86...
nvcc -allow-unsupported-compiler -D_ALLOW_COMPILER_AND_STL_VERSION_MISMATCH -ccbin "cl.exe" -O3 -arch=sm_86 -use_fast_math -std=c++17 -Xcompiler "/Zc:preprocessor /openmp /wd4068 /EHsc" zk_megakernel.cu -o zk_megakernel.exe

if not exist zk_megakernel.exe (
    echo [FATAL] ^| COMPILER ^| Error generando binario CUDA. Revisa la instalacion de CUDA Toolkit y MSVC.
    exit /b 1
)

echo [TELEMETRIA] ^| VERDICT ^| Compilacion finalizada con exito. Binario: zk_megakernel.exe
exit /b 0