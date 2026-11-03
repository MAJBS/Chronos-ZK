# Chronos-ZK: Heterogeneous Performance Benchmark Report

| Benchmark Tier | R1CS Constraints | Pure Z3 (CPU Baseline) | Chronos-ZK (Rust CPU) | Chronos-ZK (CUDA sm_86) | Speedup vs Z3 | GPU vs CPU Speedup |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| Tier 1: Micro-Circuito | 50 | 95.92 ms | 9.69 ms | **0.4251 ms** | **225.63x** | **22.8x** |
| Tier 2: Circuito Medio | 1,000 | 1489.53 ms | 12.07 ms | **0.4196 ms** | **3,549.87x** | **28.8x** |
| Tier 3: Circuito Critico | 10,000 | 1399.95 ms | 113.21 ms | **0.9065 ms** | **1,544.35x** | **124.9x** |
| Tier 4: Escala Produccion | 50,000 | 1372.66 ms | 573.49 ms | **0.3781 ms** | **3,630.42x** | **1516.8x** |
