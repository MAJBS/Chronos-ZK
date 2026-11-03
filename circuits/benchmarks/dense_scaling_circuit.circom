pragma circom 2.0.0;

// ============================================================================
// CHRONOS-ZK STRESS BENCHMARK: DENSE SCALING CIRCUIT (STRESS TEST SMT)
// PROPOSITO: Generador de cadenas cuadraticas no lineales acopladas
// ============================================================================

template DenseScalingCircuit(steps) {
    signal input in;
    signal output out;
    
    // Vector de seniales internas acopladas recursivamente
    signal s[steps + 1];
    current[0] <== in;
    s[0] <== in;

    signal intermediate_prod[steps];

    for (var i = 0; i < steps; i++) {
        // Multiplicacion no lineal acoplada: s_{i+1} = s_i * s_i + s_i + 3
        // En campos de 256 bits (BN254), esto dispara multiplicaciones modulares
        // pesadas que saturan el bit-blaster de Z3 estándar cuando steps > 1000.
        intermediate_prod[i] <== s[i] * s[i];
        s[i + 1] <== intermediate_prod[i] + s[i] + 3;
    }

    out <== s[steps];
}

// Circuito parametrizado por defecto a 1000 pasos (Régimen 2 de estrés)
component main {public [in]} = DenseScalingCircuit(1000);