pragma circom 2.0.0;

// ============================================================================
// CHRONOS-ZK TEST FIXTURE: VULNERABLE NUM2BITS (UNDER-CONSTRAINED)
// FALLA CRITICA: Omite deliberadamente la restriccion de booleaneidad b*(1-b) === 0
// ============================================================================

template Num2BitsVulnerable(n) {
    signal input in;
    signal output out[n];
    
    var acc = 0;

    for (var i = 0; i < n; i++) {
        // Asignacion de computo (Operador <-- no genera restriccion algebraica en R1CS)
        out[i] <-- (in >> i) & 1;
        acc += out[i] * (2 ** i);

        // VULNERABILIDAD INTENCIONAL:
        // El desarrollador olvido incluir la restriccion cuadratica:
        // out[i] * (1 - out[i]) === 0;
    }

    // Unica restriccion impuesta sobre la suma lineal
    in === acc;
}

// Instanciacion del componente principal para palabras de 8 bits
component main {public [in]} = Num2BitsVulnerable(8);