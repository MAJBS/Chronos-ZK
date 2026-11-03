pragma circom 2.0.0;

// ============================================================================
// CHRONOS-ZK TEST FIXTURE: VULNERABLE ISZERO (UNDER-CONSTRAINED)
// FALLA CRITICA: Omite la restriccion de acoplamiento in * out === 0
// ============================================================================

template IsZeroVulnerable() {
    signal input in;
    signal output out;
    signal inv;

    // Asignacion no restringida de la senial intermedia inversa
    inv <-- in != 0 ? 1 / in : 0;

    // Restriccion implementada: fuerza out = 0 si inv es el inverso legitimo
    out <== -in * inv + 1;

    // VULNERABILIDAD INTENCIONAL:
    // Falta la restriccion de acoplamiento que fuerza out = 0 cuando in != 0:
    // in * out === 0;
    // Sin esta ecuacion, un atacante puede fijar inv = 0 cuando in = 5,
    // forzando fraudulentamente out = 1.
}

component main {public [in]} = IsZeroVulnerable();