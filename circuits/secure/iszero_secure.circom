pragma circom 2.0.0;

// ============================================================================
// CHRONOS-ZK TEST FIXTURE: SECURE ISZERO (FULLY CONSTRAINED)
// PARCHE DE SEGURIDAD: Restriccion in * out === 0 forzada
// ============================================================================

template IsZeroSecure() {
    signal input in;
    signal output out;
    signal inv;

    inv <-- in != 0 ? 1 / in : 0;
    out <== -in * inv + 1;

    // PARCHE DE SEGURIDAD ESTRICTO:
    // Si in != 0, entonces out DEBE ser 0 para satisfacer la igualdad.
    // Si in == 0, out es 1 y la ecuacion evalua 0 * 1 === 0 de forma solida.
    in * out === 0;
}

component main {public [in]} = IsZeroSecure();