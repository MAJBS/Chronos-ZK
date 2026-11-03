pragma circom 2.0.0;

// ============================================================================
// CHRONOS-ZK TEST FIXTURE: SECURE NUM2BITS (FULLY CONSTRAINED)
// PARCHE DE SEGURIDAD: Restriccion cuadratica b*(1-b) === 0 activa
// ============================================================================

template Num2BitsSecure(n) {
    signal input in;
    signal output out[n];
    
    var acc = 0;

    for (var i = 0; i < n; i++) {
        out[i] <-- (in >> i) & 1;
        
        // PARCHE DE SEGURIDAD ESTRICTO:
        // Fuerza analiticamente que cada elemento pertenezca al conjunto binario {0, 1}
        out[i] * (1 - out[i]) === 0;
        
        acc += out[i] * (2 ** i);
    }

    in === acc;
}

component main {public [in]} = Num2BitsSecure(8);