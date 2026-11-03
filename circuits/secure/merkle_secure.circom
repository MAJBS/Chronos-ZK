pragma circom 2.0.0;

// ============================================================================
// CHRONOS-ZK TEST FIXTURE: SECURE MERKLE VERIFIER (FULLY CONSTRAINED)
// PARCHE DE SEGURIDAD: Selectores forzados a booleaneidad estricta
// ============================================================================

template CompressHashSecure() {
    signal input left;
    signal input right;
    signal output hash;

    signal prod;
    prod <== left * right;
    hash <== prod + left + right + 7;
}

template MerkleVerifierSecure(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels];
    signal output root;

    signal current[levels + 1];
    current[0] <== leaf;

    component hashers[levels];

    for (var i = 0; i < levels; i++) {
        // PARCHE DE SEGURIDAD ESTRICTO:
        // Bloquea cualquier intento de inyeccion fuera de {0, 1}
        pathIndices[i] * (1 - pathIndices[i]) === 0;

        signal s;
        s <== pathIndices[i];

        signal left;
        signal right;
        left <== current[i] + s * (pathElements[i] - current[i]);
        right <== pathElements[i] + s * (current[i] - pathElements[i]);

        hashers[i] = CompressHashSecure();
        hashers[i].left <== left;
        hashers[i].right <== right;
        current[i + 1] <== hashers[i].hash;
    }

    root <== current[levels];
}

component main {public [leaf, root]} = MerkleVerifierSecure(3);