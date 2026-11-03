pragma circom 2.0.0;

// ============================================================================
// CHRONOS-ZK TEST FIXTURE: VULNERABLE MERKLE VERIFIER (MALLEABLE PATH)
// FALLA CRITICA: Omite forzar que los selectores de ruta sean booleanos {0, 1}
// ============================================================================

// Compresor cuadratico R1CS para simular hashing de 2 a 1 sin dependencias externas
template CompressHash() {
    signal input left;
    signal input right;
    signal output hash;

    // Relacion no lineal simple: h = left * right + left + right + 7
    signal prod;
    prod <== left * right;
    hash <== prod + left + right + 7;
}

template MerkleVerifierVulnerable(levels) {
    signal input leaf;
    signal input pathElements[levels];
    signal input pathIndices[levels]; // Deberia ser estrictamente 0 o 1
    signal output root;

    signal current[levels + 1];
    current[0] <== leaf;

    component hashers[levels];

    for (var i = 0; i < levels; i++) {
        // VULNERABILIDAD INTENCIONAL:
        // Falta la restriccion de booleaneidad del selector:
        // pathIndices[i] * (1 - pathIndices[i]) === 0;

        var s = pathIndices[i];
        
        // Mux cuadratico sin validar booleaneidad de s:
        signal left;
        signal right;
        
        // Si s fuera forzado a 0 o 1, seleccionaria orden. Al ser libre,
        // admite cualquier elemento de F_p generando multiples raices validas.
        left <== current[i] + s * (pathElements[i] - current[i]);
        right <== pathElements[i] + s * (current[i] - pathElements[i]);

        hashers[i] = CompressHash();
        hashers[i].left <== left;
        hashers[i].right <== right;
        current[i + 1] <== hashers[i].hash;
    }

    root <== current[levels];
}

// Verificador de Merkle de profundidad 3 (8 hojas)
component main {public [leaf, root]} = MerkleVerifierVulnerable(3);