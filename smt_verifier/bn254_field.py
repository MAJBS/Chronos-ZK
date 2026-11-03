"""
=============================================================================
CHRONOS-ZK: ARITMETICA MODULAR ALGEBRAICA EXACTA EN BN254
Modulo: smt_verifier/bn254_field.py
Proposito: Modelado no lineal exacto sobre z3.Int con proyeccion simetrica
           centrada en [-(p-1)/2, (p-1)/2] y calculo exacto de intervalos
           diofanticos (Cero Bit-Blasting Overhead).
=============================================================================
"""

import time
import z3

# Primo escalar canonico de la curva BN254 (alt_bn128 / Ethereum / Circom)
BN254_PRIME = 21888242871839275222246405745257275088548364400416034343698204186575808495617
BN254_HALF_PRIME = BN254_PRIME // 2


def log_telemetry(fase: str, mensaje: str):
    """Telemetria forense con timestamp de alta precision."""
    t = time.time()
    ms = int((t - int(t)) * 1000)
    print(f"[{time.strftime('%H:%M:%S')}.{ms:03d}] [TELEMETRIA] | {fase:<12} | {mensaje}")


class BN254Field:
    """
    Encapsula operaciones algebraicas exactas de campo finito F_p sobre z3.Int.
    Utiliza representacion canonica simetrica para preservar signos negativos
    (ej. p - 1 -> -1) y acotar estrictamente los cocientes diofanticos en Z.
    """

    @staticmethod
    def field_val(val_int: int, prime: int = BN254_PRIME) -> int:
        """Constante entera reducida al representante estandar [0, p-1]."""
        return int(val_int) % prime

    @staticmethod
    def canonical_signed_coeff(val_int: int, prime: int = BN254_PRIME) -> int:
        """
        Proyecta un elemento de F_p al intervalo simetrico centrado [-(p-1)/2, (p-1)/2].
        Esto garantiza que coeficientes como p - 1 se representen como -1 en Z,
        preservando la identidad algebraica c === val_int (mod p) con norma minima.
        """
        c = int(val_int) % prime
        if c > (prime // 2):
            return c - prime
        return c

    @staticmethod
    def field_var(name: str) -> z3.ArithRef:
        """Crea una variable simbolica entera sobre Z para representar una senial en F_p."""
        return z3.Int(name)

    @staticmethod
    def domain_constraint(var: z3.ArithRef, prime: int = BN254_PRIME) -> z3.BoolRef:
        """Restringe estrictamente la variable simbolica al dominio canonico [0, p-1]."""
        return z3.And(var >= 0, var < prime)

    @staticmethod
    def ceil_div(numerator: int, denominator: int) -> int:
        """
        Calcula ceil(numerator / denominator) en aritmetica entera exacta de precision
        arbitraria para denominator > 0, sin errores de coma flotante.
        """
        if denominator <= 0:
            raise ValueError("El denominador debe ser estrictamente positivo.")
        return -((-numerator) // denominator)

    @staticmethod
    def floor_div(numerator: int, denominator: int) -> int:
        """
        Calcula floor(numerator / denominator) en aritmetica entera exacta de precision
        arbitraria para denominator > 0.
        """
        if denominator <= 0:
            raise ValueError("El denominador debe ser estrictamente positivo.")
        return numerator // denominator

    @staticmethod
    def eval_linear_combination_with_bounds(terms: list, witness_map: dict, prime: int = BN254_PRIME):
        """
        Evalua sum(coeff_i * w_i) sobre Z consolidando terminos repetidos y usando
        coeficientes simetricos centrados.

        Retorna una tupla (expr, min_val, max_val, is_constant):
          - expr: z3.ArithRef o int representando la combinacion lineal en Z.
          - min_val: Cota inferior exacta alcanzable en Z cuando w_i in [0, p-1].
          - max_val: Cota superior exacta alcanzable en Z cuando w_i in [0, p-1].
          - is_constant: True si la expresion no depende de variables simbolicas.
        """
        if not terms:
            return 0, 0, 0, True

        # 1. Consolidar coeficientes por signal_id modulo p
        consolidated = {}
        for signal_id, raw_coeff in terms:
            sig_id = int(signal_id)
            c_mod = int(raw_coeff) % prime
            consolidated[sig_id] = (consolidated.get(sig_id, 0) + c_mod) % prime

        # 2. Construir expresion simbolica y acumular cotas de intervalo [min_val, max_val]
        const_acc = 0
        symbolic_terms = []
        min_val = 0
        max_val = 0

        for sig_id in sorted(consolidated.keys()):
            c_signed = BN254Field.canonical_signed_coeff(consolidated[sig_id], prime)
            if c_signed == 0:
                continue

            var_ref = witness_map[sig_id]

            # Caso constante (ej. w_0 = 1 o senial fijada a entero concreto)
            if isinstance(var_ref, int):
                val_concrete = c_signed * var_ref
                const_acc += val_concrete
                min_val += val_concrete
                max_val += val_concrete
            else:
                if c_signed == 1:
                    symbolic_terms.append(var_ref)
                elif c_signed == -1:
                    symbolic_terms.append(-var_ref)
                else:
                    symbolic_terms.append(c_signed * var_ref)

                # Como var_ref in [0, prime - 1]:
                if c_signed > 0:
                    max_val += c_signed * (prime - 1)
                else:
                    min_val += c_signed * (prime - 1)

        if not symbolic_terms:
            return const_acc, min_val, max_val, True

        expr = symbolic_terms[0]
        for t in symbolic_terms[1:]:
            expr = expr + t

        if const_acc != 0:
            expr = expr + const_acc

        return expr, min_val, max_val, False

    @staticmethod
    def eval_linear_combination(terms: list, witness_map: dict, prime: int = BN254_PRIME):
        """
        Evalua sum(coeff_i * w_i) sobre Z devolviendo unicamente la expresion simbolica
        o constante entera.
        """
        expr, _, _, _ = BN254Field.eval_linear_combination_with_bounds(terms, witness_map, prime)
        return expr