//! ===========================================================================
//! CHRONOS-ZK: PROPAGADOR COINDUCTIVO EN EL BILATTICE PARACONSISTENTE L4
//! Modulo: core_pruner/src/l4_propagator.rs
//! Proposito: Evaluacion de punto fijo de Kleene en tiempo lineal O(|V|+|E|)
//!            mediante cola de propagacion (BFS Worklist) sobre los 4 estados:
//!            - Void      (00): Libre / Indeterminado en F_p
//!            - False     (01): Acotado a raices discretas {0, 1} (booleano)
//!            - True      (10): Funcionalmente determinado por entradas publicas
//!            - Dialeteia (11): Sintesis completa (01 | 10 = 11)
//! ===========================================================================

use crate::r1cs_parser::{R1CSCircuit, SparseConstraint};
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Belnap {
    Void = 0b00,      // VAL_N (0): Grado de libertad libre en F_p
    False = 0b01,     // VAL_F (1): Acotado a raices discretas finitas {0, 1}
    True = 0b10,      // VAL_T (2): Funcionalmente determinado univocamente
    Dialeteia = 0b11, // VAL_B (3): Determinado + Acotado no-linealmente (01 | 10)
}

impl Belnap {
    #[inline(always)]
    pub fn from_bits(bits: u8) -> Self {
        match bits & 0b11 {
            0b00 => Belnap::Void,
            0b01 => Belnap::False,
            0b10 => Belnap::True,
            _ => Belnap::Dialeteia,
        }
    }

    #[inline(always)]
    pub fn to_bits(self) -> u8 {
        self as u8
    }

    #[inline(always)]
    pub fn merge(self, other: Belnap) -> Self {
        Belnap::from_bits(self.to_bits() | other.to_bits())
    }

    #[inline(always)]
    pub fn is_root_bounded(self) -> bool {
        (self.to_bits() & 0b01) != 0
    }

    #[inline(always)]
    pub fn is_determined(self) -> bool {
        (self.to_bits() & 0b10) != 0
    }
}

pub struct L4State {
    pub signal_values: Vec<Belnap>,
    pub determined_signals: HashSet<usize>,
    pub boolean_bounded_signals: HashSet<usize>,
    pub malleable_candidates: Vec<usize>,
    pub iterations: usize,
}

impl L4State {
    pub fn new(num_variables: usize, public_inputs: &[usize]) -> Self {
        let safe_vars = std::cmp::max(num_variables, 1);
        let mut signal_values = vec![Belnap::Void; safe_vars];
        let mut determined_signals = HashSet::new();
        let mut boolean_bounded_signals = HashSet::new();

        signal_values[0] = Belnap::Dialeteia;
        determined_signals.insert(0);
        boolean_bounded_signals.insert(0);

        for &pub_idx in public_inputs {
            if pub_idx < safe_vars {
                signal_values[pub_idx] = Belnap::Dialeteia;
                determined_signals.insert(pub_idx);
            }
        }

        L4State {
            signal_values,
            determined_signals,
            boolean_bounded_signals,
            malleable_candidates: Vec::new(),
            iterations: 0,
        }
    }

    #[inline]
    pub fn apply_transition(&mut self, sig_id: usize, mask: Belnap) -> bool {
        if sig_id >= self.signal_values.len() {
            return false;
        }
        let old = self.signal_values[sig_id];
        let next = old.merge(mask);
        if next != old {
            self.signal_values[sig_id] = next;
            if next.is_root_bounded() {
                self.boolean_bounded_signals.insert(sig_id);
            }
            if next.is_determined() {
                self.determined_signals.insert(sig_id);
            }
            true
        } else {
            false
        }
    }
}

pub fn detect_boolean_check(c: &SparseConstraint) -> Option<usize> {
    if !c.c.is_empty() {
        return None;
    }
    if c.a.len() == 1 && c.b.len() == 2 && c.a[0].0 != 0 {
        let x_id = c.a[0].0;
        let has_one = c.b.iter().any(|(id, _)| *id == 0);
        let has_x = c.b.iter().any(|(id, coeff)| *id == x_id && coeff != "0");
        if has_one && has_x {
            return Some(x_id);
        }
    }
    if c.b.len() == 1 && c.a.len() == 2 && c.b[0].0 != 0 {
        let x_id = c.b[0].0;
        let has_one = c.a.iter().any(|(id, _)| *id == 0);
        let has_x = c.a.iter().any(|(id, coeff)| *id == x_id && coeff != "0");
        if has_one && has_x {
            return Some(x_id);
        }
    }
    None
}

pub fn detect_bilinear_zero(c: &SparseConstraint) -> Option<(usize, usize)> {
    if c.c.is_empty() && c.a.len() == 1 && c.b.len() == 1 {
        let s1 = c.a[0].0;
        let s2 = c.b[0].0;
        if s1 != 0 && s2 != 0 && s1 != s2 {
            return Some((s1, s2));
        }
    }
    None
}

pub fn propagate_l4_fixed_point(circuit: &R1CSCircuit) -> L4State {
    let mut state = L4State::new(circuit.num_variables, &circuit.public_inputs);
    let n_vars = std::cmp::max(circuit.num_variables, 1);

    // 1. Pre-indexar igualdades lineales de 2 variables `1 * x === y` en lista de adyacencia
    //    para propagacion BFS estrictamente O(|V| + |E|), y separar restricciones complejas.
    let mut linear_adj: Vec<Vec<usize>> = vec![Vec::new(); n_vars];
    let mut bilinear_zeros: HashSet<(usize, usize)> = HashSet::new();
    let mut mux_signals: HashMap<usize, (usize, usize, usize)> = HashMap::new();
    let mut complex_constraints: Vec<&SparseConstraint> = Vec::new();

    for c in &circuit.constraints {
        if let Some(bool_sig) = detect_boolean_check(c) {
            state.apply_transition(bool_sig, Belnap::False);
            continue;
        }

        if let Some((s1, s2)) = detect_bilinear_zero(c) {
            bilinear_zeros.insert((s1, s2));
            bilinear_zeros.insert((s2, s1));
            continue;
        }

        let is_a_unit = c.a.len() == 1 && c.a[0].0 == 0;
        let is_b_unit = c.b.len() == 1 && c.b[0].0 == 0;

        // Igualdad lineal directa 1 * s1 === s2
        if is_a_unit && c.b.len() == 1 && c.c.len() == 1 {
            let s1 = c.b[0].0;
            let s2 = c.c[0].0;
            if s1 < n_vars && s2 < n_vars && s1 != 0 && s2 != 0 {
                linear_adj[s1].push(s2);
                linear_adj[s2].push(s1);
                continue;
            }
        } else if is_b_unit && c.a.len() == 1 && c.c.len() == 1 {
            let s1 = c.a[0].0;
            let s2 = c.c[0].0;
            if s1 < n_vars && s2 < n_vars && s1 != 0 && s2 != 0 {
                linear_adj[s1].push(s2);
                linear_adj[s2].push(s1);
                continue;
            }
        }

        if c.a.len() == 1 && c.b.len() == 2 && c.c.len() == 2 {
            let s_id = c.a[0].0;
            let b0 = c.b[0].0;
            let b1 = c.b[1].0;
            let c0 = c.c[0].0;
            let c1 = c.c[1].0;
            if s_id != 0 && b0 != 0 && b1 != 0 {
                if (c0 == b0 || c0 == b1) && c1 != b0 && c1 != b1 {
                    mux_signals.insert(c1, (s_id, b0, b1));
                } else if (c1 == b0 || c1 == b1) && c0 != b0 && c0 != b1 {
                    mux_signals.insert(c0, (s_id, b0, b1));
                }
            }
        }

        complex_constraints.push(c);
    }

    // Funcion auxiliar para propagar determinismo en O(|V|+|E|) por la red de adyacencia lineal
    let propagate_bfs = |st: &mut L4State| -> bool {
        let mut queue: VecDeque<usize> = st.determined_signals.iter().copied().collect();
        let mut any_new = false;
        while let Some(u) = queue.pop_front() {
            if u < linear_adj.len() {
                for &v in &linear_adj[u] {
                    if !st.signal_values[v].is_determined() {
                        st.apply_transition(v, Belnap::True);
                        queue.push_back(v);
                        any_new = true;
                    }
                }
            }
        }
        any_new
    };

    let _ = propagate_bfs(&mut state);

    let mut changed = true;
    let max_iterations = std::cmp::max(complex_constraints.len() * 2, 16);

    while changed && state.iterations < max_iterations {
        changed = false;
        state.iterations += 1;

        for c in &complex_constraints {
            // REGLA 2: Sintesis de Acoplamiento IsZero:
            if c.a.len() == 1 && c.b.len() == 1 && c.c.len() == 2 {
                let s_a = c.a[0].0;
                let s_b = c.b[0].0;
                let has_const_one = c.c.iter().any(|(id, _)| *id == 0);
                let out_opt = c.c.iter().find(|(id, _)| *id != 0).map(|(id, _)| *id);

                if has_const_one {
                    if let Some(out_id) = out_opt {
                        if state.signal_values[s_a].is_determined()
                            && bilinear_zeros.contains(&(s_a, out_id))
                        {
                            if state.apply_transition(out_id, Belnap::Dialeteia) {
                                changed = true;
                            }
                        } else if state.signal_values[s_b].is_determined()
                            && bilinear_zeros.contains(&(s_b, out_id))
                        {
                            if state.apply_transition(out_id, Belnap::Dialeteia) {
                                changed = true;
                            }
                        }
                    }
                }
            }

            // REGLA 3: Inyectividad de Descomposicion Binaria (Num2Bits):
            let is_a_unit = c.a.len() == 1 && c.a[0].0 == 0;
            let is_b_unit = c.b.len() == 1 && c.b[0].0 == 0;

            if is_a_unit && c.c.len() == 1 && c.b.len() >= 2 && c.b.len() < 253 {
                let target_id = c.c[0].0;
                let all_bits_bounded = c.b.iter().all(|(sig_id, _)| {
                    *sig_id != 0 && state.signal_values[*sig_id].is_root_bounded()
                });

                if state.signal_values[target_id].is_determined() && all_bits_bounded {
                    for (bit_id, _) in &c.b {
                        if state.apply_transition(*bit_id, Belnap::Dialeteia) {
                            changed = true;
                        }
                    }
                }
            }

            // REGLA 4: Compresion Cuadratica Simetrica en Arbol de Merkle:
            if c.a.len() == 1 && c.b.len() == 1 && c.c.len() == 1 {
                let left_id = c.a[0].0;
                let right_id = c.b[0].0;
                let prod_id = c.c[0].0;

                if state.signal_values[left_id].is_determined()
                    && state.signal_values[right_id].is_determined()
                {
                    if state.apply_transition(prod_id, Belnap::True) {
                        changed = true;
                    }
                } else if let (Some(&(s1, curr1, pe1)), Some(&(s2, _curr2, _pe2))) =
                    (mux_signals.get(&left_id), mux_signals.get(&right_id))
                {
                    if s1 == s2
                        && state.signal_values[s1].is_root_bounded()
                        && state.signal_values[curr1].is_determined()
                        && state.signal_values[pe1].is_determined()
                    {
                        if state.apply_transition(prod_id, Belnap::Dialeteia) {
                            changed = true;
                        }
                    }
                }
            }

            // REGLA 5: Propagacion Lineal Multivariable y Hash de Nivel Merkle:
            if is_a_unit || is_b_unit {
                let linear_side = if is_a_unit { &c.b } else { &c.a };

                if c.c.len() == 1 && linear_side.len() == 4 {
                    let next_curr_id = c.c[0].0;
                    let non_const: Vec<usize> = linear_side
                        .iter()
                        .filter(|(id, _)| *id != 0)
                        .map(|(id, _)| *id)
                        .collect();
                    if non_const.len() == 3 {
                        let any_prod_det = non_const
                            .iter()
                            .any(|&id| state.signal_values[id].is_determined());
                        let mux_inputs_det = non_const.iter().any(|&id| {
                            if let Some(&(_s, curr_id, pe_id)) = mux_signals.get(&id) {
                                state.signal_values[curr_id].is_determined()
                                    && state.signal_values[pe_id].is_determined()
                            } else {
                                false
                            }
                        });
                        if any_prod_det && mux_inputs_det {
                            if state.apply_transition(next_curr_id, Belnap::Dialeteia) {
                                changed = true;
                            }
                        }
                    }
                }

                let mut all_vars = Vec::new();
                for (id, coeff) in linear_side {
                    if *id != 0 && coeff != "0" && !all_vars.contains(id) {
                        all_vars.push(*id);
                    }
                }
                for (id, coeff) in &c.c {
                    if *id != 0 && coeff != "0" && !all_vars.contains(id) {
                        all_vars.push(*id);
                    }
                }

                let undetermined: Vec<usize> = all_vars
                    .into_iter()
                    .filter(|&id| !state.signal_values[id].is_determined())
                    .collect();

                if undetermined.len() == 1 {
                    if state.apply_transition(undetermined[0], Belnap::True) {
                        changed = true;
                    }
                }
            }
        }

        if changed {
            let _ = propagate_bfs(&mut state);
        }
    }

    let pub_set: HashSet<usize> = circuit.public_inputs.iter().copied().collect();
    for i in 1..circuit.num_variables {
        if !pub_set.contains(&i) && !state.signal_values[i].is_determined() {
            state.malleable_candidates.push(i);
        }
    }

    state
}