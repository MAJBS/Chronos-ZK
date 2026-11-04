//! ===========================================================================
//! CHRONOS-ZK: SLICER TOPOLOGICO Y EXPORTADOR DE CONTRATO CHRONOS-IR
//! Modulo: core_pruner/src/constraint_slicer.rs
//! Proposito: Poda de subgrafos deterministas cerrados (incluyendo esponjas
//!            Poseidon / MiMC), exportacion de simbolos .sym y patrones de
//!            vulnerabilidad para el Modo Francotirador (--sniper).
//! ===========================================================================

use crate::l4_propagator::L4State;
use crate::r1cs_parser::{R1CSCircuit, SparseConstraint};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fs::File;
use std::io::Write;

#[derive(Serialize, Deserialize)]
pub struct PrunedIRJson {
    pub name: String,
    pub field_prime: String,
    pub num_variables: usize,
    pub public_inputs: Vec<usize>,
    pub private_inputs: Vec<usize>,
    pub output_signals: Vec<usize>,
    pub determined_signals: Vec<usize>,
    pub suspicious_signals: Vec<usize>,
    pub signal_symbols: BTreeMap<String, String>,
    pub sniper_patterns: BTreeMap<String, String>,
    pub r1cs_constraints: Vec<PrunedConstraintJson>,
}

#[derive(Serialize, Deserialize)]
#[allow(non_snake_case)]
pub struct PrunedConstraintJson {
    pub A: Vec<[serde_json::Value; 2]>,
    pub B: Vec<[serde_json::Value; 2]>,
    pub C: Vec<[serde_json::Value; 2]>,
}

fn extract_constraint_signals(c: &SparseConstraint) -> Vec<usize> {
    let mut sigs = Vec::new();
    for (id, coeff) in c.a.iter().chain(c.b.iter()).chain(c.c.iter()) {
        if *id != 0 && coeff != "0" && !sigs.contains(id) {
            sigs.push(*id);
        }
    }
    sigs
}

pub fn slice_and_export_ir(
    circuit: &R1CSCircuit,
    l4_state: &L4State,
    output_path: &str,
) -> Result<usize, Box<dyn std::error::Error>> {
    // 1. Aislar el cono de incertidumbre: todas las seniales NO determinadas
    //    y las seniales de salida que aun no estan determinadas.
    let mut uncertain_cone: HashSet<usize> = HashSet::new();
    for &mal_id in &l4_state.malleable_candidates {
        uncertain_cone.insert(mal_id);
    }
    for &out_id in &circuit.output_signals {
        if !l4_state.determined_signals.contains(&out_id) {
            uncertain_cone.insert(out_id);
        }
    }

    // Si todo el circuito esta determinado (circuito seguro), preservar solo la frontera
    // directa de las salidas para que Z3 certifique formalmente UNSAT.
    if uncertain_cone.is_empty() {
        for &out_id in &circuit.output_signals {
            uncertain_cone.insert(out_id);
        }
    }

    // Expandir 1 salto alrededor del cono de incertidumbre
    let mut expanded_cone = uncertain_cone.clone();
    for c in &circuit.constraints {
        let sigs = extract_constraint_signals(c);
        if sigs.iter().any(|s| uncertain_cone.contains(s)) {
            for s in sigs {
                expanded_cone.insert(s);
            }
        }
    }

    let mut surviving_constraints = Vec::new();

    for c in &circuit.constraints {
        let sigs = extract_constraint_signals(c);
        if sigs.is_empty() {
            continue;
        }

        let all_determined = sigs
            .iter()
            .all(|s| l4_state.determined_signals.contains(s));
        let touches_cone = sigs.iter().any(|s| expanded_cone.contains(s));

        // Podar toda restriccion cuyas variables esten 100% determinadas (ej. rondas
        // de Poseidon aguas arriba) y que no toque el cono de incertidumbre.
        if all_determined && !touches_cone {
            continue;
        }

        let a_json: Vec<[serde_json::Value; 2]> = c
            .a
            .iter()
            .map(|(id, coeff)| [serde_json::json!(id), serde_json::json!(coeff)])
            .collect();

        let b_json: Vec<[serde_json::Value; 2]> = c
            .b
            .iter()
            .map(|(id, coeff)| [serde_json::json!(id), serde_json::json!(coeff)])
            .collect();

        let c_json: Vec<[serde_json::Value; 2]> = c
            .c
            .iter()
            .map(|(id, coeff)| [serde_json::json!(id), serde_json::json!(coeff)])
            .collect();

        surviving_constraints.push(PrunedConstraintJson {
            A: a_json,
            B: b_json,
            C: c_json,
        });
    }

    let mut determined_sorted: Vec<usize> = l4_state.determined_signals.iter().copied().collect();
    determined_sorted.sort_unstable();

    let suspicious = if !l4_state.malleable_candidates.is_empty() {
        l4_state.malleable_candidates.clone()
    } else {
        circuit.output_signals.clone()
    };

    let mut signal_symbols = BTreeMap::new();
    for (&w_id, sym_name) in &circuit.wire_to_symbol {
        signal_symbols.insert(w_id.to_string(), sym_name.clone());
    }

    let mut sniper_patterns = BTreeMap::new();
    for (&w_id, pat) in &l4_state.vulnerability_patterns {
        sniper_patterns.insert(w_id.to_string(), pat.clone());
    }

    let ir = PrunedIRJson {
        name: circuit.name.clone(),
        field_prime: circuit.field_prime.clone(),
        num_variables: circuit.num_variables,
        public_inputs: circuit.public_inputs.clone(),
        private_inputs: circuit.private_inputs.clone(),
        output_signals: circuit.output_signals.clone(),
        determined_signals: determined_sorted,
        suspicious_signals: suspicious,
        signal_symbols,
        sniper_patterns,
        r1cs_constraints: surviving_constraints,
    };

    let json_bytes = serde_json::to_string_pretty(&ir)?;
    let mut file = File::create(output_path)?;
    file.write_all(json_bytes.as_bytes())?;

    Ok(ir.r1cs_constraints.len())
}