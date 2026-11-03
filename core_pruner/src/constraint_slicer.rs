//! ===========================================================================
//! CHRONOS-ZK: SLICER TOPOLOGICO Y EXPORTADOR DE CONTRATO CHRONOS-IR
//! Modulo: core_pruner/src/constraint_slicer.rs
//! Proposito: Poda de subgrafos deterministas cerrados (conservando el cono
//!            residual de verificacion SMT) y exportacion de pruned_ir.json.
//! ===========================================================================

use crate::l4_propagator::L4State;
use crate::r1cs_parser::{R1CSCircuit, SparseConstraint};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
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
    // 1. Construir conjunto de seniales protegidas (salidas + candidatos a maleabilidad)
    //    cuyas restricciones definitorias conforman el nucleo residual para Z3.
    let mut cone_signals: HashSet<usize> = HashSet::new();
    for &out_id in &circuit.output_signals {
        cone_signals.insert(out_id);
    }
    for &mal_id in &l4_state.malleable_candidates {
        cone_signals.insert(mal_id);
    }

    // Expandir 1 salto hacia atras sobre restricciones no-lineales acopladas a las salidas
    // para garantizar que Z3 disponga de las ecuaciones completas sobre output_signals.
    let mut expanded_cone = cone_signals.clone();
    for c in &circuit.constraints {
        let sigs = extract_constraint_signals(c);
        if sigs.iter().any(|s| cone_signals.contains(s)) {
            for s in sigs {
                expanded_cone.insert(s);
            }
        }
    }

    let mut surviving_constraints = Vec::new();

    for c in &circuit.constraints {
        let sigs = extract_constraint_signals(c);
        if sigs.is_empty() {
            // Poda de restriccion tautologica vacia 0 === 0
            continue;
        }

        let all_determined = sigs
            .iter()
            .all(|s| l4_state.determined_signals.contains(s));
        let touches_cone = sigs.iter().any(|s| expanded_cone.contains(s));

        // Si todas las seniales de la restriccion pertenecen a un subgrafo determinista
        // ya resuelto en L4 y estan desacopladas del cono de evaluacion, se poda la restriccion.
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

    let ir = PrunedIRJson {
        name: circuit.name.clone(),
        field_prime: circuit.field_prime.clone(),
        num_variables: circuit.num_variables,
        public_inputs: circuit.public_inputs.clone(),
        private_inputs: circuit.private_inputs.clone(),
        output_signals: circuit.output_signals.clone(),
        determined_signals: determined_sorted,
        suspicious_signals: suspicious,
        r1cs_constraints: surviving_constraints,
    };

    let json_bytes = serde_json::to_string_pretty(&ir)?;
    let mut file = File::create(output_path)?;
    file.write_all(json_bytes.as_bytes())?;

    Ok(ir.r1cs_constraints.len())
}