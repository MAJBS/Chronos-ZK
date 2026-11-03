//! ===========================================================================
//! CHRONOS-ZK: CLI DEL MOTOR DE PODA EN SILICIO (RUST CORE + GPU BRIDGE)
//! Modulo: core_pruner/src/main.rs
//! Proposito: Orquestador del pipeline HDC + L4 (CPU / CUDA GPU) con
//!            telemetria forense sincronizada a hora local y exportacion IR.
//! ===========================================================================

mod constraint_slicer;
mod hdc_packer;
mod l4_propagator;
mod r1cs_parser;

use crate::l4_propagator::{detect_boolean_check, Belnap, L4State};
use crate::r1cs_parser::R1CSCircuit;
use std::collections::HashSet;
use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::Command;
use std::time::Instant;

#[cfg(windows)]
#[repr(C)]
struct SystemTimeWin {
    w_year: u16,
    w_month: u16,
    w_day_of_week: u16,
    w_day: u16,
    w_hour: u16,
    w_minute: u16,
    w_second: u16,
    w_milliseconds: u16,
}

#[cfg(windows)]
extern "system" {
    fn GetLocalTime(lp_system_time: *mut SystemTimeWin);
}

pub fn log_telemetry(fase: &str, mensaje: &str) {
    #[cfg(windows)]
    let (hours, mins, s, ms) = {
        let mut st = SystemTimeWin {
            w_year: 0,
            w_month: 0,
            w_day_of_week: 0,
            w_day: 0,
            w_hour: 0,
            w_minute: 0,
            w_second: 0,
            w_milliseconds: 0,
        };
        unsafe {
            GetLocalTime(&mut st);
        }
        (st.w_hour, st.w_minute, st.w_second, st.w_milliseconds)
    };

    #[cfg(not(windows))]
    let (hours, mins, s, ms) = {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now = SystemTime::now();
        let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        let secs = duration.as_secs() % 86400;
        (
            (secs / 3600) as u16,
            ((secs % 3600) / 60) as u16,
            (secs % 60) as u16,
            duration.subsec_millis() as u16,
        )
    };

    println!(
        "[{:02}:{:02}:{:02}.{:03}] [TELEMETRIA] | {:<12} | {}",
        hours, mins, s, ms, fase, mensaje
    );
}

fn dispatch_cuda_megakernel(circuit: &R1CSCircuit, l4_state: &mut L4State) -> bool {
    let candidates = [
        "cuda_pruner/zk_megakernel.exe",
        "cuda_pruner\\zk_megakernel.exe",
        "../cuda_pruner/zk_megakernel.exe",
        "..\\cuda_pruner\\zk_megakernel.exe",
        "cuda_pruner/zk_megakernel",
        "../cuda_pruner/zk_megakernel",
    ];

    let mut cuda_bin = None;
    for path_str in &candidates {
        if Path::new(path_str).exists() {
            cuda_bin = Some(*path_str);
            break;
        }
    }

    let bin_path = match cuda_bin {
        Some(p) => p,
        None => {
            log_telemetry(
                "GPU_BRIDGE",
                "Binario CUDA no encontrado en ruta local; manteniendo convergencia L4 en CPU.",
            );
            return false;
        }
    };

    let tmp_in = "pruned_ir.gpu_in.tmp";
    let tmp_out = "pruned_ir.gpu_out.tmp";

    let mut flat_edges: Vec<(usize, usize, u8)> = Vec::new();

    for c in &circuit.constraints {
        if let Some(bool_sig) = detect_boolean_check(c) {
            flat_edges.push((bool_sig, bool_sig, 1));
        } else if c.a.len() == 1 && c.a[0].0 == 0 && c.c.len() == 1 && c.b.len() >= 2 {
            let target_id = c.c[0].0;
            let non_const_b: Vec<usize> = c
                .b
                .iter()
                .filter(|(id, coeff)| *id != 0 && coeff != "0")
                .map(|(id, _)| *id)
                .collect();

            let all_b_bounded = non_const_b
                .iter()
                .all(|&id| l4_state.signal_values[id].is_root_bounded());

            if all_b_bounded {
                for &b_id in &non_const_b {
                    flat_edges.push((b_id, target_id, 0));
                }
            } else if l4_state.signal_values[target_id].is_determined() {
                flat_edges.push((0, target_id, 0));
            } else {
                let first_b = non_const_b.first().copied().unwrap_or(target_id);
                flat_edges.push((first_b, target_id, 0));
            }
        } else {
            let non_const_a: Vec<usize> = c
                .a
                .iter()
                .filter(|(id, coeff)| *id != 0 && coeff != "0")
                .map(|(id, _)| *id)
                .collect();
            let non_const_c: Vec<usize> = c
                .c
                .iter()
                .filter(|(id, coeff)| *id != 0 && coeff != "0")
                .map(|(id, _)| *id)
                .collect();

            let sig_a = non_const_a.first().copied().unwrap_or(0);
            let sig_b = non_const_c.first().copied().unwrap_or(sig_a);

            if l4_state.signal_values[sig_b].is_determined() {
                flat_edges.push((sig_a, sig_b, 0));
            } else {
                flat_edges.push((sig_b, sig_b, 0));
            }
        }
    }

    if let Ok(mut f) = File::create(tmp_in) {
        let _ = writeln!(
            f,
            "{} {} {}",
            circuit.num_variables,
            flat_edges.len(),
            circuit.public_inputs.len()
        );
        for (idx, pub_id) in circuit.public_inputs.iter().enumerate() {
            if idx > 0 {
                let _ = write!(f, " ");
            }
            let _ = write!(f, "{}", pub_id);
        }
        let _ = writeln!(f);

        for (sa, sb, is_bool) in &flat_edges {
            let _ = writeln!(f, "{} {} {}", sa, sb, is_bool);
        }
    } else {
        return false;
    }

    log_telemetry(
        "GPU_BRIDGE",
        &format!(
            "Invocando Reactor CUDA '{}' sobre {} restricciones...",
            bin_path,
            flat_edges.len()
        ),
    );

    let status = Command::new(bin_path)
        .args(["--input", tmp_in, "--output", tmp_out])
        .status();

    let mut gpu_applied = false;
    if let Ok(exit_status) = status {
        if exit_status.success() && Path::new(tmp_out).exists() {
            if let Ok(file) = File::open(tmp_out) {
                let reader = BufReader::new(file);
                for line in reader.lines().map_while(Result::ok) {
                    let parts: Vec<&str> = line.split_whitespace().collect();
                    if parts.len() == 2 {
                        if let (Ok(sig_id), Ok(bits)) =
                            (parts[0].parse::<usize>(), parts[1].parse::<u8>())
                        {
                            l4_state.apply_transition(sig_id, Belnap::from_bits(bits));
                        }
                    }
                }
                gpu_applied = true;
            }
        }
    }

    if gpu_applied {
        let pub_set: HashSet<usize> = circuit.public_inputs.iter().copied().collect();
        l4_state.malleable_candidates.clear();
        for i in 1..circuit.num_variables {
            if !pub_set.contains(&i) && !l4_state.signal_values[i].is_determined() {
                l4_state.malleable_candidates.push(i);
            }
        }
    }

    let _ = std::fs::remove_file(tmp_in);
    let _ = std::fs::remove_file(tmp_out);
    gpu_applied
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 3 {
        eprintln!(
            "Uso: core_pruner --input <circuito.circom|r1cs.json> --output <pruned_ir.json> [--gpu | --cpu]"
        );
        std::process::exit(1);
    }

    let mut input_path = "";
    let mut output_path = "pruned_ir.json";
    let mut use_gpu = false;

    let mut i = 1;
    while i < args.len() {
        if args[i] == "--input" && i + 1 < args.len() {
            input_path = &args[i + 1];
            i += 2;
        } else if args[i] == "--output" && i + 1 < args.len() {
            output_path = &args[i + 1];
            i += 2;
        } else if args[i] == "--gpu" {
            use_gpu = true;
            i += 1;
        } else if args[i] == "--cpu" {
            use_gpu = false;
            i += 1;
        } else {
            i += 1;
        }
    }

    if input_path.is_empty() {
        eprintln!("[ERROR] Debe especificar un archivo de entrada con --input.");
        std::process::exit(1);
    }

    println!("\n================================================================================");
    log_telemetry(
        "INIT",
        &format!(
            "Inicializando Motor de Poda Coinductiva Chronos-ZK (Modo: {})",
            if use_gpu {
                "HYBRID RUST + CUDA GPU"
            } else {
                "RUST CPU"
            }
        ),
    );
    log_telemetry("INIT", &format!("Target File: {}", input_path));
    println!("================================================================================");

    let t_total = Instant::now();

    // 1. Fase de Parseo e Ingesta Topologica
    log_telemetry("AST_PARSE", "Tokenizando circuito e infiriendo matriz R1CS...");
    let mut circuit = match r1cs_parser::parse_circuit_file(input_path) {
        Ok(c) => c,
        Err(e) => {
            log_telemetry("FATAL", &format!("Fallo al parsear circuito: {}", e));
            std::process::exit(1);
        }
    };
    log_telemetry(
        "AST_PARSE",
        &format!(
            "Circuito: '{}' | Seniales: {} | Publicas: {} | Salidas: {} | Restricciones Iniciales: {}",
            circuit.name,
            circuit.num_variables,
            circuit.public_inputs.len(),
            circuit.output_signals.len(),
            circuit.constraints.len()
        ),
    );

    // 2. Fase de Compilacion Tensorial HDC (10,240 bits) y Reordenamiento de Localidad
    log_telemetry(
        "HDC_PACK",
        "Cristalizando topologia real a tensores densos de 10,240 bits...",
    );
    let (topology, hdc_time) =
        hdc_packer::build_hdc_topology(circuit.num_variables, &circuit.constraints, 42);
    let footprint_kb = topology.memory_footprint_kb();

    if topology.cluster_order.len() == circuit.constraints.len() && circuit.constraints.len() > 1 {
        let mut reordered = Vec::with_capacity(circuit.constraints.len());
        for &idx in &topology.cluster_order {
            reordered.push(circuit.constraints[idx].clone());
        }
        circuit.constraints = reordered;
    }

    log_telemetry(
        "HDC_PACK",
        &format!(
            "Hiperespacio ({:.1} KiB) cristalizado en {:.2?} | Distancia de Hamming media: {:.1} bits",
            footprint_kb, hdc_time, topology.mean_hamming_distance
        ),
    );

    // 3. Fase de Propagacion Unitaria Coinductiva L4
    log_telemetry(
        "L4_PROPAGATE",
        "Ejecutando punto fijo de Kleene en reticulo paraconsistente L4 O(|V|+|E|)...",
    );
    let t_prop = Instant::now();
    let mut l4_state = l4_propagator::propagate_l4_fixed_point(&circuit);
    if use_gpu {
        let _ = dispatch_cuda_megakernel(&circuit, &mut l4_state);
    }
    let prop_time = t_prop.elapsed();

    log_telemetry(
        "L4_PROPAGATE",
        &format!(
            "Punto fijo convergido en {:.2?} ({} iteraciones). Determinadas: {}/{} | Acotadas a Raices: {}",
            prop_time,
            l4_state.iterations,
            l4_state.determined_signals.len(),
            circuit.num_variables,
            l4_state.boolean_bounded_signals.len()
        ),
    );

    // 4. Fase de Slicing y Exportacion del Contrato Chronos-IR
    log_telemetry(
        "SLICER",
        "Podando subgrafos deterministas y aislando cono residual de maleabilidad...",
    );
    let surviving_count =
        match constraint_slicer::slice_and_export_ir(&circuit, &l4_state, output_path) {
            Ok(count) => count,
            Err(e) => {
                log_telemetry("FATAL", &format!("Fallo al exportar IR: {}", e));
                std::process::exit(1);
            }
        };

    let total_time = t_total.elapsed();
    log_telemetry(
        "CONTRACT",
        &format!(
            "Contrato IR exportado a '{}' ({}/{} restricciones retenidas en el cono residual)",
            output_path,
            surviving_count,
            circuit.constraints.len()
        ),
    );

    println!("\n--------------------------------------------------------------------------------");
    log_telemetry(
        "METRICS",
        &format!("Tiempo Total de Poda Coinductiva: {:.2?}", total_time),
    );
    log_telemetry(
        "METRICS",
        &format!(
            "Candidatos a Maleabilidad: {} seniales sin determinacion funcional aisladas",
            l4_state.malleable_candidates.len()
        ),
    );
    log_telemetry(
        "VERDICT",
        "REDUCCION COINDUCTIVA EXITOSA. LISTO PARA VERIFICACION SMT EN Z3.",
    );
    println!("--------------------------------------------------------------------------------\n");
}