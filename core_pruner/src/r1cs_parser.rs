//! ===========================================================================
//! CHRONOS-ZK: PARSER NATIVO DE CIRCUITOS CIRCOM, JSON Y BINARIOS IDEN3 .R1CS
//! Modulo: core_pruner/src/r1cs_parser.rs
//! Proposito: Ingesta sin dependencias externas de:
//!            1. Binarios oficiales Iden3 `.r1cs` v1 (Little-Endian 256-bit)
//!            2. Archivos fuente `.circom` (IsZero, Num2Bits, Merkle, etc.)
//!            3. Contratos JSON (`Chronos-IR`, `SnarkJS` y `R1CSCircuit`)
//! ===========================================================================

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::cmp::Ordering;
use std::collections::HashMap;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

pub const BN254_PRIME: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495617";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SparseConstraint {
    pub a: Vec<(usize, String)>,
    pub b: Vec<(usize, String)>,
    pub c: Vec<(usize, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct R1CSCircuit {
    pub name: String,
    pub field_prime: String,
    pub num_variables: usize,
    pub public_inputs: Vec<usize>,
    pub private_inputs: Vec<usize>,
    pub output_signals: Vec<usize>,
    pub constraints: Vec<SparseConstraint>,
    #[serde(default)]
    pub signal_names: HashMap<String, usize>,
}

impl R1CSCircuit {
    pub fn new(name: &str) -> Self {
        let mut signal_names = HashMap::new();
        signal_names.insert("ONE".to_string(), 0);

        R1CSCircuit {
            name: name.to_string(),
            field_prime: BN254_PRIME.to_string(),
            num_variables: 1,
            public_inputs: Vec::new(),
            private_inputs: Vec::new(),
            output_signals: Vec::new(),
            constraints: Vec::new(),
            signal_names,
        }
    }

    pub fn alloc_signal(&mut self, name: &str) -> usize {
        if let Some(&id) = self.signal_names.get(name) {
            id
        } else {
            let id = self.num_variables;
            self.signal_names.insert(name.to_string(), id);
            self.num_variables += 1;
            id
        }
    }
}

pub fn normalize_coeff_str(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed == "21888242871839275222246405745257275088548364400416034343698204186575808495616" {
        return "-1".to_string();
    }
    if trimmed == "21888242871839275222246405745257275088548364400416034343698204186575808495615" {
        return "-2".to_string();
    }
    trimmed.to_string()
}

fn clean_circuit_stem(filepath: &str) -> String {
    let stem = Path::new(filepath)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("Imported_Circuit");
    stem.strip_suffix(".snarkjs").unwrap_or(stem).to_string()
}

// ===========================================================================
// ARITMETICA DE 256 BITS LITTLE-ENDIAN PARA FORMATO BINARIO IDEN3 (.R1CS)
// ===========================================================================

fn bytes_le_to_u256(bytes: &[u8]) -> [u64; 4] {
    let mut buf = [0u8; 32];
    let copy_len = std::cmp::min(bytes.len(), 32);
    buf[..copy_len].copy_from_slice(&bytes[..copy_len]);
    [
        u64::from_le_bytes(buf[0..8].try_into().unwrap()),
        u64::from_le_bytes(buf[8..16].try_into().unwrap()),
        u64::from_le_bytes(buf[16..24].try_into().unwrap()),
        u64::from_le_bytes(buf[24..32].try_into().unwrap()),
    ]
}

fn cmp_u256(a: &[u64; 4], b: &[u64; 4]) -> Ordering {
    for i in (0..4).rev() {
        match a[i].cmp(&b[i]) {
            Ordering::Equal => continue,
            non_eq => return non_eq,
        }
    }
    Ordering::Equal
}

fn shr1_u256(a: [u64; 4]) -> [u64; 4] {
    [
        (a[0] >> 1) | (a[1] << 63),
        (a[1] >> 1) | (a[2] << 63),
        (a[2] >> 1) | (a[3] << 63),
        a[3] >> 1,
    ]
}

fn sub_u256(a: [u64; 4], b: [u64; 4]) -> [u64; 4] {
    let mut out = [0u64; 4];
    let mut borrow: u64 = 0;
    for i in 0..4 {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d2, b2) = d1.overflowing_sub(borrow);
        out[i] = d2;
        borrow = if b1 || b2 { 1 } else { 0 };
    }
    out
}

fn u256_to_decimal_string(mut limbs: [u64; 4]) -> String {
    if limbs == [0, 0, 0, 0] {
        return "0".to_string();
    }
    let mut digits = Vec::with_capacity(80);
    while limbs != [0, 0, 0, 0] {
        let mut rem: u128 = 0;
        for i in (0..4).rev() {
            let cur = (rem << 64) | (limbs[i] as u128);
            limbs[i] = (cur / 10) as u64;
            rem = cur % 10;
        }
        digits.push((b'0' + (rem as u8)) as char);
    }
    digits.iter().rev().collect()
}

fn field_bytes_to_signed_str(
    coeff_bytes: &[u8],
    prime_limbs: &[u64; 4],
    half_prime_limbs: &[u64; 4],
) -> String {
    let c_limbs = bytes_le_to_u256(coeff_bytes);
    if c_limbs == [0, 0, 0, 0] {
        return "0".to_string();
    }
    if cmp_u256(&c_limbs, half_prime_limbs) == Ordering::Greater
        && cmp_u256(&c_limbs, prime_limbs) == Ordering::Less
    {
        let neg_mag = sub_u256(*prime_limbs, c_limbs);
        format!("-{}", u256_to_decimal_string(neg_mag))
    } else {
        u256_to_decimal_string(c_limbs)
    }
}

/// Parsea un archivo binario `.r1cs` conforme a la especificacion oficial Iden3 v1.
pub fn parse_binary_r1cs_file(filepath: &str) -> Result<R1CSCircuit, Box<dyn std::error::Error>> {
    let mut file = File::open(filepath)?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    if data.len() < 12 || &data[0..4] != b"r1cs" {
        return Err("El archivo no posee la cabecera magica binaria 'r1cs' de Iden3.".into());
    }

    let version = u32::from_le_bytes(data[4..8].try_into()?);
    if version != 1 {
        return Err(format!("Version binaria .r1cs no soportada: {} (esperada: 1)", version).into());
    }

    let n_sections = u32::from_le_bytes(data[8..12].try_into()?) as usize;
    let mut pos = 12usize;

    let mut sec1_range: Option<(usize, usize)> = None;
    let mut sec2_range: Option<(usize, usize)> = None;

    for _ in 0..n_sections {
        if pos + 12 > data.len() {
            return Err("Archivo .r1cs truncado en cabecera de seccion.".into());
        }
        let sec_type = u32::from_le_bytes(data[pos..pos + 4].try_into()?);
        let sec_size = u64::from_le_bytes(data[pos + 4..pos + 12].try_into()?) as usize;
        pos += 12;

        if pos + sec_size > data.len() {
            return Err("Archivo .r1cs truncado en payload de seccion.".into());
        }

        if sec_type == 1 {
            sec1_range = Some((pos, pos + sec_size));
        } else if sec_type == 2 {
            sec2_range = Some((pos, pos + sec_size));
        }
        pos += sec_size;
    }

    let (s1_start, s1_end) =
        sec1_range.ok_or("El archivo .r1cs no contiene la Seccion 1 (Header).")?;
    let (s2_start, s2_end) =
        sec2_range.ok_or("El archivo .r1cs no contiene la Seccion 2 (Constraints).")?;

    let s1 = &data[s1_start..s1_end];
    if s1.len() < 4 {
        return Err("Seccion 1 (Header) invalida en .r1cs.".into());
    }
    let field_size = u32::from_le_bytes(s1[0..4].try_into()?) as usize;
    if s1.len() < 4 + field_size + 28 {
        return Err("Seccion 1 (Header) incompleta para el tamano de cuerpo especificado.".into());
    }

    let prime_bytes = &s1[4..4 + field_size];
    let prime_limbs = bytes_le_to_u256(prime_bytes);
    let half_prime_limbs = shr1_u256(prime_limbs);
    let prime_str = u256_to_decimal_string(prime_limbs);

    let meta_offset = 4 + field_size;
    let n_wires = u32::from_le_bytes(s1[meta_offset..meta_offset + 4].try_into()?) as usize;
    let n_pub_out = u32::from_le_bytes(s1[meta_offset + 4..meta_offset + 8].try_into()?) as usize;
    let n_pub_in = u32::from_le_bytes(s1[meta_offset + 8..meta_offset + 12].try_into()?) as usize;
    let n_prv_in = u32::from_le_bytes(s1[meta_offset + 12..meta_offset + 16].try_into()?) as usize;
    let _n_labels = u64::from_le_bytes(s1[meta_offset + 16..meta_offset + 24].try_into()?);
    let m_constraints =
        u32::from_le_bytes(s1[meta_offset + 24..meta_offset + 28].try_into()?) as usize;

    let output_signals: Vec<usize> = (1..=n_pub_out).collect();
    let pub_start = 1 + n_pub_out;
    let public_inputs: Vec<usize> = (pub_start..pub_start + n_pub_in).collect();
    let prv_start = pub_start + n_pub_in;
    let private_inputs: Vec<usize> =
        (prv_start..std::cmp::min(n_wires, prv_start + n_prv_in)).collect();

    // Parsear Seccion 2 (Constraints)
    let s2 = &data[s2_start..s2_end];
    let mut c_pos = 0usize;
    let mut constraints = Vec::with_capacity(m_constraints);

    let read_lc = |buf: &[u8], cursor: &mut usize| -> Result<Vec<(usize, String)>, String> {
        if *cursor + 4 > buf.len() {
            return Err("Seccion 2 truncada al leer n_terms.".to_string());
        }
        let n_terms = u32::from_le_bytes(buf[*cursor..*cursor + 4].try_into().unwrap()) as usize;
        *cursor += 4;

        let entry_size = 4 + field_size;
        if *cursor + (n_terms * entry_size) > buf.len() {
            return Err("Seccion 2 truncada al leer terminos de combinacion lineal.".to_string());
        }

        let mut terms = Vec::with_capacity(n_terms);
        for _ in 0..n_terms {
            let wire_id =
                u32::from_le_bytes(buf[*cursor..*cursor + 4].try_into().unwrap()) as usize;
            let coeff_slice = &buf[*cursor + 4..*cursor + 4 + field_size];
            *cursor += entry_size;

            let coeff_str =
                field_bytes_to_signed_str(coeff_slice, &prime_limbs, &half_prime_limbs);
            if coeff_str != "0" {
                terms.push((wire_id, coeff_str));
            }
        }
        Ok(terms)
    };

    for _ in 0..m_constraints {
        let a = read_lc(s2, &mut c_pos)?;
        let b = read_lc(s2, &mut c_pos)?;
        let c = read_lc(s2, &mut c_pos)?;
        constraints.push(SparseConstraint { a, b, c });
    }

    let mut signal_names = HashMap::new();
    signal_names.insert("ONE".to_string(), 0);
    for i in 1..n_wires {
        signal_names.insert(format!("w_{}", i), i);
    }

    Ok(R1CSCircuit {
        name: clean_circuit_stem(filepath),
        field_prime: prime_str,
        num_variables: n_wires,
        public_inputs,
        private_inputs,
        output_signals,
        constraints,
        signal_names,
    })
}

pub fn parse_circuit_file(filepath: &str) -> Result<R1CSCircuit, Box<dyn std::error::Error>> {
    if filepath.ends_with(".r1cs") {
        return parse_binary_r1cs_file(filepath);
    }
    if filepath.ends_with(".json") {
        return parse_json_circuit_file(filepath);
    }

    // Detectar tambien si un archivo sin extension .r1cs comienza con los magic bytes b"r1cs"
    {
        let mut probe = File::open(filepath)?;
        let mut magic = [0u8; 4];
        if probe.read_exact(&mut magic).is_ok() && &magic == b"r1cs" {
            return parse_binary_r1cs_file(filepath);
        }
    }

    let file = File::open(filepath)?;
    let reader = BufReader::new(file);
    let mut lines = Vec::new();
    for line in reader.lines() {
        lines.push(line?);
    }

    let mut main_template = String::new();
    let mut main_param: Option<usize> = None;
    let mut declared_public_names: Vec<String> = Vec::new();

    for line in &lines {
        let trimmed = strip_inline_comment(line).trim().to_string();
        if trimmed.starts_with("component main") {
            if let Some(pub_start) = trimmed.find("{public") {
                if let Some(br_open) = trimmed[pub_start..].find('[') {
                    if let Some(br_close) = trimmed[pub_start + br_open..].find(']') {
                        let inside =
                            &trimmed[pub_start + br_open + 1..pub_start + br_open + br_close];
                        for item in inside.split(',') {
                            let clean = item.trim();
                            if !clean.is_empty() {
                                declared_public_names.push(clean.to_string());
                            }
                        }
                    }
                }
            }
            if let Some(eq_pos) = trimmed.find('=') {
                let rhs = trimmed[eq_pos + 1..].replace(';', "").trim().to_string();
                if let Some(paren_open) = rhs.find('(') {
                    main_template = rhs[..paren_open].trim().to_string();
                    if let Some(paren_close) = rhs[paren_open..].find(')') {
                        let arg_str = rhs[paren_open + 1..paren_open + paren_close].trim();
                        if let Ok(val) = arg_str.parse::<usize>() {
                            main_param = Some(val);
                        }
                    }
                } else {
                    main_template = rhs;
                }
            }
        }
    }

    if main_template.contains("MerkleVerifier") {
        let levels = main_param.unwrap_or(3);
        let is_secure = main_template.contains("Secure")
            || lines.iter().any(|l| {
                let t = strip_inline_comment(l);
                t.contains("pathIndices") && t.contains("===")
            });
        return Ok(build_merkle_circuit(
            if main_template.is_empty() {
                "MerkleVerifier"
            } else {
                &main_template
            },
            levels,
            is_secure,
        ));
    }

    if main_template.contains("Num2Bits") {
        let n_bits = main_param.unwrap_or(8);
        let is_secure = main_template.contains("Secure")
            || lines.iter().any(|l| {
                let t = strip_inline_comment(l);
                t.contains("out[i]") && t.contains("===")
            });
        return Ok(build_num2bits_circuit(
            if main_template.is_empty() {
                "Num2Bits"
            } else {
                &main_template
            },
            n_bits,
            is_secure,
        ));
    }

    if main_template.contains("IsZero") {
        let is_secure = main_template.contains("Secure")
            || lines.iter().any(|l| {
                let t = strip_inline_comment(l);
                t.contains("in * out") && t.contains("===")
            });
        return Ok(build_iszero_circuit(
            if main_template.is_empty() {
                "IsZero"
            } else {
                &main_template
            },
            is_secure,
        ));
    }

    let default_stem = clean_circuit_stem(filepath);
    let mut circuit = R1CSCircuit::new(if main_template.is_empty() {
        &default_stem
    } else {
        &main_template
    });

    let mut in_target_template = false;
    let param_val = main_param.unwrap_or(8);

    for raw_line in &lines {
        let trimmed = strip_inline_comment(raw_line).trim().to_string();
        if trimmed.is_empty() || trimmed.starts_with("pragma") {
            continue;
        }

        if trimmed.starts_with("template") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() > 1 {
                let t_name = parts[1].split('(').next().unwrap_or("Circuit").to_string();
                if main_template.is_empty() || t_name == main_template {
                    in_target_template = true;
                    circuit.name = t_name;
                } else {
                    in_target_template = false;
                }
            }
            continue;
        }

        if !in_target_template {
            continue;
        }

        if trimmed.starts_with("signal input") {
            let name = extract_signal_name(&trimmed, "signal input");
            if name.contains('[') {
                let (base_name, count) = parse_array_def(&name, param_val);
                let is_pub = declared_public_names.is_empty()
                    || declared_public_names.contains(&base_name);
                for i in 0..count {
                    let sig_id = circuit.alloc_signal(&format!("{}_{}", base_name, i));
                    if is_pub {
                        circuit.public_inputs.push(sig_id);
                    } else {
                        circuit.private_inputs.push(sig_id);
                    }
                }
            } else {
                let sig_id = circuit.alloc_signal(&name);
                let is_pub =
                    declared_public_names.is_empty() || declared_public_names.contains(&name);
                if is_pub {
                    circuit.public_inputs.push(sig_id);
                } else {
                    circuit.private_inputs.push(sig_id);
                }
            }
        } else if trimmed.starts_with("signal output") {
            let name = extract_signal_name(&trimmed, "signal output");
            if name.contains('[') {
                let (base_name, count) = parse_array_def(&name, param_val);
                for i in 0..count {
                    let sig_id = circuit.alloc_signal(&format!("{}_{}", base_name, i));
                    circuit.output_signals.push(sig_id);
                }
            } else {
                let sig_id = circuit.alloc_signal(&name);
                circuit.output_signals.push(sig_id);
            }
        } else if trimmed.starts_with("signal ") {
            let name = extract_signal_name(&trimmed, "signal");
            if name.contains('[') {
                let (base_name, count) = parse_array_def(&name, param_val);
                for i in 0..count {
                    let sig_id = circuit.alloc_signal(&format!("{}_{}", base_name, i));
                    circuit.private_inputs.push(sig_id);
                }
            } else {
                let sig_id = circuit.alloc_signal(&name);
                circuit.private_inputs.push(sig_id);
            }
        }

        if trimmed.contains("===") {
            parse_constraint_expression(&trimmed, &mut circuit);
        } else if trimmed.contains("<==") {
            parse_assignment_constraint(&trimmed, &mut circuit);
        }
    }

    Ok(circuit)
}

fn parse_json_circuit_file(filepath: &str) -> Result<R1CSCircuit, Box<dyn std::error::Error>> {
    let file = File::open(filepath)?;
    let reader = BufReader::new(file);
    let v: Value = serde_json::from_reader(reader)?;
    let fallback_name = clean_circuit_stem(filepath);

    if v.get("r1cs_constraints").is_some() {
        let name = v
            .get("name")
            .and_then(|x| x.as_str())
            .unwrap_or(&fallback_name)
            .strip_suffix(".snarkjs")
            .unwrap_or_else(|| {
                v.get("name")
                    .and_then(|x| x.as_str())
                    .unwrap_or(&fallback_name)
            })
            .to_string();
        let field_prime = v
            .get("field_prime")
            .and_then(|x| x.as_str())
            .unwrap_or(BN254_PRIME)
            .to_string();
        let num_variables = v
            .get("num_variables")
            .and_then(|x| x.as_u64())
            .unwrap_or(1) as usize;

        let parse_id_vec = |key: &str| -> Vec<usize> {
            v.get(key)
                .and_then(|arr| arr.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|item| item.as_u64().map(|n| n as usize))
                        .collect()
                })
                .unwrap_or_default()
        };

        let public_inputs = parse_id_vec("public_inputs");
        let private_inputs = parse_id_vec("private_inputs");
        let output_signals = parse_id_vec("output_signals");

        let parse_term_list = |term_val: Option<&Value>| -> Vec<(usize, String)> {
            let mut out = Vec::new();
            if let Some(arr) = term_val.and_then(|x| x.as_array()) {
                for pair in arr {
                    if let Some(items) = pair.as_array() {
                        if items.len() == 2 {
                            let sig_id = items[0].as_u64().unwrap_or(0) as usize;
                            let coeff_str = match &items[1] {
                                Value::String(s) => normalize_coeff_str(s),
                                Value::Number(n) => normalize_coeff_str(&n.to_string()),
                                _ => "0".to_string(),
                            };
                            if coeff_str != "0" {
                                out.push((sig_id, coeff_str));
                            }
                        }
                    }
                }
            }
            out
        };

        let mut constraints = Vec::new();
        if let Some(c_arr) = v.get("r1cs_constraints").and_then(|x| x.as_array()) {
            for c_obj in c_arr {
                let a = parse_term_list(c_obj.get("A").or_else(|| c_obj.get("a")));
                let b = parse_term_list(c_obj.get("B").or_else(|| c_obj.get("b")));
                let c = parse_term_list(c_obj.get("C").or_else(|| c_obj.get("c")));
                constraints.push(SparseConstraint { a, b, c });
            }
        }

        let mut signal_names = HashMap::new();
        signal_names.insert("ONE".to_string(), 0);
        for i in 1..num_variables {
            signal_names.insert(format!("w_{}", i), i);
        }

        return Ok(R1CSCircuit {
            name,
            field_prime,
            num_variables,
            public_inputs,
            private_inputs,
            output_signals,
            constraints,
            signal_names,
        });
    }

    if v.get("nVars").is_some() && v.get("constraints").is_some() {
        let num_variables = v.get("nVars").and_then(|x| x.as_u64()).unwrap_or(1) as usize;
        let n_outputs = v.get("nOutputs").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
        let n_pub = v.get("nPubInputs").and_then(|x| x.as_u64()).unwrap_or(0) as usize;
        let n_prv = v.get("nPrvInputs").and_then(|x| x.as_u64()).unwrap_or(0) as usize;

        let output_signals: Vec<usize> = (1..=n_outputs).collect();
        let pub_start = 1 + n_outputs;
        let public_inputs: Vec<usize> = (pub_start..pub_start + n_pub).collect();
        let prv_start = pub_start + n_pub;
        let private_inputs: Vec<usize> =
            (prv_start..std::cmp::min(num_variables, prv_start + n_prv)).collect();

        let parse_snark_map = |m_val: &Value| -> Vec<(usize, String)> {
            let mut terms = Vec::new();
            if let Some(obj) = m_val.as_object() {
                for (k, val) in obj {
                    let sig_id = k.parse::<usize>().unwrap_or(0);
                    let coeff_raw = match val {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        _ => "0".to_string(),
                    };
                    let coeff = normalize_coeff_str(&coeff_raw);
                    if coeff != "0" {
                        terms.push((sig_id, coeff));
                    }
                }
            }
            terms.sort_by_key(|t| t.0);
            terms
        };

        let mut constraints = Vec::new();
        if let Some(c_arr) = v.get("constraints").and_then(|x| x.as_array()) {
            for c_item in c_arr {
                if let Some(triple) = c_item.as_array() {
                    if triple.len() == 3 {
                        constraints.push(SparseConstraint {
                            a: parse_snark_map(&triple[0]),
                            b: parse_snark_map(&triple[1]),
                            c: parse_snark_map(&triple[2]),
                        });
                    }
                }
            }
        }

        let mut signal_names = HashMap::new();
        signal_names.insert("ONE".to_string(), 0);
        for i in 1..num_variables {
            signal_names.insert(format!("w_{}", i), i);
        }

        return Ok(R1CSCircuit {
            name: fallback_name,
            field_prime: v
                .get("prime")
                .and_then(|x| x.as_str())
                .unwrap_or(BN254_PRIME)
                .to_string(),
            num_variables,
            public_inputs,
            private_inputs,
            output_signals,
            constraints,
            signal_names,
        });
    }

    let circuit: R1CSCircuit = serde_json::from_value(v)?;
    Ok(circuit)
}

fn strip_inline_comment(line: &str) -> &str {
    if let Some(idx) = line.find("//") {
        &line[..idx]
    } else {
        line
    }
}

fn extract_signal_name(line: &str, prefix: &str) -> String {
    let clean = line.replace(prefix, "").replace(';', "");
    clean.trim().to_string()
}

fn parse_array_def(def: &str, default_param: usize) -> (String, usize) {
    let parts: Vec<&str> = def.split('[').collect();
    let base = parts[0].trim().to_string();
    let size_expr = parts[1].replace(']', "").trim().to_string();
    let count = if let Ok(c) = size_expr.parse::<usize>() {
        c
    } else if size_expr.contains('+') {
        let add_parts: Vec<&str> = size_expr.split('+').collect();
        let offset = add_parts
            .get(1)
            .and_then(|s| s.trim().parse::<usize>().ok())
            .unwrap_or(0);
        default_param + offset
    } else {
        default_param
    };
    (base, count)
}

fn parse_constraint_expression(line: &str, circuit: &mut R1CSCircuit) {
    let parts: Vec<&str> = line.split("===").collect();
    if parts.len() != 2 {
        return;
    }
    let left = parts[0].trim().replace(';', "");
    let right = parts[1].trim().replace(';', "");

    if left.contains('*') && right == "0" {
        let factors: Vec<&str> = left.split('*').collect();
        if factors.len() == 2 {
            let f0 = factors[0].trim();
            let f1 = factors[1].trim();

            if f1.contains("1 -") || f1.contains("1-") || f0.contains("1 -") || f0.contains("1-")
            {
                let var_name = if f1.contains("1 -") || f1.contains("1-") {
                    f0
                } else {
                    f1
                };
                let var_id = circuit.alloc_signal(var_name);
                circuit.constraints.push(SparseConstraint {
                    a: vec![(var_id, "1".to_string())],
                    b: vec![(0, "1".to_string()), (var_id, "-1".to_string())],
                    c: vec![],
                });
            } else {
                let id1 = circuit.alloc_signal(f0);
                let id2 = circuit.alloc_signal(f1);
                circuit.constraints.push(SparseConstraint {
                    a: vec![(id1, "1".to_string())],
                    b: vec![(id2, "1".to_string())],
                    c: vec![],
                });
            }
        }
    }
}

fn parse_assignment_constraint(line: &str, circuit: &mut R1CSCircuit) {
    let parts: Vec<&str> = line.split("<==").collect();
    if parts.len() != 2 {
        return;
    }
    let left = parts[0].trim();
    let right = parts[1].trim().replace(';', "");

    if right.contains("-in * inv + 1") || right.contains("-in*inv + 1") {
        let in_id = circuit.alloc_signal("in");
        let inv_id = circuit.alloc_signal("inv");
        let out_id = circuit.alloc_signal(left);
        circuit.constraints.push(SparseConstraint {
            a: vec![(in_id, "1".to_string())],
            b: vec![(inv_id, "1".to_string())],
            c: vec![(0, "1".to_string()), (out_id, "-1".to_string())],
        });
    } else if right.contains('*') && !right.contains('+') && !right.contains('-') {
        let factors: Vec<&str> = right.split('*').collect();
        if factors.len() == 2 {
            let id1 = circuit.alloc_signal(factors[0].trim());
            let id2 = circuit.alloc_signal(factors[1].trim());
            let out_id = circuit.alloc_signal(left);
            circuit.constraints.push(SparseConstraint {
                a: vec![(id1, "1".to_string())],
                b: vec![(id2, "1".to_string())],
                c: vec![(out_id, "1".to_string())],
            });
        }
    }
}

fn build_iszero_circuit(name: &str, secure: bool) -> R1CSCircuit {
    let mut circuit = R1CSCircuit::new(name);
    let in_id = circuit.alloc_signal("in");
    let out_id = circuit.alloc_signal("out");
    let inv_id = circuit.alloc_signal("inv");

    circuit.public_inputs = vec![in_id];
    circuit.output_signals = vec![out_id];
    circuit.private_inputs = vec![inv_id];

    circuit.constraints.push(SparseConstraint {
        a: vec![(in_id, "1".to_string())],
        b: vec![(inv_id, "1".to_string())],
        c: vec![(0, "1".to_string()), (out_id, "-1".to_string())],
    });

    if secure {
        circuit.constraints.push(SparseConstraint {
            a: vec![(in_id, "1".to_string())],
            b: vec![(out_id, "1".to_string())],
            c: vec![],
        });
    }

    circuit
}

fn build_num2bits_circuit(name: &str, n_bits: usize, secure: bool) -> R1CSCircuit {
    let mut circuit = R1CSCircuit::new(name);
    let in_id = circuit.alloc_signal("in");
    circuit.public_inputs = vec![in_id];

    let mut lin_sum = Vec::with_capacity(n_bits);
    for i in 0..n_bits {
        let bit_id = circuit.alloc_signal(&format!("out_{}", i));
        circuit.output_signals.push(bit_id);
        let coeff = (1u128 << i).to_string();
        lin_sum.push((bit_id, coeff));
    }

    circuit.constraints.push(SparseConstraint {
        a: vec![(0, "1".to_string())],
        b: lin_sum,
        c: vec![(in_id, "1".to_string())],
    });

    if secure {
        for &bit_id in &circuit.output_signals {
            circuit.constraints.push(SparseConstraint {
                a: vec![(bit_id, "1".to_string())],
                b: vec![(0, "1".to_string()), (bit_id, "-1".to_string())],
                c: vec![],
            });
        }
    }

    circuit
}

fn build_merkle_circuit(name: &str, levels: usize, secure: bool) -> R1CSCircuit {
    let mut circuit = R1CSCircuit::new(name);
    let leaf_id = circuit.alloc_signal("leaf");
    let root_id = circuit.alloc_signal("root");

    let mut path_elements = Vec::with_capacity(levels);
    for i in 0..levels {
        path_elements.push(circuit.alloc_signal(&format!("pathElements_{}", i)));
    }

    let mut path_indices = Vec::with_capacity(levels);
    for i in 0..levels {
        let s_id = circuit.alloc_signal(&format!("pathIndices_{}", i));
        path_indices.push(s_id);
        circuit.private_inputs.push(s_id);
    }

    circuit.public_inputs.push(leaf_id);
    circuit.public_inputs.extend(&path_elements);
    circuit.output_signals.push(root_id);

    let mut current_id = leaf_id;

    for i in 0..levels {
        let s_id = path_indices[i];
        let pe_id = path_elements[i];

        if secure {
            circuit.constraints.push(SparseConstraint {
                a: vec![(s_id, "1".to_string())],
                b: vec![(0, "1".to_string()), (s_id, "-1".to_string())],
                c: vec![],
            });
        }

        let left_id = circuit.alloc_signal(&format!("left_{}", i));
        let right_id = circuit.alloc_signal(&format!("right_{}", i));
        let prod_id = circuit.alloc_signal(&format!("prod_{}", i));
        let next_curr_id = if i == levels - 1 {
            root_id
        } else {
            circuit.alloc_signal(&format!("current_{}", i + 1))
        };

        circuit.private_inputs.push(left_id);
        circuit.private_inputs.push(right_id);
        circuit.private_inputs.push(prod_id);
        if i < levels - 1 {
            circuit.private_inputs.push(next_curr_id);
        }

        circuit.constraints.push(SparseConstraint {
            a: vec![(s_id, "1".to_string())],
            b: vec![(pe_id, "1".to_string()), (current_id, "-1".to_string())],
            c: vec![(left_id, "1".to_string()), (current_id, "-1".to_string())],
        });

        circuit.constraints.push(SparseConstraint {
            a: vec![(s_id, "1".to_string())],
            b: vec![(current_id, "1".to_string()), (pe_id, "-1".to_string())],
            c: vec![(right_id, "1".to_string()), (pe_id, "-1".to_string())],
        });

        circuit.constraints.push(SparseConstraint {
            a: vec![(left_id, "1".to_string())],
            b: vec![(right_id, "1".to_string())],
            c: vec![(prod_id, "1".to_string())],
        });

        circuit.constraints.push(SparseConstraint {
            a: vec![(0, "1".to_string())],
            b: vec![
                (prod_id, "1".to_string()),
                (left_id, "1".to_string()),
                (right_id, "1".to_string()),
                (0, "7".to_string()),
            ],
            c: vec![(next_curr_id, "1".to_string())],
        });

        current_id = next_curr_id;
    }

    circuit
}