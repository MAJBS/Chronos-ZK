//! ===========================================================================
//! CHRONOS-ZK: COMPILADOR TOPOLOGICO HIPERDIMENSIONAL (HDC)
//! Modulo: core_pruner/src/hdc_packer.rs
//! Proposito: Empaquetamiento tensorial de 10,240 bits de la topologia real
//!            de restricciones R1CS (binding de roles A, B, C con seniales y
//!            clustering de localidad espacial por distancia de Hamming).
//! ===========================================================================

use crate::r1cs_parser::SparseConstraint;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use std::time::{Duration, Instant};

pub const HDC_U32_LEN: usize = 320; // 10,240 bits / 32 bits

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Hypervector {
    pub data: [u32; HDC_U32_LEN],
}

impl Hypervector {
    pub fn zero() -> Self {
        Hypervector {
            data: [0u32; HDC_U32_LEN],
        }
    }

    pub fn new_orthogonal(rng: &mut ChaCha8Rng) -> Self {
        let mut data = [0u32; HDC_U32_LEN];
        for elem in data.iter_mut() {
            *elem = rng.gen::<u32>();
        }
        Hypervector { data }
    }

    #[inline(always)]
    pub fn bind(&self, other: &Hypervector) -> Self {
        let mut result = [0u32; HDC_U32_LEN];
        for i in 0..HDC_U32_LEN {
            result[i] = self.data[i] ^ other.data[i];
        }
        Hypervector { data: result }
    }

    #[inline(always)]
    pub fn permute_word(&self, shift_words: usize) -> Self {
        let mut result = [0u32; HDC_U32_LEN];
        let s = shift_words % HDC_U32_LEN;
        for i in 0..HDC_U32_LEN {
            result[(i + s) % HDC_U32_LEN] = self.data[i];
        }
        Hypervector { data: result }
    }

    #[inline(always)]
    pub fn bundle_majority(a: &Hypervector, b: &Hypervector, c: &Hypervector) -> Self {
        let mut result = [0u32; HDC_U32_LEN];
        for i in 0..HDC_U32_LEN {
            result[i] =
                (a.data[i] & b.data[i]) | (a.data[i] & c.data[i]) | (b.data[i] & c.data[i]);
        }
        Hypervector { data: result }
    }

    pub fn hamming_distance(&self, other: &Hypervector) -> usize {
        let mut dist = 0usize;
        for i in 0..HDC_U32_LEN {
            dist += (self.data[i] ^ other.data[i]).count_ones() as usize;
        }
        dist
    }
}

pub struct HDCTopology {
    pub signal_tensors: Vec<Hypervector>,
    pub constraint_tensors: Vec<Hypervector>,
    pub cluster_order: Vec<usize>,
    pub mean_hamming_distance: f64,
}

impl HDCTopology {
    /// Calcula la huella de memoria exacta (en KiB) de los tensores de senial
    /// y de restriccion cristalizados en el hiperespacio de 10,240 bits.
    pub fn memory_footprint_kb(&self) -> f64 {
        let total_tensors = self.signal_tensors.len() + self.constraint_tensors.len();
        let bytes = total_tensors * HDC_U32_LEN * std::mem::size_of::<u32>();
        (bytes as f64) / 1024.0
    }
}

fn encode_linear_combination(
    terms: &[(usize, String)],
    role_hv: &Hypervector,
    signal_tensors: &[Hypervector],
) -> Hypervector {
    if terms.is_empty() {
        return *role_hv;
    }
    let mut acc = Hypervector::zero();
    for (pos, (sig_id, _coeff)) in terms.iter().enumerate() {
        if *sig_id < signal_tensors.len() {
            let sig_hv = signal_tensors[*sig_id].permute_word(pos);
            acc = acc.bind(&sig_hv);
        }
    }
    role_hv.bind(&acc)
}

pub fn build_hdc_topology(
    num_signals: usize,
    constraints: &[SparseConstraint],
    seed: u64,
) -> (HDCTopology, Duration) {
    let t0 = Instant::now();
    let mut rng = ChaCha8Rng::seed_from_u64(seed);

    let safe_signals = std::cmp::max(num_signals, 1);
    let mut signal_tensors = Vec::with_capacity(safe_signals);
    for _ in 0..safe_signals {
        signal_tensors.push(Hypervector::new_orthogonal(&mut rng));
    }

    let role_a = Hypervector::new_orthogonal(&mut rng);
    let role_b = Hypervector::new_orthogonal(&mut rng);
    let role_c = Hypervector::new_orthogonal(&mut rng);

    let mut constraint_tensors = Vec::with_capacity(constraints.len());
    for c in constraints {
        let hv_a = encode_linear_combination(&c.a, &role_a, &signal_tensors);
        let hv_b = encode_linear_combination(&c.b, &role_b, &signal_tensors);
        let hv_c = encode_linear_combination(&c.c, &role_c, &signal_tensors);
        let c_tensor = Hypervector::bundle_majority(&hv_a, &hv_b, &hv_c);
        constraint_tensors.push(c_tensor);
    }

    let mut cluster_order: Vec<usize> = (0..constraints.len()).collect();
    let mut mean_hamming_distance = 0.0;

    if !constraint_tensors.is_empty() {
        let anchor = constraint_tensors[0];
        let mut distances: Vec<(usize, usize)> = constraint_tensors
            .iter()
            .enumerate()
            .map(|(idx, hv)| (idx, anchor.hamming_distance(hv)))
            .collect();

        let total_dist: usize = distances.iter().map(|(_, d)| *d).sum();
        mean_hamming_distance = (total_dist as f64) / (constraint_tensors.len() as f64);

        distances.sort_by_key(|&(_, dist)| dist);
        cluster_order = distances.into_iter().map(|(idx, _)| idx).collect();
    }

    let elapsed = t0.elapsed();
    (
        HDCTopology {
            signal_tensors,
            constraint_tensors,
            cluster_order,
            mean_hamming_distance,
        },
        elapsed,
    )
}