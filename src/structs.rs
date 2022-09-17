use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncodeInfo {
    pub bytes_input: usize,
    pub bytes_compressed: usize, // snappy
    pub bytes_encrypted: usize,  // ecies
    pub bytes_streamed: usize,   // bao
    pub bytes_encoded: usize,    // zfec
    pub compression_factor: f32,
    pub amplification_factor: f32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DecodeInfo {
    pub fec_errors: usize,
    pub slices: usize,
}
