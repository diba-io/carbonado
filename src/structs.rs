use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncodeInfo {
    pub input_len: usize,
    pub bytes_compressed: usize, // snappy
    pub bytes_encrypted: usize,  // ecies
    pub bytes_encoded: usize,    // zfec
    pub bytes_verifiable: usize, // bao
    pub compression_factor: f32,
    pub amplification_factor: f32,
    pub padding: usize,
    pub chunk_size: usize,
}
