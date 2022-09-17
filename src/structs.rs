pub struct EncodeInfo {
    bytes_raw: usize,
    bytes_compressed: usize, // snappy
    bytes_encrypted: usize,  // ecies
    bytes_streamed: usize,   // bao
    bytes_encoded: usize,    // zfec
    compression_factor: f32,
    amplification_factor: f32,
}

pub struct DecodeInfo {
    fec_errors: usize,
    slices: usize,
    hash: bao::Hash,
}
