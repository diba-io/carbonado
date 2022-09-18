use std::io::Read;

use anyhow::{anyhow, Result};
use bao::decode::{decode as bao_decode, SliceDecoder};
use ecies::decrypt;
use log::debug;
use snap::read::FrameDecoder;
use zfec_rs::{Chunk, Fec};

use crate::{
    constants::{FEC_K, FEC_M, SLICE_LEN},
    util::decode_bao_hash,
};

/// Zfec forward error correction decoding
pub fn zfec(input: &[u8], padding: usize) -> Result<Vec<u8>> {
    let bytes_input = input.len();
    if bytes_input % FEC_M != 0 {
        return Err(anyhow!(
            "Input bytes must divide evenly over number of chunks"
        ));
    }
    let chunk_size = bytes_input / FEC_M;
    debug!("Using a chunk size of {chunk_size}");
    let fec = Fec::new(FEC_K, FEC_M)?;
    let mut chunks = vec![];
    for (i, chunk) in input.chunks_exact(chunk_size).enumerate() {
        chunks.push(Chunk::new(chunk.to_owned(), i));
    }
    let decoded = fec.decode(&chunks, padding)?;

    Ok(decoded)
}

/// Bao stream extraction
pub fn bao(decoded: &[u8], hash: &[u8]) -> Result<Vec<u8>> {
    let hash = decode_bao_hash(hash)?;
    let decoded = bao_decode(decoded, &hash)?;

    Ok(decoded)
}

/// Ecies decryption
pub fn ecies(decoded: &[u8], privkey: &[u8]) -> Result<Vec<u8>> {
    let decrypted = decrypt(privkey, decoded)?;

    Ok(decrypted)
}

/// Snappy decompression
pub fn snap(decrypted: &[u8]) -> Result<Vec<u8>> {
    let mut decompressed = vec![];
    FrameDecoder::new(decrypted).read_to_end(&mut decompressed)?;

    Ok(decompressed)
}

/// Decode data from Carbonado format in reverse order:
/// zfec -> bao -> ecies -> snap
pub fn decode(privkey: &[u8], hash: &[u8], input: &[u8], padding: usize) -> Result<Vec<u8>> {
    let decoded = zfec(input, padding)?;
    let extracted = bao(&decoded, hash)?;
    let decrypted = ecies(&extracted, privkey)?;
    let decompressed = snap(&decrypted)?;

    Ok(decompressed)
}

/// Verify a 1KB slice of a Bao stream at a specific index, after decoding it from zfec
pub fn verify_stream(hash: &[u8], slice: &[u8], index: u64) -> Result<()> {
    let slice_start = index * SLICE_LEN;
    let hash = decode_bao_hash(hash)?;
    let mut decoder = SliceDecoder::new(slice, &hash, slice_start, SLICE_LEN);
    let mut decoded = vec![];
    decoder.read_to_end(&mut decoded)?;

    Ok(())
}
