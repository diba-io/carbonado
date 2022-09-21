use std::io::{Cursor, Read};

use anyhow::{anyhow, Result};
use bao::{
    decode::{decode as bao_decode, SliceDecoder},
    encode::SliceExtractor,
    Hash,
};
use combination::combine;
use ecies::decrypt;
use log::{debug, error, warn};
use snap::read::FrameDecoder;
use zfec_rs::{Chunk, Fec};

use crate::{
    constants::{FEC_K, FEC_M, SLICE_LEN},
    encode,
    utils::decode_bao_hash,
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
    debug!("Using a zfec chunk size of {chunk_size}");
    let fec = Fec::new(FEC_K, FEC_M)?;
    let mut chunks = vec![];
    for (i, chunk) in input.chunks_exact(chunk_size).enumerate() {
        chunks.push(Chunk::new(chunk.to_vec(), i));
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

/// Extract a 1KB slice of a Bao stream at a specific index, after decoding it from zfec
pub fn extract_slice(encoded: &[u8], index: u64, padding: usize) -> Result<Vec<u8>> {
    let streamed = zfec(encoded, padding)?;
    let slice_start = index * SLICE_LEN;
    let encoded_cursor = Cursor::new(&streamed);
    let mut extractor = SliceExtractor::new(encoded_cursor, slice_start, SLICE_LEN);
    let mut slice = Vec::new();
    extractor.read_to_end(&mut slice)?;

    Ok(slice)
}

/// Verify a number of 1KB slices of a Bao stream starting at a specific index
pub fn verify_slices(hash: &Hash, streamed: &[u8], index: u64, count: u64) -> Result<()> {
    let slice_start = index * SLICE_LEN;
    let slice_len = count * SLICE_LEN;

    let encoded_cursor = Cursor::new(&streamed);
    let mut extractor = SliceExtractor::new(encoded_cursor, slice_start, slice_len);
    let mut slice = Vec::new();
    extractor.read_to_end(&mut slice)?;

    let mut decoder = SliceDecoder::new(&*slice, hash, slice_start, slice_len);
    let mut decoded = vec![];
    decoder.read_to_end(&mut decoded)?;

    Ok(())
}

/// Scrub zfec-encoded data, correcting flipped bits using error correction codes
/// Returns an error when either valid data cannot be provided, or data is already valid
pub fn scrub(input: &[u8], padding: usize, hash: &[u8]) -> Result<Vec<u8>> {
    let hash = decode_bao_hash(hash)?;
    let streamed = zfec(input, padding)?;
    match bao_decode(streamed, &hash) {
        Ok(_decoded) => Err(anyhow!("Data does not need to be scrubbed.")),
        Err(e) => {
            warn!("At least one chunk was bad. Error was: {e}. Trying combinations...");

            let zfec_bytes = input.len();
            let zfec_chunk_size = zfec_bytes / FEC_M;
            if zfec_bytes % FEC_M != 0 {
                return Err(anyhow!(
                    "Zfec bytes must divide evenly over number of chunks. Remainder: {zfec_chunk_size}"
                ));
            }
            debug!("Using a zfec chunk size of {zfec_chunk_size}");

            let m_chunks: Vec<&[u8]> = input.chunks(zfec_chunk_size).collect();
            let mut combos = 0;

            for m in FEC_K..FEC_M - 1 {
                let range: Vec<usize> = (0..FEC_M).collect();
                for chunk_indices in combine::from_vec_at(&range, m) {
                    debug!("Trying chunk indices: {chunk_indices:?}");
                    combos += 1;
                    let mut k_chunks = vec![];
                    for i in chunk_indices {
                        let chunk = m_chunks[i];
                        k_chunks.push(Chunk::new(chunk.to_vec(), i));
                    }
                    let fec = Fec::new(FEC_K, FEC_M)?;
                    let decoded = fec.decode(&k_chunks, padding)?;
                    match bao_decode(&decoded, &hash) {
                        Ok(_) => {
                            let (scrubbed, scrubbed_padding) = encode::zfec(&decoded)?;
                            assert_eq!(
                                padding, scrubbed_padding,
                                "Same amount of padding should be added for the same data"
                            );
                            return Ok(scrubbed);
                        }
                        Err(_) => continue,
                    }
                }
                debug!("Trying one fewer chunk index...");
            }
            error!("Tried {combos} chunk index combinations and failed to find one that repaired the provided data.");
            Err(anyhow!(
                "Tried {combos} chunk index combinations and failed to find one that repaired the provided data."
            ))
        }
    }
}
