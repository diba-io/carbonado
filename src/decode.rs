use std::io::{Cursor, Read};

use anyhow::{anyhow, Result};
use bao::{
    decode::{decode as bao_decode, SliceDecoder},
    encode::SliceExtractor,
    Hash,
};
use ecies::decrypt;
use log::{info, warn};
use snap::read::FrameDecoder;
use zfec_rs::{Chunk, Fec};

use crate::{
    constants::{FEC_K, FEC_M, SLICE_LEN},
    encode,
    utils::decode_bao_hash,
};

fn zfec_chunks(chunked_bytes: Vec<Vec<u8>>, padding: usize) -> Result<Vec<u8>> {
    let mut zfec_chunks = vec![];
    for (i, chunk) in chunked_bytes.into_iter().enumerate() {
        zfec_chunks.push(Chunk::new(chunk, i));
    }
    let fec = Fec::new(FEC_K, FEC_M)?;
    let decoded = fec.decode(&zfec_chunks, padding)?;
    Ok(decoded)
}

/// Zfec forward error correction decoding
pub fn zfec(input: &[u8], padding: usize) -> Result<Vec<u8>> {
    let chunks: Vec<Vec<u8>> = input
        .chunks_exact(input.len() / FEC_M)
        .map(|c| c.to_owned())
        .collect();

    let decoded = zfec_chunks(chunks, padding)?;

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
/// bao -> zfec -> ecies -> snap
pub fn decode(privkey: &[u8], hash: &[u8], input: &[u8], padding: usize) -> Result<Vec<u8>> {
    let verified = bao(input, hash)?;
    let decoded = zfec(&verified, padding)?;
    let decrypted = ecies(&decoded, privkey)?;
    let decompressed = snap(&decrypted)?;

    Ok(decompressed)
}

/// Extract a 1KB slice of a Bao stream at a specific index, after decoding it from zfec
pub fn extract_slice(encoded: &[u8], index: usize) -> Result<Vec<u8>> {
    let slice_start = index * SLICE_LEN;
    let encoded_cursor = Cursor::new(&encoded);
    let mut extractor = SliceExtractor::new(encoded_cursor, slice_start as u64, SLICE_LEN as u64);
    let mut slice = Vec::new();
    extractor.read_to_end(&mut slice)?;

    Ok(slice)
}

/// Verify a number of 1KB slices of a Bao stream starting at a specific index
pub fn verify_slices(hash: &Hash, streamed: &[u8], index: usize, count: usize) -> Result<()> {
    let slice_start = index * SLICE_LEN;
    let slice_len = count * SLICE_LEN;

    let encoded_cursor = Cursor::new(&streamed);
    let mut extractor = SliceExtractor::new(encoded_cursor, slice_start as u64, slice_len as u64);
    let mut slice = Vec::new();
    extractor.read_to_end(&mut slice)?;

    let mut decoder = SliceDecoder::new(&*slice, hash, slice_start as u64, slice_len as u64);
    let mut decoded = vec![];
    decoder.read_to_end(&mut decoded)?;

    Ok(())
}

/// Scrub zfec-encoded data, correcting flipped bits using error correction codes
/// Returns an error when either valid data cannot be provided, or data is already valid
pub fn scrub(input: &[u8], padding: usize, hash: &[u8]) -> Result<Vec<u8>> {
    let hash = decode_bao_hash(hash)?;

    match bao_decode(input, &hash) {
        Ok(_decoded) => Err(anyhow!("Data does not need to be scrubbed.")),
        Err(e) => {
            warn!("Data failed to verify with error: {e}. Scrubbing...");
            let input_len = input.len();
            let mut chunks = vec![];

            for i in 0..FEC_M {
                match extract_slice(input, i) {
                    Ok(chunk) => chunks.push(chunk),
                    Err(e) => {
                        warn!("At least one chunk was bad, at chunk index {i}. Error was: {e}.");
                    }
                }
            }

            info!("{} good chunks found, of {FEC_K} needed.", chunks.len());

            let decoded = zfec_chunks(chunks, input_len)?;
            let (scrubbed, scrubbed_padding) = encode::zfec(&decoded)?;
            assert_eq!(
                padding, scrubbed_padding,
                "Scrubbed padding is equal to original padding"
            );
            let (verified, scrubbed_hash) = encode::bao(&scrubbed)?;
            assert_eq!(
                hash, scrubbed_hash,
                "Scrubbed hash is equal to original hash"
            );
            Ok(verified)
        }
    }
}
