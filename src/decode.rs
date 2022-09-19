use std::io::{Cursor, Read};

use anyhow::{anyhow, Result};
use bao::{
    decode::{decode as bao_decode, SliceDecoder},
    encode::{encoded_size, SliceExtractor},
    Hash,
};
use ecies::decrypt;
use log::{debug, warn};
use snap::read::FrameDecoder;
use zfec_rs::{Chunk, Fec};

use crate::{
    constants::{FEC_K, FEC_M, SLICE_LEN},
    encode,
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
pub fn verify_slices(hash: &Hash, slice: &[u8], index: u64, count: u64) -> Result<()> {
    let slice_start = index * SLICE_LEN;
    let slice_len = count * SLICE_LEN;
    let mut decoder = SliceDecoder::new(slice, hash, slice_start, slice_len);
    let mut decoded = vec![];
    decoder.read_to_end(&mut decoded)?;

    Ok(())
}

// /// Verify a Bao stream at a specific start and len
// pub fn verify_stream(hash: Hash, input: &[u8], start: u64, len: u64) -> Result<()> {
//     let mut decoder = SliceDecoder::new(input, &hash, start, len);
//     let mut decoded = vec![];
//     decoder.read_to_end(&mut decoded)?;

//     Ok(())
// }

/// Scrub zfec-encoded data, correcting flipped bits using error correction codes
pub fn scrub(input: &[u8], padding: usize, hash: &[u8]) -> Result<Vec<u8>> {
    let hash = decode_bao_hash(hash)?;
    let streamed = zfec(input, padding)?;

    let zfec_bytes = input.len();
    if zfec_bytes % FEC_M != 0 {
        return Err(anyhow!(
            "Zfec bytes must divide evenly over number of chunks. Remainder: {}",
            zfec_bytes % FEC_M
        ));
    }
    let zfec_chunk_size = zfec_bytes / FEC_M;
    debug!("Using a zfec chunk size of {zfec_chunk_size}");

    let bao_bytes = streamed.len();
    let bao_slices = bao_bytes as f64 / encoded_size(SLICE_LEN as u64) as f64 / FEC_M as f64;
    debug!("Using {bao_slices} slices for {bao_bytes} Bao bytes");

    let fec = Fec::new(FEC_K, FEC_M)?;
    let mut chunks = vec![];

    for (i, chunk) in input.chunks_exact(zfec_chunk_size).enumerate() {
        let i_f = i as f64;
        debug!(
            "Verifying slices between indexes {} and {}",
            (i_f * bao_slices).round(),
            (i_f * bao_slices).round() + bao_slices.ceil(),
        );
        match verify_slices(
            &hash,
            &streamed,
            (i_f * bao_slices).round() as u64,
            bao_slices.ceil() as u64,
        ) {
            Ok(_) => {
                chunks.push(Chunk::new(chunk.to_vec(), i));
            }
            Err(e) => {
                warn!("Chunk {i} was bad, omitting. Error was: {e}");
                continue;
            }
        }
    }

    if chunks.len() < FEC_K {
        return Err(anyhow!(
            "Error decoding Zfec encoding. There should always be at least {FEC_K} valid chunks of {FEC_M} total chunks, but instead there were {}", chunks.len()
        ));
    }

    let decoded = fec.decode(&chunks, padding)?;
    let (scrubbed, _pos) = encode::zfec(&decoded)?;

    if input == scrubbed {
        Err(anyhow!("Data does not need to be scrubbed."))
    } else {
        Ok(scrubbed)
    }
}
