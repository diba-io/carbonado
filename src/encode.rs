use std::io::{Read, Write};

use anyhow::Result;
use bao::{
    encode::{encode as bao_encode, SliceExtractor},
    Hash,
};
use ecies::encrypt;
use snap::write::FrameEncoder;
use zfec_rs::Fec;

use crate::constants::{FEC_K, FEC_M, SLICE_LEN};
use crate::structs::EncodeInfo;
use crate::util::calculate_factor;

/// Snappy compression
pub fn snap(input: &[u8]) -> Result<Vec<u8>> {
    let buffer: &[u8] = input;
    let output = vec![];
    let mut writer = FrameEncoder::new(output);
    writer.write_all(buffer)?;
    let compressed = writer.into_inner()?;

    Ok(compressed)
}

/// Ecies encryption
pub fn ecies(pubkey: &[u8], compressed: &[u8]) -> Result<Vec<u8>> {
    let encrypted = encrypt(pubkey, compressed)?;

    Ok(encrypted)
}

/// Bao stream encoding
pub fn bao(encrypted: &[u8]) -> Result<(Vec<u8>, Hash)> {
    let (encoded, hash) = bao_encode(encrypted);

    Ok((encoded, hash))
}

/// Zfec forward error correction encoding
pub fn zfec(streamed: &[u8]) -> Result<(Vec<u8>, usize)> {
    let fec = Fec::new(FEC_K, FEC_M)?;
    let (mut encoded_chunks, padding) = fec.encode(streamed)?;
    let mut encoded = vec![];

    for chunk in &mut encoded_chunks {
        encoded.append(&mut chunk.data);
    }

    Ok((encoded, padding))
}

/// Encode data into Carbonado format in this order:
/// snap -> ecies -> bao -> zfec
/// It performs compression, encryption, stream encoding, and adds error correction codes, in that order.
pub fn encode(pubkey: &[u8], input: &[u8]) -> Result<(Vec<u8>, Hash, usize, EncodeInfo)> {
    let bytes_input = input.len();

    let compressed = snap(input)?;
    let bytes_compressed = compressed.len();

    let encrypted = ecies(pubkey, &compressed)?;
    let bytes_encrypted = encrypted.len();

    let (streamed, hash) = bao(&encrypted)?;
    let bytes_streamed = streamed.len();

    let (encoded, padding) = zfec(&streamed)?;
    let bytes_encoded = encoded.len();

    // Calculate totals
    let compression_factor = calculate_factor(bytes_input, bytes_compressed);
    let amplification_factor = calculate_factor(bytes_input, bytes_encoded);

    Ok((
        encoded,
        hash,
        padding,
        EncodeInfo {
            bytes_input,
            bytes_compressed,
            bytes_encrypted,
            bytes_streamed,
            bytes_encoded,
            compression_factor,
            amplification_factor,
        },
    ))
}

/// Extract a 1KB slice of a Bao stream at a specific index, after decoding it from zfec
pub fn extract_slice(encoded: &[u8], index: u64) -> Result<Vec<u8>> {
    let slice_start = index * SLICE_LEN;
    let encoded_cursor = std::io::Cursor::new(&encoded);
    let mut extractor = SliceExtractor::new(encoded_cursor, slice_start, SLICE_LEN);
    let mut slice = Vec::new();
    extractor.read_to_end(&mut slice)?;

    Ok(slice)
}
