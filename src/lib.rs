use std::io::{Read, Write};

use anyhow::Result;
use bao::{
    decode::{decode as bao_decode, SliceDecoder},
    encode::{encode as bao_encode, SliceExtractor},
    Hash,
};
use ecies::{decrypt, encrypt};
use snap::{read::FrameDecoder, write::FrameEncoder};

pub mod structs;
pub mod util;

use structs::{DecodeInfo, EncodeInfo};
use util::{calculate_factor, decode_bao_hash};

const SLICE_LEN: u64 = 1024;

/// Encode data into Carbonado format in this order:
/// snap -> ecies -> bao -> zfec
/// It performs compression, encryption, stream encoding, and adds error correction codes, in that order.
pub fn encode(pubkey: &[u8], input: &mut [u8]) -> Result<(Vec<u8>, Hash, EncodeInfo)> {
    let bytes_input = input.len();
    let buffer: &[u8] = input;
    let output = vec![];

    // Snappy compression
    let mut writer = FrameEncoder::new(output);
    writer.write_all(buffer)?;
    let compressed = writer.into_inner()?;
    let bytes_compressed = compressed.len();

    // Ecies encryption
    let encrypted = encrypt(pubkey, &compressed)?;
    let bytes_encrypted = encrypted.len();

    // Bao stream encoding
    let (encoded, hash) = bao_encode(encrypted);
    let bytes_streamed = encoded.len();

    // Zfec forward error correction encoding
    let encoded = encoded;
    let bytes_encoded = bytes_streamed;

    // Calculate totals
    let compression_factor = calculate_factor(bytes_input, bytes_compressed);
    let amplification_factor = calculate_factor(bytes_input, bytes_encoded);

    Ok((
        encoded,
        hash,
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

/// Decode data from Carbonado format in reverse order:
/// zfec -> bao -> ecies -> snap
pub fn decode(privkey: &[u8], hash: &[u8], input: &[u8]) -> Result<(Vec<u8>, DecodeInfo)> {
    // Zfec forward error correction decoding
    let decoded = input;

    // Bao stream decoding
    let hash = decode_bao_hash(hash)?;
    let decoded = bao_decode(decoded, &hash)?;

    // Ecies decryption
    let decrypted = decrypt(privkey, &decoded)?;

    // Snappy decompression
    let mut decompressed = vec![];
    FrameDecoder::new(decrypted.as_slice()).read_to_end(&mut decompressed)?;

    let fec_errors = 0;
    let slices = 0;

    Ok((decompressed, DecodeInfo { fec_errors, slices }))
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

/// Verify a 1KB slice of a Bao stream at a specific index, after decoding it from zfec
pub fn verify_stream(hash: &[u8], slice: &[u8], index: u64) -> Result<()> {
    let slice_start = index * SLICE_LEN;
    let hash = decode_bao_hash(hash)?;
    let mut decoder = SliceDecoder::new(slice, &hash, slice_start, SLICE_LEN);
    let mut decoded = vec![];
    decoder.read_to_end(&mut decoded)?;
    Ok(())
}

/// Scrub zfec-encoded data, correcting flipped bits using error correction codes
#[allow(unused_variables)]
pub fn scrub(input: &[u8]) -> Result<(Vec<u8>, usize)> {
    todo!();
}
