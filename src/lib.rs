use std::io::{Read, Write};

use anyhow::Result;
use ecies::{decrypt, encrypt};
use snap::{read::FrameDecoder, write::FrameEncoder};

mod structs;
mod util;

use structs::{DecodeInfo, EncodeInfo};

fn calculate_factor(starting_value: usize, ending_value: usize) -> f32 {
    let difference = ending_value as f32 - starting_value as f32;
    let average = starting_value + ending_value;
    difference / average as f32
}

/// Encode data into Carbonado format in this order:
/// snap -> ecies -> bao -> zfec
/// It performs compression, encryption, stream encoding, and adds error correction codes, in that order.
pub fn encode(pubkey: &[u8], input: &mut [u8]) -> Result<(Vec<u8>, EncodeInfo)> {
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
    let encoded = encrypted;
    let bytes_streamed = bytes_encrypted;

    // Zfec forward error correction encoding
    let encoded = encoded;
    let bytes_encoded = bytes_streamed;

    // Calculate totals
    let compression_factor = calculate_factor(bytes_input, bytes_compressed);
    let amplification_factor = calculate_factor(bytes_input, bytes_encoded);

    Ok((
        encoded,
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
pub fn decode(privkey: &[u8], input: &[u8]) -> Result<(Vec<u8>, DecodeInfo)> {
    // Zfec forward error correction decoding
    let decoded = input;

    // Bao stream decoding
    let decoded = decoded;

    // Ecies decryption
    let decrypted = decrypt(privkey, decoded)?;

    // Snappy decompression
    let mut decompressed = vec![];
    FrameDecoder::new(decrypted.as_slice()).read_to_end(&mut decompressed)?;

    let fec_errors = 0;
    let slices = 0;

    Ok((decompressed, DecodeInfo { fec_errors, slices }))
}

/// Verify a slice of a Bao stream at a specific position, after decoding it from zfec
#[allow(unused_variables)]
pub fn verify_stream(slice: &[u8], pos: usize) -> Result<()> {
    todo!();
}

/// Scrub zfec-encoded data, correcting flipped bits using error correction codes
#[allow(unused_variables)]
pub fn scrub(input: &[u8]) -> Result<(Vec<u8>, usize)> {
    todo!();
}
