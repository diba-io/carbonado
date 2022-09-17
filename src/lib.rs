#![allow(unused_variables)]
use std::io::{Read, Write};

use anyhow::Result;
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
pub fn encode(input: &mut [u8], privkey: &[u8]) -> Result<(Vec<u8>, EncodeInfo)> {
    let bytes_input = input.len();
    let buffer: &[u8] = input;
    let output = vec![];

    // Snappy compression
    let mut writer = FrameEncoder::new(output);
    writer.write_all(buffer)?;
    let output = writer.into_inner()?;
    let bytes_compressed = output.len();

    // Ecies encryption
    let bytes_encrypted = 0;

    // Bao stream encoding
    let bytes_streamed = 0;

    // Zfec forward error correction encoding
    let bytes_encoded = bytes_compressed;

    // Calculate totals
    let compression_factor = calculate_factor(bytes_input, bytes_compressed);
    let amplification_factor = calculate_factor(bytes_input, bytes_encoded);

    Ok((
        output,
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
pub fn decode(input: &[u8], pubkey: &[u8]) -> Result<(Vec<u8>, DecodeInfo)> {
    let mut buf = vec![];
    FrameDecoder::new(input).read_to_end(&mut buf)?;

    let fec_errors = 0;
    let slices = 0;
    // let hash = 0;

    Ok((
        buf,
        DecodeInfo {
            fec_errors,
            slices,
            // hash,
        },
    ))
}

/// Verify a slice of a Bao stream at a specific position, after decoding it from zfec
pub fn verify_stream(slice: &[u8], pos: usize) -> Result<()> {
    todo!();
}

/// Scrub zfec-encoded data, correcting flipped bits using error correction codes
pub fn scrub(input: &[u8]) -> Result<(Vec<u8>, usize)> {
    todo!();
}
