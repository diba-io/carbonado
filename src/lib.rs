#![allow(unused_variables)]
use anyhow::Result;

mod structs;
mod util;

use structs::{DecodeInfo, EncodeInfo};

/// Encode data into Carbonado format in this order:
/// snap -> ecies -> bao -> zfec
/// It performs compression, encryption, stream encoding, and adds error correction codes, in that order.
pub fn encode(data: &[u8], privkey: &[u8]) -> Result<(Vec<u8>, EncodeInfo)> {
    todo!();
}

/// Decode data from Carbonado format in reverse order:
/// zfec -> bao -> ecies -> snap
pub fn decode(data: &[u8], pubkey: &[u8]) -> Result<(Vec<u8>, DecodeInfo)> {
    todo!();
}

/// Scrub zfec-encoded data, correcting flipped bits using error correction codes
pub fn scrub(data: &[u8]) -> Result<(Vec<u8>, usize)> {
    todo!();
}

/// Verify a slice of a Bao stream at a specific position, after decoding it from zfec
pub fn verify_stream(slice: &[u8], pos: usize) -> Result<()> {
    todo!();
}
