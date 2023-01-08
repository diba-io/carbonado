use std::sync::Once;

use anyhow::Result;
use bao::Hash;
use bech32::{decode, encode, FromBase32, ToBase32, Variant};
use log::trace;

use crate::constants::{FEC_K, SLICE_LEN};

static INIT: Once = Once::new();

/// Helper function only used in tests
pub fn init_logging() {
    INIT.call_once(|| {
        use std::env::{set_var, var};

        if var("RUST_LOG").is_err() {
            set_var(
                "RUST_LOG",
                "carbonado=trace,codec=trace,apocalypse=trace,format=trace",
            );
        }

        pretty_env_logger::init();
    });
}

/// Encodes a Bao hash into a hexadecimal string
pub fn encode_bao_hash(hash: &Hash) -> String {
    let hash_hex = hash.to_hex();
    hash_hex.to_string()
}

/// Decodes a Bao hash from a hexadecimal string
pub fn decode_bao_hash(hash: &[u8]) -> Result<Hash> {
    let hash_array: [u8; bao::HASH_SIZE] = hash[..].try_into()?;
    Ok(hash_array.into())
}

/// Calculate padding (find a length that divides evenly both by Zfec FEC_K and Bao SLICE_LEN, then find the difference)
/// Returns (padding_len, chunk_size)
pub fn calc_padding_len(input_len: usize) -> (u32, u32) {
    let input_len = input_len as f64;
    let overlap_constant = SLICE_LEN as f64 * FEC_K as f64;
    let target_size = (input_len / overlap_constant).ceil() * overlap_constant;
    let padding_len = target_size - input_len;
    let chunk_size = target_size / FEC_K as f64;
    trace!("input_len: {input_len:.0}, target_size: {target_size:.0}, padding_len: {padding_len:.0}, chunk_size: {chunk_size:.0}");
    (padding_len as u32, chunk_size as u32)
}

/// Helper for encoding data to bech32m
pub fn bech32m_encode(hrp: &str, bytes: &[u8]) -> Result<String> {
    Ok(encode(hrp, bytes.to_base32(), Variant::Bech32m)?)
}

/// Helper for decoding bech32-encoded data
pub fn bech32_decode(bech32_str: &str) -> Result<(String, Vec<u8>, Variant)> {
    let (hrp, words, variant) = decode(bech32_str)?;
    Ok((hrp, Vec::<u8>::from_base32(&words)?, variant))
}
