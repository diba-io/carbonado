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
            set_var("RUST_LOG", "carbonado=trace,codec=trace,apocalypse=trace");
        }

        pretty_env_logger::init();
    });
}

pub fn decode_bao_hash(hash: &[u8]) -> Result<Hash> {
    let hash_array: [u8; bao::HASH_SIZE] = hash[..].try_into()?;

    Ok(hash_array.into())
}

/// Calculate padding (find a length that divides evenly both by Zfec FEC_K and Bao SLICE_LEN, then find the difference)
/// Returns (padding_len, chunk_size)
pub fn calc_padding_len(input_len: usize) -> (usize, usize) {
    let overlap_constant = SLICE_LEN * FEC_K;
    let target_size =
        (input_len as f64 / overlap_constant as f64).ceil() as usize * overlap_constant;
    let padding_len = target_size - input_len;
    let chunk_size = target_size / FEC_K;
    trace!("input_len: {input_len}, target_size: {target_size}, padding_len: {padding_len}, chunk_size: {chunk_size}");
    (padding_len, chunk_size)
}

pub fn bech32m_encode(hrp: &str, bytes: &[u8]) -> Result<String> {
    Ok(encode(hrp, bytes.to_base32(), Variant::Bech32m)?)
}

pub fn bech32_decode(bech32_str: &str) -> Result<(String, Vec<u8>, Variant)> {
    let (hrp, words, variant) = decode(bech32_str)?;
    Ok((hrp, Vec::<u8>::from_base32(&words)?, variant))
}
