use anyhow::Result;
use bao::Hash;

pub fn calculate_factor(starting_value: usize, ending_value: usize) -> f32 {
    let starting_value = starting_value as f32;
    let ending_value = ending_value as f32;
    (ending_value - starting_value) / ending_value
}

pub fn decode_bao_hash(hash: &[u8]) -> Result<Hash> {
    let hash_array: [u8; bao::HASH_SIZE] = hash[..].try_into()?;

    Ok(hash_array.into())
}

pub fn init_logging() {
    use std::env::{set_var, var};

    if var("RUST_LOG").is_err() {
        set_var("RUST_LOG", "carbonado=trace,codec=trace,apocalypse=trace");
    }

    pretty_env_logger::init();
}
