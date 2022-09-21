use anyhow::Result;
use bao::Hash;

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
