use anyhow::Result;
use bao::Hash;

pub fn calculate_factor(starting_value: usize, ending_value: usize) -> f32 {
    let difference = ending_value as f32 - starting_value as f32;
    let average = starting_value + ending_value;
    difference / average as f32
}

pub fn decode_bao_hash(hash: &[u8]) -> Result<Hash> {
    let hash_array: [u8; bao::HASH_SIZE] = hash[..].try_into()?;
    Ok(hash_array.into())
}
