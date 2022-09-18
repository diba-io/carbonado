use anyhow::{anyhow, Result};

mod constants;
mod decode;
mod encode;
mod structs;
pub mod util;

pub use decode::{decode, verify_stream};
pub use encode::{encode, extract_slice};

/// Scrub zfec-encoded data, correcting flipped bits using error correction codes
#[allow(unused_variables)]
pub fn scrub(encoded: &[u8], padding: usize) -> Result<Vec<u8>> {
    let (scrubbed, _) = encode::zfec(&decode::zfec(encoded, padding)?)?;

    if encoded == scrubbed {
        Err(anyhow!("Data does not need to be scrubbed."))
    } else {
        Ok(scrubbed)
    }
}
