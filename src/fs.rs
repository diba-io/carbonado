use anyhow::Result;
use bao::Hash;
use ecies::PublicKey;

use crate::constants::{Format, MAGICNO};

pub fn header(pubkey: PublicKey, hash: Hash, format: Format) -> Vec<u8> {
    let mut pubkey_bytes = pubkey.serialize_compressed().to_vec(); // 33 bytes
    let mut hash_bytes = hash.as_bytes().to_vec(); // 32 bytes
    let mut format_bytes = format.bits().to_le_bytes().to_vec(); // 2 bytes
    let mut header = Vec::with_capacity(80);
    header.append(&mut MAGICNO.to_vec());
    header.append(&mut pubkey_bytes);
    header.append(&mut hash_bytes);
    header.append(&mut format_bytes);
    header.append(&mut vec![b'\0', b'\0', b'\0']); // 3 padding null bytes
    header
}

pub fn parse_filename(header_bytes: &[u8]) -> Result<(PublicKey, Hash, Format)> {
    let pubkey = todo!();
    let hash = todo!();
    let format = todo!();
    Ok((pubkey, hash, format))
}
