use std::fs::read;

use anyhow::Result;
use carbonado::{decode, encode};
use ecies::utils::generate_keypair;

#[test]
fn contract() -> Result<()> {
    codec("tests/samples/contract.rgbc")?;
    Ok(())
}

#[test]
fn content() -> Result<()> {
    codec("tests/samples/content.png")?;
    Ok(())
}

#[test]
fn code() -> Result<()> {
    codec("tests/samples/code.tar")?;
    Ok(())
}

fn codec(path: &str) -> Result<()> {
    let mut input = read(path)?;
    let (privkey, pubkey) = generate_keypair();
    let (encoded, encode_info) = encode(&pubkey.serialize(), &mut input)?;
    println!("{encode_info:#?}");
    assert_eq!(
        encoded.len(),
        encode_info.bytes_encoded,
        "Length of encoded bytes matches bytes_encoded field"
    );
    let (decoded, decode_info) = decode(&privkey.serialize(), &encoded)?;
    println!("{decode_info:#?}");
    assert_eq!(decoded, input, "Decoded output is same as encoded input");
    Ok(())
}
