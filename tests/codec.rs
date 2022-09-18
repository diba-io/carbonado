use std::fs::read;

use anyhow::Result;
use carbonado::{decode, encode, extract_slice, verify_stream};
use ecies::utils::generate_keypair;
use wasm_bindgen_test::wasm_bindgen_test;
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

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

#[wasm_bindgen_test]
fn wasm_contract() -> Result<()> {
    codec("tests/samples/contract.rgbc")?;
    Ok(())
}

#[wasm_bindgen_test]
fn wasm_content() -> Result<()> {
    codec("tests/samples/content.png")?;
    Ok(())
}

#[wasm_bindgen_test]
fn wasm_code() -> Result<()> {
    codec("tests/samples/code.tar")?;
    Ok(())
}

fn codec(path: &str) -> Result<()> {
    let mut input = read(path)?;
    let (privkey, pubkey) = generate_keypair();
    let (encoded, hash, encode_info) = encode(&pubkey.serialize(), &mut input)?;
    println!("{encode_info:#?}");
    assert_eq!(
        encoded.len(),
        encode_info.bytes_encoded,
        "Length of encoded bytes matches bytes_encoded field"
    );
    let index = 0;
    let slice = extract_slice(&encoded, index)?;
    verify_stream(hash.as_bytes(), &slice, index)?;
    let (decoded, decode_info) = decode(&privkey.serialize(), hash.as_bytes(), &encoded)?;
    println!("{decode_info:#?}");
    assert_eq!(decoded, input, "Decoded output is same as encoded input");
    Ok(())
}
