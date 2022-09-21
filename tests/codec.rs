use std::fs::read;

use anyhow::Result;
use carbonado::{decode, encode, extract_slice, utils::init_logging, verify_slices};
use ecies::utils::generate_keypair;
use log::{debug, info};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[test]
fn contract() -> Result<()> {
    init_logging();

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
    init_logging();

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
    let input = read(path)?;
    let (privkey, pubkey) = generate_keypair();

    info!("Encoding {path}...");
    let (encoded, hash, padding, encode_info) = encode(&pubkey.serialize(), &input)?;

    debug!("Padding was {padding}. Encoding Info: {encode_info:#?}");
    assert_eq!(
        encoded.len(),
        encode_info.bytes_encoded,
        "Length of encoded bytes matches bytes_encoded field"
    );

    let offset = 0;
    info!("Extracting slice at offset: {offset}...");
    let slice = extract_slice(&encoded, offset, padding)?;

    info!("Verifying stream against hash: {hash}...");
    verify_slices(&hash, &slice, offset, 1)?;

    let decoded = decode(&privkey.serialize(), hash.as_bytes(), &encoded, padding)?;
    assert_eq!(decoded, input, "Decoded output is same as encoded input");

    info!("All good!");

    Ok(())
}
