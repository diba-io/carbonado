use std::fs::read;

use anyhow::Result;
use carbonado::{decode, encode, utils::init_logging, verify_slice};
use ecies::utils::generate_keypair;
use log::{debug, info};
use wasm_bindgen_test::{wasm_bindgen_test, wasm_bindgen_test_configure};

wasm_bindgen_test_configure!(run_in_browser);

#[test]
fn contract() -> Result<()> {
    init_logging();

    codec("tests/samples/contract.rgbc")?;
    // codec("tests/samples/navi10_arch.7z")?;

    Ok(())
}

#[test]
fn content() -> Result<()> {
    init_logging();

    codec("tests/samples/content.png")?;

    Ok(())
}

#[test]
fn code() -> Result<()> {
    init_logging();

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
    init_logging();

    codec("tests/samples/content.png")?;

    Ok(())
}

#[wasm_bindgen_test]
fn wasm_code() -> Result<()> {
    init_logging();

    codec("tests/samples/code.tar")?;

    Ok(())
}

fn codec(path: &str) -> Result<()> {
    let input = read(path)?;
    let (sk, pk) = generate_keypair();

    info!("Encoding {path}...");
    let (encoded, hash, encode_info) = encode(&pk.serialize(), &input, 15)?;

    debug!("Encoding Info: {encode_info:#?}");
    assert_eq!(
        encoded.len() as u32,
        encode_info.bytes_verifiable,
        "Length of encoded bytes matches bytes_verifiable field"
    );

    info!("Verifying stream against hash: {hash}...");
    verify_slice(&hash, &encoded, 0, encode_info.slice_count)?;

    info!("Decoding Carbonado bytes");
    let decoded = decode(
        &sk.serialize(),
        hash.as_bytes(),
        &encoded,
        encode_info.padding,
        15,
    )?;
    assert_eq!(decoded, input, "Decoded output is same as encoded input");

    info!("All good!");

    Ok(())
}
