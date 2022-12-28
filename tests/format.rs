use anyhow::Result;
use carbonado::{decode, encode, fs::Header, utils::init_logging};
use ecies::utils::generate_keypair;
use log::{debug, info};
use wasm_bindgen_test::wasm_bindgen_test_configure;

wasm_bindgen_test_configure!(run_in_browser);

#[test]
fn contract() -> Result<()> {
    init_logging();

    let input = "Hellow world!".as_bytes();
    let (privkey, pubkey) = generate_keypair();

    info!("Encoding input: {input:?}...");
    let (encoded, hash, encode_info) = encode(&pubkey.serialize(), input)?;

    debug!("Encoding Info: {encode_info:#?}");
    assert_eq!(
        encoded.len(),
        encode_info.bytes_verifiable,
        "Length of encoded bytes matches bytes_verifiable field"
    );

    info!("Decoding Carbonado bytes");
    let decoded = decode(
        &privkey.serialize(),
        hash.as_bytes(),
        &encoded,
        encode_info.padding,
    )?;
    assert_eq!(decoded, input, "Decoded output is same as encoded input");

    info!("All good!");

    Ok(())
}
