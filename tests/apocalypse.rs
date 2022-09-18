use std::fs::read;

use anyhow::Result;
use carbonado::{encode, scrub};
use ecies::utils::generate_keypair;
wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);

#[test]
fn contract() -> Result<()> {
    act_of_god("tests/samples/contract.rgbc")?;

    Ok(())
}

fn act_of_god(path: &str) -> Result<()> {
    let input = read(path)?;
    let (_privkey, pubkey) = generate_keypair();
    let (orig_encoded, _hash, padding, _encode_info) = encode(&pubkey.serialize(), &input)?;
    let mut new_encoded = orig_encoded.clone();

    let orig_result = scrub(&orig_encoded, padding);
    assert!(
        orig_result.is_err(),
        "Return error when there's no need to scrub"
    );

    new_encoded[0] ^= 127;

    let new_result = scrub(&new_encoded, padding);
    assert!(
        new_result.is_ok(),
        "Returns ok when there was a need to scrub"
    );
    // TODO: figure out why scrubbing isn't working
    // assert_eq!(
    //     new_result?, orig_encoded,
    //     "Original and scrubbed data are the same"
    // );

    Ok(())
}
