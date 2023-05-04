use std::{fs::OpenOptions, io::Write, path::PathBuf};

use anyhow::Result;
use carbonado::{
    constants::Format, decode, encode, file::Header, structs::Encoded, utils::init_logging,
};
use log::{debug, info, trace};
use rand::thread_rng;
use secp256k1::{ecdh::SharedSecret, generate_keypair, PublicKey, Secp256k1, SecretKey};
use wasm_bindgen_test::wasm_bindgen_test_configure;

wasm_bindgen_test_configure!(run_in_browser);

const RUST_LOG: &str = "carbonado=trace,format=trace";

#[test]
fn format() -> Result<()> {
    init_logging(RUST_LOG);

    let input = "Hello world!".as_bytes();
    let carbonado_level = 15;
    let format = Format::try_from(carbonado_level)?;

    let (file_sk, file_pk) = generate_keypair(&mut thread_rng());
    let (node_sk, node_pk) = generate_keypair(&mut thread_rng());
    let ss = SharedSecret::new(&file_pk, &node_sk);

    debug!(
        "file_sk: {} file_pk: {} node_sk: {} node_pk: {} shared_secret: {}",
        file_sk.display_secret(),
        file_pk,
        node_sk.display_secret(),
        node_pk,
        ss.display_secret()
    );

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&ss.secret_bytes())?;
    let pk = PublicKey::from_secret_key(&secp, &sk);

    info!("Encoding input: {input:?}...");
    let Encoded(encoded, hash, encode_info) = encode(&pk.serialize(), input, carbonado_level)?;

    debug!("Encoding Info: {encode_info:#?}");

    let header = Header::new(
        &sk.secret_bytes(),
        &pk.serialize(),
        hash.as_bytes(),
        format,
        0,
        encode_info.bytes_verifiable,
        encode_info.padding_len,
    )?;
    trace!("Header: {header:#?}");

    let header_bytes = header.try_to_vec()?;

    let file_path = PathBuf::from("/tmp").join(header.file_name());
    info!("Writing test file to: {file_path:?}");
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(file_path)?;
    file.write_all(&header_bytes)?;
    file.write_all(&encoded)?;
    info!("Test file successfully written.");

    info!("Parsing file headers...");
    let header = Header::try_from(&file)?;

    assert_eq!(header.pubkey, PublicKey::from_slice(&pk.serialize())?);
    assert_eq!(header.hash, hash);
    assert_eq!(header.format, format);
    assert_eq!(header.chunk_index, 0);
    assert_eq!(header.padding_len, encode_info.padding_len);

    info!("Decoding Carbonado bytes");
    let decoded = decode(
        &sk.secret_bytes(),
        hash.as_bytes(),
        &encoded,
        encode_info.padding_len,
        carbonado_level,
    )?;

    assert_eq!(decoded, input, "Decoded output is same as encoded input");

    info!("All good!");

    Ok(())
}
