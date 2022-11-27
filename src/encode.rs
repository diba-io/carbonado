use std::io::Write;

use anyhow::Result;
use bao::{encode::encode as bao_encode, Hash};
use ecies::encrypt;
use log::debug;
use snap::write::FrameEncoder;
use zfec_rs::Fec;

use crate::{
    constants::{FEC_K, FEC_M},
    structs::EncodeInfo,
    utils::calc_padding_len,
};

/// Snappy compression
pub fn snap(input: &[u8]) -> Result<Vec<u8>> {
    let buffer: &[u8] = input;
    let output = vec![];
    let mut writer = FrameEncoder::new(output);
    writer.write_all(buffer)?;
    let compressed = writer.into_inner()?;

    Ok(compressed)
}

/// Ecies encryption
pub fn ecies(pubkey: &[u8], compressed: &[u8]) -> Result<Vec<u8>> {
    let encrypted = encrypt(pubkey, compressed)?;

    Ok(encrypted)
}

/// Bao stream encoding
pub fn bao(input: &[u8]) -> Result<(Vec<u8>, Hash)> {
    let (encoded, hash) = bao_encode(input);

    Ok((encoded, hash))
}

/// Zfec forward error correction encoding
pub fn zfec(input: &[u8]) -> Result<(Vec<u8>, usize, usize)> {
    let input_len = input.len();
    let (padding_len, chunk_size) = calc_padding_len(input_len);
    // TODO: CSPRNG padding
    let mut padding_bytes = vec![0u8; padding_len];
    let mut padded_input = Vec::from(input);
    padded_input.append(&mut padding_bytes);
    debug!(
        "After padding has been added, input is now: {} bytes",
        padded_input.len()
    );

    let fec = Fec::new(FEC_K, FEC_M)?;
    let (mut encoded_chunks, zfec_padding) = fec.encode(&padded_input)?;

    assert_eq!(
        zfec_padding, 0,
        "Padding from Zfec should always be zero, since Carbonado adds its own padding. Padding was: {zfec_padding}"
    );

    let mut encoded = vec![];

    for chunk in &mut encoded_chunks {
        assert_eq!(
            chunk_size,
            chunk.data.len(),
            "Chunk size should be as calculated"
        );
        encoded.append(&mut chunk.data);
    }

    Ok((encoded, padding_len, chunk_size))
}

/// Encode data into Carbonado format in this order:
/// snap -> ecies -> zfec -> bao
/// It performs compression, encryption, stream encoding, and adds error correction codes, in that order.
pub fn encode(pubkey: &[u8], input: &[u8]) -> Result<(Vec<u8>, Hash, EncodeInfo)> {
    let input_len = input.len();

    let compressed = snap(input)?;
    let bytes_compressed = compressed.len();

    let encrypted = ecies(pubkey, &compressed)?;
    let bytes_encrypted = encrypted.len();

    let (encoded, padding, chunk_size) = zfec(&encrypted)?;
    let bytes_encoded = encoded.len();

    let (verifiable, hash) = bao(&encoded)?;
    let bytes_verifiable = verifiable.len();

    // Calculate totals
    let compression_factor = bytes_compressed as f32 / input_len as f32;
    let amplification_factor = bytes_verifiable as f32 / input_len as f32;

    Ok((
        verifiable,
        hash,
        EncodeInfo {
            input_len,
            bytes_compressed,
            bytes_encrypted,
            bytes_encoded,
            bytes_verifiable,
            compression_factor,
            amplification_factor,
            padding,
            chunk_size,
        },
    ))
}
