use std::io::Write;

use anyhow::Result;
use bao::{encode::encode as bao_encode, Hash};
use ecies::encrypt;
use log::debug;
use snap::write::FrameEncoder;
use zfec_rs::Fec;

use crate::{
    constants::{Format, FEC_K, FEC_M},
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
pub fn ecies(pubkey: &[u8], input: &[u8]) -> Result<Vec<u8>> {
    let encrypted = encrypt(pubkey, input)?;

    Ok(encrypted)
}

/// Bao stream encoding
pub fn bao(input: &[u8]) -> Result<(Vec<u8>, Hash)> {
    let (encoded, hash) = bao_encode(input);

    Ok((encoded, hash))
}

/// Zfec forward error correction encoding
pub fn zfec(input: &[u8]) -> Result<(Vec<u8>, u32, u32)> {
    let input_len = input.len();
    let (padding_len, chunk_size) = calc_padding_len(input_len);
    // TODO: CSPRNG padding
    let mut padding_bytes = vec![0u8; padding_len as usize];
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
            chunk.data.len() as u32,
            "Chunk size should be as calculated"
        );
        encoded.append(&mut chunk.data);
    }

    Ok((encoded, padding_len, chunk_size))
}

/// Encode data into Carbonado format in this order:
///
/// `snap -> ecies -> zfec -> bao`
///
/// It performs compression, encryption, stream encoding, and adds error correction codes, in that order.
pub fn encode(pubkey: &[u8], input: &[u8], format: u8) -> Result<(Vec<u8>, Hash, EncodeInfo)> {
    let input_len = input.len() as u32;
    let format = Format::try_from(format)?;

    let compressed;
    let encrypted;
    let encoded;
    let padding;
    let chunk_size;
    let verifiable;
    let hash;

    let bytes_compressed;
    let bytes_encrypted;
    let bytes_ecc;
    let bytes_verifiable;

    if format.contains(Format::Snappy) {
        compressed = snap(input)?;
        bytes_compressed = compressed.len() as u32;
    } else {
        compressed = input.to_owned();
        bytes_compressed = 0;
    }

    if format.contains(Format::Ecies) {
        encrypted = ecies(pubkey, &compressed)?;
        bytes_encrypted = encrypted.len() as u32;
    } else {
        encrypted = compressed;
        bytes_encrypted = 0;
    }

    if format.contains(Format::Zfec) {
        (encoded, padding, chunk_size) = zfec(&encrypted)?;
        bytes_ecc = encoded.len() as u32;
    } else {
        encoded = encrypted;
        padding = 0;
        chunk_size = 0;
        bytes_ecc = 0;
    }

    if format.contains(Format::Bao) {
        (verifiable, hash) = bao(&encoded)?;
        bytes_verifiable = verifiable.len() as u32;
    } else {
        verifiable = encoded;
        hash = Hash::from([0; 32]);
        bytes_verifiable = 0;
    }

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
            bytes_ecc,
            bytes_verifiable,
            compression_factor,
            amplification_factor,
            padding,
            chunk_size,
        },
    ))
}
