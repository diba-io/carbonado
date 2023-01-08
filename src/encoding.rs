use std::io::Write;

use anyhow::{anyhow, Result};
use bao::{encode::encode as bao_encode, Hash};
use ecies::encrypt;
use log::debug;
use snap::write::FrameEncoder;
use zfec_rs::Fec;

use crate::{
    constants::{Format, FEC_K, FEC_M, SLICE_LEN},
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
/// Returns a tuple of encoded bytes, the amount of padding used, and the length of each chunk.
pub fn zfec(input: &[u8]) -> Result<(Vec<u8>, u32, u32)> {
    let input_len = input.len();
    let (padding_len, chunk_len) = calc_padding_len(input_len);

    let mut padding_bytes = vec![0u8; padding_len as usize];
    let mut padded_input = Vec::from(input);
    padded_input.append(&mut padding_bytes);
    debug!(
        "After padding has been added, input is now: {} bytes",
        padded_input.len()
    );

    let fec = Fec::new(FEC_K, FEC_M)?;
    let (mut encoded_chunks, zfec_padding) = fec.encode(&padded_input)?;

    if zfec_padding != 0 {
        return Err(anyhow!(
        "Padding from Zfec should always be zero, since Carbonado adds its own padding. Padding was {zfec_padding}."
    ));
    }

    let mut encoded = vec![];

    for chunk in &mut encoded_chunks {
        if chunk_len != chunk.data.len() as u32 {
            return Err(anyhow!("Chunk length should be as calculated. Calculated chunk length was {chunk_len}, but actual chunk length was {}", chunk.data.len()));
        }
        encoded.append(&mut chunk.data);
    }

    Ok((encoded, padding_len, chunk_len))
}

/// Encode data into Carbonado format, performing compression, encryption, adding error correction codes, and stream verification encoding, in that order.
pub fn encode(pubkey: &[u8], input: &[u8], format: u8) -> Result<(Vec<u8>, Hash, EncodeInfo)> {
    let input_len = input.len() as u32;
    let format = Format::try_from(format)?;

    let compressed;
    let encrypted;
    let encoded;
    let padding_len;
    let chunk_len;
    let verifiable_slice_count;
    let chunk_slice_count;
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
        (encoded, padding_len, chunk_len) = zfec(&encrypted)?;
        bytes_ecc = encoded.len() as u32;
        verifiable_slice_count = (bytes_ecc / SLICE_LEN as u32) as u16;
        if verifiable_slice_count % 8 != 0 {
            return Err(anyhow!(
                "Verifiable slice count should be evenly divisible by 8. Remainder was {}.",
                verifiable_slice_count % 8
            ));
        }
        chunk_slice_count = verifiable_slice_count / 8;
    } else {
        encoded = encrypted;
        padding_len = 0;
        chunk_len = 0;
        bytes_ecc = 0;
        verifiable_slice_count = 0;
        chunk_slice_count = 0;
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
            padding_len,
            chunk_len,
            verifiable_slice_count,
            chunk_slice_count,
        },
    ))
}
