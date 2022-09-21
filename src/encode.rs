use std::io::Write;

use anyhow::Result;
use bao::{encode::encode as bao_encode, Hash};
use ecies::encrypt;
use log::debug;
use snap::write::FrameEncoder;
use zfec_rs::Fec;

use crate::{
    constants::{FEC_K, FEC_M, SLICE_LEN},
    structs::EncodeInfo,
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
pub fn bao(encrypted: &[u8]) -> Result<(Vec<u8>, Hash)> {
    let (encoded, hash) = bao_encode(encrypted);

    Ok((encoded, hash))
}

/// Zfec forward error correction encoding
pub fn zfec(streamed: &[u8]) -> Result<(Vec<u8>, usize)> {
    // Calculate padding (find a length that divides evenly both by Zfec FEC_K and Bao SLICE_LEN, then find the difference)
    let streamed_len = streamed.len();
    let overlap_constant = SLICE_LEN as usize * FEC_M;
    let target_size = streamed_len - (streamed_len % overlap_constant) + overlap_constant as usize;
    let padding_len = target_size - streamed_len;
    let chunk_size = target_size / FEC_K;
    // TODO: CSPRNG padding
    let mut padding_bytes = vec![0u8; padding_len];
    debug!("Carbonado padding: {padding_len}, Chunk Size: {chunk_size}");
    let mut padded_streamed = Vec::from(streamed);
    padded_streamed.append(&mut padding_bytes);
    debug!(
        "After padding has been added, input is now: {} bytes",
        padded_streamed.len()
    );

    let fec = Fec::new(FEC_K, FEC_M)?;
    let (mut encoded_chunks, zfec_padding) = fec.encode(&padded_streamed)?;

    assert_eq!(
        zfec_padding, 0,
        "Padding from Zfec should always be zero, since Carbonado adds its own padding. Padding was: {zfec_padding}"
    );

    let mut encoded = vec![];

    for chunk in &mut encoded_chunks {
        encoded.append(&mut chunk.data);
    }

    Ok((encoded, padding_len))
}

/// Encode data into Carbonado format in this order:
/// snap -> ecies -> bao -> zfec
/// It performs compression, encryption, stream encoding, and adds error correction codes, in that order.
pub fn encode(pubkey: &[u8], input: &[u8]) -> Result<(Vec<u8>, Hash, usize, EncodeInfo)> {
    let bytes_input = input.len();

    let compressed = snap(input)?;
    let bytes_compressed = compressed.len();

    let encrypted = ecies(pubkey, &compressed)?;
    let bytes_encrypted = encrypted.len();

    let (streamed, hash) = bao(&encrypted)?;
    let bytes_streamed = streamed.len();

    let (encoded, padding) = zfec(&streamed)?;
    let bytes_encoded = encoded.len();

    // Calculate totals
    let compression_factor = bytes_compressed as f32 / bytes_input as f32;
    let amplification_factor = bytes_encoded as f32 / bytes_input as f32;

    Ok((
        encoded,
        hash,
        padding,
        EncodeInfo {
            bytes_input,
            bytes_compressed,
            bytes_encrypted,
            bytes_streamed,
            bytes_encoded,
            compression_factor,
            amplification_factor,
        },
    ))
}
