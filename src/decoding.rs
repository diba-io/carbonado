use std::io::{Cursor, Read};

use bao::{
    decode::{decode as bao_decode, SliceDecoder},
    encode::SliceExtractor,
    Hash,
};
use ecies::decrypt;
use log::{info, trace, warn};
use snap::read::FrameDecoder;
use zfec_rs::{Chunk, Fec};

use crate::{
    constants::{Format, FEC_K, FEC_M, SLICE_LEN},
    encoding,
    error::CarbonadoError,
    structs::EncodeInfo,
    utils::decode_bao_hash,
};

fn zfec_chunks(chunked_bytes: Vec<Vec<u8>>, padding: u32) -> Result<Vec<u8>, CarbonadoError> {
    let mut zfec_chunks = vec![];

    for (i, chunk) in chunked_bytes.into_iter().enumerate() {
        zfec_chunks.push(Chunk::new(chunk, i));
    }

    let fec = Fec::new(FEC_K, FEC_M)?;
    let decoded = fec.decode(&zfec_chunks, padding as usize)?;

    Ok(decoded)
}

/// Zfec forward error correction decoding
pub fn zfec(input: &[u8], padding: u32) -> Result<Vec<u8>, CarbonadoError> {
    trace!("forward error correcting");
    let input_len = input.len();

    if input_len % FEC_M != 0 {
        return Err(CarbonadoError::UnevenZfecChunks);
    }

    let chunks: Vec<Vec<u8>> = input
        .chunks_exact(input_len / FEC_M)
        .map(|c| c.to_owned())
        .collect();

    let decoded = zfec_chunks(chunks, padding)?;

    Ok(decoded)
}

/// Bao stream extraction
pub fn bao(input: &[u8], hash: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
    trace!("verifying");
    let hash = decode_bao_hash(hash)?;
    let decoded = bao_decode(input, &hash)?;

    Ok(decoded)
}

/// Ecies decryption
pub fn ecies(input: &[u8], secret_key: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
    trace!("decrypting");
    let decrypted = decrypt(secret_key, input)?;

    Ok(decrypted)
}

/// Snappy decompression
pub fn snap(input: &[u8]) -> Result<Vec<u8>, CarbonadoError> {
    trace!("decompressing");
    let mut decompressed = vec![];
    FrameDecoder::new(input).read_to_end(&mut decompressed)?;

    Ok(decompressed)
}

/// Decode data from Carbonado format in reverse order: `bao -> zfec -> ecies -> snap`
pub fn decode(
    secret_key: &[u8],
    hash: &[u8],
    input: &[u8],
    padding: u32,
    format: u8,
) -> Result<Vec<u8>, CarbonadoError> {
    let format = Format::from(format);

    let verified = if format.contains(Format::Bao) {
        bao(input, hash)?
    } else {
        input.to_owned()
    };

    let decoded = if format.contains(Format::Zfec) {
        zfec(&verified, padding)?
    } else {
        verified
    };

    let decrypted = if format.contains(Format::Ecies) {
        ecies(&decoded, secret_key)?
    } else {
        decoded
    };

    let decompressed = if format.contains(Format::Snappy) {
        snap(&decrypted)?
    } else {
        decrypted
    };

    Ok(decompressed)
}

/// Extract a 1KB slice of a Bao stream at a specific index.
///
/// This helps for periodic verification.
pub fn extract_slice(encoded: &[u8], index: u16) -> Result<Vec<u8>, CarbonadoError> {
    let slice_start = index * SLICE_LEN;
    let encoded_cursor = Cursor::new(&encoded);
    let mut extractor = SliceExtractor::new(encoded_cursor, slice_start as u64, SLICE_LEN as u64);
    let mut slice = Vec::new();
    extractor.read_to_end(&mut slice)?;

    Ok(slice)
}

/// Verify a number of 1KB slices of a Bao stream starting at a specific index.
///
/// This is limited to u16 indices, because segments are intended to be no larger than 4MB.
pub fn verify_slice(
    hash: &Hash,
    input: &[u8],
    index: u16,
    count: u16,
) -> Result<Vec<u8>, CarbonadoError> {
    let slice_start = index as u64 * SLICE_LEN as u64;
    let slice_len = count as u64 * SLICE_LEN as u64;
    trace!("Verify slice start: {slice_start} len: {slice_len}");

    let encoded_cursor = Cursor::new(&input);
    let mut extractor = SliceExtractor::new(encoded_cursor, slice_start, slice_len);
    let mut decoder = SliceDecoder::new(&mut extractor, hash, slice_start, slice_len);
    let mut decoded = vec![];
    decoder.read_to_end(&mut decoded)?;

    Ok(decoded)
}

/// Scrub zfec-encoded data, correcting flipped bits using forward error correction codes.
/// Returns an error when either valid data cannot be provided, or data is already valid.
///
/// If data is already valid, the error message "Data does not need to be scrubbed." is returned.
/// This helps nodes prevent unnecessary writes for periodic scrubbing.
///
/// TODO: At present, this method is not deterministic, so data larger than 8KB cannot be reencoded.
/// This is still useful for data recovery, but it requires interactivity with storage clients.
pub fn scrub(
    input: &[u8],
    hash: &[u8],
    encode_info: &EncodeInfo,
) -> Result<Vec<u8>, CarbonadoError> {
    let hash = decode_bao_hash(hash)?;
    let chunk_size = encode_info.chunk_len;
    let padding = encode_info.padding_len;
    let slices_per_chunk = (chunk_size / SLICE_LEN as u32) as u16;

    match bao_decode(input, &hash) {
        Ok(_decoded) => Err(CarbonadoError::UnnecessaryScrub),
        Err(e) => {
            warn!("Data failed to verify with error: {e}. Scrubbing...");
            let mut chunks = vec![];

            for i in 0..FEC_M {
                let slice_index = i as u16 * slices_per_chunk;
                match verify_slice(&hash, input, slice_index, slices_per_chunk) {
                    Ok(chunk) => chunks.push(chunk),
                    Err(e) => {
                        warn!("At least one chunk was bad, at chunk index {i}. Error was: {e}.");
                    }
                }
            }

            info!("{} good chunks found, of {FEC_K} needed.", chunks.len());

            let decoded = zfec_chunks(chunks, padding)?;

            // TODO: Fix Zfec determinism issues for large files

            let (scrubbed, scrubbed_padding, _) = encoding::zfec(&decoded)?;
            if padding != scrubbed_padding {
                return Err(CarbonadoError::ScrubbedPaddingMismatch);
            }

            let (verifiable, scrubbed_hash) = encoding::bao(&scrubbed)?;

            if input.len() != verifiable.len() {
                return Err(CarbonadoError::ScrubbedLengthMismatch(
                    input.len(),
                    verifiable.len(),
                ));
            }

            if hash != scrubbed_hash {
                return Err(CarbonadoError::InvalidScrubbedHash);
            }

            Ok(verifiable)
        }
    }
}
