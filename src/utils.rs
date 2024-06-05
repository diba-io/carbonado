use std::{
    fmt,
    io::{Cursor, Write},
    sync::{Arc, Once, RwLock},
};

use bao::{encode::Encoder, Hash};
use bech32::{decode, encode_to_fmt, Bech32m, Hrp};
use log::trace;

use crate::{
    constants::{FEC_K, SLICE_LEN},
    error::CarbonadoError,
};

static INIT: Once = Once::new();

/// Helper function only used in tests.
pub fn init_logging(rust_log: &str) {
    INIT.call_once(|| {
        use std::env::{set_var, var};

        if var("RUST_LOG").is_err() {
            set_var("RUST_LOG", rust_log);
        }

        pretty_env_logger::init();
    });
}

/// Encodes a Bao hash into a hexadecimal string.
pub fn encode_bao_hash(hash: &Hash) -> String {
    let hash_hex = hash.to_hex();
    hash_hex.to_string()
}

/// Decodes a Bao hash from a hexadecimal string.
pub fn decode_bao_hash(hash: &[u8]) -> Result<Hash, CarbonadoError> {
    if hash.len() != bao::HASH_SIZE {
        Err(CarbonadoError::HashDecodeError(bao::HASH_SIZE, hash.len()))
    } else {
        let hash_array: [u8; bao::HASH_SIZE] = hash[..].try_into()?;
        Ok(hash_array.into())
    }
}

/// Calculate padding (find a length that divides evenly both by Zfec FEC_K and Bao SLICE_LEN, then find the difference).
///
/// Returns (padding_len, chunk_size).
pub fn calc_padding_len(input_len: usize) -> (u32, u32) {
    let input_len = input_len as f64;
    let overlap_constant = SLICE_LEN as f64 * FEC_K as f64;
    let target_size = (input_len / overlap_constant).ceil() * overlap_constant;
    let padding_len = target_size - input_len;
    let chunk_size = target_size / FEC_K as f64;
    trace!("input_len: {input_len:.0}, target_size: {target_size:.0}, padding_len: {padding_len:.0}, chunk_size: {chunk_size:.0}");
    (padding_len as u32, chunk_size as u32)
}

/// Helper for encoding data to bech32m.
pub fn bech32m_encode(hrp_str: &str, bytes: &[u8]) -> Result<String, CarbonadoError> {
    let hrp = Hrp::parse(hrp_str).map_err(CarbonadoError::InvalidHrp)?;
    let mut buf = String::new();
    encode_to_fmt::<Bech32m, String>(&mut buf, hrp, bytes)?;
    Ok(buf)
}

/// Helper for decoding bech32-encoded data.
pub fn bech32_decode(bech32_str: &str) -> Result<(String, Vec<u8>), CarbonadoError> {
    let (hrp, data) = decode(bech32_str).map_err(CarbonadoError::Bech32DecodeError)?;
    let hrp_str = hrp.to_string();
    Ok((hrp_str, data))
}

#[derive(Clone, Debug)]
pub struct BaoHash(pub bao::Hash);

impl BaoHash {
    pub fn to_bytes(&self) -> Vec<u8> {
        let Self(hash) = self;

        hash.as_bytes().to_vec()
    }
}

impl fmt::Display for BaoHash {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let Self(hash) = self;

        f.write_str(&hash.to_string())
    }
}

impl From<&[u8]> for BaoHash {
    fn from(value: &[u8]) -> Self {
        let mut hash = [0_u8; 32];
        hash.copy_from_slice(&value[0..32]);
        Self(bao::Hash::from(hash))
    }
}

impl From<bao::Hash> for BaoHash {
    fn from(hash: bao::Hash) -> Self {
        Self(hash)
    }
}

/// A threadsafe bao hasher similar to that provided by blake3
pub struct BaoHasher {
    encoder: Arc<RwLock<Encoder<Cursor<Vec<u8>>>>>,
}

impl BaoHasher {
    pub fn new() -> Arc<Self> {
        let data = Vec::new();
        let cursor = Cursor::new(data.clone());
        let encoder = Encoder::new(cursor);

        let bao_hasher = Self {
            encoder: Arc::new(RwLock::new(encoder)),
        };

        Arc::new(bao_hasher)
    }

    pub fn update(&self, buf: &[u8]) {
        let mut encoder = self.encoder.write().expect("encoder write lock");
        encoder.write_all(buf).expect("write to encoder");
    }

    pub fn finalize(&self) -> BaoHash {
        let mut encoder = self.encoder.write().expect("encoder read lock");
        BaoHash::from(encoder.finalize().expect("finalize bao hash"))
    }

    pub fn read_all(&self) -> Vec<u8> {
        let encoder = self.encoder.write().expect("encoder read lock");
        let data = encoder.clone().into_inner();
        data.into_inner().to_vec()
    }
}
