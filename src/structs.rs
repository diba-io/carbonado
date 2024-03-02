use std::{
    fmt::{self, Display},
    str::FromStr,
};

use nostr::{FromBech32, PublicKey};
use serde::{Deserialize, Serialize};

use crate::error::CarbonadoError;

/// Information from the encoding step, some of which is needed for decoding.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EncodeInfo {
    /// How many bytes input into the encoding step.
    pub input_len: u32,
    /// How many bytes total were encoded by any applicable steps for the supplied Carbonado level.
    pub output_len: u32,
    /// How large the data is after Snappy compression.
    pub bytes_compressed: u32,
    /// Compression factor.
    ///
    /// Values below 1.0 are desirable; 0.2 is typical of contracts, and 0.8 is typical of code.
    ///
    /// A value above 1.0 indicates the file grew in size, which occurs when used on incompressible file formats.
    pub compression_factor: f32,
    /// How large the data was after Ecies secp256k1 and AES-GCM authenticated encryption.
    ///
    /// This is not expected to add much overhead, typically a hundred bytes.
    pub bytes_encrypted: u32,
    /// How large the data is after adding Zfec error correction codes.
    pub bytes_ecc: u32,
    /// How large the data is after Bao encoding, for remote slice verification and integrity-checking.
    pub bytes_verifiable: u32,
    /// The total amount of file amplification. 2.0x is typical for 4/8 Zfec encoding, the others are pretty minimal, at roughly 1.1x.
    pub amplification_factor: f32,
    /// The amount of padding added to input data in order to align it with Bao slice size (1KB) and 4/8 Zfec chunk size (4KB).
    pub padding_len: u32,
    /// How many bytes are in each Zfec chunk.
    pub chunk_len: u32,
    /// How many slices are there, total.
    pub verifiable_slice_count: u16,
    /// How many slices there are per chunk.
    pub chunk_slice_count: u16,
}

/// Tuple of verifiable bytes, bao hash, and encode info struct
/// i.e., Encoded(encoded_bytes, bao_hash, encode_info)
pub struct Encoded(pub Vec<u8>, pub bao::Hash, pub EncodeInfo);

pub struct Secp256k1PubKey {
    pub pk: secp256k1::PublicKey,
    pub x_only_pk: [u8; 32],
}

impl TryFrom<&str> for Secp256k1PubKey {
    type Error = CarbonadoError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        let pk = match value.get(0..2).expect("key is at least 2 characters long") {
            "+n" => secp256k1::PublicKey::from_x_only_public_key(
                secp256k1::XOnlyPublicKey::from_slice(
                    &PublicKey::from_bech32(value.get(1..).unwrap())?.to_bytes(),
                )?,
                secp256k1::Parity::Even,
            ),
            "-n" => secp256k1::PublicKey::from_x_only_public_key(
                secp256k1::XOnlyPublicKey::from_slice(
                    &PublicKey::from_bech32(value.get(1..).unwrap())?.to_bytes(),
                )?,
                secp256k1::Parity::Odd,
            ),
            "02" => secp256k1::PublicKey::from_str(value)?,
            "03" => secp256k1::PublicKey::from_str(value)?,
            _ => return Err(CarbonadoError::IncorrectPubKeyFormat),
        };

        let (x_only_pk, _) = pk.x_only_public_key();
        let x_only_pk = x_only_pk.serialize();

        Ok(Self { pk, x_only_pk })
    }
}

impl Display for Secp256k1PubKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Self { pk, .. } = self;

        f.write_str(&pk.to_string())
    }
}

impl AsRef<[u8; 32]> for Secp256k1PubKey {
    fn as_ref(&self) -> &[u8; 32] {
        &self.x_only_pk
    }
}

impl Secp256k1PubKey {
    pub fn new(pk: secp256k1::PublicKey) -> Self {
        let (x_only_pk, _) = pk.x_only_public_key();
        let x_only_pk = x_only_pk.serialize();

        Self { pk, x_only_pk }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let Self { pk, .. } = self;

        pk.serialize().to_vec()
    }

    pub fn into_inner(&self) -> secp256k1::PublicKey {
        let Self { pk, .. } = self;

        pk.to_owned()
    }
}

#[test]
fn test_pubkey_decode() {
    let result = Secp256k1PubKey::try_from(
        "+npub14rnkcwkw0q5lnmjye7ffxvy7yxscyjl3u4mrr5qxsks76zctmz3qvuftjz",
    );
    assert!(result.is_ok());
    assert_eq!(
        result.unwrap().to_string(),
        "02a8e76c3ace7829f9ee44cf9293309e21a1824bf1e57631d00685a1ed0b0bd8a2"
    );
    let result = Secp256k1PubKey::try_from(
        "-npub14rnkcwkw0q5lnmjye7ffxvy7yxscyjl3u4mrr5qxsks76zctmz3qvuftjz",
    );
    assert!(result.is_ok());
    assert_eq!(
        result.unwrap().to_string(),
        "03a8e76c3ace7829f9ee44cf9293309e21a1824bf1e57631d00685a1ed0b0bd8a2"
    );
}
