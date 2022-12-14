use std::{
    convert::TryFrom,
    fs::File,
    io::{Read, Seek, SeekFrom},
};

use anyhow::{anyhow, Error, Result};
use bao::Hash;
use secp256k1::{schnorr::Signature, KeyPair, Message, PublicKey, Secp256k1};

use crate::{
    constants::{Format, MAGICNO},
    utils::{decode_bao_hash, encode_bao_hash},
};

/// 160 bytes should be added for Carbonado headers.
pub fn header_len() -> u64 {
    12 + 33 + 32 + 64 + 1 + 1 + 4 + 4 + 9
}

/// Contains deserialized copies of the data kept in the Carbonado header.
#[derive(Debug)]
pub struct Header {
    /// A secp256k1 compressed public key is 33 bytes.
    pub pubkey: PublicKey,
    /// A Bao hash is 32 bytes.
    pub hash: Hash,
    /// A Schnorr signature is 64 bytes.
    pub signature: Signature,
    /// A Carbonado format code is 1 byte.
    pub format: Format,
    /// A chunk index is provided so each chunk can be stored in separate files.
    pub chunk_index: u8,
    /// Number of verifiable bytes.
    pub encoded_len: u32,
    /// Number of bytes added to pad to align zfec chunks and bao slices.
    pub padding_len: u32,
}

impl TryFrom<File> for Header {
    type Error = Error;

    /// Attempts to decode a header from a file.
    fn try_from(mut file: File) -> Result<Self> {
        let mut magic_no = [0_u8; 12];
        let mut pubkey = [0_u8; 33];
        let mut hash = [0_u8; 32];
        let mut signature = [0_u8; 64];
        let mut format = [0_u8; 1];
        let mut chunk_index = [0_u8; 1];
        let mut encoded_len = [0_u8; 4];
        let mut padding_len = [0_u8; 4];

        file.seek(SeekFrom::Start(0))?;

        let mut handle = file.take(header_len());
        handle.read_exact(&mut magic_no)?;
        handle.read_exact(&mut pubkey)?;
        handle.read_exact(&mut hash)?;
        handle.read_exact(&mut signature)?;
        handle.read_exact(&mut format)?;
        handle.read_exact(&mut chunk_index)?;
        handle.read_exact(&mut encoded_len)?;
        handle.read_exact(&mut padding_len)?;

        if magic_no != MAGICNO {
            return Err(anyhow!(
                "File header lacks Carbonado magic number and may not be a proper Carbonado file. Magic number found was {:#?}.", magic_no
            ));
        }

        let pubkey = PublicKey::from_slice(&pubkey)?;
        let hash = bao::Hash::try_from(hash)?;
        let signature = Signature::from_slice(&signature)?;
        let format = Format::try_from(format[0])?;
        let chunk_index = u8::from_le_bytes(chunk_index);
        let encoded_len = u32::from_le_bytes(encoded_len);
        let padding_len = u32::from_le_bytes(padding_len);

        Ok(Header {
            pubkey,
            hash,
            signature,
            format,
            chunk_index,
            encoded_len,
            padding_len,
        })
    }
}

impl Header {
    /// Creates a new Carbonado Header struct using the provided parameters, using provided serialized primitives.
    pub fn new(
        sk: &[u8],
        hash: &[u8],
        format: Format,
        chunk_index: u8,
        encoded_len: u32,
        padding_len: u32,
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let keypair = KeyPair::from_seckey_slice(&secp, sk)?;
        let msg = Message::from_slice(hash)?;
        let signature = keypair.sign_schnorr(msg);
        let pubkey = PublicKey::from_keypair(&keypair);
        let hash = decode_bao_hash(hash)?;

        Ok(Header {
            pubkey,
            signature,
            hash,
            format,
            chunk_index,
            encoded_len,
            padding_len,
        })
    }

    /// Creates a header to be prepended to files.
    pub fn try_to_vec(&self) -> Result<Vec<u8>> {
        let mut pubkey_bytes = self.pubkey.serialize().to_vec(); // 33 bytes
        if pubkey_bytes.len() != 33 {
            return Err(anyhow!("Pubkey did not serialize into expected length."));
        }
        let mut hash_bytes = self.hash.as_bytes().to_vec(); // 32 bytes
        if hash_bytes.len() != 32 {
            return Err(anyhow!("Hash bytes were not of expected length."));
        }
        let mut signature_bytes = hex::decode(self.signature.to_string()).expect("hex encoded"); // 64 bytes
        if signature_bytes.len() != 64 {
            return Err(anyhow!("Signature bytes were not of expected length."));
        }
        let mut format_bytes = self.format.bits().to_le_bytes().to_vec(); // 1 byte
        let mut chunk_index = self.chunk_index.to_le_bytes().to_vec(); // 1 byte
        let mut encoded_len_bytes = self.encoded_len.to_le_bytes().to_vec(); // 8 bytes
        let mut padding_bytes = self.padding_len.to_le_bytes().to_vec(); // 2 bytes
        let mut header_padding = vec![0_u8; 9];

        let mut header = Vec::new();

        header.append(&mut MAGICNO.to_vec()); // 12 bytes
        header.append(&mut pubkey_bytes);
        header.append(&mut hash_bytes);
        header.append(&mut signature_bytes);
        header.append(&mut format_bytes);
        header.append(&mut chunk_index);
        header.append(&mut encoded_len_bytes);
        header.append(&mut padding_bytes);
        header.append(&mut header_padding);

        if header.len() != header_len() as usize {
            return Err(anyhow!("Invalid header length calculation"));
        }

        Ok(header)
    }

    /// Helper function for naming a Carbonado archive file.
    pub fn filename(&self) -> String {
        let hash = encode_bao_hash(&self.hash);
        let fmt = self.format.bits();
        format!("{hash}.c{fmt}")
    }
}
