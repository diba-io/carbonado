use std::{
    convert::TryFrom,
    fs::File,
    io::{Read, Seek},
};

use anyhow::{anyhow, Error, Result};
use bao::Hash;
use nom::{
    bytes::complete::take,
    number::complete::{le_u32, le_u8},
    IResult,
};
use secp256k1::{ecdsa::Signature, Message, PublicKey, SecretKey};

use crate::{
    constants::{Format, MAGICNO},
    decoding, encoding,
    structs::{EncodeInfo, Encoded},
    utils::{decode_bao_hash, encode_bao_hash},
};

/// Contains deserialized copies of the data kept in the Carbonado header.
#[derive(Clone, Debug)]
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

        file.rewind()?;

        let mut handle = file.take(Header::len() as u64);
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
        let signature = Signature::from_compact(&signature)?;

        // Verify hash against signature
        signature.verify(&Message::from_slice(&hash)?, &pubkey)?;

        let hash = bao::Hash::try_from(hash)?;

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

impl TryFrom<&[u8]> for Header {
    type Error = Error;

    /// Attempts to decode a header from a file.
    fn try_from(bytes: &[u8]) -> Result<Self> {
        let (_, (magic_no, pubkey, hash, signature, format, chunk_index, encoded_len, padding_len)) =
            Header::parse_bytes(bytes).unwrap();

        if magic_no != MAGICNO {
            return Err(anyhow!(
                "File header lacks Carbonado magic number and may not be a proper Carbonado file. Magic number found was {:#?}.", magic_no
            ));
        }

        let pubkey = PublicKey::from_slice(pubkey)?;
        let signature = Signature::from_compact(signature)?;

        // Verify hash against signature
        signature.verify(&Message::from_slice(hash)?, &pubkey)?;

        let hash: [u8; 32] = hash[0..32].try_into()?;
        let hash = bao::Hash::try_from(hash)?;

        let format = Format::try_from(format)?;

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
    /// 160 bytes should be added for Carbonado headers.
    pub fn len() -> usize {
        12 + 33 + 32 + 64 + 1 + 1 + 4 + 4 + 9
    }

    /// Creates a new Carbonado Header struct using the provided parameters, using provided serialized primitives.
    pub fn new(
        sk: &[u8],
        pk: &[u8],
        hash: &[u8],
        format: Format,
        chunk_index: u8,
        encoded_len: u32,
        padding_len: u32,
    ) -> Result<Self> {
        let msg = Message::from_slice(hash)?;
        let pubkey = PublicKey::from_slice(pk)?;
        let signature = SecretKey::from_slice(sk)?.sign_ecdsa(msg);
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
        let mut signature_bytes = self.signature.serialize_compact().to_vec(); // 64 bytes
        if signature_bytes.len() != 64 {
            return Err(anyhow!(
                "Signature bytes were not of expected length. Length was: {}",
                signature_bytes.len()
            ));
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

        if header.len() != Header::len() {
            return Err(anyhow!("Invalid header length calculation"));
        }

        Ok(header)
    }

    /// Helper function for naming a Carbonado archive file.
    pub fn file_name(&self) -> String {
        let hash = encode_bao_hash(&self.hash);
        let fmt = self.format.bits();
        format!("{hash}.c{fmt}")
    }

    #[allow(clippy::type_complexity)]
    fn parse_bytes(b: &[u8]) -> IResult<&[u8], (&[u8], &[u8], &[u8], &[u8], u8, u8, u32, u32)> {
        let (b, magic_no) = take(12u8)(b)?;
        let (b, pubkey) = take(33u8)(b)?;
        let (b, hash) = take(32u8)(b)?;
        let (b, signature) = take(64u8)(b)?;
        let (b, format) = le_u8(b)?;
        let (b, chunk_index) = le_u8(b)?;
        let (b, encoded_len) = le_u32(b)?;
        let (b, padding_len) = le_u32(b)?;

        Ok((
            b,
            (
                magic_no,
                pubkey,
                hash,
                signature,
                format,
                chunk_index,
                encoded_len,
                padding_len,
            ),
        ))
    }
}

pub fn decode(secret_key: &[u8], encoded: &[u8]) -> Result<(Header, Vec<u8>)> {
    let (header, body) = encoded.split_at(Header::len());
    let header = Header::try_from(header)?;
    let decoded = decoding::decode(
        secret_key,
        header.hash.as_bytes(),
        body,
        header.padding_len,
        header.format.into(),
    )?;

    Ok((header, decoded))
}

pub fn encode(
    sk: &[u8],
    pk: Option<&[u8]>,
    input: &[u8],
    level: u8,
) -> Result<(Vec<u8>, EncodeInfo)> {
    let pubkey = match pk {
        Some(pubkey) => PublicKey::from_slice(pubkey)?,
        None => PublicKey::from_secret_key_global(&SecretKey::from_slice(sk)?),
    }
    .serialize();

    let Encoded(mut encoded, hash, encode_info) = encoding::encode(&pubkey, input, level)?;

    let format = Format::try_from(level)?;
    let header = Header::new(
        sk,
        &pubkey,
        hash.as_bytes(),
        format,
        0,
        encode_info.output_len,
        encode_info.padding_len,
    )?;

    let mut body = header.try_to_vec()?;
    body.append(&mut encoded);

    Ok((body, encode_info))
}
