use std::{convert::TryFrom, fs::File, io::Read};

use anyhow::{anyhow, Error, Result};
use bao::Hash;
use secp256k1::{schnorr::Signature, KeyPair, Message, PublicKey, Secp256k1};

use crate::{
    constants::{Format, MAGICNO},
    utils::decode_bao_hash,
};

#[derive(Debug)]
pub struct Header {
    pub pubkey: PublicKey,
    pub hash: Hash,
    pub signature: Signature,
    pub format: Format,
    pub encoded_len: u32,
    pub padding_len: u32,
}

impl TryFrom<File> for Header {
    type Error = Error;

    fn try_from(file: File) -> Result<Self> {
        let mut magic_no = [0_u8; 12];
        let mut pubkey = [0_u8; 33];
        let mut hash = [0_u8; 32];
        let mut signature = [0_u8; 64];
        let mut format = [0_u8; 1];
        let mut encoded_len = [0_u8; 4];
        let mut padding_len = [0_u8; 4];

        let mut handle = file.take(100);
        handle.read_exact(&mut magic_no)?;
        handle.read_exact(&mut pubkey)?;
        handle.read_exact(&mut hash)?;
        handle.read_exact(&mut signature)?;
        handle.read_exact(&mut format)?;
        handle.read_exact(&mut encoded_len)?;
        handle.read_exact(&mut padding_len)?;

        if magic_no != MAGICNO {
            return Err(anyhow!(
                "File header lacks Carbonado magic number and may not be a proper Carbonado file"
            ));
        }

        let pubkey = PublicKey::from_slice(&pubkey)?;
        let hash = bao::Hash::try_from(hash)?;
        let signature = Signature::from_slice(&signature)?;
        let format = Format::try_from(format[0])?;
        let encoded_len = u32::from_le_bytes(encoded_len);
        let padding_len = u32::from_le_bytes(padding_len);

        Ok(Header {
            pubkey,
            hash,
            signature,
            format,
            encoded_len,
            padding_len,
        })
    }
}

impl Header {
    pub fn new(
        sk: &[u8],
        hash: &[u8],
        format: Format,
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
            encoded_len,
            padding_len,
        })
    }

    /// Creates a header to be prepended to files.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut pubkey_bytes = self.pubkey.serialize().to_vec(); // 33 bytes
        assert_eq!(pubkey_bytes.len(), 33);
        let mut hash_bytes = self.hash.as_bytes().to_vec(); // 32 bytes
        assert_eq!(hash_bytes.len(), 32);
        let mut signature_bytes = hex::decode(self.signature.to_string()).expect("hex encoded"); // 64 bytes
        assert_eq!(signature_bytes.len(), 64);
        let mut format_bytes = self.format.bits().to_le_bytes().to_vec(); // 1 byte
        let mut encoded_len_bytes = self.encoded_len.to_le_bytes().to_vec(); // 8 bytes
        let mut padding_bytes = self.padding_len.to_le_bytes().to_vec(); // 2 bytes

        let mut header = Vec::new();

        header.append(&mut MAGICNO.to_vec()); // 12 bytes
        header.append(&mut pubkey_bytes);
        header.append(&mut hash_bytes);
        header.append(&mut signature_bytes);
        header.append(&mut format_bytes);
        header.append(&mut encoded_len_bytes);
        header.append(&mut padding_bytes);
        header
    }
}

// fn create_file(header_bytes: &[u8], encoded_bytes: &[u8]) {
//     todo!();
// }
