use std::{convert::TryFrom, fs::File, io::Read};

use anyhow::{anyhow, Error, Result};
use bao::Hash;
use secp256k1::{schnorr::Signature, KeyPair, Message, PublicKey, Secp256k1, SecretKey};
use serde::Serialize;

use crate::constants::{Format, MAGICNO};

pub struct Header {
    pub pubkey: PublicKey,
    pub hash: Hash,
    pub signature: Signature,
    pub format: Format,
    pub verifiable_len: u64,
    pub padding: u16,
}

impl TryFrom<File> for Header {
    type Error = Error;

    fn try_from(file: File) -> Result<Self> {
        let mut magic_no = [0_u8; 12];
        let mut pubkey = [0_u8; 33];
        let mut hash = [0_u8; 32];
        let mut signature = [0_u8; 32];
        let mut format = [0_u8; 2];
        let mut verifiable_len = [0_u8; 8];
        let mut padding = [0_u8; 2];

        let mut handle = file.take(100);
        handle.read_exact(&mut magic_no)?;
        handle.read_exact(&mut pubkey)?;
        handle.read_exact(&mut hash)?;
        handle.read_exact(&mut signature)?;
        handle.read_exact(&mut format)?;
        handle.read_exact(&mut verifiable_len)?;
        handle.read_exact(&mut padding)?;

        if magic_no != MAGICNO {
            return Err(anyhow!(
                "File header lacks Carbonado magic number and may not be a proper Carbonado file"
            ));
        }
        let pubkey = PublicKey::from_slice(&pubkey)?;
        let hash = bao::Hash::try_from(hash)?;
        let signature = Signature::from_slice(&signature)?;
        let format = u16::from_le_bytes(format);
        let format = Format::try_from(format)?;
        let verifiable_len = u64::from_le_bytes(verifiable_len);
        let padding = u16::from_le_bytes(padding);

        Ok(Header {
            pubkey,
            hash,
            signature,
            format,
            verifiable_len,
            padding,
        })
    }
}

impl Header {
    pub fn new(
        sk: SecretKey,
        hash: Hash,
        format: Format,
        verifiable_len: u64,
        padding: u16,
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let keypair = KeyPair::from_secret_key(&secp, &sk);
        let msg = Message::from_slice(hash.as_bytes())?;
        let signature = keypair.sign_schnorr(msg);
        let pubkey = PublicKey::from_keypair(&keypair);

        Ok(Header {
            pubkey,
            signature,
            hash,
            format,
            verifiable_len,
            padding,
        })
    }

    /// Creates a total of 100 bytes as a header to be prepended to files.
    pub fn to_vec(&self) -> Vec<u8> {
        let mut pubkey_bytes = self.pubkey.serialize().to_vec(); // 33 bytes
        let mut hash_bytes = self.hash.as_bytes().to_vec(); // 32 bytes
                                                            // let mut signature_bytes: [u8; 32] = self.signature.serialize().unwrap().to_vec(); // 32 bytes
        let mut format_bytes = self.format.bits().to_le_bytes().to_vec(); // 2 bytes
        let mut verifiable_len_bytes = self.verifiable_len.to_le_bytes().to_vec(); // 8 bytes
        let mut padding_bytes = self.padding.to_le_bytes().to_vec(); // 2 bytes
        let mut header = Vec::with_capacity(100);

        header.append(&mut MAGICNO.to_vec()); // 12 bytes
        header.append(&mut pubkey_bytes);
        header.append(&mut hash_bytes);
        header.append(&mut format_bytes);
        header.append(&mut verifiable_len_bytes);
        header.append(&mut padding_bytes);
        header.append(&mut vec![b'\0'; 11]); // 11 padding null bytes
        header
    }
}

// fn create_file(header_bytes: &[u8], encoded_bytes: &[u8]) {
//     todo!();
// }
