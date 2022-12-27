use std::{convert::TryFrom, fs::File, io::Read};

use anyhow::{anyhow, Error, Result};
use bao::Hash;
use ecies::PublicKey;

use crate::constants::{Format, MAGICNO};

pub struct Header {
    pub pubkey: PublicKey,
    pub hash: Hash,
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
        let mut format = [0_u8; 2];
        let mut verifiable_len = [0_u8; 8];
        let mut padding = [0_u8; 2];

        let mut handle = file.take(100);
        handle.read_exact(&mut magic_no)?;
        handle.read_exact(&mut pubkey)?;
        handle.read_exact(&mut hash)?;
        handle.read_exact(&mut format)?;
        handle.read_exact(&mut verifiable_len)?;
        handle.read_exact(&mut padding)?;

        if magic_no != MAGICNO {
            return Err(anyhow!(
                "File header lacks Carbonado magic number and may not be a proper Carbonado file"
            ));
        }
        let pubkey = PublicKey::parse_compressed(&pubkey)?;
        let hash = bao::Hash::try_from(hash)?;
        let format = u16::from_le_bytes(format);
        let format = Format::try_from(format)?;
        let verifiable_len = u64::from_le_bytes(verifiable_len);
        let padding = u16::from_le_bytes(padding);

        Ok(Header {
            pubkey,
            hash,
            format,
            verifiable_len,
            padding,
        })
    }
}

impl Header {
    pub fn new(
        pubkey: PublicKey,
        hash: Hash,
        format: Format,
        verifiable_len: u64,
        padding: u16,
    ) -> Self {
        Header {
            pubkey,
            hash,
            format,
            verifiable_len,
            padding,
        }
    }

    /// Adds a total of 100 bytes to
    pub fn to_vec(&self) -> Vec<u8> {
        let mut pubkey_bytes = self.pubkey.serialize_compressed().to_vec(); // 33 bytes
        let mut hash_bytes = self.hash.as_bytes().to_vec(); // 32 bytes
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
