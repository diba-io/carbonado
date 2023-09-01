use bitmask_enum::bitmask;
use serde::{Deserialize, Serialize};

/// "Magic number" used by the Carbonado file format. 12 bytes: "CARBONADO", and a version, 00, plus a newline character
pub const MAGICNO: &[u8; 12] = b"CARBONADO00\n";

/// Bao slice length
pub const SLICE_LEN: u16 = 1024;
/// Zfec chunks needed (k)
pub const FEC_K: usize = 4;
/// Zfec chunks encoded (m)
pub const FEC_M: usize = 8;

/// ## Bitmask for Carbonado formats c0-c15
///
/// | Format | Encryption | Compression | Verifiability | Error correction | Use-cases |
/// |-----|----|----|----|----|----|
/// | c0  |    |    |    |    | Marks a file as scanned by Carbonado |
/// | c1  | ✅ |    |    |    | Encrypted incompressible throwaway append-only data streams such as CCTV footage |
/// | c2  |    | ✅ |    |    | Rotating public logs |
/// | c3  | ✅ | ✅ |    |    | Private archives |
/// | c4  |    |    | ✅ |    | Unencrypted incompressible data such as NFT/UDA image assets |
/// | c5  | ✅ |    | ✅ |    | Private media backups |
/// | c6  |    | ✅ | ✅ |    | Compiled binaries |
/// | c7  | ✅ | ✅ | ✅ |    | Full drive backups |
/// | c8  |    |    |    | ✅ | Television broadcasts |
/// | c9  | ✅ |    |    | ✅ | Encrypted transmissions |
/// | c10 |    | ✅ |    | ✅ | Compressed data streaming over lossy channels such as UDP |
/// | c11 | ✅ | ✅ |    | ✅ | Encrypted device-local Catalogs |
/// | c12 |    |    | ✅ | ✅ | Publicly-available archived media |
/// | c13 | ✅ |    | ✅ | ✅ | Georedundant private media backups |
/// | c14 |    | ✅ | ✅ | ✅ | Source code, token genesis, blockchain data |
/// | c15 | ✅ | ✅ | ✅ | ✅ | Contract data |
///
/// These operations correspond to the following implementations:
///
/// | Implementation | Operation |
/// |-------|-------|
/// | ecies | Encryption |
/// | snap  | Compression |
/// | bao   | Verifiability |
/// | zfec  | Error correction |
///
/// While the implementations are called in a different order, as outlined in [encoding::encode](crate::encode), operations are ordered this way in the bitmask in order to make the format more intuitive.
///
/// Verifiability is needed to pay others for storing or hosting your files, but it inhibits use-cases for mutable or append-only data other than snapshots, since the hash will change so frequently. Bao encoding does not have a large overhead, about 5% at most.
///
/// Any data that is verifiable but also unencrypted is instead signed by the local key. This is good for signed compiled binaries or hosted web content.
#[bitmask(u8)]
#[derive(Serialize, Deserialize)]
pub enum Format {
    Ecies,
    Snappy,
    Bao,
    Zfec,
}
