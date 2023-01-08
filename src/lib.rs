//! # Carbonado: An apocalypse-resistant data storage format for the truly paranoid.
//!
//! Carbonado is an archival format for encrypted, durable, compressed, provably replicated consensus-critical data, without need for a blockchain or powerful hardware. Decoding and encoding can be done in the browser through WebAssembly, built into remote nodes on P2P networks, kept on S3-compatible cloud storage, or locally on-disk as a single highly portable flat file container format.

////////////////////////////////////////////////////////////////////////////////

/// For details on Carbonado formats and their uses, see [the Carbonado Format bitmask constant](constants::Format)
pub mod constants;
/// Filesystem helper methods
pub mod fs;
/// See [structs::EncodeInfo](structs::EncodeInfo) for various statistics gatthered in the encoding step.
pub mod structs;
/// Various utilities to assist with Carbonado encoding steps
pub mod utils;

mod decoding;
mod encoding;

/// Encode data into Carbonado format in this order:
///
/// `snap -> ecies -> zfec -> bao`
///
/// It performs compression, encryption, stream encoding, and adds error correction codes, in that order.
pub use encoding::encode;

/// Decode data from Carbonado format in reverse order:
///
/// `bao -> zfec -> ecies -> snap`
pub use decoding::decode;

/// Extract a 1KB slice of a Bao stream at a specific index, after decoding it from zfec
pub use decoding::extract_slice;

/// Verify a number of 1KB slices of a Bao stream starting at a specific index
pub use decoding::verify_slice;

/// Scrub zfec-encoded data, correcting flipped bits using error correction codes
/// Returns an error when either valid data cannot be provided, or data is already valid
pub use decoding::scrub;
