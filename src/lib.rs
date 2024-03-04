//! # Carbonado: An apocalypse-resistant data storage format for the truly paranoid.
//!
//! Carbonado is an archival format for encrypted, durable, compressed, provably replicated consensus-critical data, without need for a blockchain or powerful hardware. Decoding and encoding can be done in the browser through WebAssembly, built into remote nodes on P2P networks, kept on S3-compatible cloud storage, or locally on-disk as a single highly portable flat file container format.

////////////////////////////////////////////////////////////////////////////////

/// For details on Carbonado formats and their uses, see the [Carbonado Format bitmask constant](constants::Format).
pub mod constants;
/// Error types
pub mod error;
/// File helper methods.
pub mod file;
/// See [structs::EncodeInfo](structs::EncodeInfo) for various statistics gatthered in the encoding step.
pub mod structs;
/// Various utilities to assist with Carbonado encoding steps.
pub mod utils;

mod decoding;
mod encoding;

pub use encoding::encode;

pub use decoding::decode;

pub use decoding::extract_slice;

pub use decoding::verify_slice;

pub use decoding::scrub;

pub use bao;
pub use blake3;
pub use secp256k1;
