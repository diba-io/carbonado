use thiserror::Error;

#[derive(Error, Debug)]
pub enum CarbonadoError {
    /// std io error
    #[error(transparent)]
    StdIoError(#[from] std::io::Error),

    /// std array tryfromslice error
    #[error(transparent)]
    StdArrayTryFromSliceError(#[from] std::array::TryFromSliceError),

    /// Infallable error (errors that can never happen)
    #[error(transparent)]
    Infallible(#[from] std::convert::Infallible),

    /// Error decoding hexadecimal-encoded string
    #[error(transparent)]
    HexDecodeError(#[from] hex::FromHexError),

    /// Bech32 encode error
    #[error(transparent)]
    Bech32EncodeError(#[from] bech32::EncodeError),

    /// Bech32 decode error
    #[error(transparent)]
    Bech32DecodeError(#[from] bech32::DecodeError),

    /// Bech32 hrp error
    #[error(transparent)]
    Bech32HrpError(#[from] bech32::primitives::hrp::Error),

    /// snap error
    #[error(transparent)]
    SnapError(#[from] snap::Error),

    /// Snappy into_inner error when writing bytes to compression
    #[error("Snappy into_inner error when writing bytes to compression.")]
    SnapWriteIntoInnerError(String),

    /// ecies error
    #[error(transparent)]
    EciesError(#[from] ecies::SecpError),

    /// bao decode error
    #[error(transparent)]
    BaoDecodeError(#[from] bao::decode::Error),

    /// zfec_rs error
    #[error(transparent)]
    ZfecError(#[from] zfec_rs::Error),

    /// An uneven number of input bytes were provided for zfec chunks
    #[error("Input bytes must divide evenly over number of zfec chunks.")]
    UnevenZfecChunks,

    /// Unnecessary scrub
    #[error("Data does not need to be scrubbed.")]
    UnnecessaryScrub,

    /// Scrubbed padding has different lengths
    #[error("Scrubbed padding should remain the same.")]
    ScrubbedPaddingMismatch,

    /// Scrubbed data has different lengths
    #[error("Mismatch between scrubbed data length, input len: {0}, scrubbed len: {1}")]
    ScrubbedLengthMismatch(usize, usize),

    /// Hash decode error
    #[error("Hash must be {0} bytes long, an input of {1} bytes was provided.")]
    HashDecodeError(usize, usize),

    /// Invalid scrubbed bao hash
    #[error("Scrubbed hash is not equal to original hash.")]
    InvalidScrubbedHash,

    /// Zfec padding should be zero when encoding
    #[error("Padding from Zfec should always be zero, since Carbonado adds its own padding. Padding was {0}.")]
    EncodeZfecPaddingError(usize),

    /// Invalid chunk length
    #[error("Chunk length should be as calculated. Calculated chunk length was {0}, but actual chunk length was {1}")]
    EncodeInvalidChunkLength(u32, usize),

    /// Invalid verifiable slice length
    #[error("Verifiable slice count should be evenly divisible by 8. Remainder was {0}.")]
    InvalidVerifiableSliceCount(u16),

    /// secp256k1 error
    #[error(transparent)]
    Secp256k1Error(#[from] secp256k1::Error),

    /// Invalid magic number
    #[error("File header lacks Carbonado magic number and may not be a proper Carbonado file. Magic number found was {0}.")]
    InvalidMagicNumber(String),

    /// Pubkey serialization error
    #[error("Pubkey did not serialize into expected length.")]
    PubkeySerializationError,

    /// Hash bytes length error
    #[error("Hash bytes were not of expected length.")]
    HashBytesLengthError,

    /// Unexpected signature bytes length
    #[error("Signature bytes were not of expected length. Length was: {0}.")]
    UnexpectedSignatureBytesLength(usize),

    /// Invalid header length calculation
    #[error("Invalid header length calculation")]
    InvalidHeaderLength,
}
