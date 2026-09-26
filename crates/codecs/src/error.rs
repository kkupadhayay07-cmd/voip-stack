//! Codec error type shared across the suite.

/// Errors produced by encoders, decoders and DSP utilities.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CodecError {
    /// Input payload or PCM slice is malformed for the current codec state.
    #[error("invalid codec data: {0}")]
    InvalidData(String),
    /// Capability not implemented / not compiled in.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),
    /// Error surfaced by the libopus binding.
    #[error("opus error: {0}")]
    Opus(String),
    /// Resampler configuration or state error.
    #[error("resampler error: {0}")]
    Resampler(String),
    /// Internal invariant violation (should never happen).
    #[error("internal codec error: {0}")]
    Internal(String),
}

/// Convenient result alias.
pub type Result<T> = std::result::Result<T, CodecError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_equality() {
        let e = CodecError::InvalidData("bad frame".into());
        assert_eq!(e.to_string(), "invalid codec data: bad frame");
        assert_eq!(e, CodecError::InvalidData("bad frame".into()));
        assert_ne!(e, CodecError::Unsupported("x"));
        let _: Result<()> = Err(e);
    }

    #[test]
    fn is_std_error() {
        fn assert_error<T: std::error::Error>(_: &T) {}
        assert_error(&CodecError::Opus("x".into()));
    }
}
