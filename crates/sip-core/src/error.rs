//! Error types for the SIP message layer.

/// Errors produced while parsing or framing SIP messages.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    /// A syntactically invalid construct. `line`/`col` are 1-based and
    /// refer to the position in the input buffer (0/0 when the error was
    /// produced by a header/URI sub-parser without positional context).
    #[error("malformed at line {line}, col {col}: {what}")]
    Malformed {
        /// 1-based line number.
        line: usize,
        /// 1-based column number.
        col: usize,
        /// Human readable description.
        what: String,
    },
    /// The input exceeds a configured hard limit (message size, header
    /// count, ...).
    #[error("message exceeds limit {limit}")]
    TooLarge {
        /// The limit that was exceeded.
        limit: usize,
    },
    /// Stream-mode framing: the buffer ended before the announced
    /// `Content-Length` of body bytes (or before the header section) was
    /// complete. `expected == 0` means the header section itself was still
    /// incomplete.
    #[error("truncated: expected {expected} body bytes, got {got}")]
    Truncated {
        /// Number of body bytes announced by Content-Length (0 = header section incomplete).
        expected: usize,
        /// Number of body bytes actually available.
        got: usize,
    },
    /// The start line announced a SIP version other than `SIP/2.0`.
    #[error("unsupported SIP version: {0}")]
    UnsupportedVersion(String),
    /// A `Content-Length` header carried a negative or otherwise invalid
    /// numeric value.
    #[error("bad Content-Length: {0}")]
    BadContentLength(i64),
}

impl ParseError {
    /// Convenience constructor for a position-less `Malformed` error.
    pub(crate) fn malformed(what: impl Into<String>) -> Self {
        ParseError::Malformed {
            line: 0,
            col: 0,
            what: what.into(),
        }
    }
}

/// Result alias used throughout the message layer.
pub type Result<T> = std::result::Result<T, ParseError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_messages() {
        let e = ParseError::Malformed {
            line: 3,
            col: 7,
            what: "bad thing".to_string(),
        };
        assert_eq!(e.to_string(), "malformed at line 3, col 7: bad thing");
        assert_eq!(
            ParseError::TooLarge { limit: 65536 }.to_string(),
            "message exceeds limit 65536"
        );
        assert_eq!(
            ParseError::Truncated {
                expected: 10,
                got: 4
            }
            .to_string(),
            "truncated: expected 10 body bytes, got 4"
        );
        assert_eq!(
            ParseError::UnsupportedVersion("SIP/1.0".into()).to_string(),
            "unsupported SIP version: SIP/1.0"
        );
        assert_eq!(
            ParseError::BadContentLength(-5).to_string(),
            "bad Content-Length: -5"
        );
    }

    #[test]
    fn equality_and_clone() {
        let a = ParseError::TooLarge { limit: 1 };
        let b = a.clone();
        assert_eq!(a, b);
        assert_ne!(a, ParseError::TooLarge { limit: 2 });
    }
}
