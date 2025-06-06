//! Error types for the rust_tree_sitter library

use thiserror::Error;

/// Result type alias for this library
pub type Result<T> = std::result::Result<T, Error>;

/// Main error type for the library
#[derive(Error, Debug)]
pub enum Error {
    /// Error setting the language on a parser
    #[error("Failed to set language: {0}")]
    LanguageError(String),

    /// Error during parsing
    #[error("Parse error: {0}")]
    ParseError(String),

    /// Error with query compilation or execution
    #[error("Query error: {0}")]
    QueryError(String),

    /// Error with tree navigation or manipulation
    #[error("Tree error: {0}")]
    TreeError(String),

    /// IO error when reading files
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    /// UTF-8 encoding error
    #[error("UTF-8 error: {0}")]
    Utf8Error(#[from] std::str::Utf8Error),

    /// Invalid input provided to the library
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Feature not supported
    #[error("Feature not supported: {0}")]
    NotSupported(String),

    /// Internal library error
    #[error("Internal error: {0}")]
    Internal(String),
}

impl Error {
    /// Create a new language error
    pub fn language<S: Into<String>>(msg: S) -> Self {
        Self::LanguageError(msg.into())
    }

    /// Create a new parse error
    pub fn parse<S: Into<String>>(msg: S) -> Self {
        Self::ParseError(msg.into())
    }

    /// Create a new query error
    pub fn query<S: Into<String>>(msg: S) -> Self {
        Self::QueryError(msg.into())
    }

    /// Create a new tree error
    pub fn tree<S: Into<String>>(msg: S) -> Self {
        Self::TreeError(msg.into())
    }

    /// Create a new invalid input error
    pub fn invalid_input<S: Into<String>>(msg: S) -> Self {
        Self::InvalidInput(msg.into())
    }

    /// Create a new not supported error
    pub fn not_supported<S: Into<String>>(msg: S) -> Self {
        Self::NotSupported(msg.into())
    }

    /// Create a new internal error
    pub fn internal<S: Into<String>>(msg: S) -> Self {
        Self::Internal(msg.into())
    }
}

/// Convert tree-sitter language error to our error type
impl From<tree_sitter::LanguageError> for Error {
    fn from(err: tree_sitter::LanguageError) -> Self {
        Self::LanguageError(format!("Tree-sitter language error: {:?}", err))
    }
}

/// Convert tree-sitter query error to our error type
impl From<tree_sitter::QueryError> for Error {
    fn from(err: tree_sitter::QueryError) -> Self {
        Self::QueryError(format!("Tree-sitter query error: {:?}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_creation() {
        let err = Error::language("test language error");
        assert!(matches!(err, Error::LanguageError(_)));
        assert_eq!(err.to_string(), "Failed to set language: test language error");

        let err = Error::parse("test parse error");
        assert!(matches!(err, Error::ParseError(_)));
        assert_eq!(err.to_string(), "Parse error: test parse error");
    }

    #[test]
    fn test_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let err: Error = io_err.into();
        assert!(matches!(err, Error::IoError(_)));
    }
}
