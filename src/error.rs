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

    /// File system related errors
    #[error("File system error: {0}")]
    FileSystemError(String),

    /// Path validation errors
    #[error("Invalid path: {0}")]
    InvalidPath(String),

    /// Configuration errors
    #[error("Configuration error: {0}")]
    ConfigError(String),

    /// Network/HTTP related errors
    #[error("Network error: {0}")]
    NetworkError(String),

    /// Security related errors
    #[error("Security error: {0}")]
    SecurityError(String),

    /// Analysis errors
    #[error("Analysis error: {0}")]
    AnalysisError(String),

    /// Timeout errors
    #[error("Operation timed out: {0}")]
    TimeoutError(String),

    /// Resource limit errors
    #[error("Resource limit exceeded: {0}")]
    ResourceLimitError(String),

    /// Serialization/deserialization errors
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Anyhow error (for external libraries)
    #[error("External error: {0}")]
    Anyhow(#[from] anyhow::Error),

    /// Syntax errors with detailed location information
    #[error("Syntax error at line {line}, column {column}: {message}")]
    SyntaxError {
        line: usize,
        column: usize,
        message: String,
        file_path: Option<String>,
    },

    /// Memory allocation or limit errors
    #[error("Memory error: {0}")]
    MemoryError(String),

    /// Unsupported language feature errors
    #[error("Unsupported language feature: {feature} in {language}")]
    UnsupportedFeature {
        feature: String,
        language: String,
    },

    /// File encoding errors (beyond UTF-8)
    #[error("Encoding error: {0}")]
    EncodingError(String),

    /// Tree-sitter specific parsing errors
    #[error("Tree-sitter error: {0}")]
    TreeSitterError(String),

    /// Concurrent access errors
    #[error("Concurrency error: {0}")]
    ConcurrencyError(String),

    /// Validation errors for input data
    #[error("Validation error: {0}")]
    ValidationError(String),

    /// Recovery operation errors
    #[error("Recovery failed: {0}")]
    RecoveryError(String),

    /// Semantic analysis errors
    #[error("Semantic analysis error: {0}")]
    SemanticError(String),

    /// RDF/Graph related errors
    #[error("Graph error: {0}")]
    GraphError(String),

    /// Invalid IRI errors
    #[error("Invalid IRI: {0}")]
    InvalidIri(String),

    /// Entity not found errors
    #[error("Entity not found: {0}")]
    EntityNotFound(String),

    /// Graph not initialized errors
    #[error("Graph not initialized: {0}")]
    GraphNotInitialized(String),

    /// Lock acquisition errors
    #[error("Lock error: {0}")]
    LockError(String),

    /// Invalid configuration errors
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),

    /// Dimension mismatch errors for embeddings
    #[error("Dimension mismatch: {0}")]
    DimensionMismatch(String),

    /// Unsupported language errors
    #[error("Unsupported language: {0}")]
    UnsupportedLanguage(String),

    /// File read errors with path context
    #[error("Failed to read file {0}: {1}")]
    FileReadError(std::path::PathBuf, String),
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

    /// Create a new file system error
    pub fn file_system<S: Into<String>>(msg: S) -> Self {
        Self::FileSystemError(msg.into())
    }

    /// Create a new invalid path error
    pub fn invalid_path<S: Into<String>>(msg: S) -> Self {
        Self::InvalidPath(msg.into())
    }

    /// Create a new configuration error
    pub fn config<S: Into<String>>(msg: S) -> Self {
        Self::ConfigError(msg.into())
    }

    /// Create a new network error
    pub fn network<S: Into<String>>(msg: S) -> Self {
        Self::NetworkError(msg.into())
    }

    /// Create a new security error
    pub fn security<S: Into<String>>(msg: S) -> Self {
        Self::SecurityError(msg.into())
    }

    /// Create a new analysis error
    pub fn analysis<S: Into<String>>(msg: S) -> Self {
        Self::AnalysisError(msg.into())
    }

    /// Create a new timeout error
    pub fn timeout<S: Into<String>>(msg: S) -> Self {
        Self::TimeoutError(msg.into())
    }

    /// Create a new resource limit error
    pub fn resource_limit<S: Into<String>>(msg: S) -> Self {
        Self::ResourceLimitError(msg.into())
    }

    /// Create a new serialization error
    pub fn serialization<S: Into<String>>(msg: S) -> Self {
        Self::SerializationError(msg.into())
    }

    /// Create a new syntax error with location information
    pub fn syntax_error<S: Into<String>>(
        line: usize,
        column: usize,
        message: S,
        file_path: Option<String>,
    ) -> Self {
        Self::SyntaxError {
            line,
            column,
            message: message.into(),
            file_path,
        }
    }

    /// Create a new memory error
    pub fn memory<S: Into<String>>(msg: S) -> Self {
        Self::MemoryError(msg.into())
    }

    /// Create a new unsupported feature error
    pub fn unsupported_feature<S: Into<String>, T: Into<String>>(feature: S, language: T) -> Self {
        Self::UnsupportedFeature {
            feature: feature.into(),
            language: language.into(),
        }
    }

    /// Create a new encoding error
    pub fn encoding<S: Into<String>>(msg: S) -> Self {
        Self::EncodingError(msg.into())
    }

    /// Create a new tree-sitter error
    pub fn tree_sitter<S: Into<String>>(msg: S) -> Self {
        Self::TreeSitterError(msg.into())
    }

    /// Create a new concurrency error
    pub fn concurrency<S: Into<String>>(msg: S) -> Self {
        Self::ConcurrencyError(msg.into())
    }

    /// Create a new validation error
    pub fn validation<S: Into<String>>(msg: S) -> Self {
        Self::ValidationError(msg.into())
    }

    /// Create a new recovery error
    pub fn recovery<S: Into<String>>(msg: S) -> Self {
        Self::RecoveryError(msg.into())
    }

    /// Create a new semantic error
    pub fn semantic<S: Into<String>>(msg: S) -> Self {
        Self::SemanticError(msg.into())
    }

    /// Create a new graph error
    pub fn graph<S: Into<String>>(msg: S) -> Self {
        Self::GraphError(msg.into())
    }

    /// Create a new invalid IRI error
    pub fn invalid_iri<S: Into<String>>(msg: S) -> Self {
        Self::InvalidIri(msg.into())
    }

    /// Create a new entity not found error
    pub fn entity_not_found<S: Into<String>>(msg: S) -> Self {
        Self::EntityNotFound(msg.into())
    }

    /// Create a new graph not initialized error
    pub fn graph_not_initialized<S: Into<String>>(msg: S) -> Self {
        Self::GraphNotInitialized(msg.into())
    }

    /// Create a new lock error
    pub fn lock<S: Into<String>>(msg: S) -> Self {
        Self::LockError(msg.into())
    }

    /// Create a new invalid configuration error
    pub fn invalid_configuration<S: Into<String>>(msg: S) -> Self {
        Self::InvalidConfiguration(msg.into())
    }

    /// Create a new dimension mismatch error
    pub fn dimension_mismatch<S: Into<String>>(msg: S) -> Self {
        Self::DimensionMismatch(msg.into())
    }

    /// Create a new unsupported language error
    pub fn unsupported_language<S: Into<String>>(msg: S) -> Self {
        Self::UnsupportedLanguage(msg.into())
    }

    /// Create a new file read error
    pub fn file_read_error<S: Into<String>>(path: std::path::PathBuf, msg: S) -> Self {
        Self::FileReadError(path, msg.into())
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            Error::TimeoutError(_) => true,
            Error::NetworkError(_) => true,
            Error::ResourceLimitError(_) => true,
            Error::ConfigError(_) => true,
            Error::InvalidInput(_) => true,
            Error::InvalidPath(_) => true,
            Error::SyntaxError { .. } => true,
            Error::MemoryError(_) => true,
            Error::EncodingError(_) => true,
            Error::ValidationError(_) => true,
            Error::ConcurrencyError(_) => true,
            _ => false,
        }
    }

    /// Get a user-friendly error message with recovery suggestions
    pub fn user_message(&self) -> String {
        match self {
            Error::LanguageError(msg) => {
                format!("Language configuration error: {}. Please check that the language is supported and properly configured.", msg)
            }
            Error::ParseError(msg) => {
                format!("Failed to parse source code: {}. Please check the syntax of your source files.", msg)
            }
            Error::QueryError(msg) => {
                format!("Query execution failed: {}. Please verify your query syntax.", msg)
            }
            Error::IoError(err) => {
                format!("File operation failed: {}. Please check file permissions and disk space.", err)
            }
            Error::InvalidPath(msg) => {
                format!("Invalid file path: {}. Please provide a valid file or directory path.", msg)
            }
            Error::ConfigError(msg) => {
                format!("Configuration error: {}. Please check your configuration file.", msg)
            }
            Error::NetworkError(msg) => {
                format!("Network error: {}. Please check your internet connection and try again.", msg)
            }
            Error::TimeoutError(msg) => {
                format!("Operation timed out: {}. Try increasing timeout limits or processing smaller files.", msg)
            }
            Error::ResourceLimitError(msg) => {
                format!("Resource limit exceeded: {}. Try processing smaller files or increasing memory limits.", msg)
            }
            Error::SecurityError(msg) => {
                format!("Security error: {}. Please review file permissions and security settings.", msg)
            }
            Error::SyntaxError { line, column, message, file_path } => {
                let file_info = file_path.as_ref()
                    .map(|p| format!(" in file {}", p))
                    .unwrap_or_default();
                format!("Syntax error at line {}, column {}{}: {}. Please check the source code syntax.",
                       line, column, file_info, message)
            }
            Error::MemoryError(msg) => {
                format!("Memory error: {}. Try processing smaller files or increasing available memory.", msg)
            }
            Error::UnsupportedFeature { feature, language } => {
                format!("Unsupported feature '{}' in language '{}'. This feature may not be implemented yet.",
                       feature, language)
            }
            Error::EncodingError(msg) => {
                format!("Encoding error: {}. Please ensure the file is properly encoded.", msg)
            }
            Error::TreeSitterError(msg) => {
                format!("Tree-sitter parsing error: {}. The source code may have syntax issues.", msg)
            }
            Error::ConcurrencyError(msg) => {
                format!("Concurrency error: {}. Try reducing parallel processing or check for resource conflicts.", msg)
            }
            Error::ValidationError(msg) => {
                format!("Validation error: {}. Please check the input data format and requirements.", msg)
            }
            Error::RecoveryError(msg) => {
                format!("Recovery operation failed: {}. Manual intervention may be required.", msg)
            }
            _ => self.to_string(),
        }
    }

    /// Get error category for logging and metrics
    pub fn category(&self) -> &'static str {
        match self {
            Error::LanguageError(_) => "language",
            Error::ParseError(_) => "parsing",
            Error::QueryError(_) => "query",
            Error::TreeError(_) => "tree",
            Error::IoError(_) => "io",
            Error::Utf8Error(_) => "encoding",
            Error::InvalidInput(_) => "input",
            Error::NotSupported(_) => "feature",
            Error::Internal(_) => "internal",
            Error::FileSystemError(_) => "filesystem",
            Error::InvalidPath(_) => "path",
            Error::ConfigError(_) => "config",
            Error::NetworkError(_) => "network",
            Error::SecurityError(_) => "security",
            Error::AnalysisError(_) => "analysis",
            Error::TimeoutError(_) => "timeout",
            Error::ResourceLimitError(_) => "resource",
            Error::SerializationError(_) => "serialization",
            Error::Anyhow(_) => "external",
            Error::SyntaxError { .. } => "syntax",
            Error::MemoryError(_) => "memory",
            Error::UnsupportedFeature { .. } => "unsupported_feature",
            Error::EncodingError(_) => "encoding",
            Error::TreeSitterError(_) => "tree_sitter",
            Error::ConcurrencyError(_) => "concurrency",
            Error::ValidationError(_) => "validation",
            Error::RecoveryError(_) => "recovery",
            Error::SemanticError(_) => "semantic",
            Error::GraphError(_) => "graph",
            Error::InvalidIri(_) => "invalid_iri",
            Error::EntityNotFound(_) => "entity_not_found",
            Error::GraphNotInitialized(_) => "graph_not_initialized",
            Error::LockError(_) => "lock",
            Error::InvalidConfiguration(_) => "invalid_configuration",
            Error::DimensionMismatch(_) => "dimension_mismatch",
            Error::UnsupportedLanguage(_) => "unsupported_language",
            Error::FileReadError(_, _) => "file_read",
        }
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

/// Convert serde JSON errors to our error type
impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::SerializationError(format!("JSON serialization error: {}", err))
    }
}

/// Convert reqwest errors to our error type
impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Self {
        if err.is_timeout() {
            Self::TimeoutError(format!("HTTP request timeout: {}", err))
        } else if err.is_connect() {
            Self::NetworkError(format!("HTTP connection error: {}", err))
        } else {
            Self::NetworkError(format!("HTTP error: {}", err))
        }
    }
}

/// Convert path strip prefix errors to our error type
impl From<std::path::StripPrefixError> for Error {
    fn from(err: std::path::StripPrefixError) -> Self {
        Self::InvalidPath(format!("Path strip prefix error: {}", err))
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
