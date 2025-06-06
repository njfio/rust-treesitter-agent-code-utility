//! # Rust Tree-sitter Library
//!
//! A comprehensive Rust library for processing source code using tree-sitter.
//! This library provides high-level abstractions for parsing, navigating, and
//! querying syntax trees across multiple programming languages.
//!
//! ## Features
//!
//! - Multi-language parsing support (Rust, JavaScript, Python, C, C++)
//! - Incremental parsing for efficient updates
//! - Syntax tree navigation utilities
//! - Query system for pattern matching
//! - Thread-safe parser management
//! - Memory-efficient tree handling
//!
//! ## Quick Start
//!
//! ```rust
//! use rust_tree_sitter::{Parser, Language};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let parser = Parser::new(Language::Rust)?;
//! let source = "fn main() { println!(\"Hello, world!\"); }";
//! let tree = parser.parse(source, None)?;
//!
//! println!("Root node: {}", tree.root_node().kind());
//! # Ok(())
//! # }
//! ```

pub mod analyzer;
pub mod error;
pub mod languages;
pub mod parser;
pub mod query;
pub mod tree;

// Re-export commonly used types
pub use analyzer::{CodebaseAnalyzer, AnalysisConfig, AnalysisResult, FileInfo, Symbol};
pub use error::{Error, Result};
pub use languages::Language;
pub use parser::{Parser, ParseOptions, create_edit};
pub use query::{Query, QueryCapture, QueryMatch, QueryBuilder};
pub use tree::{Node, SyntaxTree, TreeCursor, TreeEdit};

// Re-export tree-sitter types that users might need
pub use tree_sitter::{InputEdit, Point, Range};

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Supported language information
#[derive(Debug, Clone)]
pub struct LanguageInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub file_extensions: &'static [&'static str],
}

/// Get information about all supported languages
pub fn supported_languages() -> Vec<LanguageInfo> {
    vec![
        LanguageInfo {
            name: "Rust",
            version: "0.21.0",
            file_extensions: &["rs"],
        },
        LanguageInfo {
            name: "JavaScript",
            version: "0.21.0",
            file_extensions: &["js", "mjs", "jsx"],
        },
        LanguageInfo {
            name: "Python",
            version: "0.21.0",
            file_extensions: &["py", "pyi"],
        },
        LanguageInfo {
            name: "C",
            version: "0.21.0",
            file_extensions: &["c", "h"],
        },
        LanguageInfo {
            name: "C++",
            version: "0.22.0",
            file_extensions: &["cpp", "cxx", "cc", "hpp", "hxx"],
        },
    ]
}

/// Detect language from file extension
pub fn detect_language_from_extension(extension: &str) -> Option<Language> {
    match extension.to_lowercase().as_str() {
        "rs" => Some(Language::Rust),
        "js" | "mjs" | "jsx" => Some(Language::JavaScript),
        "py" | "pyi" => Some(Language::Python),
        "c" | "h" => Some(Language::C),
        "cpp" | "cxx" | "cc" | "hpp" | "hxx" => Some(Language::Cpp),
        _ => None,
    }
}

/// Detect language from file path
pub fn detect_language_from_path(path: &str) -> Option<Language> {
    std::path::Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .and_then(detect_language_from_extension)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_detection() {
        assert_eq!(detect_language_from_extension("rs"), Some(Language::Rust));
        assert_eq!(detect_language_from_extension("js"), Some(Language::JavaScript));
        assert_eq!(detect_language_from_extension("py"), Some(Language::Python));
        assert_eq!(detect_language_from_extension("unknown"), None);
    }

    #[test]
    fn test_path_detection() {
        assert_eq!(detect_language_from_path("main.rs"), Some(Language::Rust));
        assert_eq!(detect_language_from_path("src/lib.rs"), Some(Language::Rust));
        assert_eq!(detect_language_from_path("script.py"), Some(Language::Python));
        assert_eq!(detect_language_from_path("unknown.txt"), None);
    }

    #[test]
    fn test_supported_languages() {
        let languages = supported_languages();
        assert!(!languages.is_empty());
        assert!(languages.iter().any(|lang| lang.name == "Rust"));
    }
}
