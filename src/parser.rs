//! Parser functionality for tree-sitter

use crate::error::{Error, Result};
use crate::languages::Language;
use crate::tree::SyntaxTree;
use std::sync::{Arc, Mutex};
use tree_sitter::{InputEdit, Point};

/// Configuration options for parsing
#[derive(Debug, Clone, Copy)]
pub struct ParseOptions {
    /// Maximum number of bytes to parse (None for unlimited)
    pub max_bytes: Option<usize>,
    /// Timeout for parsing in milliseconds (None for no timeout)
    pub timeout_millis: Option<u64>,
    /// Whether to include extra information in the tree
    pub include_extras: bool,
}

impl Default for ParseOptions {
    fn default() -> Self {
        Self {
            max_bytes: None,
            timeout_millis: Some(5000), // 5 second default timeout
            include_extras: true,
        }
    }
}

/// A thread-safe wrapper around tree-sitter parser
pub struct Parser {
    inner: Arc<Mutex<tree_sitter::Parser>>,
    language: Language,
    options: ParseOptions,
}

impl Parser {
    /// Create a new parser for the specified language
    pub fn new(language: Language) -> Result<Self> {
        let mut parser = tree_sitter::Parser::new();
        let ts_language = language.tree_sitter_language()?;
        
        parser.set_language(&ts_language)
            .map_err(|e| Error::language_error_with_cause(language.name(), "parser initialization", format!("{:?}", e)))?;

        Ok(Self {
            inner: Arc::new(Mutex::new(parser)),
            language,
            options: ParseOptions::default(),
        })
    }

    /// Create a new parser with custom options
    pub fn with_options(language: Language, options: ParseOptions) -> Result<Self> {
        let mut parser = Self::new(language)?;
        parser.options = options;
        Ok(parser)
    }

    /// Get the current language
    pub fn language(&self) -> Language {
        self.language
    }

    /// Get the current parse options
    pub fn options(&self) -> &ParseOptions {
        &self.options
    }

    /// Set new parse options
    pub fn set_options(&mut self, options: ParseOptions) {
        self.options = options;
    }

    /// Parse source code into a syntax tree
    pub fn parse(&self, source: &str, old_tree: Option<&SyntaxTree>) -> Result<SyntaxTree> {
        let mut parser = self.inner.lock()
            .map_err(|e| Error::internal_error("parser", format!("Failed to acquire parser lock: {}", e)))?;

        // Apply parsing options
        if let Some(timeout) = self.options.timeout_millis {
            parser.set_timeout_micros(timeout * 1000);
        }

        // Convert old tree if provided
        let old_ts_tree = old_tree.map(|t| t.inner());

        // Parse the source
        let tree = parser.parse(source, old_ts_tree)
            .ok_or_else(|| Error::parse_error("Failed to parse source code"))?;

        // Note: We allow trees with errors to be returned, as they can still be useful
        // The caller can check tree.has_error() if they need to know about parse errors

        Ok(SyntaxTree::new(tree, source.to_string()))
    }

    /// Parse source code from bytes
    pub fn parse_bytes(&self, source: &[u8], old_tree: Option<&SyntaxTree>) -> Result<SyntaxTree> {
        let source_str = std::str::from_utf8(source)?;
        self.parse(source_str, old_tree)
    }

    /// Parse a file
    pub fn parse_file(&self, path: &str) -> Result<SyntaxTree> {
        let source = std::fs::read_to_string(path)?;
        self.parse(&source, None)
    }

    /// Parse with incremental updates
    pub fn parse_incremental(
        &self,
        source: &str,
        old_tree: &mut SyntaxTree,
        edits: &[InputEdit],
    ) -> Result<SyntaxTree> {
        // Apply edits to the old tree
        for edit in edits {
            old_tree.edit(edit);
        }

        // Parse with the edited tree
        self.parse(source, Some(old_tree))
    }

    /// Reset the parser state
    pub fn reset(&self) -> Result<()> {
        let mut parser = self.inner.lock()
            .map_err(|e| Error::internal_error("parser", format!("Failed to acquire parser lock: {}", e)))?;
        
        parser.reset();
        Ok(())
    }

    /// Set a new language for this parser
    pub fn set_language(&mut self, language: Language) -> Result<()> {
        let ts_language = language.tree_sitter_language()?;
        
        let mut parser = self.inner.lock()
            .map_err(|e| Error::internal_error("parser", format!("Failed to acquire parser lock: {}", e)))?;
        
        parser.set_language(&ts_language)
            .map_err(|e| Error::language_error_with_cause(language.name(), "language change", format!("{:?}", e)))?;
        
        self.language = language;
        Ok(())
    }

    /// Clone this parser (creates a new parser with the same configuration)
    pub fn clone_parser(&self) -> Result<Self> {
        Self::with_options(self.language, self.options)
    }
}

impl Clone for Parser {
    fn clone(&self) -> Self {
        // Note: This creates a new parser instance rather than sharing the inner parser
        // This is safer for concurrent use
        Self::with_options(self.language, self.options)
            .expect("Failed to clone parser: parser creation should always succeed with valid language and options")
    }
}

/// Helper function to create an InputEdit from simple parameters
pub fn create_edit(
    start_byte: usize,
    old_end_byte: usize,
    new_end_byte: usize,
    start_row: usize,
    start_column: usize,
    old_end_row: usize,
    old_end_column: usize,
    new_end_row: usize,
    new_end_column: usize,
) -> InputEdit {
    InputEdit {
        start_byte,
        old_end_byte,
        new_end_byte,
        start_position: Point::new(start_row, start_column),
        old_end_position: Point::new(old_end_row, old_end_column),
        new_end_position: Point::new(new_end_row, new_end_column),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parser_creation() {
        let parser = Parser::new(Language::Rust);
        assert!(parser.is_ok());
        
        let parser = parser.unwrap();
        assert_eq!(parser.language(), Language::Rust);
    }

    #[test]
    fn test_basic_parsing() {
        let parser = Parser::new(Language::Rust).unwrap();
        let source = "fn main() { println!(\"Hello, world!\"); }";
        
        let tree = parser.parse(source, None);
        assert!(tree.is_ok());
        
        let tree = tree.unwrap();
        assert_eq!(tree.root_node().kind(), "source_file");
    }

    #[test]
    fn test_parse_options() {
        let options = ParseOptions {
            max_bytes: Some(1000),
            timeout_millis: Some(1000),
            include_extras: false,
        };
        
        let parser = Parser::with_options(Language::Rust, options);
        assert!(parser.is_ok());
        
        let parser = parser.unwrap();
        assert_eq!(parser.options().max_bytes, Some(1000));
        assert_eq!(parser.options().timeout_millis, Some(1000));
        assert!(!parser.options().include_extras);
    }

    #[test]
    fn test_parser_clone() {
        let parser1 = Parser::new(Language::Rust).unwrap();
        let parser2 = parser1.clone();
        
        assert_eq!(parser1.language(), parser2.language());
    }
}
