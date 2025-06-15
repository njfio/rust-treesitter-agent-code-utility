//! Parser functionality for tree-sitter

use crate::error::{Error, Result};
use crate::languages::Language;
use crate::tree::SyntaxTree;
use crate::parsing_error_handler::{ParsingErrorHandler, ParseError, ErrorSeverity};
use std::sync::{Arc, Mutex};
use std::time::Instant;
use std::path::Path;
use tree_sitter::{InputEdit, Point};

/// Configuration options for parsing
#[derive(Debug, Clone)]
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
    error_handler: ParsingErrorHandler,
}

impl Parser {
    /// Create a new parser for the specified language
    pub fn new(language: Language) -> Result<Self> {
        let mut parser = tree_sitter::Parser::new();
        let ts_language = language.tree_sitter_language()?;
        
        parser.set_language(&ts_language)
            .map_err(|e| Error::language(format!("Failed to set language {}: {:?}", language.name(), e)))?;

        Ok(Self {
            inner: Arc::new(Mutex::new(parser)),
            language,
            options: ParseOptions::default(),
            error_handler: ParsingErrorHandler::default(),
        })
    }

    /// Create a new parser with custom options
    pub fn with_options(language: Language, options: ParseOptions) -> Result<Self> {
        let mut parser = Self::new(language)?;
        parser.options = options;
        Ok(parser)
    }

    /// Create a new parser with custom error handler
    pub fn with_error_handler(language: Language, error_handler: ParsingErrorHandler) -> Result<Self> {
        let mut parser = Self::new(language)?;
        parser.error_handler = error_handler;
        Ok(parser)
    }

    /// Create a new parser with custom options and error handler
    pub fn with_options_and_error_handler(
        language: Language,
        options: ParseOptions,
        error_handler: ParsingErrorHandler
    ) -> Result<Self> {
        let mut parser = Self::new(language)?;
        parser.options = options;
        parser.error_handler = error_handler;
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

    /// Get the error handler
    pub fn error_handler(&self) -> &ParsingErrorHandler {
        &self.error_handler
    }

    /// Get mutable access to the error handler
    pub fn error_handler_mut(&mut self) -> &mut ParsingErrorHandler {
        &mut self.error_handler
    }

    /// Get parsing errors collected during the last parsing operations
    pub fn get_parsing_errors(&self) -> &[ParseError] {
        self.error_handler.get_errors()
    }

    /// Get parsing metrics
    pub fn get_parsing_metrics(&self) -> &crate::parsing_error_handler::ParsingMetrics {
        self.error_handler.get_metrics()
    }

    /// Clear all collected errors and reset metrics
    pub fn clear_errors(&mut self) {
        self.error_handler.clear();
    }

    /// Check if the error limit has been reached
    pub fn has_reached_error_limit(&self) -> bool {
        self.error_handler.has_reached_error_limit()
    }

    /// Set new parse options
    pub fn set_options(&mut self, options: ParseOptions) {
        self.options = options;
    }

    /// Parse source code into a syntax tree with comprehensive error handling
    pub fn parse(&mut self, source: &str, old_tree: Option<&SyntaxTree>) -> Result<SyntaxTree> {
        let start_time = Instant::now();

        // Validate content before parsing
        self.error_handler.validate_content(source, None)?;

        let mut parser = self.inner.lock()
            .map_err(|e| Error::concurrency(format!("Failed to acquire parser lock: {}", e)))?;

        // Apply parsing options
        if let Some(timeout) = self.options.timeout_millis {
            parser.set_timeout_micros(timeout * 1000);
        }

        // Convert old tree if provided
        let old_ts_tree = old_tree.map(|t| t.inner());

        // Parse the source with timeout handling
        let tree = match parser.parse(source, old_ts_tree) {
            Some(tree) => tree,
            None => {
                let parse_time = start_time.elapsed();
                self.error_handler.update_metrics(parse_time, false);

                if let Some(timeout) = self.options.timeout_millis {
                    if parse_time.as_millis() >= timeout as u128 {
                        return Err(Error::timeout(format!(
                            "Parsing timed out after {}ms",
                            parse_time.as_millis()
                        )));
                    }
                }

                return Err(Error::tree_sitter("Failed to parse source code - tree-sitter returned None"));
            }
        };

        let parse_time = start_time.elapsed();
        let has_errors = tree.root_node().has_error();

        // Handle parsing errors if present
        if has_errors {
            let parse_errors = self.error_handler.handle_parse_error(tree.clone(), source, None, self.language);

            // Check if we should fail fast or continue with partial results
            let critical_errors = parse_errors.iter()
                .any(|e| matches!(e.severity, ErrorSeverity::Critical));

            if critical_errors {
                self.error_handler.update_metrics(parse_time, false);
                return Err(Error::syntax_error(
                    parse_errors[0].line,
                    parse_errors[0].column,
                    parse_errors[0].message.clone(),
                    None,
                ));
            }
        }

        self.error_handler.update_metrics(parse_time, !has_errors);
        Ok(SyntaxTree::new(tree, source.to_string()))
    }

    /// Parse source code from bytes
    pub fn parse_bytes(&mut self, source: &[u8], old_tree: Option<&SyntaxTree>) -> Result<SyntaxTree> {
        let source_str = std::str::from_utf8(source)?;
        self.parse(source_str, old_tree)
    }

    /// Parse a file with comprehensive error handling
    pub fn parse_file<P: AsRef<Path>>(&mut self, path: P) -> Result<SyntaxTree> {
        let path = path.as_ref();

        // Validate file before reading
        self.error_handler.validate_file(path)?;

        // Read file with proper error handling
        let source = std::fs::read_to_string(path)
            .map_err(|e| Error::IoError(e))?;

        // Validate content
        self.error_handler.validate_content(&source, Some(path))?;

        // Parse with file context
        self.parse_with_file_context(&source, None, path)
    }

    /// Parse source code with file context for better error reporting
    pub fn parse_with_file_context<P: AsRef<Path>>(
        &mut self,
        source: &str,
        old_tree: Option<&SyntaxTree>,
        file_path: P,
    ) -> Result<SyntaxTree> {
        let file_path = file_path.as_ref();
        let start_time = Instant::now();

        // Validate content before parsing
        self.error_handler.validate_content(source, Some(file_path))?;

        let mut parser = self.inner.lock()
            .map_err(|e| Error::concurrency(format!("Failed to acquire parser lock: {}", e)))?;

        // Apply parsing options
        if let Some(timeout) = self.options.timeout_millis {
            parser.set_timeout_micros(timeout * 1000);
        }

        // Convert old tree if provided
        let old_ts_tree = old_tree.map(|t| t.inner());

        // Parse the source with timeout handling
        let tree = match parser.parse(source, old_ts_tree) {
            Some(tree) => tree,
            None => {
                let parse_time = start_time.elapsed();
                self.error_handler.update_metrics(parse_time, false);

                if let Some(timeout) = self.options.timeout_millis {
                    if parse_time.as_millis() >= timeout as u128 {
                        return Err(Error::timeout(format!(
                            "Parsing timed out after {}ms for file: {}",
                            parse_time.as_millis(),
                            file_path.display()
                        )));
                    }
                }

                return Err(Error::tree_sitter(format!(
                    "Failed to parse file: {} - tree-sitter returned None",
                    file_path.display()
                )));
            }
        };

        let parse_time = start_time.elapsed();
        let has_errors = tree.root_node().has_error();

        // Handle parsing errors if present
        if has_errors {
            let parse_errors = self.error_handler.handle_parse_error(tree.clone(), source, Some(file_path), self.language);

            // Check if we should fail fast or continue with partial results
            let critical_errors = parse_errors.iter()
                .any(|e| matches!(e.severity, ErrorSeverity::Critical));

            if critical_errors {
                self.error_handler.update_metrics(parse_time, false);
                return Err(Error::syntax_error(
                    parse_errors[0].line,
                    parse_errors[0].column,
                    parse_errors[0].message.clone(),
                    Some(file_path.display().to_string()),
                ));
            }
        }

        self.error_handler.update_metrics(parse_time, !has_errors);
        Ok(SyntaxTree::new(tree, source.to_string()))
    }

    /// Parse with incremental updates
    pub fn parse_incremental(
        &mut self,
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
            .map_err(|e| Error::internal(format!("Failed to acquire parser lock: {}", e)))?;
        
        parser.reset();
        Ok(())
    }

    /// Set a new language for this parser
    pub fn set_language(&mut self, language: Language) -> Result<()> {
        let ts_language = language.tree_sitter_language()?;
        
        let mut parser = self.inner.lock()
            .map_err(|e| Error::internal(format!("Failed to acquire parser lock: {}", e)))?;
        
        parser.set_language(&ts_language)
            .map_err(|e| Error::language(format!("Failed to set language {}: {:?}", language.name(), e)))?;
        
        self.language = language;
        Ok(())
    }

    /// Clone this parser (creates a new parser with the same configuration)
    pub fn clone_parser(&self) -> Result<Self> {
        Self::with_options(self.language, self.options.clone())
    }
}

impl Clone for Parser {
    fn clone(&self) -> Self {
        // Note: This creates a new parser instance rather than sharing the inner parser
        // This is safer for concurrent use
        Self::with_options(self.language, self.options.clone())
            .expect("Failed to clone parser")
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
    fn test_parser_creation() -> Result<()> {
        let parser = Parser::new(Language::Rust)?;
        assert_eq!(parser.language(), Language::Rust);
        Ok(())
    }

    #[test]
    fn test_basic_parsing() -> Result<()> {
        let mut parser = Parser::new(Language::Rust)?;
        let source = "fn main() { println!(\"Hello, world!\"); }";

        let tree = parser.parse(source, None)?;
        assert_eq!(tree.root_node().kind(), "source_file");
        Ok(())
    }

    #[test]
    fn test_parse_options() -> Result<()> {
        let options = ParseOptions {
            max_bytes: Some(1000),
            timeout_millis: Some(1000),
            include_extras: false,
        };

        let parser = Parser::with_options(Language::Rust, options.clone())?;
        assert_eq!(parser.options().max_bytes, Some(1000));
        assert_eq!(parser.options().timeout_millis, Some(1000));
        assert!(!parser.options().include_extras);
        Ok(())
    }

    #[test]
    fn test_parser_clone() -> Result<()> {
        let parser1 = Parser::new(Language::Rust)?;
        let parser2 = parser1.clone();

        assert_eq!(parser1.language(), parser2.language());
        Ok(())
    }
}
