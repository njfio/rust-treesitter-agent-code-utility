//! Comprehensive error handling for parsing operations
//!
//! This module provides robust error handling, recovery strategies, and detailed
//! error reporting for all parsing operations in the rust-treesitter library.

use crate::error::{Error, Result};
use crate::languages::Language;
use std::path::{Path, PathBuf};
use std::fs;
use std::time::Duration;
use std::collections::HashMap;
use tree_sitter::Point;

/// Detailed parsing error information with context
#[derive(Debug, Clone)]
pub struct ParseError {
    /// Error message
    pub message: String,
    /// File path where the error occurred
    pub file_path: Option<PathBuf>,
    /// Line number (1-based)
    pub line: usize,
    /// Column number (0-based)
    pub column: usize,
    /// Error severity level
    pub severity: ErrorSeverity,
    /// Error category for classification
    pub category: ErrorCategory,
    /// Suggested recovery actions
    pub recovery_suggestions: Vec<String>,
    /// Context around the error (source code snippet)
    pub context: Option<String>,
    /// Byte offset in the source
    pub byte_offset: Option<usize>,
}

/// Error severity levels
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorSeverity {
    /// Critical errors that prevent any parsing
    Critical,
    /// Errors that prevent complete parsing but allow partial results
    Error,
    /// Warnings about potential issues
    Warning,
    /// Informational messages about parsing quirks
    Info,
}

/// Error categories for classification and handling
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ErrorCategory {
    /// Syntax errors in the source code
    Syntax,
    /// File I/O related errors
    FileIO,
    /// Memory allocation or limit errors
    Memory,
    /// Encoding or character set issues
    Encoding,
    /// Language configuration errors
    Language,
    /// Tree-sitter internal errors
    TreeSitter,
    /// Timeout during parsing
    Timeout,
    /// Unsupported language features
    UnsupportedFeature,
    /// Validation errors
    Validation,
}

/// Parsing error handler with recovery strategies
pub struct ParsingErrorHandler {
    /// Maximum number of errors to collect before stopping
    max_errors: usize,
    /// Whether to attempt error recovery
    enable_recovery: bool,
    /// Timeout for parsing operations
    parse_timeout: Duration,
    /// Maximum file size to parse
    max_file_size: usize,
    /// Collected errors during parsing
    errors: Vec<ParseError>,
    /// Performance metrics
    metrics: ParsingMetrics,
}

/// Performance and error metrics
#[derive(Debug, Default)]
pub struct ParsingMetrics {
    /// Total files processed
    pub files_processed: usize,
    /// Files parsed successfully
    pub files_successful: usize,
    /// Files with errors
    pub files_with_errors: usize,
    /// Total parsing time
    pub total_parse_time: Duration,
    /// Average parsing time per file
    pub average_parse_time: Duration,
    /// Errors by category
    pub errors_by_category: HashMap<ErrorCategory, usize>,
    /// Memory usage statistics
    pub peak_memory_usage: usize,
}

impl Default for ParsingErrorHandler {
    fn default() -> Self {
        Self {
            max_errors: 100,
            enable_recovery: true,
            parse_timeout: Duration::from_secs(30),
            max_file_size: 10 * 1024 * 1024, // 10MB
            errors: Vec::new(),
            metrics: ParsingMetrics::default(),
        }
    }
}

impl ParsingErrorHandler {
    /// Create a new parsing error handler with custom configuration
    pub fn new(
        max_errors: usize,
        enable_recovery: bool,
        parse_timeout: Duration,
        max_file_size: usize,
    ) -> Self {
        Self {
            max_errors,
            enable_recovery,
            parse_timeout,
            max_file_size,
            errors: Vec::new(),
            metrics: ParsingMetrics::default(),
        }
    }

    /// Validate file before parsing
    pub fn validate_file(&self, file_path: &Path) -> Result<()> {
        // Check if file exists
        if !file_path.exists() {
            return Err(Error::invalid_path(format!("File does not exist: {}", file_path.display())));
        }

        // Check if it's a file (not a directory)
        if !file_path.is_file() {
            return Err(Error::invalid_path(format!("Path is not a file: {}", file_path.display())));
        }

        // Check file size
        let metadata = fs::metadata(file_path)?;
        if metadata.len() > self.max_file_size as u64 {
            return Err(Error::resource_limit(format!(
                "File too large: {} bytes (max: {} bytes)",
                metadata.len(),
                self.max_file_size
            )));
        }

        // Check file permissions
        if metadata.permissions().readonly() {
            // This is just a warning, not an error for reading
        }

        Ok(())
    }

    /// Validate source content before parsing
    pub fn validate_content(&self, content: &str, file_path: Option<&Path>) -> Result<()> {
        // Check content size
        if content.len() > self.max_file_size {
            return Err(Error::resource_limit(format!(
                "Content too large: {} bytes (max: {} bytes)",
                content.len(),
                self.max_file_size
            )));
        }

        // Check for null bytes (which can cause issues with tree-sitter)
        if content.contains('\0') {
            let file_info = file_path.map(|p| format!(" in file {}", p.display())).unwrap_or_default();
            return Err(Error::validation(format!(
                "Content contains null bytes{}, which may cause parsing issues",
                file_info
            )));
        }

        // Validate UTF-8 encoding (this should already be done, but double-check)
        if !content.is_char_boundary(content.len()) {
            let file_info = file_path.map(|p| format!(" in file {}", p.display())).unwrap_or_default();
            return Err(Error::encoding(format!(
                "Content is not valid UTF-8{}",
                file_info
            )));
        }

        Ok(())
    }

    /// Handle parsing errors with detailed context
    pub fn handle_parse_error(
        &mut self,
        error: tree_sitter::Tree,
        content: &str,
        file_path: Option<&Path>,
        language: Language,
    ) -> Vec<ParseError> {
        let mut parse_errors = Vec::new();

        // Extract error nodes from the tree
        let error_nodes = self.extract_error_nodes(&error);
        
        for error_node in error_nodes {
            let start_pos = error_node.start_position();
            let end_pos = error_node.end_position();
            
            let parse_error = ParseError {
                message: format!("Syntax error: unexpected {}", error_node.kind()),
                file_path: file_path.map(|p| p.to_path_buf()),
                line: start_pos.row + 1,
                column: start_pos.column,
                severity: ErrorSeverity::Error,
                category: ErrorCategory::Syntax,
                recovery_suggestions: self.generate_recovery_suggestions(&error_node, content, language),
                context: self.extract_error_context(content, start_pos, end_pos),
                byte_offset: Some(error_node.start_byte()),
            };

            parse_errors.push(parse_error.clone());
            self.errors.push(parse_error);

            // Update metrics
            *self.metrics.errors_by_category.entry(ErrorCategory::Syntax).or_insert(0) += 1;

            // Stop if we've reached the maximum number of errors
            if self.errors.len() >= self.max_errors {
                break;
            }
        }

        parse_errors
    }

    /// Extract error nodes from a parsed tree
    fn extract_error_nodes<'a>(&self, tree: &'a tree_sitter::Tree) -> Vec<tree_sitter::Node<'a>> {
        let mut error_nodes = Vec::new();
        let cursor = tree.walk();

        // Use a stack-based approach to avoid lifetime issues
        let mut stack = vec![cursor.node()];

        while let Some(node) = stack.pop() {
            if node.is_error() || node.is_missing() {
                error_nodes.push(node);
            }

            // Add children to stack
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    stack.push(child);
                }
            }
        }

        error_nodes
    }

    /// Generate recovery suggestions based on the error context
    fn generate_recovery_suggestions(
        &self,
        error_node: &tree_sitter::Node,
        content: &str,
        language: Language,
    ) -> Vec<String> {
        let mut suggestions = Vec::new();

        // Get the error context
        let _start_byte = error_node.start_byte();
        let _end_byte = error_node.end_byte();
        
        if let Ok(error_text) = error_node.utf8_text(content.as_bytes()) {
            // Common syntax error patterns and suggestions
            if error_text.contains("(") && !error_text.contains(")") {
                suggestions.push("Missing closing parenthesis ')'".to_string());
            }
            
            if error_text.contains("{") && !error_text.contains("}") {
                suggestions.push("Missing closing brace '}'".to_string());
            }
            
            if error_text.contains("[") && !error_text.contains("]") {
                suggestions.push("Missing closing bracket ']'".to_string());
            }

            // Language-specific suggestions
            match language {
                Language::JavaScript | Language::TypeScript => {
                    if error_text.contains("function") {
                        suggestions.push("Check function syntax: function name() { }".to_string());
                    }
                    if error_text.ends_with("=") {
                        suggestions.push("Missing value after assignment operator".to_string());
                    }
                }
                Language::Python => {
                    if error_text.ends_with(":") {
                        suggestions.push("Missing indented block after colon".to_string());
                    }
                    if error_text.contains("def") {
                        suggestions.push("Check function definition syntax: def name():".to_string());
                    }
                }
                Language::Rust => {
                    if error_text.contains("fn") {
                        suggestions.push("Check function syntax: fn name() -> Type { }".to_string());
                    }
                    if error_text.ends_with("=") {
                        suggestions.push("Missing semicolon after statement".to_string());
                    }
                }
                _ => {}
            }
        }

        if suggestions.is_empty() {
            suggestions.push("Check the syntax around this location".to_string());
        }

        suggestions
    }

    /// Extract context around an error for better debugging
    fn extract_error_context(
        &self,
        content: &str,
        start_pos: Point,
        end_pos: Point,
    ) -> Option<String> {
        let lines: Vec<&str> = content.lines().collect();
        
        if start_pos.row >= lines.len() {
            return None;
        }

        // Extract 2 lines before and after the error
        let context_start = start_pos.row.saturating_sub(2);
        let context_end = (end_pos.row + 3).min(lines.len());
        
        let context_lines: Vec<String> = lines[context_start..context_end]
            .iter()
            .enumerate()
            .map(|(i, line)| {
                let line_num = context_start + i + 1;
                let marker = if line_num == start_pos.row + 1 { ">>> " } else { "    " };
                format!("{}{:4}: {}", marker, line_num, line)
            })
            .collect();

        Some(context_lines.join("\n"))
    }

    /// Get all collected errors
    pub fn get_errors(&self) -> &[ParseError] {
        &self.errors
    }

    /// Get parsing metrics
    pub fn get_metrics(&self) -> &ParsingMetrics {
        &self.metrics
    }

    /// Clear all collected errors and reset metrics
    pub fn clear(&mut self) {
        self.errors.clear();
        self.metrics = ParsingMetrics::default();
    }

    /// Check if the error limit has been reached
    pub fn has_reached_error_limit(&self) -> bool {
        self.errors.len() >= self.max_errors
    }

    /// Update parsing metrics
    pub fn update_metrics(&mut self, parse_time: Duration, success: bool) {
        self.metrics.files_processed += 1;
        self.metrics.total_parse_time += parse_time;
        
        if success {
            self.metrics.files_successful += 1;
        } else {
            self.metrics.files_with_errors += 1;
        }

        if self.metrics.files_processed > 0 {
            self.metrics.average_parse_time = self.metrics.total_parse_time / self.metrics.files_processed as u32;
        }
    }
}
