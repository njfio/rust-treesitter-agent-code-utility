//! Input validation and sanitization utilities
//!
//! This module provides comprehensive input validation for CLI commands and API calls,
//! ensuring security and preventing common attack vectors like path traversal.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::collections::HashSet;

/// Maximum allowed file size for processing (100MB)
pub const MAX_FILE_SIZE: usize = 100 * 1024 * 1024;

/// Maximum allowed directory depth for traversal
pub const MAX_DIRECTORY_DEPTH: usize = 50;

/// Maximum allowed pattern length for queries
pub const MAX_PATTERN_LENGTH: usize = 10000;

/// Maximum allowed timeout in milliseconds
pub const MAX_TIMEOUT_MS: u64 = 300_000; // 5 minutes

/// Supported output formats
pub const SUPPORTED_FORMATS: &[&str] = &[
    "json", "table", "markdown", "text", "ascii", "unicode", "mermaid", "html"
];

/// Supported languages
pub const SUPPORTED_LANGUAGES: &[&str] = &[
    "rust", "javascript", "typescript", "python", "c", "cpp", "go"
];

/// Supported security severity levels
pub const SUPPORTED_SEVERITIES: &[&str] = &[
    "critical", "high", "medium", "low", "info"
];

/// Supported refactoring categories
pub const SUPPORTED_REFACTOR_CATEGORIES: &[&str] = &[
    "complexity", "duplication", "naming", "performance", "architecture"
];

/// Supported performance categories
pub const SUPPORTED_PERFORMANCE_CATEGORIES: &[&str] = &[
    "complexity", "memory", "cpu", "io"
];

/// Input validator for CLI commands and API calls
pub struct InputValidator {
    allowed_extensions: HashSet<String>,
    blocked_paths: HashSet<PathBuf>,
}

impl InputValidator {
    /// Create a new input validator with default settings
    pub fn new() -> Self {
        let mut allowed_extensions = HashSet::new();
        allowed_extensions.extend([
            "rs", "js", "ts", "py", "c", "cpp", "cc", "cxx", "h", "hpp", "go",
            "java", "kt", "swift", "rb", "php", "cs", "fs", "scala", "clj",
            "hs", "ml", "elm", "dart", "lua", "r", "jl", "nim", "zig"
        ].iter().map(|s| s.to_string()));

        let mut blocked_paths = HashSet::new();
        blocked_paths.extend([
            PathBuf::from("/etc"),
            PathBuf::from("/proc"),
            PathBuf::from("/sys"),
            PathBuf::from("/dev"),
            PathBuf::from("/root"),
            PathBuf::from("C:\\Windows"),
            PathBuf::from("C:\\System32"),
        ]);

        Self {
            allowed_extensions,
            blocked_paths,
        }
    }

    /// Validate a file path for security and accessibility
    pub fn validate_path<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf> {
        let path = path.as_ref();

        // Convert to absolute path to prevent path traversal
        let canonical_path = path.canonicalize()
            .map_err(|e| Error::invalid_input(format!("Invalid path '{}': {}", path.display(), e)))?;

        // Check if path exists
        if !canonical_path.exists() {
            return Err(Error::invalid_input(format!("Path does not exist: {}", canonical_path.display())));
        }

        // Check for blocked paths (only if they exist)
        for blocked in &self.blocked_paths {
            if blocked.exists() && canonical_path.starts_with(blocked) {
                return Err(Error::invalid_input(format!("Access denied to path: {}", canonical_path.display())));
            }
        }

        // Check for suspicious path components (but allow hidden directories in temp paths)
        let path_str = canonical_path.to_string_lossy();
        if !path_str.contains("/tmp/") && !path_str.contains("\\Temp\\") {
            for component in canonical_path.components() {
                let component_str = component.as_os_str().to_string_lossy();
                if component_str.contains("..") {
                    return Err(Error::invalid_input(format!("Suspicious path component: {}", component_str)));
                }
            }
        }

        Ok(canonical_path)
    }

    /// Validate a directory path
    pub fn validate_directory<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf> {
        let validated_path = self.validate_path(path)?;
        
        if !validated_path.is_dir() {
            return Err(Error::invalid_input(format!("Path is not a directory: {}", validated_path.display())));
        }

        Ok(validated_path)
    }

    /// Validate a file path
    pub fn validate_file<P: AsRef<Path>>(&self, path: P) -> Result<PathBuf> {
        let validated_path = self.validate_path(path)?;
        
        if !validated_path.is_file() {
            return Err(Error::invalid_input(format!("Path is not a file: {}", validated_path.display())));
        }

        // Check file extension
        if let Some(extension) = validated_path.extension() {
            let ext_str = extension.to_string_lossy().to_lowercase();
            if !self.allowed_extensions.contains(&ext_str) {
                return Err(Error::invalid_input(format!("Unsupported file extension: {}", ext_str)));
            }
        }

        // Check file size
        let metadata = validated_path.metadata()
            .map_err(|e| Error::file_system(format!("Cannot read file metadata: {}", e)))?;
        
        if metadata.len() > MAX_FILE_SIZE as u64 {
            return Err(Error::invalid_input(format!("File too large: {} bytes (max: {} bytes)", 
                metadata.len(), MAX_FILE_SIZE)));
        }

        Ok(validated_path)
    }

    /// Validate output format
    pub fn validate_format(&self, format: &str) -> Result<String> {
        let format_lower = format.to_lowercase();
        if !SUPPORTED_FORMATS.contains(&format_lower.as_str()) {
            return Err(Error::invalid_input(format!(
                "Unsupported format '{}'. Supported formats: {}", 
                format, SUPPORTED_FORMATS.join(", ")
            )));
        }
        Ok(format_lower)
    }

    /// Validate language
    pub fn validate_language(&self, language: &str) -> Result<String> {
        let language_lower = language.to_lowercase();
        if !SUPPORTED_LANGUAGES.contains(&language_lower.as_str()) {
            return Err(Error::invalid_input(format!(
                "Unsupported language '{}'. Supported languages: {}", 
                language, SUPPORTED_LANGUAGES.join(", ")
            )));
        }
        Ok(language_lower)
    }

    /// Validate security severity level
    pub fn validate_severity(&self, severity: &str) -> Result<String> {
        let severity_lower = severity.to_lowercase();
        if !SUPPORTED_SEVERITIES.contains(&severity_lower.as_str()) {
            return Err(Error::invalid_input(format!(
                "Unsupported severity '{}'. Supported severities: {}", 
                severity, SUPPORTED_SEVERITIES.join(", ")
            )));
        }
        Ok(severity_lower)
    }

    /// Validate refactoring category
    pub fn validate_refactor_category(&self, category: &str) -> Result<String> {
        let category_lower = category.to_lowercase();
        if !SUPPORTED_REFACTOR_CATEGORIES.contains(&category_lower.as_str()) {
            return Err(Error::invalid_input(format!(
                "Unsupported refactoring category '{}'. Supported categories: {}", 
                category, SUPPORTED_REFACTOR_CATEGORIES.join(", ")
            )));
        }
        Ok(category_lower)
    }

    /// Validate performance category
    pub fn validate_performance_category(&self, category: &str) -> Result<String> {
        let category_lower = category.to_lowercase();
        if !SUPPORTED_PERFORMANCE_CATEGORIES.contains(&category_lower.as_str()) {
            return Err(Error::invalid_input(format!(
                "Unsupported performance category '{}'. Supported categories: {}", 
                category, SUPPORTED_PERFORMANCE_CATEGORIES.join(", ")
            )));
        }
        Ok(category_lower)
    }

    /// Validate tree-sitter query pattern
    pub fn validate_query_pattern(&self, pattern: &str) -> Result<String> {
        if pattern.is_empty() {
            return Err(Error::invalid_input("Query pattern cannot be empty".to_string()));
        }

        if pattern.len() > MAX_PATTERN_LENGTH {
            return Err(Error::invalid_input(format!(
                "Query pattern too long: {} characters (max: {})", 
                pattern.len(), MAX_PATTERN_LENGTH
            )));
        }

        // Basic syntax validation - check for balanced parentheses
        let mut paren_count = 0;
        let mut bracket_count = 0;
        
        for ch in pattern.chars() {
            match ch {
                '(' => paren_count += 1,
                ')' => {
                    paren_count -= 1;
                    if paren_count < 0 {
                        return Err(Error::invalid_input("Unmatched closing parenthesis in query pattern".to_string()));
                    }
                }
                '[' => bracket_count += 1,
                ']' => {
                    bracket_count -= 1;
                    if bracket_count < 0 {
                        return Err(Error::invalid_input("Unmatched closing bracket in query pattern".to_string()));
                    }
                }
                _ => {}
            }
        }

        if paren_count != 0 {
            return Err(Error::invalid_input("Unmatched parentheses in query pattern".to_string()));
        }

        if bracket_count != 0 {
            return Err(Error::invalid_input("Unmatched brackets in query pattern".to_string()));
        }

        Ok(pattern.to_string())
    }

    /// Validate numeric range
    pub fn validate_range(&self, value: usize, min: usize, max: usize, name: &str) -> Result<usize> {
        if value < min || value > max {
            return Err(Error::invalid_input(format!(
                "{} must be between {} and {}, got {}", 
                name, min, max, value
            )));
        }
        Ok(value)
    }

    /// Validate timeout value
    pub fn validate_timeout(&self, timeout_ms: u64) -> Result<u64> {
        if timeout_ms == 0 {
            return Err(Error::invalid_input("Timeout must be greater than 0".to_string()));
        }
        
        if timeout_ms > MAX_TIMEOUT_MS {
            return Err(Error::invalid_input(format!(
                "Timeout too large: {}ms (max: {}ms)", 
                timeout_ms, MAX_TIMEOUT_MS
            )));
        }
        
        Ok(timeout_ms)
    }

    /// Validate percentage value
    pub fn validate_percentage(&self, value: f64, name: &str) -> Result<f64> {
        if value < 0.0 || value > 100.0 {
            return Err(Error::invalid_input(format!(
                "{} must be between 0.0 and 100.0, got {}", 
                name, value
            )));
        }
        Ok(value)
    }

    /// Sanitize string input by removing potentially dangerous characters
    pub fn sanitize_string(&self, input: &str) -> String {
        input
            .chars()
            .filter(|&c| c.is_alphanumeric() || " -_.,()[]{}:;".contains(c))
            .collect()
    }

    /// Validate and sanitize symbol name
    pub fn validate_symbol_name(&self, name: &str) -> Result<String> {
        if name.is_empty() {
            return Err(Error::invalid_input("Symbol name cannot be empty".to_string()));
        }

        if name.len() > 1000 {
            return Err(Error::invalid_input("Symbol name too long".to_string()));
        }

        // Allow alphanumeric, underscore, and common programming symbols
        let sanitized: String = name
            .chars()
            .filter(|&c| c.is_alphanumeric() || "_:.*?[]{}()".contains(c))
            .collect();

        if sanitized.is_empty() {
            return Err(Error::invalid_input("Symbol name contains no valid characters".to_string()));
        }

        Ok(sanitized)
    }
}

impl Default for InputValidator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_validate_format() {
        let validator = InputValidator::new();

        assert!(validator.validate_format("json").is_ok());
        assert!(validator.validate_format("JSON").is_ok());
        assert!(validator.validate_format("table").is_ok());
        assert!(validator.validate_format("markdown").is_ok());

        assert!(validator.validate_format("invalid").is_err());
        assert!(validator.validate_format("").is_err());
    }

    #[test]
    fn test_validate_language() {
        let validator = InputValidator::new();

        assert!(validator.validate_language("rust").is_ok());
        assert!(validator.validate_language("RUST").is_ok());
        assert!(validator.validate_language("javascript").is_ok());
        assert!(validator.validate_language("python").is_ok());

        assert!(validator.validate_language("invalid").is_err());
        assert!(validator.validate_language("").is_err());
    }

    #[test]
    fn test_validate_severity() {
        let validator = InputValidator::new();

        assert!(validator.validate_severity("critical").is_ok());
        assert!(validator.validate_severity("HIGH").is_ok());
        assert!(validator.validate_severity("medium").is_ok());
        assert!(validator.validate_severity("low").is_ok());
        assert!(validator.validate_severity("info").is_ok());

        assert!(validator.validate_severity("invalid").is_err());
        assert!(validator.validate_severity("").is_err());
    }

    #[test]
    fn test_validate_query_pattern() {
        let validator = InputValidator::new();

        assert!(validator.validate_query_pattern("(function_item)").is_ok());
        assert!(validator.validate_query_pattern("(function_item name: (identifier) @name)").is_ok());
        assert!(validator.validate_query_pattern("[\"function\"]").is_ok());

        assert!(validator.validate_query_pattern("").is_err());
        assert!(validator.validate_query_pattern("(unmatched").is_err());
        assert!(validator.validate_query_pattern("unmatched)").is_err());
        assert!(validator.validate_query_pattern("[unmatched").is_err());
        assert!(validator.validate_query_pattern("unmatched]").is_err());

        // Test pattern too long
        let long_pattern = "a".repeat(MAX_PATTERN_LENGTH + 1);
        assert!(validator.validate_query_pattern(&long_pattern).is_err());
    }

    #[test]
    fn test_validate_range() {
        let validator = InputValidator::new();

        assert!(validator.validate_range(5, 1, 10, "test").is_ok());
        assert!(validator.validate_range(1, 1, 10, "test").is_ok());
        assert!(validator.validate_range(10, 1, 10, "test").is_ok());

        assert!(validator.validate_range(0, 1, 10, "test").is_err());
        assert!(validator.validate_range(11, 1, 10, "test").is_err());
    }

    #[test]
    fn test_validate_timeout() {
        let validator = InputValidator::new();

        assert!(validator.validate_timeout(1000).is_ok());
        assert!(validator.validate_timeout(MAX_TIMEOUT_MS).is_ok());

        assert!(validator.validate_timeout(0).is_err());
        assert!(validator.validate_timeout(MAX_TIMEOUT_MS + 1).is_err());
    }

    #[test]
    fn test_validate_percentage() {
        let validator = InputValidator::new();

        assert!(validator.validate_percentage(0.0, "test").is_ok());
        assert!(validator.validate_percentage(50.5, "test").is_ok());
        assert!(validator.validate_percentage(100.0, "test").is_ok());

        assert!(validator.validate_percentage(-0.1, "test").is_err());
        assert!(validator.validate_percentage(100.1, "test").is_err());
    }

    #[test]
    fn test_sanitize_string() {
        let validator = InputValidator::new();

        assert_eq!(validator.sanitize_string("hello world"), "hello world");
        assert_eq!(validator.sanitize_string("test_function()"), "test_function()");
        assert_eq!(validator.sanitize_string("hello<script>alert('xss')</script>"), "helloscriptalert(xss)script");
        assert_eq!(validator.sanitize_string("test\x00null\x01byte"), "testnullbyte");
    }

    #[test]
    fn test_validate_symbol_name() {
        let validator = InputValidator::new();

        assert!(validator.validate_symbol_name("function_name").is_ok());
        assert!(validator.validate_symbol_name("Class::method").is_ok());
        assert!(validator.validate_symbol_name("*pattern*").is_ok());
        assert!(validator.validate_symbol_name("test[0]").is_ok());

        assert!(validator.validate_symbol_name("").is_err());

        let long_name = "a".repeat(1001);
        assert!(validator.validate_symbol_name(&long_name).is_err());
    }

    #[test]
    fn test_validate_directory() {
        let validator = InputValidator::new();
        let temp_dir = TempDir::new().unwrap();

        // Valid directory
        assert!(validator.validate_directory(temp_dir.path()).is_ok());

        // Non-existent directory
        let non_existent = temp_dir.path().join("non_existent");
        assert!(validator.validate_directory(&non_existent).is_err());

        // File instead of directory
        let file_path = temp_dir.path().join("test.txt");
        fs::write(&file_path, "test content").unwrap();
        assert!(validator.validate_directory(&file_path).is_err());
    }

    #[test]
    fn test_validate_file() {
        let validator = InputValidator::new();
        let temp_dir = TempDir::new().unwrap();

        // Valid file
        let file_path = temp_dir.path().join("test.rs");
        fs::write(&file_path, "fn main() {}").unwrap();
        assert!(validator.validate_file(&file_path).is_ok());

        // Non-existent file
        let non_existent = temp_dir.path().join("non_existent.rs");
        assert!(validator.validate_file(&non_existent).is_err());

        // Directory instead of file
        assert!(validator.validate_file(temp_dir.path()).is_err());

        // Unsupported extension
        let unsupported_file = temp_dir.path().join("test.exe");
        fs::write(&unsupported_file, "binary content").unwrap();
        assert!(validator.validate_file(&unsupported_file).is_err());
    }

    #[test]
    fn test_validate_refactor_category() {
        let validator = InputValidator::new();

        assert!(validator.validate_refactor_category("complexity").is_ok());
        assert!(validator.validate_refactor_category("DUPLICATION").is_ok());
        assert!(validator.validate_refactor_category("naming").is_ok());
        assert!(validator.validate_refactor_category("performance").is_ok());
        assert!(validator.validate_refactor_category("architecture").is_ok());

        assert!(validator.validate_refactor_category("invalid").is_err());
        assert!(validator.validate_refactor_category("").is_err());
    }

    #[test]
    fn test_validate_performance_category() {
        let validator = InputValidator::new();

        assert!(validator.validate_performance_category("complexity").is_ok());
        assert!(validator.validate_performance_category("MEMORY").is_ok());
        assert!(validator.validate_performance_category("cpu").is_ok());
        assert!(validator.validate_performance_category("io").is_ok());

        assert!(validator.validate_performance_category("invalid").is_err());
        assert!(validator.validate_performance_category("").is_err());
    }
}
