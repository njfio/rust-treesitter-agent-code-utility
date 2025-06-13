//! Error handling utilities and patterns for the rust_tree_sitter library
//! 
//! This module provides utilities to systematically replace unwrap() calls
//! with proper error handling patterns.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};

/// Extension trait for Option<T> to provide better error handling
pub trait OptionExt<T> {
    /// Convert Option to Result with a custom error message
    fn ok_or_error<S: Into<String>>(self, msg: S) -> Result<T>;
    
    /// Convert Option to Result with an invalid input error
    fn ok_or_invalid_input<S: Into<String>>(self, msg: S) -> Result<T>;
    
    /// Convert Option to Result with an internal error
    fn ok_or_internal<S: Into<String>>(self, msg: S) -> Result<T>;
}

impl<T> OptionExt<T> for Option<T> {
    fn ok_or_error<S: Into<String>>(self, msg: S) -> Result<T> {
        self.ok_or_else(|| Error::internal(msg))
    }
    
    fn ok_or_invalid_input<S: Into<String>>(self, msg: S) -> Result<T> {
        self.ok_or_else(|| Error::invalid_input(msg))
    }
    
    fn ok_or_internal<S: Into<String>>(self, msg: S) -> Result<T> {
        self.ok_or_else(|| Error::internal(msg))
    }
}

/// Extension trait for Result<T, E> to provide better error context
pub trait ResultExt<T, E> {
    /// Add context to an error
    fn with_context<S: Into<String>>(self, context: S) -> Result<T>;
    
    /// Add context with a closure for lazy evaluation
    fn with_context_lazy<F, S>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> S,
        S: Into<String>;
}

impl<T, E: std::fmt::Display> ResultExt<T, E> for std::result::Result<T, E> {
    fn with_context<S: Into<String>>(self, context: S) -> Result<T> {
        self.map_err(|e| Error::internal(format!("{}: {}", context.into(), e)))
    }
    
    fn with_context_lazy<F, S>(self, f: F) -> Result<T>
    where
        F: FnOnce() -> S,
        S: Into<String>,
    {
        self.map_err(|e| Error::internal(format!("{}: {}", f().into(), e)))
    }
}

/// Path validation utilities
pub struct PathValidator;

impl PathValidator {
    /// Validate that a path exists and is readable
    pub fn validate_readable_path<P: AsRef<Path>>(path: P) -> Result<PathBuf> {
        let path = path.as_ref();
        
        if !path.exists() {
            return Err(Error::invalid_path(format!("Path does not exist: {}", path.display())));
        }
        
        // Check if we can read the path
        match std::fs::metadata(path) {
            Ok(metadata) => {
                if metadata.is_dir() {
                    // For directories, try to read the directory
                    std::fs::read_dir(path)
                        .map_err(|e| Error::file_system(format!("Cannot read directory {}: {}", path.display(), e)))?;
                } else {
                    // For files, try to read the file
                    std::fs::File::open(path)
                        .map_err(|e| Error::file_system(format!("Cannot read file {}: {}", path.display(), e)))?;
                }
                Ok(path.to_path_buf())
            }
            Err(e) => Err(Error::file_system(format!("Cannot access path {}: {}", path.display(), e))),
        }
    }
    
    /// Validate that a path is safe (no directory traversal)
    pub fn validate_safe_path<P: AsRef<Path>>(path: P, base: P) -> Result<PathBuf> {
        let path = path.as_ref();
        let base = base.as_ref();
        
        let canonical_path = path.canonicalize()
            .map_err(|e| Error::invalid_path(format!("Cannot canonicalize path {}: {}", path.display(), e)))?;
            
        let canonical_base = base.canonicalize()
            .map_err(|e| Error::invalid_path(format!("Cannot canonicalize base path {}: {}", base.display(), e)))?;
        
        if !canonical_path.starts_with(&canonical_base) {
            return Err(Error::security(format!(
                "Path {} is outside of allowed base directory {}", 
                path.display(), 
                base.display()
            )));
        }
        
        Ok(canonical_path)
    }
    
    /// Validate file size limits
    pub fn validate_file_size<P: AsRef<Path>>(path: P, max_size: u64) -> Result<u64> {
        let path = path.as_ref();
        let metadata = std::fs::metadata(path)
            .map_err(|e| Error::file_system(format!("Cannot get file metadata for {}: {}", path.display(), e)))?;
            
        let size = metadata.len();
        if size > max_size {
            return Err(Error::resource_limit(format!(
                "File {} is too large: {} bytes (max: {} bytes)",
                path.display(),
                size,
                max_size
            )));
        }
        
        Ok(size)
    }
}

/// Safe string operations
pub struct SafeString;

impl SafeString {
    /// Safely convert bytes to UTF-8 string
    pub fn from_utf8_safe(bytes: &[u8]) -> Result<&str> {
        std::str::from_utf8(bytes)
            .map_err(|e| Error::invalid_input(format!("Invalid UTF-8 sequence: {}", e)))
    }
    
    /// Safely parse a string to a number
    pub fn parse_number<T: std::str::FromStr>(s: &str) -> Result<T>
    where
        T::Err: std::fmt::Display,
    {
        s.parse()
            .map_err(|e| Error::invalid_input(format!("Cannot parse '{}' as number: {}", s, e)))
    }
    
    /// Safely truncate a string to a maximum length
    pub fn truncate_safe(s: &str, max_len: usize) -> String {
        if s.len() <= max_len {
            s.to_string()
        } else {
            format!("{}...", &s[..max_len.saturating_sub(3)])
        }
    }
}

/// Collection utilities with bounds checking
pub struct SafeCollection;

impl SafeCollection {
    /// Safely get an element from a vector
    pub fn get_safe<T>(vec: &[T], index: usize) -> Result<&T> {
        vec.get(index)
            .ok_or_else(|| Error::invalid_input(format!("Index {} out of bounds for collection of length {}", index, vec.len())))
    }
    
    /// Safely get a mutable element from a vector
    pub fn get_mut_safe<T>(vec: &mut [T], index: usize) -> Result<&mut T> {
        let len = vec.len();
        vec.get_mut(index)
            .ok_or_else(|| Error::invalid_input(format!("Index {} out of bounds for collection of length {}", index, len)))
    }
    
    /// Safely pop from a vector
    pub fn pop_safe<T>(vec: &mut Vec<T>) -> Result<T> {
        vec.pop()
            .ok_or_else(|| Error::invalid_input("Cannot pop from empty vector"))
    }
}

/// Timeout utilities
pub struct TimeoutHandler;

impl TimeoutHandler {
    /// Create a timeout error with context
    pub fn timeout_error<S: Into<String>>(operation: S, duration: std::time::Duration) -> Error {
        Error::timeout(format!("Operation '{}' timed out after {:?}", operation.into(), duration))
    }
    
    /// Check if an operation should timeout
    pub fn check_timeout(start: std::time::Instant, timeout: std::time::Duration, operation: &str) -> Result<()> {
        if start.elapsed() > timeout {
            Err(Self::timeout_error(operation, timeout))
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_option_ext() {
        let some_value: Option<i32> = Some(42);
        let none_value: Option<i32> = None;
        
        assert!(some_value.ok_or_error("test").is_ok());
        assert!(none_value.ok_or_error("test").is_err());
    }

    #[test]
    fn test_path_validator() {
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        
        // Test valid path
        assert!(PathValidator::validate_readable_path(temp_path).is_ok());
        
        // Test invalid path
        let invalid_path = temp_path.join("nonexistent");
        assert!(PathValidator::validate_readable_path(&invalid_path).is_err());
    }

    #[test]
    fn test_safe_string() {
        assert!(SafeString::from_utf8_safe(b"hello").is_ok());
        assert!(SafeString::from_utf8_safe(&[0xFF, 0xFE]).is_err());
        
        assert_eq!(SafeString::parse_number::<i32>("42").unwrap(), 42);
        assert!(SafeString::parse_number::<i32>("not_a_number").is_err());
    }

    #[test]
    fn test_safe_collection() {
        let vec = vec![1, 2, 3];
        assert_eq!(*SafeCollection::get_safe(&vec, 1).unwrap(), 2);
        assert!(SafeCollection::get_safe(&vec, 10).is_err());
    }
}
