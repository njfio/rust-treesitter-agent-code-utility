//! Enhanced error handling and recovery mechanisms
//!
//! This module provides comprehensive error handling, recovery strategies,
//! and context propagation for robust operation in production environments.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use std::fs;
use std::time::{Duration, Instant};
use std::collections::HashMap;

/// Error recovery strategy for different types of failures
#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryStrategy {
    /// Skip the failed operation and continue
    Skip,
    /// Retry the operation with exponential backoff
    Retry { max_attempts: u32, base_delay: Duration },
    /// Use a fallback approach
    Fallback,
    /// Fail fast and propagate the error
    FailFast,
}

/// Context information for error reporting and debugging
#[derive(Debug, Clone)]
pub struct ErrorContext {
    pub operation: String,
    pub file_path: Option<PathBuf>,
    pub line_number: Option<usize>,
    pub additional_info: HashMap<String, String>,
    pub timestamp: Instant,
}

impl ErrorContext {
    pub fn new(operation: impl Into<String>) -> Self {
        Self {
            operation: operation.into(),
            file_path: None,
            line_number: None,
            additional_info: HashMap::new(),
            timestamp: Instant::now(),
        }
    }

    pub fn with_file<P: AsRef<Path>>(mut self, path: P) -> Self {
        self.file_path = Some(path.as_ref().to_path_buf());
        self
    }

    pub fn with_line(mut self, line: usize) -> Self {
        self.line_number = Some(line);
        self
    }

    pub fn with_info(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.additional_info.insert(key.into(), value.into());
        self
    }
}

/// Enhanced error handler with recovery capabilities
pub struct ErrorHandler {
    recovery_strategies: HashMap<String, RecoveryStrategy>,
    error_counts: HashMap<String, u32>,
    max_errors_per_operation: u32,
}

impl ErrorHandler {
    /// Create a new error handler with default recovery strategies
    pub fn new() -> Self {
        let mut recovery_strategies = HashMap::new();
        
        // Default recovery strategies for common operations
        recovery_strategies.insert("file_read".to_string(), RecoveryStrategy::Retry {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
        });
        recovery_strategies.insert("file_write".to_string(), RecoveryStrategy::Retry {
            max_attempts: 3,
            base_delay: Duration::from_millis(100),
        });
        recovery_strategies.insert("parse".to_string(), RecoveryStrategy::Skip);
        recovery_strategies.insert("network".to_string(), RecoveryStrategy::Retry {
            max_attempts: 5,
            base_delay: Duration::from_millis(500),
        });
        recovery_strategies.insert("critical".to_string(), RecoveryStrategy::FailFast);

        Self {
            recovery_strategies,
            error_counts: HashMap::new(),
            max_errors_per_operation: 10,
        }
    }

    /// Set recovery strategy for a specific operation type
    pub fn set_recovery_strategy(&mut self, operation: impl Into<String>, strategy: RecoveryStrategy) {
        self.recovery_strategies.insert(operation.into(), strategy);
    }

    /// Handle an error with appropriate recovery strategy
    pub fn handle_error(&mut self, error: Error, context: ErrorContext) -> Result<()> {
        let operation_key = context.operation.clone();
        
        // Increment error count for this operation
        let error_count = self.error_counts.entry(operation_key.clone()).or_insert(0);
        *error_count += 1;

        // Check if we've exceeded the maximum error count
        if *error_count > self.max_errors_per_operation {
            return Err(Error::internal(format!(
                "Too many errors for operation '{}': {} errors exceeded limit of {}",
                operation_key, error_count, self.max_errors_per_operation
            )));
        }

        // Get recovery strategy for this operation
        let strategy = self.recovery_strategies
            .get(&operation_key)
            .cloned()
            .unwrap_or(RecoveryStrategy::FailFast);

        match strategy {
            RecoveryStrategy::Skip => {
                eprintln!("Warning: Skipping failed operation '{}': {}", operation_key, error);
                Ok(())
            }
            RecoveryStrategy::Retry { max_attempts, base_delay } => {
                if *error_count <= max_attempts {
                    let delay = base_delay * 2_u32.pow(*error_count - 1);
                    eprintln!("Info: Retrying operation '{}' in {:?} (attempt {})", operation_key, delay, error_count);
                    std::thread::sleep(delay);
                    Ok(())
                } else {
                    Err(Error::internal(format!(
                        "Operation '{}' failed after {} attempts: {}",
                        operation_key, max_attempts, error
                    )))
                }
            }
            RecoveryStrategy::Fallback => {
                eprintln!("Warning: Using fallback for operation '{}': {}", operation_key, error);
                Ok(())
            }
            RecoveryStrategy::FailFast => {
                Err(error)
            }
        }
    }

    /// Reset error count for a specific operation
    pub fn reset_error_count(&mut self, operation: &str) {
        self.error_counts.remove(operation);
    }

    /// Get error statistics
    pub fn get_error_stats(&self) -> HashMap<String, u32> {
        self.error_counts.clone()
    }
}

/// Safe file operations with enhanced error handling
pub struct SafeFileOperations {
    error_handler: ErrorHandler,
}

impl SafeFileOperations {
    pub fn new() -> Self {
        Self {
            error_handler: ErrorHandler::new(),
        }
    }

    /// Safely read a file with error recovery
    pub fn read_file<P: AsRef<Path>>(&mut self, path: P) -> Result<String> {
        let path = path.as_ref();
        let context = ErrorContext::new("file_read").with_file(path);

        loop {
            match fs::read_to_string(path) {
                Ok(content) => {
                    self.error_handler.reset_error_count("file_read");
                    return Ok(content);
                }
                Err(e) => {
                    let error = Error::file_system(format!("Failed to read file '{}': {}", path.display(), e));
                    
                    match self.error_handler.handle_error(error, context.clone()) {
                        Ok(()) => continue, // Retry
                        Err(final_error) => return Err(final_error),
                    }
                }
            }
        }
    }

    /// Safely write to a file with error recovery
    pub fn write_file<P: AsRef<Path>>(&mut self, path: P, content: &str) -> Result<()> {
        let path = path.as_ref();
        let context = ErrorContext::new("file_write").with_file(path);

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .map_err(|e| Error::file_system(format!("Failed to create directory '{}': {}", parent.display(), e)))?;
            }
        }

        loop {
            match fs::write(path, content) {
                Ok(()) => {
                    self.error_handler.reset_error_count("file_write");
                    return Ok(());
                }
                Err(e) => {
                    let error = Error::file_system(format!("Failed to write file '{}': {}", path.display(), e));
                    
                    match self.error_handler.handle_error(error, context.clone()) {
                        Ok(()) => continue, // Retry
                        Err(final_error) => return Err(final_error),
                    }
                }
            }
        }
    }

    /// Safely check if a file exists
    pub fn file_exists<P: AsRef<Path>>(&self, path: P) -> bool {
        path.as_ref().exists()
    }

    /// Safely get file metadata
    pub fn get_metadata<P: AsRef<Path>>(&mut self, path: P) -> Result<fs::Metadata> {
        let path = path.as_ref();
        let context = ErrorContext::new("metadata_read").with_file(path);

        match fs::metadata(path) {
            Ok(metadata) => Ok(metadata),
            Err(e) => {
                let error = Error::file_system(format!("Failed to read metadata for '{}': {}", path.display(), e));
                match self.error_handler.handle_error(error, context) {
                    Ok(()) => {
                        // For metadata operations, we don't retry, just return a default error
                        Err(Error::file_system(format!("Metadata unavailable for '{}'", path.display())))
                    }
                    Err(final_error) => Err(final_error),
                }
            }
        }
    }

    /// Safely list directory contents
    pub fn list_directory<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<PathBuf>> {
        let path = path.as_ref();
        let context = ErrorContext::new("directory_list").with_file(path);

        loop {
            match fs::read_dir(path) {
                Ok(entries) => {
                    let mut paths = Vec::new();
                    for entry in entries {
                        match entry {
                            Ok(entry) => paths.push(entry.path()),
                            Err(e) => {
                                eprintln!("Warning: Failed to read directory entry in '{}': {}", path.display(), e);
                                // Continue with other entries
                            }
                        }
                    }
                    self.error_handler.reset_error_count("directory_list");
                    return Ok(paths);
                }
                Err(e) => {
                    let error = Error::file_system(format!("Failed to list directory '{}': {}", path.display(), e));
                    
                    match self.error_handler.handle_error(error, context.clone()) {
                        Ok(()) => continue, // Retry
                        Err(final_error) => return Err(final_error),
                    }
                }
            }
        }
    }
}

impl Default for ErrorHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for SafeFileOperations {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_error_context_creation() {
        let context = ErrorContext::new("test_operation")
            .with_file("/test/path")
            .with_line(42)
            .with_info("key", "value");

        assert_eq!(context.operation, "test_operation");
        assert_eq!(context.file_path, Some(PathBuf::from("/test/path")));
        assert_eq!(context.line_number, Some(42));
        assert_eq!(context.additional_info.get("key"), Some(&"value".to_string()));
    }

    #[test]
    fn test_error_handler_creation() {
        let handler = ErrorHandler::new();
        assert!(handler.recovery_strategies.contains_key("file_read"));
        assert!(handler.recovery_strategies.contains_key("parse"));
        assert_eq!(handler.error_counts.len(), 0);
    }

    #[test]
    fn test_recovery_strategy_setting() {
        let mut handler = ErrorHandler::new();
        handler.set_recovery_strategy("custom_op", RecoveryStrategy::Skip);

        assert_eq!(
            handler.recovery_strategies.get("custom_op"),
            Some(&RecoveryStrategy::Skip)
        );
    }

    #[test]
    fn test_skip_recovery_strategy() {
        let mut handler = ErrorHandler::new();
        handler.set_recovery_strategy("test_op", RecoveryStrategy::Skip);

        let error = Error::internal("test error");
        let context = ErrorContext::new("test_op");

        let result = handler.handle_error(error, context);
        assert!(result.is_ok());
        assert_eq!(handler.error_counts.get("test_op"), Some(&1));
    }

    #[test]
    fn test_fail_fast_recovery_strategy() {
        let mut handler = ErrorHandler::new();
        handler.set_recovery_strategy("test_op", RecoveryStrategy::FailFast);

        let error = Error::internal("test error");
        let context = ErrorContext::new("test_op");

        let result = handler.handle_error(error, context);
        assert!(result.is_err());
    }

    #[test]
    fn test_max_errors_exceeded() {
        let mut handler = ErrorHandler::new();
        handler.max_errors_per_operation = 2;
        handler.set_recovery_strategy("test_op", RecoveryStrategy::Skip);

        let context = ErrorContext::new("test_op");

        // First two errors should be handled
        for _ in 0..2 {
            let error = Error::internal("test error");
            let result = handler.handle_error(error, context.clone());
            assert!(result.is_ok());
        }

        // Third error should exceed the limit
        let error = Error::internal("test error");
        let result = handler.handle_error(error, context);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Too many errors"));
    }

    #[test]
    fn test_error_count_reset() {
        let mut handler = ErrorHandler::new();
        handler.set_recovery_strategy("test_op", RecoveryStrategy::Skip);

        let error = Error::internal("test error");
        let context = ErrorContext::new("test_op");

        let _ = handler.handle_error(error, context);
        assert_eq!(handler.error_counts.get("test_op"), Some(&1));

        handler.reset_error_count("test_op");
        assert_eq!(handler.error_counts.get("test_op"), None);
    }

    #[test]
    fn test_safe_file_operations_read_success() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let content = "Hello, world!";

        fs::write(&file_path, content).unwrap();

        let mut safe_ops = SafeFileOperations::new();
        let result = safe_ops.read_file(&file_path);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), content);
    }

    #[test]
    fn test_safe_file_operations_read_nonexistent() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("nonexistent.txt");

        let mut safe_ops = SafeFileOperations::new();
        let result = safe_ops.read_file(&file_path);

        assert!(result.is_err());
    }

    #[test]
    fn test_safe_file_operations_write_success() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let content = "Hello, world!";

        let mut safe_ops = SafeFileOperations::new();
        let result = safe_ops.write_file(&file_path, content);

        assert!(result.is_ok());
        assert!(file_path.exists());

        let read_content = fs::read_to_string(&file_path).unwrap();
        assert_eq!(read_content, content);
    }

    #[test]
    fn test_safe_file_operations_write_with_directory_creation() {
        let temp_dir = TempDir::new().unwrap();
        let nested_path = temp_dir.path().join("nested").join("directory").join("test.txt");
        let content = "Hello, world!";

        let mut safe_ops = SafeFileOperations::new();
        let result = safe_ops.write_file(&nested_path, content);

        assert!(result.is_ok());
        assert!(nested_path.exists());

        let read_content = fs::read_to_string(&nested_path).unwrap();
        assert_eq!(read_content, content);
    }

    #[test]
    fn test_safe_file_operations_file_exists() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");

        let safe_ops = SafeFileOperations::new();
        assert!(!safe_ops.file_exists(&file_path));

        fs::write(&file_path, "content").unwrap();
        assert!(safe_ops.file_exists(&file_path));
    }

    #[test]
    fn test_safe_file_operations_get_metadata() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.txt");
        let content = "Hello, world!";

        fs::write(&file_path, content).unwrap();

        let mut safe_ops = SafeFileOperations::new();
        let result = safe_ops.get_metadata(&file_path);

        assert!(result.is_ok());
        let metadata = result.unwrap();
        assert_eq!(metadata.len(), content.len() as u64);
    }

    #[test]
    fn test_safe_file_operations_list_directory() {
        let temp_dir = TempDir::new().unwrap();
        let file1 = temp_dir.path().join("file1.txt");
        let file2 = temp_dir.path().join("file2.txt");

        fs::write(&file1, "content1").unwrap();
        fs::write(&file2, "content2").unwrap();

        let mut safe_ops = SafeFileOperations::new();
        let result = safe_ops.list_directory(temp_dir.path());

        assert!(result.is_ok());
        let paths = result.unwrap();
        assert_eq!(paths.len(), 2);
        assert!(paths.contains(&file1));
        assert!(paths.contains(&file2));
    }

    #[test]
    fn test_error_stats() {
        let mut handler = ErrorHandler::new();
        handler.set_recovery_strategy("test_op", RecoveryStrategy::Skip);

        let error = Error::internal("test error");
        let context = ErrorContext::new("test_op");

        let _ = handler.handle_error(error, context);

        let stats = handler.get_error_stats();
        assert_eq!(stats.get("test_op"), Some(&1));
    }
}
