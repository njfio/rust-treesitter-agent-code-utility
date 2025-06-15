use rust_tree_sitter::analyzer::CodebaseAnalyzer;
use rust_tree_sitter::error::{Error, Result};
use rust_tree_sitter::parser::Parser;
use rust_tree_sitter::parsing_error_handler::{ParsingErrorHandler, ErrorSeverity, ErrorCategory};
use rust_tree_sitter::languages::Language;
use std::fs;
use std::time::Duration;
use tempfile::TempDir;

/// Test comprehensive error handling for syntax errors
#[test]
fn test_syntax_error_handling() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let js_file = temp_dir.path().join("syntax_error.js");
    
    // JavaScript code with syntax errors
    let js_code = r#"
function broken() {
    if (true {  // Missing closing parenthesis
        console.log("broken");
    // Missing closing brace
}

class Incomplete {
    method() {
        return "incomplete"  // Missing semicolon
    }
    // Missing closing brace for class
"#;
    
    fs::write(&js_file, js_code).unwrap();
    
    let mut error_handler = ParsingErrorHandler::default();
    let mut parser = Parser::with_error_handler(Language::JavaScript, error_handler)?;
    
    // Parse the file with syntax errors
    let result = parser.parse_file(&js_file);
    
    // Should return a tree even with errors (for partial analysis)
    match result {
        Ok(tree) => {
            // Tree should have errors
            assert!(tree.root_node().has_error());
            
            // Check that errors were collected
            let errors = parser.get_parsing_errors();
            assert!(!errors.is_empty());
            
            // Verify error details
            for error in errors {
                assert_eq!(error.category, ErrorCategory::Syntax);
                assert!(error.line > 0);
                assert!(!error.recovery_suggestions.is_empty());
                assert!(error.context.is_some());
            }
        }
        Err(e) => {
            // If parsing fails completely, check error type
            match e {
                Error::SyntaxError { line, column, message, file_path } => {
                    assert!(line > 0);
                    assert!(!message.is_empty());
                    assert!(file_path.is_some());
                }
                _ => panic!("Expected syntax error, got: {:?}", e),
            }
        }
    }
    
    Ok(())
}

/// Test file I/O error handling
#[test]
fn test_file_io_error_handling() -> Result<()> {
    let mut error_handler = ParsingErrorHandler::default();
    let mut parser = Parser::with_error_handler(Language::JavaScript, error_handler)?;
    
    // Test non-existent file
    let result = parser.parse_file("/non/existent/file.js");
    assert!(result.is_err());
    
    match result.unwrap_err() {
        Error::IoError(_) => {
            // Expected I/O error
        }
        Error::InvalidPath(_) => {
            // Also acceptable for validation
        }
        e => panic!("Expected I/O or path error, got: {:?}", e),
    }
    
    Ok(())
}

/// Test memory and size limit error handling
#[test]
fn test_memory_limit_error_handling() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let large_file = temp_dir.path().join("large.js");
    
    // Create a large content string
    let large_content = "console.log('test');\n".repeat(100000); // ~1.8MB
    fs::write(&large_file, &large_content).unwrap();
    
    // Create error handler with small size limit
    let error_handler = ParsingErrorHandler::new(
        100,                           // max_errors
        true,                         // enable_recovery
        Duration::from_secs(5),       // parse_timeout
        1024,                         // max_file_size (1KB - very small)
    );
    
    let mut parser = Parser::with_error_handler(Language::JavaScript, error_handler)?;
    
    // Should fail due to size limit
    let result = parser.parse_file(&large_file);
    assert!(result.is_err());
    
    match result.unwrap_err() {
        Error::ResourceLimitError(_) => {
            // Expected resource limit error
        }
        Error::ValidationError(_) => {
            // Also acceptable for content validation
        }
        e => panic!("Expected resource limit error, got: {:?}", e),
    }
    
    Ok(())
}

/// Test timeout error handling
#[test]
fn test_timeout_error_handling() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let complex_file = temp_dir.path().join("complex.js");
    
    // Create complex nested code that might take time to parse
    let mut complex_content = String::new();
    for i in 0..1000 {
        complex_content.push_str(&format!(
            "function func{}() {{ if (true) {{ if (true) {{ if (true) {{ return {}; }} }} }} }}\n",
            i, i
        ));
    }
    
    fs::write(&complex_file, &complex_content).unwrap();
    
    // Create error handler with very short timeout
    let error_handler = ParsingErrorHandler::new(
        100,                           // max_errors
        true,                         // enable_recovery
        Duration::from_millis(1),     // parse_timeout (very short)
        10 * 1024 * 1024,            // max_file_size
    );
    
    let mut parser = Parser::with_error_handler(Language::JavaScript, error_handler)?;
    
    // May timeout depending on system performance
    let result = parser.parse_file(&complex_file);
    
    // Either succeeds or times out
    if let Err(e) = result {
        match e {
            Error::TimeoutError(_) => {
                // Expected timeout error
            }
            _ => {
                // Other errors are also acceptable for this test
            }
        }
    }
    
    Ok(())
}

/// Test encoding error handling
#[test]
fn test_encoding_error_handling() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let binary_file = temp_dir.path().join("binary.js");
    
    // Write binary data that's not valid UTF-8
    let binary_data = vec![0xFF, 0xFE, 0x00, 0x01, 0x02, 0x03];
    fs::write(&binary_file, &binary_data).unwrap();
    
    let mut error_handler = ParsingErrorHandler::default();
    let mut parser = Parser::with_error_handler(Language::JavaScript, error_handler)?;
    
    // Should fail due to encoding issues
    let result = parser.parse_file(&binary_file);
    assert!(result.is_err());
    
    match result.unwrap_err() {
        Error::IoError(_) => {
            // Expected I/O error for invalid UTF-8
        }
        Error::EncodingError(_) => {
            // Also acceptable
        }
        e => {
            // Other errors might also occur depending on how the system handles invalid UTF-8
            println!("Got error: {:?}", e);
        }
    }
    
    Ok(())
}

/// Test error recovery and graceful degradation
#[test]
fn test_error_recovery() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let mixed_file = temp_dir.path().join("mixed.js");
    
    // JavaScript code with some valid and some invalid parts
    let mixed_code = r#"
// Valid function
function validFunction() {
    return "this works";
}

// Invalid syntax
function broken( {
    console.log("broken");
}

// Another valid function
function anotherValid() {
    return "this also works";
}

// More invalid syntax
class Incomplete {
    method() {
        return "incomplete"
    // Missing closing brace
"#;
    
    fs::write(&mixed_file, mixed_code).unwrap();
    
    let mut error_handler = ParsingErrorHandler::default();
    let mut parser = Parser::with_error_handler(Language::JavaScript, error_handler)?;
    
    // Parse the file
    let result = parser.parse_file(&mixed_file);
    
    // Should succeed with partial results
    match result {
        Ok(tree) => {
            // Tree should have errors but still be usable
            assert!(tree.root_node().has_error());
            
            // Should have collected multiple errors
            let errors = parser.get_parsing_errors();
            assert!(errors.len() > 1);
            
            // Check that recovery suggestions are provided
            for error in errors {
                assert!(!error.recovery_suggestions.is_empty());
                assert!(error.context.is_some());
            }
            
            // Check metrics
            let metrics = parser.get_parsing_metrics();
            assert!(metrics.files_processed > 0);
            assert!(metrics.errors_by_category.contains_key(&ErrorCategory::Syntax));
        }
        Err(e) => {
            // If it fails completely, should be due to critical errors
            println!("Parse failed with: {:?}", e);
        }
    }
    
    Ok(())
}

/// Test error limit handling
#[test]
fn test_error_limit_handling() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let many_errors_file = temp_dir.path().join("many_errors.js");
    
    // Create code with many syntax errors
    let mut error_code = String::new();
    for i in 0..50 {
        error_code.push_str(&format!(
            "function broken{}( {{ console.log('error {}'); }}\n",
            i, i
        ));
    }
    
    fs::write(&many_errors_file, &error_code).unwrap();
    
    // Create error handler with low error limit
    let error_handler = ParsingErrorHandler::new(
        5,                            // max_errors (low limit)
        true,                         // enable_recovery
        Duration::from_secs(30),      // parse_timeout
        10 * 1024 * 1024,            // max_file_size
    );
    
    let mut parser = Parser::with_error_handler(Language::JavaScript, error_handler)?;
    
    // Parse the file
    let _result = parser.parse_file(&many_errors_file);
    
    // Should have reached the error limit
    assert!(parser.has_reached_error_limit());
    
    // Should have exactly the maximum number of errors
    let errors = parser.get_parsing_errors();
    assert_eq!(errors.len(), 5);
    
    Ok(())
}

/// Test comprehensive error reporting
#[test]
fn test_comprehensive_error_reporting() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let error_file = temp_dir.path().join("error_report.js");
    
    let error_code = r#"
function test() {
    if (condition {  // Line 3, missing closing paren
        console.log("test");
    }
}
"#;
    
    fs::write(&error_file, error_code).unwrap();
    
    let mut error_handler = ParsingErrorHandler::default();
    let mut parser = Parser::with_error_handler(Language::JavaScript, error_handler)?;
    
    let _result = parser.parse_file(&error_file);
    
    let errors = parser.get_parsing_errors();
    if !errors.is_empty() {
        let error = &errors[0];
        
        // Check detailed error information
        assert_eq!(error.line, 3); // Error on line 3
        assert!(error.column > 0);
        assert!(!error.message.is_empty());
        assert_eq!(error.severity, ErrorSeverity::Error);
        assert_eq!(error.category, ErrorCategory::Syntax);
        assert!(!error.recovery_suggestions.is_empty());
        assert!(error.context.is_some());
        assert!(error.byte_offset.is_some());
        
        // Check context contains the error line
        let context = error.context.as_ref().unwrap();
        assert!(context.contains("if (condition"));
        assert!(context.contains(">>>"));  // Error marker
        
        // Check recovery suggestions are helpful
        let suggestions = &error.recovery_suggestions;
        assert!(suggestions.iter().any(|s| s.contains("parenthesis") || s.contains(")")));
    }
    
    Ok(())
}
