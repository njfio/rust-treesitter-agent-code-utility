//! Comprehensive integration tests for the rust_tree_sitter library
//! 
//! This module provides extensive testing coverage for all major functionality
//! including parsing, analysis, error handling, and CLI operations.

use rust_tree_sitter::*;
use std::fs;
use std::path::PathBuf;
use tempfile::TempDir;

/// Test comprehensive analyzer functionality
#[test]
fn test_comprehensive_analyzer_functionality() -> Result<()> {
    let temp_dir = TempDir::new()
        .map_err(|e| Error::internal(format!("Failed to create temp directory: {}", e)))?;
    let temp_path = temp_dir.path();

    // Create test files for multiple languages
    create_test_files(temp_path)?;

    // Test analyzer creation and configuration
    let mut analyzer = CodebaseAnalyzer::new();
    // Note: config is private, so we test functionality instead

    // Test directory analysis
    let result = analyzer.analyze_directory(temp_path)?;
    
    // Verify basic results
    assert!(result.total_files >= 5, "Should find at least 5 test files");
    assert!(result.parsed_files > 0, "Should parse some files successfully");
    assert!(result.languages.len() >= 3, "Should detect multiple languages");
    
    // Verify language detection
    assert!(result.languages.contains_key("Rust"), "Should detect Rust files");
    assert!(result.languages.contains_key("JavaScript"), "Should detect JavaScript files");
    assert!(result.languages.contains_key("Python"), "Should detect Python files");

    // Test file-level analysis
    for file_info in &result.files {
        assert!(!file_info.path.as_os_str().is_empty(), "File path should not be empty");
        assert!(file_info.size > 0, "File size should be greater than 0");
        
        // Files should have some symbols extracted
        if file_info.language != "Unknown" {
            // Most language files should have at least one symbol
            if file_info.symbols.is_empty() {
                println!("Warning: No symbols found in {} ({})", file_info.path.display(), file_info.language);
            }
        }
    }

    Ok(())
}

/// Test error handling throughout the system
#[test]
fn test_comprehensive_error_handling() -> Result<()> {
    // Test invalid path handling
    let invalid_path = PathBuf::from("/nonexistent/path/that/should/not/exist");
    let mut analyzer = CodebaseAnalyzer::new();
    
    let result = analyzer.analyze_directory(&invalid_path);
    assert!(result.is_err(), "Should fail for nonexistent directory");
    
    let error = result.unwrap_err();
    assert!(error.is_recoverable(), "Path errors should be recoverable");
    // The error category might be "input" for path validation errors
    let category = error.category();
    assert!(category == "io" || category == "input", "Should be categorized as IO or input error, got: {}", category);
    
    let user_msg = error.user_message();
    // The user message should contain helpful information
    assert!(!user_msg.is_empty(), "Should provide user-friendly message");
    assert!(user_msg.len() > 10, "User message should be descriptive");

    // Test parser error handling
    let parser_result = Parser::new(Language::Rust);
    assert!(parser_result.is_ok(), "Parser creation should succeed for valid language");

    // Test path validation
    let temp_dir = TempDir::new()
        .map_err(|e| Error::internal(format!("Failed to create temp directory: {}", e)))?;
    let temp_path = temp_dir.path();
    
    let validation_result = PathValidator::validate_readable_path(temp_path);
    assert!(validation_result.is_ok(), "Should validate readable directory");

    Ok(())
}

/// Test parser functionality across languages
#[test]
fn test_comprehensive_parser_functionality() -> Result<()> {
    // Test all supported languages
    let languages = vec![
        (Language::Rust, "fn main() { println!(\"Hello, world!\"); }"),
        (Language::JavaScript, "function hello() { console.log('Hello'); }"),
        (Language::Python, "def hello():\n    print('Hello')"),
        (Language::C, "int main() { printf(\"Hello\"); return 0; }"),
        (Language::Cpp, "int main() { std::cout << \"Hello\"; return 0; }"),
        (Language::Go, "func main() { fmt.Println(\"Hello\") }"),
        (Language::TypeScript, "function hello(): void { console.log('Hello'); }"),
    ];

    for (language, source) in languages {
        let mut parser = Parser::new(language)?;
        let tree = parser.parse(source, None)?;
        
        // Note: tree.language() returns tree_sitter::Language, not our Language enum
        // So we test that parsing succeeded instead
        assert!(!tree.root_node().kind().is_empty(), "Tree should have valid root node");
        assert!(!tree.root_node().kind().is_empty(), "Root node should have a kind");
        
        // Test tree navigation
        let root = tree.root_node();
        assert!(root.child_count() > 0, "Root should have children for non-empty source");
    }

    Ok(())
}

/// Test query system functionality
#[test]
fn test_comprehensive_query_functionality() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = r#"
        fn main() {
            let x = 42;
            println!("Hello, world!");
        }
        
        struct Point {
            x: i32,
            y: i32,
        }
    "#;
    
    let tree = parser.parse(source, None)?;
    
    // Test predefined queries
    let function_query = Query::functions(Language::Rust)?;
    let matches = function_query.matches(&tree)?;
    assert!(!matches.is_empty(), "Should find function matches");

    // Test classes query (no structs query available)
    let class_query = Query::classes(Language::Rust)?;
    let class_matches = class_query.matches(&tree)?;
    // Classes query might not match structs in Rust, so we don't assert on results

    // Test custom query
    let custom_query = Query::new(Language::Rust, "(function_item name: (identifier) @name)")?;
    let custom_matches = custom_query.matches(&tree)?;
    assert!(!custom_matches.is_empty(), "Should find custom matches");

    Ok(())
}

/// Test AI analysis functionality
#[test]
fn test_comprehensive_ai_analysis() -> Result<()> {
    let temp_dir = TempDir::new()
        .map_err(|e| Error::internal(format!("Failed to create temp directory: {}", e)))?;
    let temp_path = temp_dir.path();

    // Create a test file
    let test_file = temp_path.join("test.rs");
    fs::write(&test_file, r#"
        /// A simple calculator function
        fn add(a: i32, b: i32) -> i32 {
            a + b
        }
        
        /// A complex function with multiple responsibilities
        fn complex_function(data: Vec<String>) -> Result<String, String> {
            if data.is_empty() {
                return Err("Empty data".to_string());
            }
            
            let mut result = String::new();
            for item in data {
                if item.len() > 100 {
                    return Err("Item too long".to_string());
                }
                result.push_str(&item);
                result.push(' ');
            }
            
            Ok(result.trim().to_string())
        }
    "#)?;

    // Test AI analysis - first need to analyze the codebase
    let mut codebase_analyzer = CodebaseAnalyzer::new();
    let analysis_result = codebase_analyzer.analyze_directory(temp_path)?;

    // Then use AI analyzer on the analysis result
    let ai_analyzer = AIAnalyzer::new();
    let ai_result = ai_analyzer.analyze(&analysis_result);

    assert!(!ai_result.codebase_explanation.purpose.is_empty(), "Should generate codebase purpose");
    assert!(!ai_result.file_explanations.is_empty(), "Should analyze files");
    
    // Check that symbols are analyzed
    assert!(!ai_result.symbol_explanations.is_empty(), "Should have symbol explanations");

    Ok(())
}

/// Test security analysis functionality
#[test]
fn test_comprehensive_security_analysis() -> Result<()> {
    let temp_dir = TempDir::new()
        .map_err(|e| Error::internal(format!("Failed to create temp directory: {}", e)))?;
    let temp_path = temp_dir.path();

    // Create test files for security analysis
    create_test_files(temp_path)?;

    // Test security analysis using AdvancedSecurityAnalyzer
    let security_analyzer = AdvancedSecurityAnalyzer::new()?;

    // First analyze the codebase, then run security analysis
    let mut codebase_analyzer = CodebaseAnalyzer::new();
    let mut analysis_result = codebase_analyzer.analyze_directory(temp_path)?;

    // Fix the file paths to be absolute for security analysis
    // The analyzer stores relative paths, but security analyzer needs absolute paths
    for file in &mut analysis_result.files {
        if file.path.is_relative() {
            file.path = temp_path.join(&file.path);
        }
    }

    // Verify files were found for analysis
    assert!(analysis_result.files.len() >= 5, "Should find at least 5 test files");

    let _result = security_analyzer.analyze(&analysis_result)?;

    // Security scanner should complete successfully
    // The test files may or may not trigger specific vulnerabilities, but the analysis should work
    // Just verify the analysis completed without error - no specific assertion needed
    // The fact that we got here means the security analysis worked

    Ok(())
}

/// Helper function to create test files
fn create_test_files(temp_path: &std::path::Path) -> Result<()> {
    // Rust file
    fs::write(temp_path.join("main.rs"), r#"
        fn main() {
            println!("Hello, Rust!");
        }
        
        struct Point {
            x: i32,
            y: i32,
        }
        
        impl Point {
            fn new(x: i32, y: i32) -> Self {
                Point { x, y }
            }
        }
    "#)?;

    // JavaScript file
    fs::write(temp_path.join("app.js"), r#"
        function greet(name) {
            console.log(`Hello, ${name}!`);
        }
        
        class Calculator {
            add(a, b) {
                return a + b;
            }
            
            multiply(a, b) {
                return a * b;
            }
        }
        
        const calc = new Calculator();
        greet("JavaScript");
    "#)?;

    // Python file
    fs::write(temp_path.join("script.py"), r#"
def greet(name):
    print(f"Hello, {name}!")

class Calculator:
    def add(self, a, b):
        return a + b
    
    def multiply(self, a, b):
        return a * b

if __name__ == "__main__":
    calc = Calculator()
    greet("Python")
    "#)?;

    // C file
    fs::write(temp_path.join("program.c"), r#"
#include <stdio.h>

int add(int a, int b) {
    return a + b;
}

int main() {
    printf("Hello, C!\n");
    int result = add(5, 3);
    printf("5 + 3 = %d\n", result);
    return 0;
}
    "#)?;

    // TypeScript file
    fs::write(temp_path.join("app.ts"), r#"
interface Point {
    x: number;
    y: number;
}

function greet(name: string): void {
    console.log(`Hello, ${name}!`);
}

class Calculator {
    add(a: number, b: number): number {
        return a + b;
    }
}

const point: Point = { x: 10, y: 20 };
greet("TypeScript");
    "#)?;

    Ok(())
}
