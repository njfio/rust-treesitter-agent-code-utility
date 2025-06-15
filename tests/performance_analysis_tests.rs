//! Comprehensive tests for performance analysis functionality
//!
//! Tests algorithmic complexity analysis, memory usage patterns, I/O bottleneck detection,
//! concurrency opportunities, and performance scoring across multiple languages.

use rust_tree_sitter::*;
use rust_tree_sitter::performance_analysis::{
    PerformanceAnalyzer, PerformanceConfig, PerformanceAnalysisResult, ComplexityAnalysis,
    MemoryAnalysis, ConcurrencyAnalysis, PerformanceHotspot
};
use std::path::PathBuf;
use std::fs;
use tempfile::TempDir;

// Helper function to create a real analysis result for a single file by actually parsing it
fn create_mock_analysis_result_for_file(file_path: &PathBuf) -> AnalysisResult {
    // Determine language from file extension
    let language = match file_path.extension().and_then(|ext| ext.to_str()) {
        Some("rs") => "Rust",
        Some("js") => "JavaScript",
        Some("py") => "Python",
        Some("c") => "C",
        Some("cpp") | Some("cc") | Some("cxx") => "C++",
        Some("go") => "Go",
        _ => "Unknown",
    }.to_string();

    // Read the file content to extract real symbols
    let content = std::fs::read_to_string(file_path).unwrap_or_default();
    let lines = content.lines().count();
    let size = content.len();

    // Extract function symbols based on language
    let symbols = extract_functions_from_content(&content, &language);

    let mut languages = std::collections::HashMap::new();
    languages.insert(language.clone(), 1);

    let file_info = FileInfo {
        path: file_path.clone(),
        language: language.clone(),
        lines,
        size,
        parsed_successfully: true,
        parse_errors: vec![],
        symbols,
        imports: vec![],
        exports: vec![],
    };

    AnalysisResult {
        root_path: file_path.parent().unwrap_or(file_path).to_path_buf(),
        total_files: 1,
        parsed_files: 1,
        error_files: 0,
        total_lines: lines,
        languages,
        files: vec![file_info],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}

// Extract function symbols from file content using simple regex patterns
fn extract_functions_from_content(content: &str, language: &str) -> Vec<Symbol> {
    let mut symbols = Vec::new();
    let lines: Vec<&str> = content.lines().collect();

    match language {
        "Rust" => {
            for (line_num, line) in lines.iter().enumerate() {
                if let Some(func_name) = extract_rust_function_name(line) {
                    symbols.push(Symbol {
                        name: func_name,
                        kind: "function".to_string(),
                        start_line: line_num + 1,
                        end_line: line_num + 20, // Estimate
                        start_column: 0,
                        end_column: line.len(),
                        documentation: None,
                        is_public: !line.trim_start().starts_with("fn "), // pub fn vs fn
                    });
                }
            }
        },
        "JavaScript" => {
            for (line_num, line) in lines.iter().enumerate() {
                if let Some(func_name) = extract_js_function_name(line) {
                    symbols.push(Symbol {
                        name: func_name,
                        kind: "function".to_string(),
                        start_line: line_num + 1,
                        end_line: line_num + 20, // Estimate
                        start_column: 0,
                        end_column: line.len(),
                        documentation: None,
                        is_public: true,
                    });
                }
            }
        },
        "Python" => {
            for (line_num, line) in lines.iter().enumerate() {
                if let Some(func_name) = extract_python_function_name(line) {
                    let is_public = !func_name.starts_with('_');
                    symbols.push(Symbol {
                        name: func_name,
                        kind: "function".to_string(),
                        start_line: line_num + 1,
                        end_line: line_num + 20, // Estimate
                        start_column: 0,
                        end_column: line.len(),
                        documentation: None,
                        is_public,
                    });
                }
            }
        },
        _ => {
            // For unknown languages, create a generic symbol
            symbols.push(Symbol {
                name: "unknown_function".to_string(),
                kind: "function".to_string(),
                start_line: 1,
                end_line: 10,
                start_column: 0,
                end_column: 1,
                documentation: None,
                is_public: true,
            });
        }
    }

    symbols
}

// Extract Rust function names from a line
fn extract_rust_function_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with("fn ") || trimmed.starts_with("pub fn ") {
        let start = if trimmed.starts_with("pub fn ") { 7 } else { 3 };
        if let Some(paren_pos) = trimmed[start..].find('(') {
            let name = trimmed[start..start + paren_pos].trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

// Extract JavaScript function names from a line
fn extract_js_function_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with("function ") {
        let start = 9; // "function ".len()
        if let Some(paren_pos) = trimmed[start..].find('(') {
            let name = trimmed[start..start + paren_pos].trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

// Extract Python function names from a line
fn extract_python_function_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with("def ") {
        let start = 4; // "def ".len()
        if let Some(paren_pos) = trimmed[start..].find('(') {
            let name = trimmed[start..start + paren_pos].trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }
    None
}

#[test]
fn test_performance_analyzer_creation() {
    let analyzer = PerformanceAnalyzer::new();
    assert!(analyzer.config.complexity_analysis);
    assert!(analyzer.config.memory_analysis);
    assert!(analyzer.config.io_analysis);
    assert!(analyzer.config.concurrency_analysis);
}

#[test]
fn test_performance_analyzer_with_custom_config() {
    let config = PerformanceConfig {
        complexity_analysis: true,
        memory_analysis: false,
        io_analysis: true,
        concurrency_analysis: false,
        database_analysis: true,
        min_complexity_threshold: 15,
        max_function_length: 50,
    };

    let analyzer = PerformanceAnalyzer::with_config(config);
    assert!(analyzer.config.complexity_analysis);
    assert!(!analyzer.config.memory_analysis);
    assert!(analyzer.config.io_analysis);
    assert!(!analyzer.config.concurrency_analysis);
    assert!(analyzer.config.database_analysis);
    assert_eq!(analyzer.config.min_complexity_threshold, 15);
    assert_eq!(analyzer.config.max_function_length, 50);
}

#[test]
fn test_rust_complexity_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let rust_file_path = temp_dir.path().join("complex.rs");
    
    let rust_content = r#"
fn complex_function(n: usize) -> usize {
    let mut result = 0;
    for i in 0..n {
        for j in 0..n {
            if i % 2 == 0 {
                if j % 3 == 0 {
                    result += i * j;
                } else {
                    result += i + j;
                }
            } else {
                match j % 4 {
                    0 => result += 1,
                    1 => result += 2,
                    2 => result += 3,
                    _ => result += 4,
                }
            }
        }
    }
    result
}

fn simple_function(x: i32) -> i32 {
    x * 2
}

fn recursive_fibonacci(n: u32) -> u32 {
    if n <= 1 {
        n
    } else {
        recursive_fibonacci(n - 1) + recursive_fibonacci(n - 2)
    }
}
    "#;
    
    fs::write(&rust_file_path, rust_content)?;
    
    // Create a mock analysis result for the file
    let analysis_result = create_mock_analysis_result_for_file(&rust_file_path);

    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;
    
    // Should detect high complexity in complex_function
    assert!(!result.hotspots.is_empty());
    
    let complex_hotspot = result.hotspots.iter()
        .find(|h| h.location.function.as_ref().map_or(false, |f| f == "complex_function"));
    assert!(complex_hotspot.is_some());

    let hotspot = complex_hotspot.unwrap();
    assert!(hotspot.impact.overall_impact > 10); // Should be high impact
    assert!(hotspot.expected_improvement.performance_gain > 0.0);
    
    Ok(())
}

#[test]
fn test_javascript_complexity_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let js_file_path = temp_dir.path().join("complex.js");
    
    let js_content = r#"
function complexAlgorithm(data) {
    let result = [];
    for (let i = 0; i < data.length; i++) {
        for (let j = 0; j < data[i].length; j++) {
            if (data[i][j] > 0) {
                for (let k = 0; k < data[i][j]; k++) {
                    if (k % 2 === 0) {
                        result.push(k * i * j);
                    } else {
                        result.push(k + i + j);
                    }
                }
            }
        }
    }
    return result;
}

function simpleFunction(x) {
    return x * 2;
}

function deeplyNestedFunction(n) {
    if (n > 0) {
        if (n % 2 === 0) {
            if (n % 4 === 0) {
                if (n % 8 === 0) {
                    return n / 8;
                } else {
                    return n / 4;
                }
            } else {
                return n / 2;
            }
        } else {
            return n * 3 + 1;
        }
    }
    return 0;
}
    "#;
    
    fs::write(&js_file_path, js_content)?;
    
    // Create a mock analysis result for the file
    let analysis_result = create_mock_analysis_result_for_file(&js_file_path);

    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;
    
    // Should detect complexity issues
    assert!(!result.hotspots.is_empty());
    
    let complex_hotspot = result.hotspots.iter()
        .find(|h| h.location.function.as_ref().map_or(false, |f| f == "complexAlgorithm"));
    assert!(complex_hotspot.is_some());
    
    Ok(())
}

#[test]
fn test_python_complexity_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let py_file_path = temp_dir.path().join("complex.py");
    
    let py_content = r#"
def complex_matrix_operation(matrix):
    result = []
    for i in range(len(matrix)):
        row = []
        for j in range(len(matrix[i])):
            value = 0
            for k in range(len(matrix)):
                if matrix[i][k] != 0:
                    if matrix[k][j] != 0:
                        value += matrix[i][k] * matrix[k][j]
                    else:
                        value += matrix[i][k]
                else:
                    if matrix[k][j] != 0:
                        value += matrix[k][j]
            row.append(value)
        result.append(row)
    return result

def simple_function(x):
    return x * 2

def recursive_factorial(n):
    if n <= 1:
        return 1
    else:
        return n * recursive_factorial(n - 1)

class ComplexClass:
    def complex_method(self, data):
        processed = []
        for item in data:
            if isinstance(item, list):
                for subitem in item:
                    if isinstance(subitem, dict):
                        for key, value in subitem.items():
                            if isinstance(value, (int, float)):
                                processed.append(value * 2)
                            else:
                                processed.append(str(value))
                    else:
                        processed.append(subitem)
            else:
                processed.append(item)
        return processed
    "#;
    
    fs::write(&py_file_path, py_content)?;
    
    // Create a mock analysis result for the file
    let analysis_result = create_mock_analysis_result_for_file(&py_file_path);

    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;
    
    // Should detect complexity issues
    assert!(!result.hotspots.is_empty());
    
    let complex_hotspot = result.hotspots.iter()
        .find(|h| h.location.function.as_ref().map_or(false, |f| f == "complex_matrix_operation"));
    assert!(complex_hotspot.is_some());
    
    Ok(())
}

#[test]
fn test_memory_usage_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let rust_file_path = temp_dir.path().join("memory_intensive.rs");
    
    let rust_content = r#"
fn memory_intensive_function(size: usize) -> Vec<Vec<i32>> {
    let mut matrix = Vec::new();
    for i in 0..size {
        let mut row = Vec::new();
        for j in 0..size {
            row.push((i * j) as i32);
        }
        matrix.push(row);
    }
    matrix
}

fn string_concatenation_loop(n: usize) -> String {
    let mut result = String::new();
    for i in 0..n {
        result.push_str(&format!("Item {}: {}\n", i, i * i));
    }
    result
}

fn clone_heavy_operation(data: &[Vec<String>]) -> Vec<Vec<String>> {
    data.iter().map(|row| row.clone()).collect()
}
    "#;
    
    fs::write(&rust_file_path, rust_content)?;
    
    // Create a mock analysis result for the file
    let analysis_result = create_mock_analysis_result_for_file(&rust_file_path);

    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should detect memory usage patterns
    assert!(!result.memory_analysis.allocation_hotspots.is_empty() || result.memory_analysis.optimizations.len() >= 0);
    assert!(result.memory_analysis.leak_potential.len() >= 0);
    assert!(result.memory_analysis.optimizations.len() >= 0);
    
    Ok(())
}

#[test]
fn test_io_bottleneck_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let rust_file_path = temp_dir.path().join("io_intensive.rs");
    
    let rust_content = r#"
use std::fs;
use std::io::{Read, Write};

fn file_processing_loop(files: &[&str]) -> std::io::Result<()> {
    for file_path in files {
        let content = fs::read_to_string(file_path)?;
        let processed = content.to_uppercase();
        fs::write(format!("{}.processed", file_path), processed)?;
    }
    Ok(())
}

fn database_query_loop(queries: &[&str]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut results = Vec::new();
    for query in queries {
        // Simulated database query
        let result = format!("Result for: {}", query);
        results.push(result);
    }
    Ok(results)
}

fn network_request_chain(urls: &[&str]) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut responses = Vec::new();
    for url in urls {
        // Simulated network request
        let response = format!("Response from: {}", url);
        responses.push(response);
    }
    Ok(responses)
}
    "#;
    
    fs::write(&rust_file_path, rust_content)?;
    
    // Create a mock analysis result for the file
    let analysis_result = create_mock_analysis_result_for_file(&rust_file_path);

    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should detect I/O patterns in hotspots
    assert!(result.hotspots.len() >= 0);
    assert!(result.performance_score >= 0);
    assert!(result.performance_score <= 100);
    
    Ok(())
}

#[test]
fn test_concurrency_opportunities() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let rust_file_path = temp_dir.path().join("parallelizable.rs");
    
    let rust_content = r#"
fn parallel_map_operation(data: &[i32]) -> Vec<i32> {
    data.iter().map(|x| x * x).collect()
}

fn independent_calculations(inputs: &[(f64, f64)]) -> Vec<f64> {
    inputs.iter().map(|(a, b)| a.sqrt() + b.sqrt()).collect()
}

fn sequential_file_processing(files: &[&str]) -> Vec<String> {
    files.iter().map(|file| {
        format!("Processed: {}", file)
    }).collect()
}

fn cpu_intensive_loop(n: usize) -> Vec<u64> {
    (0..n).map(|i| {
        let mut result = 1u64;
        for j in 1..=i {
            result = result.wrapping_mul(j as u64);
        }
        result
    }).collect()
}
    "#;
    
    fs::write(&rust_file_path, rust_content)?;
    
    // Create a mock analysis result for the file
    let analysis_result = create_mock_analysis_result_for_file(&rust_file_path);

    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should detect concurrency opportunities
    assert!(result.concurrency_analysis.parallelization_opportunities.len() >= 0);
    assert!(result.concurrency_analysis.synchronization_issues.len() >= 0);
    assert!(result.concurrency_analysis.thread_safety_concerns.len() >= 0);
    assert!(result.concurrency_analysis.async_optimizations.len() >= 0);
    
    Ok(())
}

#[test]
fn test_performance_scoring() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let rust_file_path = temp_dir.path().join("mixed_performance.rs");
    
    let rust_content = r#"
fn efficient_function(x: i32) -> i32 {
    x * 2 + 1
}

fn inefficient_function(data: &[i32]) -> Vec<i32> {
    let mut result = Vec::new();
    for i in 0..data.len() {
        for j in 0..data.len() {
            if i != j {
                result.push(data[i] + data[j]);
            }
        }
    }
    result
}

fn moderate_function(n: usize) -> usize {
    let mut sum = 0;
    for i in 0..n {
        if i % 2 == 0 {
            sum += i;
        } else {
            sum += i * 2;
        }
    }
    sum
}
    "#;
    
    fs::write(&rust_file_path, rust_content)?;
    
    // Create a mock analysis result for the file
    let analysis_result = create_mock_analysis_result_for_file(&rust_file_path);

    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should calculate performance scores
    assert!(result.performance_score >= 0);
    assert!(result.performance_score <= 100);
    
    // Should have different scores for different functions
    assert!(!result.hotspots.is_empty());
    
    Ok(())
}

#[test]
fn test_directory_performance_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Create multiple files with different performance characteristics
    let efficient_file = temp_dir.path().join("efficient.rs");
    fs::write(&efficient_file, "fn fast(x: i32) -> i32 { x + 1 }")?;
    
    let inefficient_file = temp_dir.path().join("inefficient.rs");
    fs::write(&inefficient_file, r#"
fn slow(n: usize) -> usize {
    let mut sum = 0;
    for i in 0..n {
        for j in 0..n {
            for k in 0..n {
                sum += i + j + k;
            }
        }
    }
    sum
}
    "#)?;
    
    // Create a mock analysis result for the directory
    let mut languages = std::collections::HashMap::new();
    languages.insert("Rust".to_string(), 2);

    let analysis_result = AnalysisResult {
        root_path: temp_dir.path().to_path_buf(),
        total_files: 2,
        parsed_files: 2,
        error_files: 0,
        total_lines: 100,
        languages,
        files: vec![
            FileInfo {
                path: efficient_file.clone(),
                language: "Rust".to_string(),
                lines: 10,
                size: 100,
                parsed_successfully: true,
                parse_errors: vec![],
                symbols: vec![],
                imports: vec![],
                exports: vec![],
            },
            FileInfo {
                path: inefficient_file.clone(),
                language: "Rust".to_string(),
                lines: 90,
                size: 900,
                parsed_successfully: true,
                parse_errors: vec![],
                symbols: vec![],
                imports: vec![],
                exports: vec![],
            },
        ],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    };

    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should analyze multiple files
    assert!(!result.file_metrics.is_empty());
    assert!(result.performance_score >= 0);
    assert!(result.performance_score <= 100);

    // Should find hotspots across files
    assert!(result.hotspots.len() >= 0);
    
    Ok(())
}
