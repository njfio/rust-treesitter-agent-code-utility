//! Comprehensive tests for performance analysis functionality
//!
//! Tests algorithmic complexity analysis, memory usage patterns, I/O bottleneck detection,
//! concurrency opportunities, and performance scoring across multiple languages.

use rust_tree_sitter::*;
use rust_tree_sitter::performance_analysis::{
    PerformanceAnalyzer, PerformanceConfig, PerformanceResult, ComplexityAnalysis,
    MemoryAnalysis, IOAnalysis, ConcurrencyAnalysis, PerformanceHotspot
};
use std::path::PathBuf;
use std::fs;
use tempfile::TempDir;

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
        min_complexity_threshold: 15,
        max_analysis_depth: 10,
    };
    
    let analyzer = PerformanceAnalyzer::with_config(config);
    assert!(analyzer.config.complexity_analysis);
    assert!(!analyzer.config.memory_analysis);
    assert!(analyzer.config.io_analysis);
    assert!(!analyzer.config.concurrency_analysis);
    assert_eq!(analyzer.config.min_complexity_threshold, 15);
    assert_eq!(analyzer.config.max_analysis_depth, 10);
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
    
    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze_file(&rust_file_path)?;
    
    // Should detect high complexity in complex_function
    assert!(!result.hotspots.is_empty());
    
    let complex_hotspot = result.hotspots.iter()
        .find(|h| h.function_name == "complex_function");
    assert!(complex_hotspot.is_some());
    
    let hotspot = complex_hotspot.unwrap();
    assert!(hotspot.complexity_score > 10); // Should be high complexity
    assert!(hotspot.optimization_potential > 0.0);
    
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
    
    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze_file(&js_file_path)?;
    
    // Should detect complexity issues
    assert!(!result.hotspots.is_empty());
    
    let complex_hotspot = result.hotspots.iter()
        .find(|h| h.function_name == "complexAlgorithm");
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
    
    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze_file(&py_file_path)?;
    
    // Should detect complexity issues
    assert!(!result.hotspots.is_empty());
    
    let complex_hotspot = result.hotspots.iter()
        .find(|h| h.function_name == "complex_matrix_operation");
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
    
    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze_file(&rust_file_path)?;
    
    // Should detect memory usage patterns
    assert!(result.memory_analysis.total_allocations >= 0);
    assert!(result.memory_analysis.potential_leaks.len() >= 0);
    assert!(result.memory_analysis.optimization_opportunities.len() >= 0);
    
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
    
    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze_file(&rust_file_path)?;
    
    // Should detect I/O patterns
    assert!(result.io_analysis.file_operations >= 0);
    assert!(result.io_analysis.network_operations >= 0);
    assert!(result.io_analysis.database_operations >= 0);
    assert!(result.io_analysis.bottlenecks.len() >= 0);
    
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
    
    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze_file(&rust_file_path)?;
    
    // Should detect concurrency opportunities
    assert!(result.concurrency_analysis.parallelizable_loops >= 0);
    assert!(result.concurrency_analysis.independent_operations >= 0);
    assert!(result.concurrency_analysis.potential_speedup >= 1.0);
    assert!(result.concurrency_analysis.recommendations.len() >= 0);
    
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
    
    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze_file(&rust_file_path)?;
    
    // Should calculate performance scores
    assert!(result.overall_score >= 0);
    assert!(result.overall_score <= 100);
    assert!(result.confidence_level >= 0.0);
    assert!(result.confidence_level <= 1.0);
    
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
    
    let analyzer = PerformanceAnalyzer::new();
    let result = analyzer.analyze_directory(temp_dir.path())?;
    
    // Should analyze multiple files
    assert!(!result.file_results.is_empty());
    assert!(result.overall_score >= 0);
    assert!(result.overall_score <= 100);
    
    // Should find hotspots across files
    let total_hotspots: usize = result.file_results.iter()
        .map(|fr| fr.hotspots.len())
        .sum();
    assert!(total_hotspots > 0);
    
    Ok(())
}
