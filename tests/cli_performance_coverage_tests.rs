//! Integration tests for performance and coverage CLI commands
//! 
//! This module tests the newly implemented performance and coverage analysis commands
//! to ensure they work correctly with real codebases and produce expected outputs.

use std::process::Command;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_performance_command_basic() {
    let output = Command::new("./target/debug/tree-sitter-cli")
        .args(&["performance", "src", "--top", "3", "--format", "json"])
        .output()
        .expect("Failed to execute performance command");

    assert!(output.status.success(), "Performance command should succeed");
    
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    
    // Should contain JSON output
    assert!(stdout.contains("["), "Output should contain JSON array");
    assert!(stdout.contains("file"), "Output should contain file information");
    assert!(stdout.contains("complexity"), "Output should contain complexity information");
}

#[test]
fn test_performance_command_with_category_filter() {
    let output = Command::new("./target/debug/tree-sitter-cli")
        .args(&["performance", "src", "--category", "complexity", "--format", "table"])
        .output()
        .expect("Failed to execute performance command with category filter");

    assert!(output.status.success(), "Performance command with category should succeed");
    
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    
    // Should contain table headers
    assert!(stdout.contains("PERFORMANCE HOTSPOTS"), "Output should contain performance hotspots header");
    assert!(stdout.contains("Complexity"), "Output should contain complexity column");
    assert!(stdout.contains("Severity"), "Output should contain severity column");
}

#[test]
fn test_coverage_command_basic() {
    let output = Command::new("./target/debug/tree-sitter-cli")
        .args(&["coverage", "src", "--format", "json"])
        .output()
        .expect("Failed to execute coverage command");

    assert!(output.status.success(), "Coverage command should succeed");
    
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    
    // Should contain JSON output
    assert!(stdout.contains("["), "Output should contain JSON array");
    assert!(stdout.contains("coverage_percentage"), "Output should contain coverage percentage");
    assert!(stdout.contains("function"), "Output should contain function information");
}

#[test]
fn test_coverage_command_with_detailed_analysis() {
    let output = Command::new("./target/debug/tree-sitter-cli")
        .args(&["coverage", "src", "--detailed", "--format", "table"])
        .output()
        .expect("Failed to execute coverage command with detailed analysis");

    assert!(output.status.success(), "Coverage command with detailed analysis should succeed");
    
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    
    // Should contain table headers and summary
    assert!(stdout.contains("TEST COVERAGE ANALYSIS"), "Output should contain coverage analysis header");
    assert!(stdout.contains("Coverage %"), "Output should contain coverage percentage column");
    assert!(stdout.contains("COVERAGE SUMMARY"), "Output should contain coverage summary");
    assert!(stdout.contains("Average Coverage"), "Output should contain average coverage");
}

#[test]
fn test_performance_command_with_output_file() {
    let temp_dir = TempDir::new().expect("Failed to create temp directory");
    let output_file = temp_dir.path().join("performance_report.json");

    let output = Command::new("./target/debug/tree-sitter-cli")
        .args(&[
            "performance", 
            "src", 
            "--format", "json",
            "--output", output_file.to_str().unwrap()
        ])
        .output()
        .expect("Failed to execute performance command with output file");

    assert!(output.status.success(), "Performance command with output file should succeed");
    assert!(output_file.exists(), "Output file should be created");
    
    let file_content = fs::read_to_string(&output_file).expect("Failed to read output file");
    assert!(file_content.contains("["), "Output file should contain JSON array");
}

#[test]
fn test_coverage_command_with_uncovered_only_filter() {
    let output = Command::new("./target/debug/tree-sitter-cli")
        .args(&["coverage", "src", "--uncovered-only", "--format", "table"])
        .output()
        .expect("Failed to execute coverage command with uncovered-only filter");

    assert!(output.status.success(), "Coverage command with uncovered-only should succeed");
    
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    
    // Should contain coverage analysis
    assert!(stdout.contains("TEST COVERAGE ANALYSIS"), "Output should contain coverage analysis header");
}

#[test]
fn test_performance_command_help() {
    let output = Command::new("./target/debug/tree-sitter-cli")
        .args(&["performance", "--help"])
        .output()
        .expect("Failed to execute performance help command");

    assert!(output.status.success(), "Performance help command should succeed");
    
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    
    // Should contain help information
    assert!(stdout.contains("Performance hotspot detection"), "Help should contain command description");
    assert!(stdout.contains("--format"), "Help should contain format option");
    assert!(stdout.contains("--category"), "Help should contain category option");
    assert!(stdout.contains("--top"), "Help should contain top option");
}

#[test]
fn test_coverage_command_help() {
    let output = Command::new("./target/debug/tree-sitter-cli")
        .args(&["coverage", "--help"])
        .output()
        .expect("Failed to execute coverage help command");

    assert!(output.status.success(), "Coverage help command should succeed");
    
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    
    // Should contain help information
    assert!(stdout.contains("Test coverage analysis"), "Help should contain command description");
    assert!(stdout.contains("--format"), "Help should contain format option");
    assert!(stdout.contains("--test-dir"), "Help should contain test-dir option");
    assert!(stdout.contains("--uncovered-only"), "Help should contain uncovered-only option");
}

#[test]
fn test_performance_command_with_minimum_complexity() {
    let output = Command::new("./target/debug/tree-sitter-cli")
        .args(&["performance", "src", "--min-complexity", "20", "--format", "table"])
        .output()
        .expect("Failed to execute performance command with minimum complexity");

    assert!(output.status.success(), "Performance command with min complexity should succeed");
    
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    
    // Should contain performance analysis or no hotspots message
    assert!(
        stdout.contains("PERFORMANCE HOTSPOTS") || stdout.contains("No performance hotspots found"),
        "Output should contain either hotspots or no hotspots message"
    );
}

#[test]
fn test_coverage_command_with_minimum_coverage_threshold() {
    let output = Command::new("./target/debug/tree-sitter-cli")
        .args(&["coverage", "src", "--min-coverage", "50", "--format", "table"])
        .output()
        .expect("Failed to execute coverage command with minimum coverage");

    assert!(output.status.success(), "Coverage command with min coverage should succeed");
    
    let stdout = String::from_utf8(output.stdout).expect("Invalid UTF-8 output");
    
    // Should contain coverage analysis
    assert!(stdout.contains("TEST COVERAGE ANALYSIS"), "Output should contain coverage analysis header");
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    
    /// Test that both commands work together in a workflow
    #[test]
    fn test_performance_and_coverage_workflow() {
        // First run performance analysis
        let perf_output = Command::new("./target/debug/tree-sitter-cli")
            .args(&["performance", "src", "--top", "5", "--format", "json"])
            .output()
            .expect("Failed to execute performance command");

        assert!(perf_output.status.success(), "Performance command should succeed");

        // Then run coverage analysis
        let cov_output = Command::new("./target/debug/tree-sitter-cli")
            .args(&["coverage", "src", "--format", "json"])
            .output()
            .expect("Failed to execute coverage command");

        assert!(cov_output.status.success(), "Coverage command should succeed");

        // Both should produce valid JSON
        let perf_stdout = String::from_utf8(perf_output.stdout).expect("Invalid UTF-8 output");
        let cov_stdout = String::from_utf8(cov_output.stdout).expect("Invalid UTF-8 output");

        assert!(perf_stdout.contains("["), "Performance output should contain JSON array");
        assert!(cov_stdout.contains("["), "Coverage output should contain JSON array");
    }
}
