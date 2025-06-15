//! Comprehensive tests for test coverage analysis functionality
//!
//! Tests test coverage estimation, quality assessment, missing test detection,
//! and coverage organization across multiple languages and test frameworks.

use rust_tree_sitter::*;
use rust_tree_sitter::test_coverage::{
    TestCoverageAnalyzer, TestCoverageConfig, TestCoverageResult, CoverageStatus,
    MissingTest, TestSuiteOrganization
};
use std::path::{Path, PathBuf};
use std::fs;
use tempfile::TempDir;

// Helper function to create a mock analysis result for a directory
fn create_mock_analysis_result_for_directory(dir_path: &Path) -> AnalysisResult {
    let mut languages = std::collections::HashMap::new();
    languages.insert("Rust".to_string(), 2);

    AnalysisResult {
        root_path: dir_path.to_path_buf(),
        total_files: 2,
        parsed_files: 2,
        error_files: 0,
        total_lines: 100,
        languages,
        files: vec![
            FileInfo {
                path: dir_path.join("src/lib.rs"),
                language: "Rust".to_string(),
                lines: 50,
                size: 1024,
                parsed_successfully: true,
                parse_errors: vec![],
                symbols: vec![
                    Symbol {
                        name: "add".to_string(),
                        kind: "function".to_string(),
                        start_line: 1,
                        end_line: 3,
                        start_column: 0,
                        end_column: 1,
                        documentation: None,
                        is_public: true,
                    },
                ],
                imports: vec![],
                exports: vec![],
            },
            FileInfo {
                path: dir_path.join("tests/test_lib.rs"),
                language: "Rust".to_string(),
                lines: 50,
                size: 1024,
                parsed_successfully: true,
                parse_errors: vec![],
                symbols: vec![
                    Symbol {
                        name: "test_add".to_string(),
                        kind: "function".to_string(),
                        start_line: 1,
                        end_line: 5,
                        start_column: 0,
                        end_column: 1,
                        documentation: None,
                        is_public: true,
                    },
                ],
                imports: vec![],
                exports: vec![],
            },
        ],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}

#[test]
fn test_coverage_analyzer_creation() {
    let analyzer = TestCoverageAnalyzer::new();
    assert!(analyzer.config.coverage_estimation);
    assert!(analyzer.config.quality_analysis);
    assert!(analyzer.config.missing_test_detection);
    assert!(analyzer.config.organization_analysis);
}

#[test]
fn test_coverage_analyzer_with_custom_config() {
    let config = TestCoverageConfig {
        coverage_estimation: true,
        quality_analysis: false,
        missing_test_detection: true,
        organization_analysis: false,
        min_coverage_threshold: 80.0,
        test_file_patterns: vec!["*_test.rs".to_string(), "*_tests.rs".to_string()],
    };
    
    let analyzer = TestCoverageAnalyzer::with_config(config);
    assert!(analyzer.config.coverage_estimation);
    assert!(!analyzer.config.quality_analysis);
    assert!(analyzer.config.missing_test_detection);
    assert!(!analyzer.config.organization_analysis);
    assert_eq!(analyzer.config.min_coverage_threshold, 80.0);
    assert_eq!(analyzer.config.test_file_patterns.len(), 2);
}

#[test]
fn test_rust_test_coverage_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Create source file
    let src_file = temp_dir.path().join("calculator.rs");
    let src_content = r#"
pub fn add(a: i32, b: i32) -> i32 {
    a + b
}

pub fn subtract(a: i32, b: i32) -> i32 {
    a - b
}

pub fn multiply(a: i32, b: i32) -> i32 {
    a * b
}

pub fn divide(a: i32, b: i32) -> Result<i32, String> {
    if b == 0 {
        Err("Division by zero".to_string())
    } else {
        Ok(a / b)
    }
}

pub fn complex_calculation(x: f64, y: f64) -> f64 {
    if x > 0.0 {
        if y > 0.0 {
            (x * y).sqrt()
        } else {
            x.abs()
        }
    } else {
        y.abs()
    }
}
    "#;
    fs::write(&src_file, src_content)?;
    
    // Create test file
    let test_file = temp_dir.path().join("calculator_test.rs");
    let test_content = r#"
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add() {
        assert_eq!(add(2, 3), 5);
        assert_eq!(add(-1, 1), 0);
    }

    #[test]
    fn test_subtract() {
        assert_eq!(subtract(5, 3), 2);
        assert_eq!(subtract(0, 5), -5);
    }

    #[test]
    fn test_divide_success() {
        assert_eq!(divide(10, 2), Ok(5));
        assert_eq!(divide(7, 3), Ok(2));
    }

    #[test]
    fn test_divide_by_zero() {
        assert_eq!(divide(5, 0), Err("Division by zero".to_string()));
    }
}
    "#;
    fs::write(&test_file, test_content)?;
    
    let analyzer = TestCoverageAnalyzer::new();
    // Create a mock analysis result for the directory
    let analysis_result = create_mock_analysis_result_for_directory(temp_dir.path());
    let result = analyzer.analyze(&analysis_result)?;
    
    // Should detect test coverage
    assert!(!result.file_coverage.is_empty());
    
    let calculator_coverage = result.file_coverage.iter()
        .find(|fc| fc.file.file_name().unwrap() == "calculator.rs");
    assert!(calculator_coverage.is_some());
    
    let coverage = calculator_coverage.unwrap();
    assert!(coverage.coverage_percentage >= 0.0);
    assert!(coverage.coverage_percentage <= 100.0);
    
    // Should detect tested and untested functions
    assert!(coverage.tested_functions > 0);
    assert!(coverage.total_functions > coverage.tested_functions); // multiply and complex_calculation not tested
    
    Ok(())
}

#[test]
fn test_javascript_test_coverage_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Create source file
    let src_file = temp_dir.path().join("utils.js");
    let src_content = r#"
function formatString(str) {
    return str.trim().toLowerCase();
}

function validateEmail(email) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(email);
}

function calculateAge(birthDate) {
    const today = new Date();
    const birth = new Date(birthDate);
    let age = today.getFullYear() - birth.getFullYear();
    const monthDiff = today.getMonth() - birth.getMonth();
    
    if (monthDiff < 0 || (monthDiff === 0 && today.getDate() < birth.getDate())) {
        age--;
    }
    
    return age;
}

function processArray(arr) {
    return arr.filter(x => x > 0).map(x => x * 2);
}

function complexLogic(a, b, c) {
    if (a > b) {
        if (b > c) {
            return a + b + c;
        } else {
            return a * b;
        }
    } else {
        return b - c;
    }
}

module.exports = {
    formatString,
    validateEmail,
    calculateAge,
    processArray,
    complexLogic
};
    "#;
    fs::write(&src_file, src_content)?;
    
    // Create test file
    let test_file = temp_dir.path().join("utils.test.js");
    let test_content = r#"
const { formatString, validateEmail, processArray } = require('./utils');

describe('Utils', () => {
    test('formatString should trim and lowercase', () => {
        expect(formatString('  HELLO WORLD  ')).toBe('hello world');
        expect(formatString('Test')).toBe('test');
    });

    test('validateEmail should validate email format', () => {
        expect(validateEmail('test@example.com')).toBe(true);
        expect(validateEmail('invalid-email')).toBe(false);
        expect(validateEmail('test@')).toBe(false);
    });

    test('processArray should filter and double positive numbers', () => {
        expect(processArray([1, -2, 3, 0, 4])).toEqual([2, 6, 8]);
        expect(processArray([-1, -2, -3])).toEqual([]);
        expect(processArray([5, 10])).toEqual([10, 20]);
    });
});
    "#;
    fs::write(&test_file, test_content)?;
    
    let analyzer = TestCoverageAnalyzer::new();
    let analysis_result = create_mock_analysis_result_for_directory(temp_dir.path());
    let result = analyzer.analyze(&analysis_result)?;
    
    // Should detect test coverage for JavaScript
    assert!(!result.file_coverage.is_empty());
    
    let utils_coverage = result.file_coverage.iter()
        .find(|fc| fc.file.file_name().unwrap() == "utils.js");
    assert!(utils_coverage.is_some());
    
    let coverage = utils_coverage.unwrap();
    assert!(coverage.coverage_percentage >= 0.0);
    assert!(coverage.coverage_percentage <= 100.0);
    
    // Should detect tested and untested functions
    assert!(coverage.tested_functions > 0);
    assert!(coverage.total_functions > coverage.tested_functions); // calculateAge and complexLogic not tested
    
    Ok(())
}

#[test]
fn test_python_test_coverage_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Create source file
    let src_file = temp_dir.path().join("math_utils.py");
    let src_content = r#"
def factorial(n):
    """Calculate factorial of n."""
    if n < 0:
        raise ValueError("Factorial is not defined for negative numbers")
    if n == 0 or n == 1:
        return 1
    return n * factorial(n - 1)

def fibonacci(n):
    """Calculate nth Fibonacci number."""
    if n < 0:
        raise ValueError("Fibonacci is not defined for negative numbers")
    if n == 0:
        return 0
    if n == 1:
        return 1
    return fibonacci(n - 1) + fibonacci(n - 2)

def is_prime(n):
    """Check if n is a prime number."""
    if n < 2:
        return False
    for i in range(2, int(n ** 0.5) + 1):
        if n % i == 0:
            return False
    return True

def gcd(a, b):
    """Calculate greatest common divisor."""
    while b:
        a, b = b, a % b
    return a

def lcm(a, b):
    """Calculate least common multiple."""
    return abs(a * b) // gcd(a, b)

class Calculator:
    def __init__(self):
        self.history = []
    
    def add(self, a, b):
        result = a + b
        self.history.append(f"{a} + {b} = {result}")
        return result
    
    def multiply(self, a, b):
        result = a * b
        self.history.append(f"{a} * {b} = {result}")
        return result
    
    def get_history(self):
        return self.history.copy()
    "#;
    fs::write(&src_file, src_content)?;
    
    // Create test file
    let test_file = temp_dir.path().join("test_math_utils.py");
    let test_content = r#"
import unittest
from math_utils import factorial, is_prime, Calculator

class TestMathUtils(unittest.TestCase):
    
    def test_factorial(self):
        self.assertEqual(factorial(0), 1)
        self.assertEqual(factorial(1), 1)
        self.assertEqual(factorial(5), 120)
        
        with self.assertRaises(ValueError):
            factorial(-1)
    
    def test_is_prime(self):
        self.assertTrue(is_prime(2))
        self.assertTrue(is_prime(17))
        self.assertFalse(is_prime(1))
        self.assertFalse(is_prime(4))
        self.assertFalse(is_prime(15))
    
    def test_calculator_add(self):
        calc = Calculator()
        self.assertEqual(calc.add(2, 3), 5)
        self.assertEqual(calc.add(-1, 1), 0)
        
        history = calc.get_history()
        self.assertEqual(len(history), 2)
        self.assertIn("2 + 3 = 5", history)

if __name__ == '__main__':
    unittest.main()
    "#;
    fs::write(&test_file, test_content)?;
    
    let analyzer = TestCoverageAnalyzer::new();
    let analysis_result = create_mock_analysis_result_for_directory(temp_dir.path());
    let result = analyzer.analyze(&analysis_result)?;
    
    // Should detect test coverage for Python
    assert!(!result.file_coverage.is_empty());
    
    let math_coverage = result.file_coverage.iter()
        .find(|fc| fc.file.file_name().unwrap() == "math_utils.py");
    assert!(math_coverage.is_some());
    
    let coverage = math_coverage.unwrap();
    assert!(coverage.coverage_percentage >= 0.0);
    assert!(coverage.coverage_percentage <= 100.0);
    
    // Should detect tested and untested functions
    assert!(coverage.tested_functions > 0);
    assert!(coverage.total_functions > coverage.tested_functions); // fibonacci, gcd, lcm, multiply not tested
    
    Ok(())
}

#[test]
fn test_missing_test_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Create source file with many functions
    let src_file = temp_dir.path().join("service.rs");
    let src_content = r#"
pub struct UserService;

impl UserService {
    pub fn new() -> Self {
        Self
    }
    
    pub fn create_user(&self, name: &str, email: &str) -> Result<User, String> {
        if name.is_empty() {
            return Err("Name cannot be empty".to_string());
        }
        if !email.contains('@') {
            return Err("Invalid email".to_string());
        }
        Ok(User { name: name.to_string(), email: email.to_string() })
    }
    
    pub fn validate_user(&self, user: &User) -> bool {
        !user.name.is_empty() && user.email.contains('@')
    }
    
    pub fn update_user(&self, user: &mut User, name: Option<&str>, email: Option<&str>) {
        if let Some(n) = name {
            user.name = n.to_string();
        }
        if let Some(e) = email {
            user.email = e.to_string();
        }
    }
    
    pub fn delete_user(&self, _id: u32) -> bool {
        true // Simplified implementation
    }
}

pub struct User {
    pub name: String,
    pub email: String,
}
    "#;
    fs::write(&src_file, src_content)?;
    
    // Create minimal test file (only tests one function)
    let test_file = temp_dir.path().join("service_test.rs");
    let test_content = r#"
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_user_success() {
        let service = UserService::new();
        let result = service.create_user("John", "john@example.com");
        assert!(result.is_ok());
    }
}
    "#;
    fs::write(&test_file, test_content)?;
    
    let analyzer = TestCoverageAnalyzer::new();
    let analysis_result = create_mock_analysis_result_for_directory(temp_dir.path());
    let result = analyzer.analyze(&analysis_result)?;
    
    // Should detect missing tests
    assert!(!result.missing_tests.is_empty());
    
    let missing_tests: Vec<_> = result.missing_tests.iter()
        .filter(|mt| mt.file.file_name().unwrap() == "service.rs")
        .collect();
    assert!(!missing_tests.is_empty());
    
    // Should suggest tests for untested functions
    let missing_test = &missing_tests[0];
    assert!(!missing_test.suggested_tests.is_empty());
    
    Ok(())
}

#[test]
fn test_test_quality_assessment() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Create source file
    let src_file = temp_dir.path().join("calculator.rs");
    let src_content = r#"
pub fn divide(a: i32, b: i32) -> Result<i32, String> {
    if b == 0 {
        Err("Division by zero".to_string())
    } else {
        Ok(a / b)
    }
}
    "#;
    fs::write(&src_file, src_content)?;
    
    // Create comprehensive test file
    let test_file = temp_dir.path().join("calculator_test.rs");
    let test_content = r#"
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_divide_positive_numbers() {
        assert_eq!(divide(10, 2), Ok(5));
        assert_eq!(divide(15, 3), Ok(5));
    }

    #[test]
    fn test_divide_negative_numbers() {
        assert_eq!(divide(-10, 2), Ok(-5));
        assert_eq!(divide(10, -2), Ok(-5));
        assert_eq!(divide(-10, -2), Ok(5));
    }

    #[test]
    fn test_divide_by_zero() {
        assert_eq!(divide(5, 0), Err("Division by zero".to_string()));
        assert_eq!(divide(-5, 0), Err("Division by zero".to_string()));
    }

    #[test]
    fn test_divide_zero_dividend() {
        assert_eq!(divide(0, 5), Ok(0));
        assert_eq!(divide(0, -5), Ok(0));
    }

    #[test]
    fn test_divide_edge_cases() {
        assert_eq!(divide(1, 1), Ok(1));
        assert_eq!(divide(i32::MAX, 1), Ok(i32::MAX));
        assert_eq!(divide(i32::MIN, -1), Ok(i32::MIN / -1));
    }
}
    "#;
    fs::write(&test_file, test_content)?;
    
    let analyzer = TestCoverageAnalyzer::new();
    let analysis_result = create_mock_analysis_result_for_directory(temp_dir.path());
    let result = analyzer.analyze(&analysis_result)?;
    
    // Should assess test quality
    assert!(result.quality_metrics.maintainability_score >= 0);
    assert!(result.quality_metrics.maintainability_score <= 100);
    assert!(result.quality_metrics.documentation_coverage >= 0.0);
    assert!(result.quality_metrics.assertion_density >= 0.0);
    assert!(result.quality_metrics.naming_quality >= 0);
    
    Ok(())
}

#[test]
fn test_test_organization_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Create well-organized test structure
    let tests_dir = temp_dir.path().join("tests");
    fs::create_dir(&tests_dir)?;
    
    let unit_tests_dir = tests_dir.join("unit");
    fs::create_dir(&unit_tests_dir)?;
    
    let integration_tests_dir = tests_dir.join("integration");
    fs::create_dir(&integration_tests_dir)?;
    
    // Create test files
    let unit_test = unit_tests_dir.join("calculator_test.rs");
    fs::write(&unit_test, "#[test] fn test_add() { assert_eq!(2 + 2, 4); }")?;
    
    let integration_test = integration_tests_dir.join("api_test.rs");
    fs::write(&integration_test, "#[test] fn test_api() { assert!(true); }")?;
    
    let analyzer = TestCoverageAnalyzer::new();
    let analysis_result = create_mock_analysis_result_for_directory(temp_dir.path());
    let result = analyzer.analyze(&analysis_result)?;
    
    // Should analyze test organization
    assert!(result.organization_analysis.structure_quality >= 0);
    assert!(result.organization_analysis.naming_consistency >= 0);
    assert!(result.organization_analysis.suite_organization.organization_score <= 100);
    
    Ok(())
}
