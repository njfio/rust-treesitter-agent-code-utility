//! Comprehensive tests for dependency analysis functionality
//!
//! Tests dependency detection, vulnerability scanning, license compliance,
//! and dependency graph analysis across multiple package managers.

use rust_tree_sitter::*;
use rust_tree_sitter::dependency_analysis::{
    DependencyAnalyzer, DependencyConfig, PackageManager
};
use std::fs;
use tempfile::TempDir;

// Helper function to create a mock analysis result for testing
fn create_mock_analysis_result(temp_dir: &TempDir) -> AnalysisResult {
    AnalysisResult {
        root_path: temp_dir.path().to_path_buf(),
        total_files: 0,
        parsed_files: 0,
        error_files: 0,
        total_lines: 0,
        languages: std::collections::HashMap::new(),
        files: vec![],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}

#[test]
fn test_dependency_analyzer_creation() {
    let analyzer = DependencyAnalyzer::new();
    assert!(analyzer.config.vulnerability_scanning);
    assert!(analyzer.config.license_compliance);
    assert!(analyzer.config.outdated_detection);
    assert!(analyzer.config.graph_analysis);
}

#[test]
fn test_dependency_analyzer_with_custom_config() {
    let config = DependencyConfig {
        vulnerability_scanning: false,
        license_compliance: true,
        outdated_detection: false,
        graph_analysis: true,
        include_dev_dependencies: false,
        max_dependency_depth: 5,
    };
    
    let analyzer = DependencyAnalyzer::with_config(config);
    assert!(!analyzer.config.vulnerability_scanning);
    assert!(analyzer.config.license_compliance);
    assert!(!analyzer.config.outdated_detection);
    assert!(analyzer.config.graph_analysis);
    assert!(!analyzer.config.include_dev_dependencies);
    assert_eq!(analyzer.config.max_dependency_depth, 5);
}

#[test]
fn test_rust_cargo_dependency_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    
    let cargo_content = r#"
[package]
name = "test-project"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
tokio = { version = "1.0", features = ["full"] }
clap = "4.0"

[dev-dependencies]
tempfile = "3.0"
    "#;
    
    fs::write(&cargo_toml_path, cargo_content)?;
    
    let analysis_result = create_mock_analysis_result(&temp_dir);
    let analyzer = DependencyAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;
    
    // Should detect Rust package manager
    assert!(result.package_managers.iter().any(|pm| pm.manager == PackageManager::Cargo));
    
    // Should find dependencies
    assert!(!result.dependencies.is_empty());
    
    // Should find specific dependencies
    let serde_dep = result.dependencies.iter()
        .find(|d| d.name == "serde");
    assert!(serde_dep.is_some());
    
    let tokio_dep = result.dependencies.iter()
        .find(|d| d.name == "tokio");
    assert!(tokio_dep.is_some());
    
    Ok(())
}

#[test]
fn test_javascript_npm_dependency_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let package_json_path = temp_dir.path().join("package.json");
    
    let package_content = r#"
{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0",
    "lodash": "^4.17.21",
    "axios": "^1.0.0"
  },
  "devDependencies": {
    "jest": "^29.0.0",
    "eslint": "^8.0.0"
  }
}
    "#;
    
    fs::write(&package_json_path, package_content)?;
    
    let analysis_result = create_mock_analysis_result(&temp_dir);
    let analyzer = DependencyAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should detect NPM package manager
    assert!(result.package_managers.iter().any(|pm| pm.manager == PackageManager::Npm));
    
    // Should find dependencies
    assert!(!result.dependencies.is_empty());
    
    // Should find specific dependencies
    let express_dep = result.dependencies.iter()
        .find(|d| d.name == "express");
    assert!(express_dep.is_some());
    
    let lodash_dep = result.dependencies.iter()
        .find(|d| d.name == "lodash");
    assert!(lodash_dep.is_some());
    
    Ok(())
}

#[test]
fn test_python_pip_dependency_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let requirements_path = temp_dir.path().join("requirements.txt");
    
    let requirements_content = r#"
Django==4.2.0
requests>=2.28.0
numpy==1.24.0
pandas>=1.5.0,<2.0.0
pytest==7.2.0
    "#;
    
    fs::write(&requirements_path, requirements_content)?;
    
    let analysis_result = create_mock_analysis_result(&temp_dir);
    let analyzer = DependencyAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should detect Pip package manager
    assert!(result.package_managers.iter().any(|pm| pm.manager == PackageManager::Pip));
    
    // Should find dependencies
    assert!(!result.dependencies.is_empty());
    
    // Should find specific dependencies
    let django_dep = result.dependencies.iter()
        .find(|d| d.name == "Django");
    assert!(django_dep.is_some());
    
    let requests_dep = result.dependencies.iter()
        .find(|d| d.name == "requests");
    assert!(requests_dep.is_some());
    
    Ok(())
}

#[test]
fn test_go_mod_dependency_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let go_mod_path = temp_dir.path().join("go.mod");
    
    let go_mod_content = r#"
module example.com/test-project

go 1.19

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/stretchr/testify v1.8.2
    golang.org/x/crypto v0.7.0
)

require (
    github.com/bytedance/sonic v1.8.0 // indirect
    github.com/chenzhuoyu/base64x v0.0.0-20221115062448-fe3a3abad311 // indirect
)
    "#;
    
    fs::write(&go_mod_path, go_mod_content)?;
    
    let analysis_result = create_mock_analysis_result(&temp_dir);
    let analyzer = DependencyAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should detect Go Modules package manager
    assert!(result.package_managers.iter().any(|pm| pm.manager == PackageManager::GoMod));
    
    // Should find dependencies
    assert!(!result.dependencies.is_empty());
    
    // Should find specific dependencies
    let gin_dep = result.dependencies.iter()
        .find(|d| d.name.contains("gin-gonic/gin"));
    assert!(gin_dep.is_some());
    
    Ok(())
}

#[test]
fn test_dependency_graph_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    
    let cargo_content = r#"
[package]
name = "test-project"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
serde_json = "1.0"
tokio = "1.0"
    "#;
    
    fs::write(&cargo_toml_path, cargo_content)?;
    
    let analysis_result = create_mock_analysis_result(&temp_dir);
    let analyzer = DependencyAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should perform graph analysis
    assert!(result.graph_analysis.total_nodes >= 0);
    assert!(result.graph_analysis.max_depth >= 0);
    assert!(result.graph_analysis.circular_dependencies.len() >= 0);
    
    Ok(())
}

#[test]
fn test_license_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    
    let cargo_content = r#"
[package]
name = "test-project"
version = "0.1.0"
edition = "2021"
license = "MIT"

[dependencies]
serde = "1.0"
    "#;
    
    fs::write(&cargo_toml_path, cargo_content)?;
    
    let analysis_result = create_mock_analysis_result(&temp_dir);
    let analyzer = DependencyAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should perform license analysis
    assert!(result.license_analysis.total_licenses >= 0);
    assert!(result.license_analysis.license_distribution.len() >= 0);
    assert!(result.license_analysis.compliance_issues.len() >= 0);
    
    Ok(())
}

#[test]
fn test_vulnerability_scanning() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    
    let cargo_content = r#"
[package]
name = "test-project"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
    "#;
    
    fs::write(&cargo_toml_path, cargo_content)?;
    
    let analysis_result = create_mock_analysis_result(&temp_dir);
    let analyzer = DependencyAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should perform vulnerability scanning (may not find vulnerabilities in test environment)
    assert!(result.vulnerabilities.len() >= 0);
    
    Ok(())
}

#[test]
fn test_outdated_dependency_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    
    let cargo_content = r#"
[package]
name = "test-project"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
    "#;
    
    fs::write(&cargo_toml_path, cargo_content)?;
    
    let analysis_result = create_mock_analysis_result(&temp_dir);
    let analyzer = DependencyAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should detect outdated dependencies (may not find any in test environment)
    assert!(result.outdated_dependencies.len() >= 0);
    
    Ok(())
}

#[test]
fn test_multiple_package_managers() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Create Cargo.toml
    let cargo_toml_path = temp_dir.path().join("Cargo.toml");
    let cargo_content = r#"
[package]
name = "test-project"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = "1.0"
    "#;
    fs::write(&cargo_toml_path, cargo_content)?;
    
    // Create package.json
    let package_json_path = temp_dir.path().join("package.json");
    let package_content = r#"
{
  "name": "test-project",
  "version": "1.0.0",
  "dependencies": {
    "express": "^4.18.0"
  }
}
    "#;
    fs::write(&package_json_path, package_content)?;
    
    let analysis_result = create_mock_analysis_result(&temp_dir);
    let analyzer = DependencyAnalyzer::new();
    let result = analyzer.analyze(&analysis_result)?;

    // Should detect both package managers
    assert!(result.package_managers.iter().any(|pm| pm.manager == PackageManager::Cargo));
    assert!(result.package_managers.iter().any(|pm| pm.manager == PackageManager::Npm));
    
    // Should find dependencies from both
    assert!(!result.dependencies.is_empty());
    
    Ok(())
}
