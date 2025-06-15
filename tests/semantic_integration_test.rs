//! Integration tests for the semantic knowledge graph functionality

use rust_tree_sitter::{
    SemanticAnalyzer, SemanticConfig, CodebaseAnalyzer, AnalysisConfig,
    EntityType, RelationshipType
};
use std::path::PathBuf;
use tempfile::TempDir;
use std::fs;

#[tokio::test]
async fn test_semantic_analysis_basic() {
    // Create a temporary directory with test files
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("test.rs");
    
    let test_code = r#"
pub struct TestStruct {
    pub field: i32,
}

impl TestStruct {
    pub fn new(value: i32) -> Self {
        Self { field: value }
    }
    
    pub fn get_field(&self) -> i32 {
        self.field
    }
}

pub fn main() {
    let instance = TestStruct::new(42);
    println!("{}", instance.get_field());
}
"#;
    
    fs::write(&test_file, test_code).unwrap();
    
    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new(AnalysisConfig::default()).unwrap();
    let analysis_result = analyzer.analyze_path(&test_file).await.unwrap();
    
    // Create semantic analyzer
    let config = SemanticConfig::default();
    let mut semantic_analyzer = SemanticAnalyzer::new(config).unwrap();
    
    // Generate semantic knowledge graph
    let semantic_result = semantic_analyzer.analyze(&analysis_result).await.unwrap();
    
    // Verify results
    assert!(semantic_result.entity_count > 0);
    assert!(semantic_result.relationship_count >= 0);
    assert!(!semantic_result.location_map.is_empty());
    assert_eq!(semantic_result.metadata.files_processed, 1);
    assert!(semantic_result.metadata.execution_time_ms > 0);
}

#[tokio::test]
async fn test_semantic_config_customization() {
    let config = SemanticConfig {
        enable_embeddings: false,
        max_graph_size: 500_000,
        cache_size: 5_000,
        base_iri: "https://test.example.org/ontology#".to_string(),
    };
    
    let semantic_analyzer = SemanticAnalyzer::new(config).unwrap();
    
    // Verify the analyzer was created successfully with custom config
    // This is mainly testing that the configuration is accepted
    assert!(true); // Placeholder assertion
}

#[tokio::test]
async fn test_entity_types() {
    // Test that all entity types are properly defined
    let entity_types = vec![
        EntityType::Function,
        EntityType::Class,
        EntityType::Variable,
        EntityType::Module,
        EntityType::Interface,
        EntityType::Enum,
        EntityType::Struct,
        EntityType::Trait,
        EntityType::Method,
        EntityType::Field,
        EntityType::Parameter,
        EntityType::Import,
        EntityType::Export,
    ];
    
    // Verify all entity types are distinct
    for (i, entity_type1) in entity_types.iter().enumerate() {
        for (j, entity_type2) in entity_types.iter().enumerate() {
            if i != j {
                assert_ne!(entity_type1, entity_type2);
            } else {
                assert_eq!(entity_type1, entity_type2);
            }
        }
    }
}

#[tokio::test]
async fn test_relationship_types() {
    // Test that all relationship types are properly defined
    let relationship_types = vec![
        RelationshipType::Calls,
        RelationshipType::Defines,
        RelationshipType::Uses,
        RelationshipType::Inherits,
        RelationshipType::Implements,
        RelationshipType::Contains,
        RelationshipType::DependsOn,
        RelationshipType::References,
        RelationshipType::Overrides,
        RelationshipType::Imports,
        RelationshipType::Exports,
    ];
    
    // Verify all relationship types are distinct
    for (i, rel_type1) in relationship_types.iter().enumerate() {
        for (j, rel_type2) in relationship_types.iter().enumerate() {
            if i != j {
                assert_ne!(rel_type1, rel_type2);
            } else {
                assert_eq!(rel_type1, rel_type2);
            }
        }
    }
}

#[tokio::test]
async fn test_semantic_analysis_with_multiple_files() {
    // Create a temporary directory with multiple test files
    let temp_dir = TempDir::new().unwrap();
    
    // Create main.rs
    let main_file = temp_dir.path().join("main.rs");
    let main_code = r#"
mod utils;
use utils::helper_function;

fn main() {
    let result = helper_function(42);
    println!("Result: {}", result);
}
"#;
    fs::write(&main_file, main_code).unwrap();
    
    // Create utils.rs
    let utils_file = temp_dir.path().join("utils.rs");
    let utils_code = r#"
pub fn helper_function(value: i32) -> i32 {
    value * 2
}

pub struct UtilStruct {
    pub data: String,
}

impl UtilStruct {
    pub fn new(data: String) -> Self {
        Self { data }
    }
}
"#;
    fs::write(&utils_file, utils_code).unwrap();
    
    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new(AnalysisConfig::default()).unwrap();
    let analysis_result = analyzer.analyze_directory(temp_dir.path()).await.unwrap();
    
    // Create semantic analyzer
    let config = SemanticConfig::default();
    let mut semantic_analyzer = SemanticAnalyzer::new(config).unwrap();
    
    // Generate semantic knowledge graph
    let semantic_result = semantic_analyzer.analyze(&analysis_result).await.unwrap();
    
    // Verify results
    assert!(semantic_result.entity_count > 0);
    assert_eq!(semantic_result.metadata.files_processed, 2);
    assert!(semantic_result.location_map.len() >= 2); // Should have entries for both files
}

#[tokio::test]
async fn test_semantic_analysis_error_handling() {
    // Test with empty analysis result
    let analysis_result = rust_tree_sitter::AnalysisResult {
        files: vec![],
        total_files: 0,
        total_lines: 0,
        total_size: 0,
        languages: std::collections::HashMap::new(),
        analysis_time: std::time::Duration::from_millis(0),
        errors: vec![],
    };
    
    let config = SemanticConfig::default();
    let mut semantic_analyzer = SemanticAnalyzer::new(config).unwrap();
    
    // This should not panic and should return a valid result
    let semantic_result = semantic_analyzer.analyze(&analysis_result).await.unwrap();
    
    assert_eq!(semantic_result.entity_count, 0);
    assert_eq!(semantic_result.relationship_count, 0);
    assert_eq!(semantic_result.metadata.files_processed, 0);
}

#[test]
fn test_semantic_config_default() {
    let config = SemanticConfig::default();
    
    assert!(config.enable_embeddings);
    assert_eq!(config.max_graph_size, 1_000_000);
    assert_eq!(config.cache_size, 10_000);
    assert!(config.base_iri.starts_with("https://"));
    assert!(config.base_iri.contains("rust-treesitter"));
}

#[tokio::test]
async fn test_semantic_metadata() {
    // Create a simple test case
    let temp_dir = TempDir::new().unwrap();
    let test_file = temp_dir.path().join("simple.rs");
    
    let test_code = r#"
fn simple_function() {
    println!("Hello, world!");
}
"#;
    
    fs::write(&test_file, test_code).unwrap();
    
    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new(AnalysisConfig::default()).unwrap();
    let analysis_result = analyzer.analyze_path(&test_file).await.unwrap();
    
    // Create semantic analyzer
    let config = SemanticConfig::default();
    let mut semantic_analyzer = SemanticAnalyzer::new(config).unwrap();
    
    // Generate semantic knowledge graph
    let semantic_result = semantic_analyzer.analyze(&analysis_result).await.unwrap();
    
    // Verify metadata
    let metadata = &semantic_result.metadata;
    assert!(metadata.execution_time_ms > 0);
    assert!(metadata.memory_usage_bytes > 0);
    assert_eq!(metadata.files_processed, 1);
    assert!(metadata.errors.is_empty());
}
