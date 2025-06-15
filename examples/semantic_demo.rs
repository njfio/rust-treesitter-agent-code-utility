//! # Semantic Knowledge Graph Demo
//!
//! This example demonstrates the semantic knowledge graph functionality
//! of the rust-treesitter library.

use rust_tree_sitter::{
    SemanticAnalyzer, SemanticConfig, EntityType, RelationshipType
};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("🧠 Semantic Knowledge Graph Demo");
    println!("================================");
    
    // Create semantic analyzer with default configuration
    let config = SemanticConfig::default();
    println!("📋 Configuration:");
    println!("  - Enable embeddings: {}", config.enable_embeddings);
    println!("  - Max graph size: {}", config.max_graph_size);
    println!("  - Cache size: {}", config.cache_size);
    println!("  - Base IRI: {}", config.base_iri);
    
    let _semantic_analyzer = SemanticAnalyzer::new(config)?;
    println!("✅ Semantic analyzer created successfully");
    
    // Create a mock analysis result for demonstration
    let analysis_result = create_mock_analysis_result();
    println!("📊 Created mock analysis result with {} files", analysis_result.files.len());
    
    // This would normally work with real analysis results:
    // let semantic_result = semantic_analyzer.analyze(&analysis_result).await?;
    
    // For now, demonstrate the types and configuration
    demonstrate_entity_types();
    demonstrate_relationship_types();
    
    println!("🎉 Demo completed successfully!");
    
    Ok(())
}

fn create_mock_analysis_result() -> rust_tree_sitter::AnalysisResult {
    // Create a minimal mock analysis result using the default implementation
    rust_tree_sitter::AnalysisResult::default()
}

fn demonstrate_entity_types() {
    println!("\n🏷️  Entity Types Supported:");
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
    
    for (i, entity_type) in entity_types.iter().enumerate() {
        println!("  {}. {:?}", i + 1, entity_type);
    }
}

fn demonstrate_relationship_types() {
    println!("\n🔗 Relationship Types Supported:");
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
    
    for (i, relationship_type) in relationship_types.iter().enumerate() {
        println!("  {}. {:?}", i + 1, relationship_type);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_config_creation() {
        let config = SemanticConfig::default();
        assert!(config.enable_embeddings);
        assert_eq!(config.max_graph_size, 1_000_000);
        assert_eq!(config.cache_size, 10_000);
        assert!(config.base_iri.starts_with("https://"));
    }

    #[test]
    fn test_semantic_analyzer_creation() {
        let config = SemanticConfig::default();
        let result = SemanticAnalyzer::new(config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_entity_types_completeness() {
        // Verify all entity types are distinct
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
        
        // Check that all types are unique
        let mut unique_types = std::collections::HashSet::new();
        for entity_type in &entity_types {
            assert!(unique_types.insert(entity_type), "Duplicate entity type found: {:?}", entity_type);
        }
        
        assert_eq!(unique_types.len(), entity_types.len());
    }

    #[test]
    fn test_relationship_types_completeness() {
        // Verify all relationship types are distinct
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
        
        // Check that all types are unique
        let mut unique_types = std::collections::HashSet::new();
        for relationship_type in &relationship_types {
            assert!(unique_types.insert(relationship_type), "Duplicate relationship type found: {:?}", relationship_type);
        }
        
        assert_eq!(unique_types.len(), relationship_types.len());
    }

    #[tokio::test]
    async fn test_mock_analysis_result() {
        let analysis_result = create_mock_analysis_result();
        assert_eq!(analysis_result.parsed_files, 0);
        assert_eq!(analysis_result.error_files, 0);
        assert_eq!(analysis_result.symbols.len(), 0);
        assert_eq!(analysis_result.dependencies.len(), 0);
    }
}
