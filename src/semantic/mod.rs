//! # Semantic Knowledge Graph Module
//!
//! This module provides semantic knowledge graph generation capabilities for code analysis.
//! It transforms Abstract Syntax Trees (ASTs) from tree-sitter into RDF knowledge graphs
//! that capture code entities, relationships, and semantic information.
//!
//! ## Features
//!
//! - AST-to-RDF mapping with configurable ontologies
//! - Code entity extraction (functions, classes, variables, etc.)
//! - Relationship inference (calls, dependencies, inheritance)
//! - Graph storage and querying capabilities
//! - Semantic similarity analysis using embeddings
//!
//! ## Architecture
//!
//! The module is organized into several key components:
//!
//! - `graph_builder`: Core AST-to-RDF mapping logic
//! - `ontology`: Code ontology definitions and management
//! - `storage`: RDF graph storage and persistence
//! - `query`: Graph querying and traversal interfaces
//! - `embeddings`: Code embedding generation for similarity analysis

pub mod graph_builder;
pub mod ontology;
pub mod storage;
pub mod query;
pub mod embeddings;

use crate::error::Result;
use crate::analyzer::AnalysisResult;
use oxrdf::{Graph, NamedNode};
use std::collections::HashMap;
use uuid::Uuid;

/// Main semantic analyzer that orchestrates knowledge graph generation
#[derive(Debug)]
pub struct SemanticAnalyzer {
    graph_builder: graph_builder::SemanticGraphBuilder,
    storage: storage::RdfStore,
    query_engine: query::GraphQueryEngine,
}

/// Configuration for semantic analysis
#[derive(Debug, Clone)]
pub struct SemanticConfig {
    /// Enable embedding generation for similarity analysis
    pub enable_embeddings: bool,
    /// Maximum graph size before triggering cleanup
    pub max_graph_size: usize,
    /// Cache size for frequently accessed entities
    pub cache_size: usize,
    /// Ontology base IRI
    pub base_iri: String,
}

impl Default for SemanticConfig {
    fn default() -> Self {
        Self {
            enable_embeddings: true,
            max_graph_size: 1_000_000,
            cache_size: 10_000,
            base_iri: "https://rust-treesitter.org/ontology#".to_string(),
        }
    }
}

/// Result of semantic analysis containing the knowledge graph and metadata
#[derive(Debug)]
pub struct SemanticAnalysisResult {
    /// The generated RDF knowledge graph
    pub graph: Graph,
    /// Number of entities extracted
    pub entity_count: usize,
    /// Number of relationships discovered
    pub relationship_count: usize,
    /// Mapping from source locations to graph nodes
    pub location_map: HashMap<String, Vec<NamedNode>>,
    /// Analysis metadata
    pub metadata: SemanticMetadata,
}

/// Metadata about the semantic analysis process
#[derive(Debug)]
pub struct SemanticMetadata {
    /// Analysis execution time in milliseconds
    pub execution_time_ms: u64,
    /// Memory usage in bytes
    pub memory_usage_bytes: usize,
    /// Number of files processed
    pub files_processed: usize,
    /// Errors encountered during analysis
    pub errors: Vec<String>,
}

/// Represents a code entity in the knowledge graph
#[derive(Debug, Clone)]
pub struct CodeEntity {
    /// Unique identifier for the entity
    pub id: Uuid,
    /// RDF IRI for the entity
    pub iri: NamedNode,
    /// Entity type (function, class, variable, etc.)
    pub entity_type: EntityType,
    /// Source location information
    pub location: EntityLocation,
    /// Entity properties
    pub properties: HashMap<String, String>,
}

/// Types of code entities that can be extracted
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum EntityType {
    Function,
    Class,
    Variable,
    Module,
    Interface,
    Enum,
    Struct,
    Trait,
    Method,
    Field,
    Parameter,
    Import,
    Export,
}

/// Location information for a code entity
#[derive(Debug, Clone)]
pub struct EntityLocation {
    /// File path
    pub file_path: String,
    /// Start line number (1-based)
    pub start_line: usize,
    /// End line number (1-based)
    pub end_line: usize,
    /// Start column (0-based)
    pub start_column: usize,
    /// End column (0-based)
    pub end_column: usize,
}

/// Represents a relationship between code entities
#[derive(Debug, Clone)]
pub struct CodeRelationship {
    /// Source entity
    pub subject: NamedNode,
    /// Relationship type
    pub predicate: RelationshipType,
    /// Target entity
    pub object: NamedNode,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f32,
}

/// Types of relationships between code entities
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum RelationshipType {
    Calls,
    Defines,
    Uses,
    Inherits,
    Implements,
    Contains,
    DependsOn,
    References,
    Overrides,
    Imports,
    Exports,
}

impl SemanticAnalyzer {
    /// Create a new semantic analyzer with the given configuration
    pub fn new(config: SemanticConfig) -> Result<Self> {
        let ontology = ontology::CodeOntology::new(&config.base_iri)?;
        let graph_builder = graph_builder::SemanticGraphBuilder::new(ontology, config.clone())?;
        let storage = storage::RdfStore::new(config.cache_size)?;
        let query_engine = query::GraphQueryEngine::new()?;

        Ok(Self {
            graph_builder,
            storage,
            query_engine,
        })
    }

    /// Analyze a codebase and generate a semantic knowledge graph
    pub async fn analyze(&mut self, analysis_result: &AnalysisResult) -> Result<SemanticAnalysisResult> {
        let start_time = std::time::Instant::now();
        
        // Build the knowledge graph from the analysis result
        let graph = self.graph_builder.build_graph(analysis_result).await?;
        
        // Store the graph
        self.storage.store_graph(&graph).await?;
        
        // Calculate metadata
        let execution_time_ms = start_time.elapsed().as_millis() as u64;
        let entity_count = self.count_entities(&graph)?;
        let relationship_count = self.count_relationships(&graph)?;
        let location_map = self.build_location_map(&graph)?;
        
        let metadata = SemanticMetadata {
            execution_time_ms,
            memory_usage_bytes: std::mem::size_of_val(&graph),
            files_processed: analysis_result.files.len(),
            errors: Vec::new(),
        };

        Ok(SemanticAnalysisResult {
            graph,
            entity_count,
            relationship_count,
            location_map,
            metadata,
        })
    }

    /// Query the knowledge graph for relationships
    pub async fn query_relationships(
        &self,
        entity_iri: &str,
        depth: u32,
    ) -> Result<Vec<CodeRelationship>> {
        self.query_engine.find_relationships(entity_iri, depth).await
    }

    /// Find similar entities based on semantic similarity
    pub async fn find_similar_entities(
        &self,
        entity_iri: &str,
        threshold: f32,
    ) -> Result<Vec<(NamedNode, f32)>> {
        self.query_engine.find_similar_entities(entity_iri, threshold).await
    }

    // Helper methods
    fn count_entities(&self, graph: &Graph) -> Result<usize> {
        // Count unique subjects in the graph
        let mut entities = std::collections::HashSet::new();
        for triple in graph.iter() {
            if let oxrdf::SubjectRef::NamedNode(node) = triple.subject {
                entities.insert(node.into_owned());
            }
        }
        Ok(entities.len())
    }

    fn count_relationships(&self, graph: &Graph) -> Result<usize> {
        Ok(graph.len())
    }

    fn build_location_map(&self, graph: &Graph) -> Result<HashMap<String, Vec<NamedNode>>> {
        let mut location_map = HashMap::new();
        
        // Extract location information from graph triples
        for triple in graph.iter() {
            if let oxrdf::SubjectRef::NamedNode(subject) = triple.subject {
                // Extract file path from the IRI or properties
                if let Some(file_path) = self.extract_file_path_from_iri(&subject.into_owned()) {
                    location_map
                        .entry(file_path)
                        .or_insert_with(Vec::new)
                        .push(subject.into_owned());
                }
            }
        }
        
        Ok(location_map)
    }

    fn extract_file_path_from_iri(&self, iri: &NamedNode) -> Option<String> {
        // Extract file path from IRI fragment or query parameters
        let iri_str = iri.as_str();
        if let Some(fragment) = iri_str.split('#').nth(1) {
            if let Some(file_part) = fragment.split('/').next() {
                return Some(file_part.to_string());
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_semantic_config_default() {
        let config = SemanticConfig::default();
        assert!(config.enable_embeddings);
        assert_eq!(config.max_graph_size, 1_000_000);
        assert_eq!(config.cache_size, 10_000);
        assert!(config.base_iri.starts_with("https://"));
    }

    #[test]
    fn test_entity_type_equality() {
        assert_eq!(EntityType::Function, EntityType::Function);
        assert_ne!(EntityType::Function, EntityType::Class);
    }

    #[test]
    fn test_relationship_type_equality() {
        assert_eq!(RelationshipType::Calls, RelationshipType::Calls);
        assert_ne!(RelationshipType::Calls, RelationshipType::Defines);
    }
}
