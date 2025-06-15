//! # Semantic Graph Builder Module
//!
//! This module handles the conversion of Abstract Syntax Trees (ASTs) from tree-sitter
//! into RDF knowledge graphs. It extracts code entities, relationships, and semantic
//! information to create a comprehensive representation of the codebase structure.

use crate::error::{Error, Result};
use crate::analyzer::{AnalysisResult, FileInfo, Symbol};
use crate::semantic::{
    SemanticConfig, EntityType, RelationshipType, CodeEntity, CodeRelationship, EntityLocation
};
use crate::semantic::ontology::CodeOntology;
use crate::tree::{Node, SyntaxTree};
use crate::parser::Parser;
use crate::languages::Language;
use oxrdf::{Graph, Triple, NamedNode, Subject, Term, Literal};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use rayon::prelude::*;

/// Semantic graph builder that converts ASTs to RDF knowledge graphs
#[derive(Debug)]
pub struct SemanticGraphBuilder {
    /// Code ontology for RDF vocabulary
    ontology: CodeOntology,
    /// Configuration for graph building
    config: SemanticConfig,
    /// Entity extractors for different languages
    extractors: HashMap<Language, Box<dyn EntityExtractor + Send + Sync>>,
}

/// Trait for extracting entities from language-specific ASTs
pub trait EntityExtractor: std::fmt::Debug {
    /// Extract entities from a syntax tree
    fn extract_entities(&self, tree: &SyntaxTree, file_path: &str) -> Result<Vec<CodeEntity>>;
    
    /// Extract relationships between entities
    fn extract_relationships(&self, tree: &SyntaxTree, entities: &[CodeEntity]) -> Result<Vec<CodeRelationship>>;
    
    /// Get the language this extractor handles
    fn language(&self) -> Language;
}

/// Context for building the semantic graph
#[derive(Debug)]
struct BuildContext {
    /// Current file being processed
    current_file: String,
    /// Mapping from entity names to IRIs
    entity_map: HashMap<String, NamedNode>,
    /// All extracted entities
    entities: Vec<CodeEntity>,
    /// All extracted relationships
    relationships: Vec<CodeRelationship>,
}

impl SemanticGraphBuilder {
    /// Create a new semantic graph builder
    pub fn new(ontology: CodeOntology, config: SemanticConfig) -> Result<Self> {
        let mut extractors: HashMap<Language, Box<dyn EntityExtractor + Send + Sync>> = HashMap::new();
        
        // Register language-specific extractors
        extractors.insert(Language::Rust, Box::new(RustEntityExtractor::new()));
        extractors.insert(Language::JavaScript, Box::new(JavaScriptEntityExtractor::new()));
        extractors.insert(Language::Python, Box::new(PythonEntityExtractor::new()));
        extractors.insert(Language::TypeScript, Box::new(TypeScriptEntityExtractor::new()));
        extractors.insert(Language::Go, Box::new(GoEntityExtractor::new()));
        extractors.insert(Language::C, Box::new(CEntityExtractor::new()));
        extractors.insert(Language::Cpp, Box::new(CppEntityExtractor::new()));

        Ok(Self {
            ontology,
            config,
            extractors,
        })
    }

    /// Build a knowledge graph from analysis results
    pub async fn build_graph(&self, analysis_result: &AnalysisResult) -> Result<Graph> {
        let mut graph = Graph::new();
        let mut context = BuildContext {
            current_file: String::new(),
            entity_map: HashMap::new(),
            entities: Vec::new(),
            relationships: Vec::new(),
        };

        // Process files in parallel for better performance
        let file_results: Result<Vec<_>> = analysis_result.files
            .par_iter()
            .map(|file_info| self.process_file(file_info))
            .collect();

        let file_results = file_results?;

        // Merge results from all files
        for (entities, relationships) in file_results {
            context.entities.extend(entities);
            context.relationships.extend(relationships);
        }

        // Build entity map for relationship resolution
        for entity in &context.entities {
            let key = format!("{}:{}", entity.location.file_path, entity.id);
            context.entity_map.insert(key, entity.iri.clone());
        }

        // Convert entities to RDF triples
        for entity in &context.entities {
            self.add_entity_triples(&mut graph, entity)?;
        }

        // Convert relationships to RDF triples
        for relationship in &context.relationships {
            self.add_relationship_triple(&mut graph, relationship)?;
        }

        // Add file-level metadata
        for file_info in &analysis_result.files {
            self.add_file_metadata(&mut graph, file_info)?;
        }

        tracing::info!(
            "Built knowledge graph with {} entities and {} relationships",
            context.entities.len(),
            context.relationships.len()
        );

        Ok(graph)
    }

    /// Process a single file and extract entities and relationships
    fn process_file(&self, file_info: &FileInfo) -> Result<(Vec<CodeEntity>, Vec<CodeRelationship>)> {
        // Determine the language from file extension
        let language = crate::detect_language_from_path(&file_info.path.to_string_lossy())
            .ok_or_else(|| Error::UnsupportedLanguage(file_info.language.clone()))?;

        // Get the appropriate extractor
        let extractor = self.extractors.get(&language)
            .ok_or_else(|| Error::UnsupportedLanguage(language.to_string()))?;

        // Parse the file to get the syntax tree
        let mut parser = Parser::new(language)?;
        let source_code = std::fs::read_to_string(&file_info.path)
            .map_err(|e| Error::FileReadError(file_info.path.clone(), e.to_string()))?;
        let tree = parser.parse(&source_code, None)?;

        // Extract entities and relationships
        let entities = extractor.extract_entities(&tree, &file_info.path.to_string_lossy())?;
        let relationships = extractor.extract_relationships(&tree, &entities)?;

        Ok((entities, relationships))
    }

    /// Add RDF triples for a code entity
    fn add_entity_triples(&self, graph: &mut Graph, entity: &CodeEntity) -> Result<()> {
        let subject = Subject::NamedNode(entity.iri.clone());

        // Add type triple
        if let Some(entity_class) = self.ontology.get_entity_class(&entity.entity_type) {
            let type_triple = Triple::new(
                subject.clone(),
                oxrdf::vocab::rdf::TYPE,
                Term::NamedNode(entity_class.clone()),
            );
            graph.insert(&type_triple);
        }

        // Add location information
        let source_file_triple = Triple::new(
            subject.clone(),
            self.ontology.common_properties.source_file.clone(),
            Term::Literal(self.ontology.create_string_literal(&entity.location.file_path)),
        );
        graph.insert(&source_file_triple);

        let line_number_triple = Triple::new(
            subject.clone(),
            self.ontology.common_properties.line_number.clone(),
            Term::Literal(self.ontology.create_integer_literal(entity.location.start_line as i32)),
        );
        graph.insert(&line_number_triple);

        // Add entity properties
        for (property_name, property_value) in &entity.properties {
            if let Ok(property_iri) = NamedNode::new(format!("{}{}", self.ontology.base_iri, property_name)) {
                let property_triple = Triple::new(
                    subject.clone(),
                    property_iri,
                    Term::Literal(self.ontology.create_string_literal(property_value)),
                );
                graph.insert(&property_triple);
            }
        }

        Ok(())
    }

    /// Add RDF triple for a code relationship
    fn add_relationship_triple(&self, graph: &mut Graph, relationship: &CodeRelationship) -> Result<()> {
        if let Some(predicate) = self.ontology.get_relationship_property(&relationship.predicate) {
            let triple = Triple::new(
                Subject::NamedNode(relationship.subject.clone()),
                predicate.clone(),
                Term::NamedNode(relationship.object.clone()),
            );
            graph.insert(&triple);

            // Add confidence score if available
            if relationship.confidence < 1.0 {
                let confidence_property = NamedNode::new(format!("{}confidence", self.ontology.base_iri))
                    .map_err(|e| Error::InvalidIri(e.to_string()))?;
                let confidence_triple = Triple::new(
                    Subject::NamedNode(relationship.subject.clone()),
                    confidence_property,
                    Term::Literal(self.ontology.create_float_literal(relationship.confidence)),
                );
                graph.insert(&confidence_triple);
            }
        }

        Ok(())
    }

    /// Add file-level metadata to the graph
    fn add_file_metadata(&self, graph: &mut Graph, file_info: &FileInfo) -> Result<()> {
        let file_iri = self.ontology.create_file_iri(&file_info.path.to_string_lossy())?;
        let subject = Subject::NamedNode(file_iri);

        // Add file type
        let file_class = NamedNode::new(format!("{}File", self.ontology.base_iri))
            .map_err(|e| Error::InvalidIri(e.to_string()))?;
        let type_triple = Triple::new(
            subject.clone(),
            oxrdf::vocab::rdf::TYPE,
            Term::NamedNode(file_class),
        );
        graph.insert(&type_triple);

        // Add language information
        let language_triple = Triple::new(
            subject.clone(),
            self.ontology.common_properties.language.clone(),
            Term::Literal(self.ontology.create_string_literal(&file_info.language)),
        );
        graph.insert(&language_triple);

        // Add size information
        let size_property = NamedNode::new(format!("{}size", self.ontology.base_iri))
            .map_err(|e| Error::InvalidIri(e.to_string()))?;
        let size_triple = Triple::new(
            subject.clone(),
            size_property,
            Term::Literal(self.ontology.create_integer_literal(file_info.size as i32)),
        );
        graph.insert(&size_triple);

        // Add line count
        let lines_property = NamedNode::new(format!("{}lines", self.ontology.base_iri))
            .map_err(|e| Error::InvalidIri(e.to_string()))?;
        let lines_triple = Triple::new(
            subject,
            lines_property,
            Term::Literal(self.ontology.create_integer_literal(file_info.lines as i32)),
        );
        graph.insert(&lines_triple);

        Ok(())
    }
}

// Language-specific entity extractors

/// Rust entity extractor
#[derive(Debug)]
struct RustEntityExtractor;

impl RustEntityExtractor {
    fn new() -> Self {
        Self
    }
}

impl EntityExtractor for RustEntityExtractor {
    fn extract_entities(&self, tree: &SyntaxTree, file_path: &str) -> Result<Vec<CodeEntity>> {
        let mut entities = Vec::new();
        let root = tree.root_node();
        
        self.extract_entities_recursive(&root, file_path, &mut entities)?;
        
        Ok(entities)
    }

    fn extract_relationships(&self, tree: &SyntaxTree, entities: &[CodeEntity]) -> Result<Vec<CodeRelationship>> {
        let mut relationships = Vec::new();
        let root = tree.root_node();
        
        self.extract_relationships_recursive(&root, entities, &mut relationships)?;
        
        Ok(relationships)
    }

    fn language(&self) -> Language {
        Language::Rust
    }
}

impl RustEntityExtractor {
    fn extract_entities_recursive(&self, node: &Node, file_path: &str, entities: &mut Vec<CodeEntity>) -> Result<()> {
        match node.kind() {
            "function_item" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let entity = self.create_function_entity(&name_node, file_path)?;
                    entities.push(entity);
                }
            }
            "struct_item" => {
                if let Some(name_node) = node.child_by_field_name("name") {
                    let entity = self.create_struct_entity(&name_node, file_path)?;
                    entities.push(entity);
                }
            }
            "impl_item" => {
                // Extract methods from impl blocks
                for i in 0..node.child_count() {
                    if let Some(child) = node.child(i) {
                        if child.kind() == "function_item" {
                            if let Some(name_node) = child.child_by_field_name("name") {
                                let entity = self.create_method_entity(&name_node, file_path)?;
                                entities.push(entity);
                            }
                        }
                    }
                }
            }
            _ => {}
        }

        // Recursively process child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.extract_entities_recursive(&child, file_path, entities)?;
            }
        }

        Ok(())
    }

    fn extract_relationships_recursive(&self, node: &Node, entities: &[CodeEntity], relationships: &mut Vec<CodeRelationship>) -> Result<()> {
        // Extract function calls
        if node.kind() == "call_expression" {
            if let Some(_function_node) = node.child_by_field_name("function") {
                // Find the calling function and called function
                // This is a simplified implementation
                // In practice, you'd need more sophisticated analysis
            }
        }

        // Recursively process child nodes
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                self.extract_relationships_recursive(&child, entities, relationships)?;
            }
        }

        Ok(())
    }

    fn create_function_entity(&self, name_node: &Node, file_path: &str) -> Result<CodeEntity> {
        let name = name_node.text().unwrap_or("unknown").to_string();
        let id = Uuid::new_v4();
        let iri = NamedNode::new(format!("https://rust-treesitter.org/ontology#entity/{}", id))
            .map_err(|e| Error::InvalidIri(e.to_string()))?;

        let location = EntityLocation {
            file_path: file_path.to_string(),
            start_line: name_node.start_position().row + 1,
            end_line: name_node.end_position().row + 1,
            start_column: name_node.start_position().column,
            end_column: name_node.end_position().column,
        };

        let mut properties = HashMap::new();
        properties.insert("name".to_string(), name);

        Ok(CodeEntity {
            id,
            iri,
            entity_type: EntityType::Function,
            location,
            properties,
        })
    }

    fn create_struct_entity(&self, name_node: &Node, file_path: &str) -> Result<CodeEntity> {
        let name = name_node.text().unwrap_or("unknown").to_string();
        let id = Uuid::new_v4();
        let iri = NamedNode::new(format!("https://rust-treesitter.org/ontology#entity/{}", id))
            .map_err(|e| Error::InvalidIri(e.to_string()))?;

        let location = EntityLocation {
            file_path: file_path.to_string(),
            start_line: name_node.start_position().row + 1,
            end_line: name_node.end_position().row + 1,
            start_column: name_node.start_position().column,
            end_column: name_node.end_position().column,
        };

        let mut properties = HashMap::new();
        properties.insert("name".to_string(), name);

        Ok(CodeEntity {
            id,
            iri,
            entity_type: EntityType::Struct,
            location,
            properties,
        })
    }

    fn create_method_entity(&self, name_node: &Node, file_path: &str) -> Result<CodeEntity> {
        let name = name_node.text().unwrap_or("unknown").to_string();
        let id = Uuid::new_v4();
        let iri = NamedNode::new(format!("https://rust-treesitter.org/ontology#entity/{}", id))
            .map_err(|e| Error::InvalidIri(e.to_string()))?;

        let location = EntityLocation {
            file_path: file_path.to_string(),
            start_line: name_node.start_position().row + 1,
            end_line: name_node.end_position().row + 1,
            start_column: name_node.start_position().column,
            end_column: name_node.end_position().column,
        };

        let mut properties = HashMap::new();
        properties.insert("name".to_string(), name);

        Ok(CodeEntity {
            id,
            iri,
            entity_type: EntityType::Method,
            location,
            properties,
        })
    }
}

// Placeholder implementations for other language extractors
// These would be implemented similarly to RustEntityExtractor

#[derive(Debug)]
struct JavaScriptEntityExtractor;
impl JavaScriptEntityExtractor { fn new() -> Self { Self } }
impl EntityExtractor for JavaScriptEntityExtractor {
    fn extract_entities(&self, _tree: &SyntaxTree, _file_path: &str) -> Result<Vec<CodeEntity>> { Ok(Vec::new()) }
    fn extract_relationships(&self, _tree: &SyntaxTree, _entities: &[CodeEntity]) -> Result<Vec<CodeRelationship>> { Ok(Vec::new()) }
    fn language(&self) -> Language { Language::JavaScript }
}

#[derive(Debug)]
struct PythonEntityExtractor;
impl PythonEntityExtractor { fn new() -> Self { Self } }
impl EntityExtractor for PythonEntityExtractor {
    fn extract_entities(&self, _tree: &SyntaxTree, _file_path: &str) -> Result<Vec<CodeEntity>> { Ok(Vec::new()) }
    fn extract_relationships(&self, _tree: &SyntaxTree, _entities: &[CodeEntity]) -> Result<Vec<CodeRelationship>> { Ok(Vec::new()) }
    fn language(&self) -> Language { Language::Python }
}

#[derive(Debug)]
struct TypeScriptEntityExtractor;
impl TypeScriptEntityExtractor { fn new() -> Self { Self } }
impl EntityExtractor for TypeScriptEntityExtractor {
    fn extract_entities(&self, _tree: &SyntaxTree, _file_path: &str) -> Result<Vec<CodeEntity>> { Ok(Vec::new()) }
    fn extract_relationships(&self, _tree: &SyntaxTree, _entities: &[CodeEntity]) -> Result<Vec<CodeRelationship>> { Ok(Vec::new()) }
    fn language(&self) -> Language { Language::TypeScript }
}

#[derive(Debug)]
struct GoEntityExtractor;
impl GoEntityExtractor { fn new() -> Self { Self } }
impl EntityExtractor for GoEntityExtractor {
    fn extract_entities(&self, _tree: &SyntaxTree, _file_path: &str) -> Result<Vec<CodeEntity>> { Ok(Vec::new()) }
    fn extract_relationships(&self, _tree: &SyntaxTree, _entities: &[CodeEntity]) -> Result<Vec<CodeRelationship>> { Ok(Vec::new()) }
    fn language(&self) -> Language { Language::Go }
}

#[derive(Debug)]
struct CEntityExtractor;
impl CEntityExtractor { fn new() -> Self { Self } }
impl EntityExtractor for CEntityExtractor {
    fn extract_entities(&self, _tree: &SyntaxTree, _file_path: &str) -> Result<Vec<CodeEntity>> { Ok(Vec::new()) }
    fn extract_relationships(&self, _tree: &SyntaxTree, _entities: &[CodeEntity]) -> Result<Vec<CodeRelationship>> { Ok(Vec::new()) }
    fn language(&self) -> Language { Language::C }
}

#[derive(Debug)]
struct CppEntityExtractor;
impl CppEntityExtractor { fn new() -> Self { Self } }
impl EntityExtractor for CppEntityExtractor {
    fn extract_entities(&self, _tree: &SyntaxTree, _file_path: &str) -> Result<Vec<CodeEntity>> { Ok(Vec::new()) }
    fn extract_relationships(&self, _tree: &SyntaxTree, _entities: &[CodeEntity]) -> Result<Vec<CodeRelationship>> { Ok(Vec::new()) }
    fn language(&self) -> Language { Language::Cpp }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rust_extractor_creation() {
        let extractor = RustEntityExtractor::new();
        assert_eq!(extractor.language(), Language::Rust);
    }

    #[test]
    fn test_graph_builder_creation() {
        let ontology = CodeOntology::new("https://test.org/ontology#").unwrap();
        let config = SemanticConfig::default();
        let builder = SemanticGraphBuilder::new(ontology, config).unwrap();
        assert_eq!(builder.extractors.len(), 7); // All supported languages
    }
}
