//! # Code Ontology Module
//!
//! This module defines the ontology for representing code entities and relationships
//! in RDF format. It provides a structured vocabulary for describing programming
//! language constructs and their semantic relationships.

use crate::error::{Error, Result};
use crate::semantic::{EntityType, RelationshipType};
use oxrdf::{NamedNode, Literal};
use std::collections::HashMap;

/// Code ontology that defines the vocabulary for representing code in RDF
#[derive(Debug, Clone)]
pub struct CodeOntology {
    /// Base IRI for the ontology
    pub base_iri: String,
    /// Mapping from entity types to RDF classes
    pub entity_classes: HashMap<EntityType, NamedNode>,
    /// Mapping from relationship types to RDF properties
    pub relationship_properties: HashMap<RelationshipType, NamedNode>,
    /// Common RDF properties used in the ontology
    pub common_properties: CommonProperties,
}

/// Common RDF properties used throughout the ontology
#[derive(Debug, Clone)]
pub struct CommonProperties {
    /// Property for source file location
    pub source_file: NamedNode,
    /// Property for line number
    pub line_number: NamedNode,
    /// Property for column number
    pub column_number: NamedNode,
    /// Property for entity name
    pub name: NamedNode,
    /// Property for entity signature
    pub signature: NamedNode,
    /// Property for documentation
    pub documentation: NamedNode,
    /// Property for visibility (public/private)
    pub visibility: NamedNode,
    /// Property for language
    pub language: NamedNode,
    /// Property for complexity metrics
    pub complexity: NamedNode,
}

impl CodeOntology {
    /// Create a new code ontology with the given base IRI
    pub fn new(base_iri: &str) -> Result<Self> {
        let base_iri = base_iri.to_string();
        
        // Create entity class mappings
        let entity_classes = Self::create_entity_classes(&base_iri)?;
        
        // Create relationship property mappings
        let relationship_properties = Self::create_relationship_properties(&base_iri)?;
        
        // Create common properties
        let common_properties = Self::create_common_properties(&base_iri)?;

        Ok(Self {
            base_iri,
            entity_classes,
            relationship_properties,
            common_properties,
        })
    }

    /// Get the RDF class for a given entity type
    pub fn get_entity_class(&self, entity_type: &EntityType) -> Option<&NamedNode> {
        self.entity_classes.get(entity_type)
    }

    /// Get the RDF property for a given relationship type
    pub fn get_relationship_property(&self, relationship_type: &RelationshipType) -> Option<&NamedNode> {
        self.relationship_properties.get(relationship_type)
    }

    /// Create a new entity IRI with the given identifier
    pub fn create_entity_iri(&self, identifier: &str) -> Result<NamedNode> {
        let iri = format!("{}entity/{}", self.base_iri, identifier);
        NamedNode::new(iri).map_err(|e| Error::InvalidIri(e.to_string()))
    }

    /// Create a new file IRI with the given file path
    pub fn create_file_iri(&self, file_path: &str) -> Result<NamedNode> {
        let sanitized_path = file_path.replace(['/', '\\', '.'], "_");
        let iri = format!("{}file/{}", self.base_iri, sanitized_path);
        NamedNode::new(iri).map_err(|e| Error::InvalidIri(e.to_string()))
    }

    /// Create a literal value for the given string
    pub fn create_string_literal(&self, value: &str) -> Literal {
        Literal::new_simple_literal(value)
    }

    /// Create a literal value for the given integer
    pub fn create_integer_literal(&self, value: i32) -> Literal {
        Literal::new_typed_literal(value.to_string(), oxrdf::vocab::xsd::INTEGER)
    }

    /// Create a literal value for the given float
    pub fn create_float_literal(&self, value: f32) -> Literal {
        Literal::new_typed_literal(value.to_string(), oxrdf::vocab::xsd::FLOAT)
    }

    // Private helper methods

    fn create_entity_classes(base_iri: &str) -> Result<HashMap<EntityType, NamedNode>> {
        let mut classes = HashMap::new();

        let entity_mappings = [
            (EntityType::Function, "Function"),
            (EntityType::Class, "Class"),
            (EntityType::Variable, "Variable"),
            (EntityType::Module, "Module"),
            (EntityType::Interface, "Interface"),
            (EntityType::Enum, "Enum"),
            (EntityType::Struct, "Struct"),
            (EntityType::Trait, "Trait"),
            (EntityType::Method, "Method"),
            (EntityType::Field, "Field"),
            (EntityType::Parameter, "Parameter"),
            (EntityType::Import, "Import"),
            (EntityType::Export, "Export"),
        ];

        for (entity_type, class_name) in entity_mappings {
            let iri = format!("{}{}", base_iri, class_name);
            let named_node = NamedNode::new(iri)
                .map_err(|e| Error::InvalidIri(format!("Failed to create IRI for {}: {}", class_name, e)))?;
            classes.insert(entity_type, named_node);
        }

        Ok(classes)
    }

    fn create_relationship_properties(base_iri: &str) -> Result<HashMap<RelationshipType, NamedNode>> {
        let mut properties = HashMap::new();

        let relationship_mappings = [
            (RelationshipType::Calls, "calls"),
            (RelationshipType::Defines, "defines"),
            (RelationshipType::Uses, "uses"),
            (RelationshipType::Inherits, "inherits"),
            (RelationshipType::Implements, "implements"),
            (RelationshipType::Contains, "contains"),
            (RelationshipType::DependsOn, "dependsOn"),
            (RelationshipType::References, "references"),
            (RelationshipType::Overrides, "overrides"),
            (RelationshipType::Imports, "imports"),
            (RelationshipType::Exports, "exports"),
        ];

        for (relationship_type, property_name) in relationship_mappings {
            let iri = format!("{}{}", base_iri, property_name);
            let named_node = NamedNode::new(iri)
                .map_err(|e| Error::InvalidIri(format!("Failed to create IRI for {}: {}", property_name, e)))?;
            properties.insert(relationship_type, named_node);
        }

        Ok(properties)
    }

    fn create_common_properties(base_iri: &str) -> Result<CommonProperties> {
        let create_property = |name: &str| -> Result<NamedNode> {
            let iri = format!("{}{}", base_iri, name);
            NamedNode::new(iri).map_err(|e| Error::InvalidIri(format!("Failed to create property {}: {}", name, e)))
        };

        Ok(CommonProperties {
            source_file: create_property("sourceFile")?,
            line_number: create_property("lineNumber")?,
            column_number: create_property("columnNumber")?,
            name: create_property("name")?,
            signature: create_property("signature")?,
            documentation: create_property("documentation")?,
            visibility: create_property("visibility")?,
            language: create_property("language")?,
            complexity: create_property("complexity")?,
        })
    }
}

/// Utility functions for working with the ontology
impl CodeOntology {
    /// Check if a given IRI belongs to this ontology
    pub fn is_ontology_iri(&self, iri: &NamedNode) -> bool {
        iri.as_str().starts_with(&self.base_iri)
    }

    /// Extract the local name from an ontology IRI
    pub fn extract_local_name(&self, iri: &NamedNode) -> Option<String> {
        if self.is_ontology_iri(iri) {
            let iri_str = iri.as_str();
            if let Some(local_part) = iri_str.strip_prefix(&self.base_iri) {
                return Some(local_part.to_string());
            }
        }
        None
    }

    /// Get all entity classes defined in the ontology
    pub fn get_all_entity_classes(&self) -> Vec<&NamedNode> {
        self.entity_classes.values().collect()
    }

    /// Get all relationship properties defined in the ontology
    pub fn get_all_relationship_properties(&self) -> Vec<&NamedNode> {
        self.relationship_properties.values().collect()
    }

    /// Validate that an entity type is supported by the ontology
    pub fn is_supported_entity_type(&self, entity_type: &EntityType) -> bool {
        self.entity_classes.contains_key(entity_type)
    }

    /// Validate that a relationship type is supported by the ontology
    pub fn is_supported_relationship_type(&self, relationship_type: &RelationshipType) -> bool {
        self.relationship_properties.contains_key(relationship_type)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ontology_creation() {
        let ontology = CodeOntology::new("https://example.org/ontology#").unwrap();
        assert_eq!(ontology.base_iri, "https://example.org/ontology#");
        assert!(!ontology.entity_classes.is_empty());
        assert!(!ontology.relationship_properties.is_empty());
    }

    #[test]
    fn test_entity_class_retrieval() {
        let ontology = CodeOntology::new("https://example.org/ontology#").unwrap();
        let function_class = ontology.get_entity_class(&EntityType::Function);
        assert!(function_class.is_some());
        assert!(function_class.unwrap().as_str().contains("Function"));
    }

    #[test]
    fn test_relationship_property_retrieval() {
        let ontology = CodeOntology::new("https://example.org/ontology#").unwrap();
        let calls_property = ontology.get_relationship_property(&RelationshipType::Calls);
        assert!(calls_property.is_some());
        assert!(calls_property.unwrap().as_str().contains("calls"));
    }

    #[test]
    fn test_entity_iri_creation() {
        let ontology = CodeOntology::new("https://example.org/ontology#").unwrap();
        let entity_iri = ontology.create_entity_iri("test_function").unwrap();
        assert!(entity_iri.as_str().contains("entity/test_function"));
    }

    #[test]
    fn test_file_iri_creation() {
        let ontology = CodeOntology::new("https://example.org/ontology#").unwrap();
        let file_iri = ontology.create_file_iri("src/main.rs").unwrap();
        assert!(file_iri.as_str().contains("file/src_main_rs"));
    }

    #[test]
    fn test_literal_creation() {
        let ontology = CodeOntology::new("https://example.org/ontology#").unwrap();
        
        let string_lit = ontology.create_string_literal("test");
        assert_eq!(string_lit.value(), "test");
        
        let int_lit = ontology.create_integer_literal(42);
        assert_eq!(int_lit.value(), "42");
        
        let float_lit = ontology.create_float_literal(3.14);
        assert_eq!(float_lit.value(), "3.14");
    }

    #[test]
    fn test_ontology_iri_validation() {
        let ontology = CodeOntology::new("https://example.org/ontology#").unwrap();
        let entity_iri = ontology.create_entity_iri("test").unwrap();
        assert!(ontology.is_ontology_iri(&entity_iri));
        
        let external_iri = NamedNode::new("https://other.org/test").unwrap();
        assert!(!ontology.is_ontology_iri(&external_iri));
    }

    #[test]
    fn test_local_name_extraction() {
        let ontology = CodeOntology::new("https://example.org/ontology#").unwrap();
        let entity_iri = ontology.create_entity_iri("test_function").unwrap();
        let local_name = ontology.extract_local_name(&entity_iri).unwrap();
        assert!(local_name.contains("entity/test_function"));
    }

    #[test]
    fn test_supported_types() {
        let ontology = CodeOntology::new("https://example.org/ontology#").unwrap();
        assert!(ontology.is_supported_entity_type(&EntityType::Function));
        assert!(ontology.is_supported_relationship_type(&RelationshipType::Calls));
    }
}
