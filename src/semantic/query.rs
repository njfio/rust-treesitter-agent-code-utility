//! # Graph Query Module
//!
//! This module provides querying capabilities for RDF knowledge graphs.
//! It supports relationship traversal, similarity search, and complex
//! graph pattern matching for semantic code analysis.

use crate::error::{Error, Result};
use crate::semantic::{CodeRelationship, RelationshipType};
use oxrdf::{Graph, NamedNode};
use std::collections::{HashMap, HashSet, VecDeque};
use petgraph::{Graph as PetGraph, Directed};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use petgraph::algo::{dijkstra, connected_components};

/// Graph query engine for semantic analysis
#[derive(Debug)]
pub struct GraphQueryEngine {
    /// Cached graph structure for efficient traversal
    graph_cache: Option<PetGraph<NamedNode, RelationshipType, Directed>>,
    /// Mapping from RDF nodes to graph indices
    node_map: HashMap<NamedNode, NodeIndex>,
    /// Reverse mapping from graph indices to RDF nodes
    reverse_node_map: HashMap<NodeIndex, NamedNode>,
}

/// Result of a relationship query
#[derive(Debug, Clone)]
pub struct RelationshipQueryResult {
    /// The relationships found
    pub relationships: Vec<CodeRelationship>,
    /// The depth at which each relationship was found
    pub depths: Vec<u32>,
    /// Total number of nodes traversed
    pub nodes_traversed: usize,
    /// Query execution time in microseconds
    pub execution_time_us: u64,
}

/// Result of a similarity search
#[derive(Debug, Clone)]
pub struct SimilarityResult {
    /// Similar entities with their similarity scores
    pub similar_entities: Vec<(NamedNode, f32)>,
    /// The algorithm used for similarity calculation
    pub algorithm: SimilarityAlgorithm,
    /// Query execution time in microseconds
    pub execution_time_us: u64,
}

/// Algorithms available for similarity calculation
#[derive(Debug, Clone, PartialEq)]
pub enum SimilarityAlgorithm {
    /// Structural similarity based on graph topology
    Structural,
    /// Semantic similarity based on entity properties
    Semantic,
    /// Combined structural and semantic similarity
    Hybrid,
}

/// Configuration for graph queries
#[derive(Debug, Clone)]
pub struct QueryConfig {
    /// Maximum depth for relationship traversal
    pub max_depth: u32,
    /// Maximum number of results to return
    pub max_results: usize,
    /// Minimum similarity threshold
    pub similarity_threshold: f32,
    /// Enable caching of query results
    pub enable_caching: bool,
}

impl Default for QueryConfig {
    fn default() -> Self {
        Self {
            max_depth: 5,
            max_results: 100,
            similarity_threshold: 0.5,
            enable_caching: true,
        }
    }
}

impl GraphQueryEngine {
    /// Create a new graph query engine
    pub fn new() -> Result<Self> {
        Ok(Self {
            graph_cache: None,
            node_map: HashMap::new(),
            reverse_node_map: HashMap::new(),
        })
    }

    /// Build internal graph structure from RDF triples for efficient querying
    pub fn build_graph_cache(&mut self, rdf_graph: &Graph) -> Result<()> {
        let mut petgraph = PetGraph::new();
        let mut node_map = HashMap::new();
        let mut reverse_node_map = HashMap::new();

        // First pass: add all nodes
        let mut unique_nodes = HashSet::new();
        for triple in rdf_graph.iter() {
            if let oxrdf::SubjectRef::NamedNode(subject) = triple.subject {
                unique_nodes.insert(subject.into_owned());
            }
            if let oxrdf::TermRef::NamedNode(object) = triple.object {
                unique_nodes.insert(object.into_owned());
            }
        }

        // Add nodes to petgraph
        for node in unique_nodes {
            let index = petgraph.add_node(node.clone());
            node_map.insert(node.clone(), index);
            reverse_node_map.insert(index, node);
        }

        // Second pass: add edges
        for triple in rdf_graph.iter() {
            if let (oxrdf::SubjectRef::NamedNode(subject), oxrdf::TermRef::NamedNode(object)) = (triple.subject, triple.object) {
                let subject_owned = subject.into_owned();
                let object_owned = object.into_owned();
                if let (Some(&subject_idx), Some(&object_idx)) = (node_map.get(&subject_owned), node_map.get(&object_owned)) {
                    // Determine relationship type from predicate
                    let relationship_type = self.predicate_to_relationship_type(&triple.predicate.into_owned());
                    petgraph.add_edge(subject_idx, object_idx, relationship_type);
                }
            }
        }

        self.graph_cache = Some(petgraph);
        self.node_map = node_map;
        self.reverse_node_map = reverse_node_map;

        tracing::info!(
            "Built graph cache with {} nodes and {} edges",
            self.node_map.len(),
            self.graph_cache.as_ref().unwrap().edge_count()
        );

        Ok(())
    }

    /// Find relationships starting from a given entity up to a specified depth
    pub async fn find_relationships(
        &self,
        entity_iri: &str,
        depth: u32,
    ) -> Result<Vec<CodeRelationship>> {
        let start_time = std::time::Instant::now();
        
        let entity_node = NamedNode::new(entity_iri)
            .map_err(|e| Error::InvalidIri(e.to_string()))?;

        let relationships = if let Some(graph) = &self.graph_cache {
            self.find_relationships_cached(&entity_node, depth, graph)?
        } else {
            return Err(Error::GraphNotInitialized("Graph cache not built".to_string()));
        };

        tracing::debug!(
            "Found {} relationships for {} in {:?}",
            relationships.len(),
            entity_iri,
            start_time.elapsed()
        );

        Ok(relationships)
    }

    /// Find similar entities based on structural or semantic similarity
    pub async fn find_similar_entities(
        &self,
        entity_iri: &str,
        threshold: f32,
    ) -> Result<Vec<(NamedNode, f32)>> {
        let start_time = std::time::Instant::now();
        
        let entity_node = NamedNode::new(entity_iri)
            .map_err(|e| Error::InvalidIri(e.to_string()))?;

        let similar_entities = if let Some(graph) = &self.graph_cache {
            self.find_similar_entities_cached(&entity_node, threshold, graph)?
        } else {
            return Err(Error::GraphNotInitialized("Graph cache not built".to_string()));
        };

        tracing::debug!(
            "Found {} similar entities for {} in {:?}",
            similar_entities.len(),
            entity_iri,
            start_time.elapsed()
        );

        Ok(similar_entities)
    }

    /// Get all entities connected to a given entity within a certain distance
    pub async fn get_connected_entities(
        &self,
        entity_iri: &str,
        max_distance: u32,
    ) -> Result<Vec<NamedNode>> {
        let entity_node = NamedNode::new(entity_iri)
            .map_err(|e| Error::InvalidIri(e.to_string()))?;

        if let Some(graph) = &self.graph_cache {
            if let Some(&start_idx) = self.node_map.get(&entity_node) {
                let distances = dijkstra(graph, start_idx, None, |_| 1);
                
                let connected_entities: Vec<NamedNode> = distances
                    .into_iter()
                    .filter(|(_, distance)| *distance <= max_distance as i32)
                    .filter_map(|(node_idx, _)| self.reverse_node_map.get(&node_idx).cloned())
                    .collect();

                return Ok(connected_entities);
            }
        }

        Err(Error::EntityNotFound(entity_iri.to_string()))
    }

    /// Get strongly connected components in the graph
    pub async fn get_connected_components(&self) -> Result<Vec<Vec<NamedNode>>> {
        if let Some(graph) = &self.graph_cache {
            let components = connected_components(graph);
            let mut component_groups = vec![Vec::new(); components];
            
            for (node_idx, component_id) in self.reverse_node_map.keys().enumerate() {
                if let Some(node) = self.reverse_node_map.get(&NodeIndex::new(node_idx)) {
                    let comp_idx = components.min(component_id.index());
                    if comp_idx < component_groups.len() {
                        component_groups[comp_idx].push(node.clone());
                    }
                }
            }

            return Ok(component_groups.into_iter().filter(|group| !group.is_empty()).collect());
        }

        Err(Error::GraphNotInitialized("Graph cache not built".to_string()))
    }

    // Private helper methods

    fn find_relationships_cached(
        &self,
        entity_node: &NamedNode,
        max_depth: u32,
        graph: &PetGraph<NamedNode, RelationshipType, Directed>,
    ) -> Result<Vec<CodeRelationship>> {
        let mut relationships = Vec::new();
        let mut visited = HashSet::new();
        let mut queue = VecDeque::new();

        if let Some(&start_idx) = self.node_map.get(entity_node) {
            queue.push_back((start_idx, 0));
            visited.insert(start_idx);

            while let Some((current_idx, depth)) = queue.pop_front() {
                if depth >= max_depth {
                    continue;
                }

                // Get outgoing edges
                for edge_ref in graph.edges(current_idx) {
                    let target_idx = edge_ref.target();
                    let relationship_type = edge_ref.weight();

                    if let (Some(subject), Some(object)) = (
                        self.reverse_node_map.get(&current_idx),
                        self.reverse_node_map.get(&target_idx),
                    ) {
                        let relationship = CodeRelationship {
                            subject: subject.clone(),
                            predicate: relationship_type.clone(),
                            object: object.clone(),
                            confidence: 1.0, // Default confidence
                        };
                        relationships.push(relationship);

                        if !visited.contains(&target_idx) {
                            visited.insert(target_idx);
                            queue.push_back((target_idx, depth + 1));
                        }
                    }
                }
            }
        }

        Ok(relationships)
    }

    fn find_similar_entities_cached(
        &self,
        entity_node: &NamedNode,
        threshold: f32,
        graph: &PetGraph<NamedNode, RelationshipType, Directed>,
    ) -> Result<Vec<(NamedNode, f32)>> {
        let mut similar_entities = Vec::new();

        if let Some(&entity_idx) = self.node_map.get(entity_node) {
            // Calculate structural similarity based on common neighbors
            for (other_node, &other_idx) in &self.node_map {
                if other_node == entity_node {
                    continue;
                }

                let similarity = self.calculate_structural_similarity(entity_idx, other_idx, graph);
                if similarity >= threshold {
                    similar_entities.push((other_node.clone(), similarity));
                }
            }

            // Sort by similarity score (descending)
            similar_entities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        }

        Ok(similar_entities)
    }

    fn calculate_structural_similarity(
        &self,
        node1: NodeIndex,
        node2: NodeIndex,
        graph: &PetGraph<NamedNode, RelationshipType, Directed>,
    ) -> f32 {
        // Get neighbors of both nodes
        let neighbors1: HashSet<NodeIndex> = graph.neighbors(node1).collect();
        let neighbors2: HashSet<NodeIndex> = graph.neighbors(node2).collect();

        if neighbors1.is_empty() && neighbors2.is_empty() {
            return 0.0;
        }

        // Calculate Jaccard similarity
        let intersection_size = neighbors1.intersection(&neighbors2).count();
        let union_size = neighbors1.union(&neighbors2).count();

        if union_size == 0 {
            0.0
        } else {
            intersection_size as f32 / union_size as f32
        }
    }

    fn predicate_to_relationship_type(&self, predicate: &NamedNode) -> RelationshipType {
        let predicate_str = predicate.as_str();

        if predicate_str.contains("calls") {
            RelationshipType::Calls
        } else if predicate_str.contains("defines") {
            RelationshipType::Defines
        } else if predicate_str.contains("uses") {
            RelationshipType::Uses
        } else if predicate_str.contains("inherits") {
            RelationshipType::Inherits
        } else if predicate_str.contains("implements") {
            RelationshipType::Implements
        } else if predicate_str.contains("contains") {
            RelationshipType::Contains
        } else if predicate_str.contains("dependsOn") {
            RelationshipType::DependsOn
        } else if predicate_str.contains("references") {
            RelationshipType::References
        } else if predicate_str.contains("overrides") {
            RelationshipType::Overrides
        } else if predicate_str.contains("imports") {
            RelationshipType::Imports
        } else if predicate_str.contains("exports") {
            RelationshipType::Exports
        } else {
            RelationshipType::References // Default fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxrdf::{Literal, vocab::rdf, Triple, Subject, Term};

    #[tokio::test]
    async fn test_query_engine_creation() {
        let engine = GraphQueryEngine::new().unwrap();
        assert!(engine.graph_cache.is_none());
        assert!(engine.node_map.is_empty());
    }

    #[tokio::test]
    async fn test_graph_cache_building() {
        let mut engine = GraphQueryEngine::new().unwrap();
        let mut graph = Graph::new();

        // Add some test triples
        let subject = NamedNode::new("http://example.org/subject").unwrap();
        let predicate = NamedNode::new("http://example.org/calls").unwrap();
        let object = NamedNode::new("http://example.org/object").unwrap();

        let triple = Triple::new(
            Subject::NamedNode(subject.clone()),
            predicate,
            Term::NamedNode(object.clone()),
        );
        graph.insert(&triple);

        engine.build_graph_cache(&graph).unwrap();
        
        assert!(engine.graph_cache.is_some());
        assert_eq!(engine.node_map.len(), 2); // subject and object
    }

    #[tokio::test]
    async fn test_relationship_finding() {
        let mut engine = GraphQueryEngine::new().unwrap();
        let mut graph = Graph::new();

        // Create a simple graph: A calls B
        let subject = NamedNode::new("http://example.org/A").unwrap();
        let predicate = NamedNode::new("http://example.org/calls").unwrap();
        let object = NamedNode::new("http://example.org/B").unwrap();

        let triple = Triple::new(
            Subject::NamedNode(subject.clone()),
            predicate,
            Term::NamedNode(object),
        );
        graph.insert(&triple);

        engine.build_graph_cache(&graph).unwrap();
        
        let relationships = engine.find_relationships("http://example.org/A", 1).await.unwrap();
        assert_eq!(relationships.len(), 1);
        assert_eq!(relationships[0].predicate, RelationshipType::Calls);
    }

    #[test]
    fn test_similarity_calculation() {
        let engine = GraphQueryEngine::new().unwrap();
        let mut graph = PetGraph::new();
        
        let node1 = graph.add_node(NamedNode::new("http://example.org/A").unwrap());
        let node2 = graph.add_node(NamedNode::new("http://example.org/B").unwrap());
        
        // Test similarity calculation with empty neighbors
        let similarity = engine.calculate_structural_similarity(node1, node2, &graph);
        assert_eq!(similarity, 0.0);
    }

    #[test]
    fn test_predicate_to_relationship_type() {
        let engine = GraphQueryEngine::new().unwrap();
        
        let calls_predicate = NamedNode::new("http://example.org/calls").unwrap();
        assert_eq!(engine.predicate_to_relationship_type(&calls_predicate), RelationshipType::Calls);

        let defines_predicate = NamedNode::new("http://example.org/defines").unwrap();
        assert_eq!(engine.predicate_to_relationship_type(&defines_predicate), RelationshipType::Defines);
    }
}
