//! # RDF Storage Module
//!
//! This module provides storage and persistence capabilities for RDF knowledge graphs.
//! It includes in-memory storage with caching, serialization support, and efficient
//! graph operations for semantic analysis.

use crate::error::{Error, Result};
use oxrdf::{Graph, Triple, NamedNode, Subject, Term};
use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::{Arc, RwLock};

/// RDF storage system with caching and persistence capabilities
#[derive(Debug)]
pub struct RdfStore {
    /// Main graph storage
    graph: Arc<RwLock<Graph>>,
    /// LRU cache for frequently accessed triples
    triple_cache: Arc<RwLock<LruCache<String, Vec<Triple>>>>,
    /// Index for fast subject lookups
    subject_index: Arc<RwLock<HashMap<NamedNode, Vec<Triple>>>>,
    /// Index for fast predicate lookups
    predicate_index: Arc<RwLock<HashMap<NamedNode, Vec<Triple>>>>,
    /// Index for fast object lookups
    object_index: Arc<RwLock<HashMap<String, Vec<Triple>>>>,
    /// Statistics about the store
    stats: Arc<RwLock<StoreStatistics>>,
}

/// Statistics about the RDF store
#[derive(Debug, Default)]
pub struct StoreStatistics {
    /// Total number of triples stored
    pub triple_count: usize,
    /// Number of unique subjects
    pub subject_count: usize,
    /// Number of unique predicates
    pub predicate_count: usize,
    /// Number of cache hits
    pub cache_hits: usize,
    /// Number of cache misses
    pub cache_misses: usize,
    /// Total memory usage in bytes (approximate)
    pub memory_usage_bytes: usize,
}

/// Query result containing triples and metadata
#[derive(Debug)]
pub struct QueryResult {
    /// Matching triples
    pub triples: Vec<Triple>,
    /// Execution time in microseconds
    pub execution_time_us: u64,
    /// Whether the result came from cache
    pub from_cache: bool,
}

impl RdfStore {
    /// Create a new RDF store with the specified cache size
    pub fn new(cache_size: usize) -> Result<Self> {
        let cache_capacity = NonZeroUsize::new(cache_size)
            .ok_or_else(|| Error::InvalidConfiguration("Cache size must be greater than 0".to_string()))?;

        Ok(Self {
            graph: Arc::new(RwLock::new(Graph::new())),
            triple_cache: Arc::new(RwLock::new(LruCache::new(cache_capacity))),
            subject_index: Arc::new(RwLock::new(HashMap::new())),
            predicate_index: Arc::new(RwLock::new(HashMap::new())),
            object_index: Arc::new(RwLock::new(HashMap::new())),
            stats: Arc::new(RwLock::new(StoreStatistics::default())),
        })
    }

    /// Store a complete graph in the RDF store
    pub async fn store_graph(&self, graph: &Graph) -> Result<()> {
        let start_time = std::time::Instant::now();
        
        // Clear existing data
        self.clear().await?;
        
        // Insert all triples from the graph
        for triple in graph.iter() {
            self.insert_triple(triple.into_owned()).await?;
        }
        
        // Update statistics
        let mut stats = self.stats.write()
            .map_err(|_| Error::LockError("Failed to acquire stats write lock".to_string()))?;
        stats.memory_usage_bytes = self.estimate_memory_usage();
        
        tracing::info!(
            "Stored graph with {} triples in {:?}",
            graph.len(),
            start_time.elapsed()
        );
        
        Ok(())
    }

    /// Insert a single triple into the store
    pub async fn insert_triple(&self, triple: Triple) -> Result<()> {
        // Insert into main graph
        {
            let mut graph = self.graph.write()
                .map_err(|_| Error::LockError("Failed to acquire graph write lock".to_string()))?;
            graph.insert(&triple);
        }

        // Update indices
        self.update_indices(&triple).await?;
        
        // Update statistics
        {
            let mut stats = self.stats.write()
                .map_err(|_| Error::LockError("Failed to acquire stats write lock".to_string()))?;
            stats.triple_count += 1;
        }

        // Invalidate relevant cache entries
        self.invalidate_cache_for_triple(&triple).await?;

        Ok(())
    }

    /// Query triples by subject
    pub async fn query_by_subject(&self, subject: &NamedNode) -> Result<QueryResult> {
        let start_time = std::time::Instant::now();
        let cache_key = format!("subject:{}", subject.as_str());

        // Check cache first
        if let Some(cached_triples) = self.get_from_cache(&cache_key).await? {
            return Ok(QueryResult {
                triples: cached_triples,
                execution_time_us: start_time.elapsed().as_micros() as u64,
                from_cache: true,
            });
        }

        // Query from index
        let triples = {
            let index = self.subject_index.read()
                .map_err(|_| Error::LockError("Failed to acquire subject index read lock".to_string()))?;
            index.get(subject).cloned().unwrap_or_default()
        };

        // Cache the result
        self.put_in_cache(cache_key, triples.clone()).await?;

        Ok(QueryResult {
            triples,
            execution_time_us: start_time.elapsed().as_micros() as u64,
            from_cache: false,
        })
    }

    /// Query triples by predicate
    pub async fn query_by_predicate(&self, predicate: &NamedNode) -> Result<QueryResult> {
        let start_time = std::time::Instant::now();
        let cache_key = format!("predicate:{}", predicate.as_str());

        // Check cache first
        if let Some(cached_triples) = self.get_from_cache(&cache_key).await? {
            return Ok(QueryResult {
                triples: cached_triples,
                execution_time_us: start_time.elapsed().as_micros() as u64,
                from_cache: true,
            });
        }

        // Query from index
        let triples = {
            let index = self.predicate_index.read()
                .map_err(|_| Error::LockError("Failed to acquire predicate index read lock".to_string()))?;
            index.get(predicate).cloned().unwrap_or_default()
        };

        // Cache the result
        self.put_in_cache(cache_key, triples.clone()).await?;

        Ok(QueryResult {
            triples,
            execution_time_us: start_time.elapsed().as_micros() as u64,
            from_cache: false,
        })
    }

    /// Query triples by subject and predicate
    pub async fn query_by_subject_predicate(
        &self,
        subject: &NamedNode,
        predicate: &NamedNode,
    ) -> Result<QueryResult> {
        let start_time = std::time::Instant::now();
        let cache_key = format!("sp:{}:{}", subject.as_str(), predicate.as_str());

        // Check cache first
        if let Some(cached_triples) = self.get_from_cache(&cache_key).await? {
            return Ok(QueryResult {
                triples: cached_triples,
                execution_time_us: start_time.elapsed().as_micros() as u64,
                from_cache: true,
            });
        }

        // Query by subject first (usually more selective)
        let subject_triples = self.query_by_subject(subject).await?;
        
        // Filter by predicate
        let triples: Vec<Triple> = subject_triples.triples
            .into_iter()
            .filter(|triple| {
                &triple.predicate == predicate
            })
            .collect();

        // Cache the result
        self.put_in_cache(cache_key, triples.clone()).await?;

        Ok(QueryResult {
            triples,
            execution_time_us: start_time.elapsed().as_micros() as u64,
            from_cache: false,
        })
    }

    /// Get all unique subjects in the store
    pub async fn get_all_subjects(&self) -> Result<Vec<NamedNode>> {
        let index = self.subject_index.read()
            .map_err(|_| Error::LockError("Failed to acquire subject index read lock".to_string()))?;
        Ok(index.keys().cloned().collect())
    }

    /// Get all unique predicates in the store
    pub async fn get_all_predicates(&self) -> Result<Vec<NamedNode>> {
        let index = self.predicate_index.read()
            .map_err(|_| Error::LockError("Failed to acquire predicate index read lock".to_string()))?;
        Ok(index.keys().cloned().collect())
    }

    /// Get store statistics
    pub async fn get_statistics(&self) -> Result<StoreStatistics> {
        let stats = self.stats.read()
            .map_err(|_| Error::LockError("Failed to acquire stats read lock".to_string()))?;
        Ok(StoreStatistics {
            triple_count: stats.triple_count,
            subject_count: stats.subject_count,
            predicate_count: stats.predicate_count,
            cache_hits: stats.cache_hits,
            cache_misses: stats.cache_misses,
            memory_usage_bytes: stats.memory_usage_bytes,
        })
    }

    /// Clear all data from the store
    pub async fn clear(&self) -> Result<()> {
        // Clear main graph
        {
            let mut graph = self.graph.write()
                .map_err(|_| Error::LockError("Failed to acquire graph write lock".to_string()))?;
            *graph = Graph::new();
        }

        // Clear indices
        {
            let mut subject_index = self.subject_index.write()
                .map_err(|_| Error::LockError("Failed to acquire subject index write lock".to_string()))?;
            subject_index.clear();
        }
        {
            let mut predicate_index = self.predicate_index.write()
                .map_err(|_| Error::LockError("Failed to acquire predicate index write lock".to_string()))?;
            predicate_index.clear();
        }
        {
            let mut object_index = self.object_index.write()
                .map_err(|_| Error::LockError("Failed to acquire object index write lock".to_string()))?;
            object_index.clear();
        }

        // Clear cache
        {
            let mut cache = self.triple_cache.write()
                .map_err(|_| Error::LockError("Failed to acquire cache write lock".to_string()))?;
            cache.clear();
        }

        // Reset statistics
        {
            let mut stats = self.stats.write()
                .map_err(|_| Error::LockError("Failed to acquire stats write lock".to_string()))?;
            *stats = StoreStatistics::default();
        }

        Ok(())
    }

    // Private helper methods

    async fn update_indices(&self, triple: &Triple) -> Result<()> {
        // Update subject index
        if let Subject::NamedNode(subject) = &triple.subject {
            let mut subject_index = self.subject_index.write()
                .map_err(|_| Error::LockError("Failed to acquire subject index write lock".to_string()))?;
            subject_index
                .entry(subject.clone())
                .or_insert_with(Vec::new)
                .push(triple.clone());
        }

        // Update predicate index
        {
            let mut predicate_index = self.predicate_index.write()
                .map_err(|_| Error::LockError("Failed to acquire predicate index write lock".to_string()))?;
            predicate_index
                .entry(triple.predicate.clone())
                .or_insert_with(Vec::new)
                .push(triple.clone());
        }

        // Update object index
        let object_key = match &triple.object {
            Term::NamedNode(node) => node.as_str().to_string(),
            Term::BlankNode(node) => format!("_:{}", node.as_str()),
            Term::Literal(literal) => literal.value().to_string(),
        };
        
        let mut object_index = self.object_index.write()
            .map_err(|_| Error::LockError("Failed to acquire object index write lock".to_string()))?;
        object_index
            .entry(object_key)
            .or_insert_with(Vec::new)
            .push(triple.clone());

        Ok(())
    }

    async fn get_from_cache(&self, key: &str) -> Result<Option<Vec<Triple>>> {
        let mut cache = self.triple_cache.write()
            .map_err(|_| Error::LockError("Failed to acquire cache write lock".to_string()))?;
        
        if let Some(triples) = cache.get(key) {
            let mut stats = self.stats.write()
                .map_err(|_| Error::LockError("Failed to acquire stats write lock".to_string()))?;
            stats.cache_hits += 1;
            Ok(Some(triples.clone()))
        } else {
            let mut stats = self.stats.write()
                .map_err(|_| Error::LockError("Failed to acquire stats write lock".to_string()))?;
            stats.cache_misses += 1;
            Ok(None)
        }
    }

    async fn put_in_cache(&self, key: String, triples: Vec<Triple>) -> Result<()> {
        let mut cache = self.triple_cache.write()
            .map_err(|_| Error::LockError("Failed to acquire cache write lock".to_string()))?;
        cache.put(key, triples);
        Ok(())
    }

    async fn invalidate_cache_for_triple(&self, triple: &Triple) -> Result<()> {
        let mut cache = self.triple_cache.write()
            .map_err(|_| Error::LockError("Failed to acquire cache write lock".to_string()))?;
        
        // Invalidate subject-based cache entries
        if let Subject::NamedNode(subject) = &triple.subject {
            let subject_key = format!("subject:{}", subject.as_str());
            cache.pop(&subject_key);
        }

        // Invalidate predicate-based cache entries
        {
            let predicate_key = format!("predicate:{}", triple.predicate.as_str());
            cache.pop(&predicate_key);
        }

        Ok(())
    }

    fn estimate_memory_usage(&self) -> usize {
        // Rough estimation of memory usage
        let graph_size = {
            let graph = self.graph.read().unwrap();
            graph.len() * std::mem::size_of::<Triple>()
        };
        
        let index_size = {
            let subject_index = self.subject_index.read().unwrap();
            let predicate_index = self.predicate_index.read().unwrap();
            let object_index = self.object_index.read().unwrap();
            
            subject_index.len() * 64 + predicate_index.len() * 64 + object_index.len() * 64
        };
        
        graph_size + index_size
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oxrdf::{Literal, vocab::xsd};

    #[tokio::test]
    async fn test_store_creation() {
        let store = RdfStore::new(1000).unwrap();
        let stats = store.get_statistics().await.unwrap();
        assert_eq!(stats.triple_count, 0);
    }

    #[tokio::test]
    async fn test_triple_insertion() {
        let store = RdfStore::new(1000).unwrap();
        
        let subject = NamedNode::new("http://example.org/subject").unwrap();
        let predicate = NamedNode::new("http://example.org/predicate").unwrap();
        let object = Term::Literal(Literal::new_simple_literal("object"));
        
        let triple = Triple::new(subject.clone(), predicate.clone(), object);
        store.insert_triple(triple).await.unwrap();
        
        let stats = store.get_statistics().await.unwrap();
        assert_eq!(stats.triple_count, 1);
    }

    #[tokio::test]
    async fn test_subject_query() {
        let store = RdfStore::new(1000).unwrap();
        
        let subject = NamedNode::new("http://example.org/subject").unwrap();
        let predicate = NamedNode::new("http://example.org/predicate").unwrap();
        let object = Term::Literal(Literal::new_simple_literal("object"));
        
        let triple = Triple::new(subject.clone(), predicate, object);
        store.insert_triple(triple).await.unwrap();
        
        let result = store.query_by_subject(&subject).await.unwrap();
        assert_eq!(result.triples.len(), 1);
        assert!(!result.from_cache);
        
        // Query again to test cache
        let result2 = store.query_by_subject(&subject).await.unwrap();
        assert_eq!(result2.triples.len(), 1);
        assert!(result2.from_cache);
    }
}
