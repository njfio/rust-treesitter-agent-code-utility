//! # Code Embeddings Module
//!
//! This module provides code embedding generation capabilities for semantic similarity
//! analysis. It converts code entities into vector representations that capture
//! semantic meaning and enable similarity comparisons.

use crate::error::{Error, Result};
use crate::semantic::CodeEntity;
use std::collections::HashMap;
use std::hash::{Hash, Hasher};

/// Code embedding generator that creates vector representations of code entities
#[derive(Debug)]
pub struct CodeEmbedder {
    /// Vocabulary mapping from tokens to indices
    vocabulary: HashMap<String, usize>,
    /// Embedding dimension
    embedding_dim: usize,
    /// Pre-trained embeddings (if available)
    pretrained_embeddings: Option<HashMap<String, Vec<f32>>>,
}

/// Configuration for code embedding generation
#[derive(Debug, Clone)]
pub struct EmbeddingConfig {
    /// Dimension of the embedding vectors
    pub embedding_dim: usize,
    /// Maximum vocabulary size
    pub max_vocab_size: usize,
    /// Minimum token frequency to include in vocabulary
    pub min_token_frequency: usize,
    /// Whether to use pre-trained embeddings
    pub use_pretrained: bool,
    /// Path to pre-trained embedding file
    pub pretrained_path: Option<String>,
}

impl Default for EmbeddingConfig {
    fn default() -> Self {
        Self {
            embedding_dim: 128,
            max_vocab_size: 10000,
            min_token_frequency: 2,
            use_pretrained: false,
            pretrained_path: None,
        }
    }
}

/// Vector representation of a code entity
#[derive(Debug, Clone)]
pub struct CodeEmbedding {
    /// The entity this embedding represents
    pub entity_id: uuid::Uuid,
    /// The embedding vector
    pub vector: Vec<f32>,
    /// Metadata about the embedding
    pub metadata: EmbeddingMetadata,
}

/// Metadata about an embedding
#[derive(Debug, Clone)]
pub struct EmbeddingMetadata {
    /// The algorithm used to generate the embedding
    pub algorithm: EmbeddingAlgorithm,
    /// Confidence score for the embedding quality
    pub confidence: f32,
    /// Timestamp when the embedding was generated
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Features used to generate the embedding
    pub features: Vec<String>,
}

/// Algorithms available for embedding generation
#[derive(Debug, Clone, PartialEq)]
pub enum EmbeddingAlgorithm {
    /// Simple bag-of-words with TF-IDF weighting
    TfIdf,
    /// Token-based embedding with positional encoding
    TokenBased,
    /// AST structure-aware embedding
    StructuralAst,
    /// Hybrid approach combining multiple methods
    Hybrid,
}

/// Result of similarity calculation between embeddings
#[derive(Debug, Clone)]
pub struct SimilarityScore {
    /// Cosine similarity score (0.0 to 1.0)
    pub cosine_similarity: f32,
    /// Euclidean distance
    pub euclidean_distance: f32,
    /// Manhattan distance
    pub manhattan_distance: f32,
}

impl CodeEmbedder {
    /// Create a new code embedder with the given configuration
    pub fn new(config: EmbeddingConfig) -> Result<Self> {
        let pretrained_embeddings = if config.use_pretrained {
            if let Some(path) = &config.pretrained_path {
                Some(Self::load_pretrained_embeddings(path)?)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            vocabulary: HashMap::new(),
            embedding_dim: config.embedding_dim,
            pretrained_embeddings,
        })
    }

    /// Build vocabulary from a collection of code entities
    pub fn build_vocabulary(&mut self, entities: &[CodeEntity]) -> Result<()> {
        let mut token_counts = HashMap::new();

        // Extract tokens from all entities
        for entity in entities {
            let tokens = self.extract_tokens(entity)?;
            for token in tokens {
                *token_counts.entry(token).or_insert(0) += 1;
            }
        }

        // Build vocabulary from frequent tokens
        let mut vocab_entries: Vec<(String, usize)> = token_counts.into_iter().collect();
        vocab_entries.sort_by(|a, b| b.1.cmp(&a.1)); // Sort by frequency (descending)

        self.vocabulary.clear();
        for (i, (token, _count)) in vocab_entries.into_iter().take(10000).enumerate() {
            self.vocabulary.insert(token, i);
        }

        tracing::info!("Built vocabulary with {} tokens", self.vocabulary.len());
        Ok(())
    }

    /// Generate embedding for a code entity
    pub fn generate_embedding(&self, entity: &CodeEntity) -> Result<CodeEmbedding> {
        let algorithm = EmbeddingAlgorithm::Hybrid;
        let vector = match algorithm {
            EmbeddingAlgorithm::TfIdf => self.generate_tfidf_embedding(entity)?,
            EmbeddingAlgorithm::TokenBased => self.generate_token_embedding(entity)?,
            EmbeddingAlgorithm::StructuralAst => self.generate_structural_embedding(entity)?,
            EmbeddingAlgorithm::Hybrid => self.generate_hybrid_embedding(entity)?,
        };

        let features = self.extract_features(entity)?;
        let confidence = self.calculate_embedding_confidence(&vector, &features);

        let metadata = EmbeddingMetadata {
            algorithm,
            confidence,
            generated_at: chrono::Utc::now(),
            features,
        };

        Ok(CodeEmbedding {
            entity_id: entity.id,
            vector,
            metadata,
        })
    }

    /// Calculate similarity between two embeddings
    pub fn calculate_similarity(&self, embedding1: &CodeEmbedding, embedding2: &CodeEmbedding) -> Result<SimilarityScore> {
        if embedding1.vector.len() != embedding2.vector.len() {
            return Err(Error::DimensionMismatch(
                "Embedding vectors must have the same dimension".to_string()
            ));
        }

        let cosine_similarity = self.cosine_similarity(&embedding1.vector, &embedding2.vector);
        let euclidean_distance = self.euclidean_distance(&embedding1.vector, &embedding2.vector);
        let manhattan_distance = self.manhattan_distance(&embedding1.vector, &embedding2.vector);

        Ok(SimilarityScore {
            cosine_similarity,
            euclidean_distance,
            manhattan_distance,
        })
    }

    /// Find the most similar entities to a given entity
    pub fn find_similar_entities(
        &self,
        target_embedding: &CodeEmbedding,
        candidate_embeddings: &[CodeEmbedding],
        threshold: f32,
    ) -> Result<Vec<(uuid::Uuid, f32)>> {
        let mut similarities = Vec::new();

        for candidate in candidate_embeddings {
            if candidate.entity_id == target_embedding.entity_id {
                continue; // Skip self
            }

            let similarity = self.calculate_similarity(target_embedding, candidate)?;
            if similarity.cosine_similarity >= threshold {
                similarities.push((candidate.entity_id, similarity.cosine_similarity));
            }
        }

        // Sort by similarity score (descending)
        similarities.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));

        Ok(similarities)
    }

    // Private helper methods

    fn extract_tokens(&self, entity: &CodeEntity) -> Result<Vec<String>> {
        let mut tokens = Vec::new();

        // Extract tokens from entity name
        if let Some(name) = entity.properties.get("name") {
            tokens.extend(self.tokenize_identifier(name));
        }

        // Extract tokens from entity signature
        if let Some(signature) = entity.properties.get("signature") {
            tokens.extend(self.tokenize_code(signature));
        }

        // Add entity type as a token
        tokens.push(format!("TYPE_{:?}", entity.entity_type));

        Ok(tokens)
    }

    fn tokenize_identifier(&self, identifier: &str) -> Vec<String> {
        let mut tokens = Vec::new();
        
        // Split camelCase and snake_case
        let mut current_token = String::new();
        for ch in identifier.chars() {
            if ch.is_uppercase() && !current_token.is_empty() {
                tokens.push(current_token.to_lowercase());
                current_token = ch.to_string();
            } else if ch == '_' {
                if !current_token.is_empty() {
                    tokens.push(current_token.to_lowercase());
                    current_token.clear();
                }
            } else {
                current_token.push(ch);
            }
        }
        
        if !current_token.is_empty() {
            tokens.push(current_token.to_lowercase());
        }

        tokens
    }

    fn tokenize_code(&self, code: &str) -> Vec<String> {
        // Simple tokenization - split on whitespace and punctuation
        code.split_whitespace()
            .flat_map(|word| {
                word.split(&['(', ')', '{', '}', '[', ']', ',', ';', ':', '.'])
                    .filter(|token| !token.is_empty())
                    .map(|token| token.to_lowercase())
            })
            .collect()
    }

    fn generate_tfidf_embedding(&self, entity: &CodeEntity) -> Result<Vec<f32>> {
        let mut vector = vec![0.0; self.embedding_dim];
        let tokens = self.extract_tokens(entity)?;
        
        // Simple TF-IDF implementation
        let mut token_counts = HashMap::new();
        for token in &tokens {
            *token_counts.entry(token).or_insert(0) += 1;
        }

        for (token, count) in token_counts {
            if let Some(&vocab_index) = self.vocabulary.get(token) {
                if vocab_index < self.embedding_dim {
                    // Simple TF-IDF: tf * log(N/df)
                    // For simplicity, assume df = 1 (would need document frequency in practice)
                    let tf = count as f32 / tokens.len() as f32;
                    let idf = (1000.0_f32 / 1.0_f32).ln(); // Simplified IDF
                    vector[vocab_index] = tf * idf;
                }
            }
        }

        Ok(vector)
    }

    fn generate_token_embedding(&self, entity: &CodeEntity) -> Result<Vec<f32>> {
        let mut vector = vec![0.0; self.embedding_dim];
        let tokens = self.extract_tokens(entity)?;

        // Use pre-trained embeddings if available
        if let Some(pretrained) = &self.pretrained_embeddings {
            let mut embedding_sum = vec![0.0; self.embedding_dim];
            let mut count = 0;

            for token in &tokens {
                if let Some(token_embedding) = pretrained.get(token) {
                    for (i, &value) in token_embedding.iter().enumerate() {
                        if i < self.embedding_dim {
                            embedding_sum[i] += value;
                        }
                    }
                    count += 1;
                }
            }

            if count > 0 {
                for i in 0..self.embedding_dim {
                    vector[i] = embedding_sum[i] / count as f32;
                }
            }
        } else {
            // Fallback to simple one-hot encoding
            for token in &tokens {
                if let Some(&vocab_index) = self.vocabulary.get(token) {
                    if vocab_index < self.embedding_dim {
                        vector[vocab_index] = 1.0;
                    }
                }
            }
        }

        Ok(vector)
    }

    fn generate_structural_embedding(&self, entity: &CodeEntity) -> Result<Vec<f32>> {
        let mut vector = vec![0.0; self.embedding_dim];
        
        // Encode structural features
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        use std::hash::Hash;
        entity.entity_type.hash(&mut hasher);
        let type_hash = hasher.finish() as usize % self.embedding_dim;
        vector[type_hash] = 1.0;

        // Encode location features
        let line_feature = (entity.location.start_line % self.embedding_dim) as usize;
        if line_feature < self.embedding_dim {
            vector[line_feature] += 0.5;
        }

        Ok(vector)
    }

    fn generate_hybrid_embedding(&self, entity: &CodeEntity) -> Result<Vec<f32>> {
        let tfidf_embedding = self.generate_tfidf_embedding(entity)?;
        let token_embedding = self.generate_token_embedding(entity)?;
        let structural_embedding = self.generate_structural_embedding(entity)?;

        // Combine embeddings with weights
        let mut hybrid_vector = vec![0.0; self.embedding_dim];
        for i in 0..self.embedding_dim {
            hybrid_vector[i] = 0.4 * tfidf_embedding[i] + 
                              0.4 * token_embedding[i] + 
                              0.2 * structural_embedding[i];
        }

        Ok(hybrid_vector)
    }

    fn extract_features(&self, entity: &CodeEntity) -> Result<Vec<String>> {
        let mut features = Vec::new();
        
        features.push(format!("type:{:?}", entity.entity_type));
        features.push(format!("file:{}", entity.location.file_path));
        
        if let Some(name) = entity.properties.get("name") {
            features.push(format!("name:{}", name));
        }

        Ok(features)
    }

    fn calculate_embedding_confidence(&self, vector: &[f32], features: &[String]) -> f32 {
        // Simple confidence calculation based on vector magnitude and feature count
        let magnitude: f32 = vector.iter().map(|x| x * x).sum::<f32>().sqrt();
        let feature_score = (features.len() as f32 / 10.0).min(1.0);
        
        (magnitude / self.embedding_dim as f32 + feature_score) / 2.0
    }

    fn cosine_similarity(&self, vec1: &[f32], vec2: &[f32]) -> f32 {
        let dot_product: f32 = vec1.iter().zip(vec2.iter()).map(|(a, b)| a * b).sum();
        let magnitude1: f32 = vec1.iter().map(|x| x * x).sum::<f32>().sqrt();
        let magnitude2: f32 = vec2.iter().map(|x| x * x).sum::<f32>().sqrt();
        
        if magnitude1 == 0.0 || magnitude2 == 0.0 {
            0.0
        } else {
            dot_product / (magnitude1 * magnitude2)
        }
    }

    fn euclidean_distance(&self, vec1: &[f32], vec2: &[f32]) -> f32 {
        vec1.iter()
            .zip(vec2.iter())
            .map(|(a, b)| (a - b).powi(2))
            .sum::<f32>()
            .sqrt()
    }

    fn manhattan_distance(&self, vec1: &[f32], vec2: &[f32]) -> f32 {
        vec1.iter()
            .zip(vec2.iter())
            .map(|(a, b)| (a - b).abs())
            .sum()
    }

    fn load_pretrained_embeddings(_path: &str) -> Result<HashMap<String, Vec<f32>>> {
        // Placeholder implementation - would load from file in practice
        tracing::warn!("Pre-trained embeddings loading not implemented, using empty map");
        Ok(HashMap::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::{EntityType, EntityLocation};
    use std::collections::HashMap;

    fn create_test_entity() -> CodeEntity {
        CodeEntity {
            id: uuid::Uuid::new_v4(),
            iri: oxrdf::NamedNode::new("http://example.org/test").unwrap(),
            entity_type: EntityType::Function,
            location: EntityLocation {
                file_path: "test.rs".to_string(),
                start_line: 1,
                end_line: 5,
                start_column: 0,
                end_column: 10,
            },
            properties: {
                let mut props = HashMap::new();
                props.insert("name".to_string(), "test_function".to_string());
                props
            },
        }
    }

    #[test]
    fn test_embedder_creation() {
        let config = EmbeddingConfig::default();
        let embedder = CodeEmbedder::new(config).unwrap();
        assert_eq!(embedder.embedding_dim, 128);
        assert!(embedder.vocabulary.is_empty());
    }

    #[test]
    fn test_token_extraction() {
        let config = EmbeddingConfig::default();
        let embedder = CodeEmbedder::new(config).unwrap();
        let entity = create_test_entity();
        
        let tokens = embedder.extract_tokens(&entity).unwrap();
        assert!(!tokens.is_empty());
        assert!(tokens.contains(&"test".to_string()));
        assert!(tokens.contains(&"function".to_string()));
    }

    #[test]
    fn test_identifier_tokenization() {
        let config = EmbeddingConfig::default();
        let embedder = CodeEmbedder::new(config).unwrap();
        
        let tokens = embedder.tokenize_identifier("testFunction");
        assert_eq!(tokens, vec!["test", "function"]);
        
        let tokens = embedder.tokenize_identifier("test_function");
        assert_eq!(tokens, vec!["test", "function"]);
    }

    #[test]
    fn test_embedding_generation() {
        let config = EmbeddingConfig::default();
        let embedder = CodeEmbedder::new(config).unwrap();
        let entity = create_test_entity();
        
        let embedding = embedder.generate_embedding(&entity).unwrap();
        assert_eq!(embedding.vector.len(), 128);
        assert_eq!(embedding.entity_id, entity.id);
        assert_eq!(embedding.metadata.algorithm, EmbeddingAlgorithm::Hybrid);
    }

    #[test]
    fn test_similarity_calculation() {
        let config = EmbeddingConfig::default();
        let embedder = CodeEmbedder::new(config).unwrap();
        
        let vec1 = vec![1.0, 0.0, 0.0];
        let vec2 = vec![0.0, 1.0, 0.0];
        let vec3 = vec![1.0, 0.0, 0.0];
        
        assert_eq!(embedder.cosine_similarity(&vec1, &vec2), 0.0);
        assert_eq!(embedder.cosine_similarity(&vec1, &vec3), 1.0);
        
        assert_eq!(embedder.euclidean_distance(&vec1, &vec3), 0.0);
        assert!(embedder.euclidean_distance(&vec1, &vec2) > 0.0);
    }
}
