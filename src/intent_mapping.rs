//! Intent-to-Implementation Mapping System
//! 
//! This module provides comprehensive mapping between natural language requirements,
//! design intent, and actual code implementation for AI-assisted development.

use crate::{Result, FileInfo, AnalysisResult};
use crate::constants::intent_mapping::*;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Intent-to-implementation mapping system
#[derive(Debug, Clone)]
pub struct IntentMappingSystem {
    /// Parsed requirements and intents
    requirements: Vec<Requirement>,
    /// Implementation artifacts
    implementations: Vec<Implementation>,
    /// Mapping relationships
    mappings: Vec<IntentMapping>,
    /// Traceability matrix
    traceability: TraceabilityMatrix,
    /// Configuration
    config: MappingConfig,
}

/// A requirement or intent specification
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Requirement {
    /// Unique identifier
    pub id: String,
    /// Requirement type
    pub requirement_type: RequirementType,
    /// Natural language description
    pub description: String,
    /// Priority level
    pub priority: Priority,
    /// Acceptance criteria
    pub acceptance_criteria: Vec<String>,
    /// Stakeholder information
    pub stakeholders: Vec<String>,
    /// Tags and metadata
    pub tags: Vec<String>,
    /// Status
    pub status: RequirementStatus,
}

/// Types of requirements
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RequirementType {
    /// Functional requirement
    Functional,
    /// Non-functional requirement
    NonFunctional,
    /// Business requirement
    Business,
    /// Technical requirement
    Technical,
    /// User story
    UserStory,
    /// Epic
    Epic,
    /// Feature request
    Feature,
    /// Bug fix requirement
    BugFix,
    /// Performance requirement
    Performance,
    /// Security requirement
    Security,
}

/// Priority levels
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Priority {
    Low,
    Medium,
    High,
    Critical,
}

/// Requirement status
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RequirementStatus {
    Draft,
    Approved,
    InProgress,
    Implemented,
    Tested,
    Deployed,
    Rejected,
}

/// Implementation artifact
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Implementation {
    /// Unique identifier
    pub id: String,
    /// Implementation type
    pub implementation_type: ImplementationType,
    /// File path
    pub file_path: PathBuf,
    /// Code elements
    pub code_elements: Vec<CodeElement>,
    /// Implementation status
    pub status: ImplementationStatus,
    /// Quality metrics
    pub quality_metrics: QualityMetrics,
    /// Documentation
    pub documentation: Option<String>,
}

/// Types of implementation artifacts
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ImplementationType {
    Function,
    Class,
    Module,
    Interface,
    Database,
    API,
    Configuration,
    Test,
    Documentation,
    Infrastructure,
}

/// Code element within an implementation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CodeElement {
    /// Element name
    pub name: String,
    /// Element type
    pub element_type: String,
    /// Line range
    pub line_range: (usize, usize),
    /// Complexity score
    pub complexity: f64,
    /// Test coverage
    pub test_coverage: f64,
}

/// Implementation status
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ImplementationStatus {
    NotStarted,
    InProgress,
    Complete,
    Tested,
    Deployed,
    Deprecated,
}

/// Quality metrics for implementations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct QualityMetrics {
    /// Code coverage percentage
    pub coverage: f64,
    /// Complexity score
    pub complexity: f64,
    /// Maintainability index
    pub maintainability: f64,
    /// Performance score
    pub performance: f64,
    /// Security score
    pub security: f64,
}

/// Mapping between intent and implementation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct IntentMapping {
    /// Mapping identifier
    pub id: String,
    /// Requirement ID
    pub requirement_id: String,
    /// Implementation ID
    pub implementation_id: String,
    /// Mapping type
    pub mapping_type: MappingType,
    /// Confidence score (0.0 to 1.0)
    pub confidence: f64,
    /// Mapping rationale
    pub rationale: String,
    /// Validation status
    pub validation_status: ValidationStatus,
    /// Last updated timestamp
    pub last_updated: u64,
}

/// Types of mappings
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum MappingType {
    /// Direct one-to-one mapping
    Direct,
    /// One requirement to multiple implementations
    OneToMany,
    /// Multiple requirements to one implementation
    ManyToOne,
    /// Partial implementation
    Partial,
    /// Derived implementation
    Derived,
    /// Inferred mapping
    Inferred,
}

/// Validation status of mappings
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ValidationStatus {
    NotValidated,
    Valid,
    Invalid,
    NeedsReview,
    Outdated,
}

/// Traceability matrix for requirements
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TraceabilityMatrix {
    /// Forward traceability (requirement -> implementation)
    pub forward_trace: HashMap<String, Vec<String>>,
    /// Backward traceability (implementation -> requirement)
    pub backward_trace: HashMap<String, Vec<String>>,
    /// Coverage metrics
    pub coverage_metrics: CoverageMetrics,
}

/// Coverage metrics for traceability
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CoverageMetrics {
    /// Percentage of requirements with implementations
    pub requirement_coverage: f64,
    /// Percentage of implementations with requirements
    pub implementation_coverage: f64,
    /// Orphaned requirements (no implementation)
    pub orphaned_requirements: usize,
    /// Orphaned implementations (no requirement)
    pub orphaned_implementations: usize,
}

/// Configuration for intent mapping
#[derive(Debug, Clone)]
pub struct MappingConfig {
    /// Minimum confidence threshold for automatic mappings
    pub confidence_threshold: f64,
    /// Enable natural language processing
    pub enable_nlp: bool,
    /// Enable semantic similarity analysis
    pub enable_semantic_analysis: bool,
    /// Maximum mapping distance for similarity
    pub max_mapping_distance: f64,
    /// Auto-validation threshold
    pub auto_validation_threshold: f64,
}

impl Default for MappingConfig {
    fn default() -> Self {
        Self {
            confidence_threshold: DEFAULT_CONFIDENCE_THRESHOLD,
            enable_nlp: true,
            enable_semantic_analysis: true,
            max_mapping_distance: DEFAULT_MAX_MAPPING_DISTANCE,
            auto_validation_threshold: DEFAULT_AUTO_VALIDATION_THRESHOLD,
        }
    }
}

/// Result of intent mapping analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MappingAnalysisResult {
    /// Total requirements analyzed
    pub total_requirements: usize,
    /// Total implementations analyzed
    pub total_implementations: usize,
    /// Generated mappings
    pub mappings: Vec<IntentMapping>,
    /// Traceability matrix
    pub traceability: TraceabilityMatrix,
    /// Gap analysis
    pub gaps: Vec<MappingGap>,
    /// Recommendations
    pub recommendations: Vec<MappingRecommendation>,
    /// Analysis timestamp
    pub timestamp: u64,
}

/// Gap in requirement-implementation mapping
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MappingGap {
    /// Gap type
    pub gap_type: GapType,
    /// Description
    pub description: String,
    /// Affected requirement/implementation IDs
    pub affected_items: Vec<String>,
    /// Severity level
    pub severity: Priority,
    /// Suggested actions
    pub suggested_actions: Vec<String>,
}

/// Types of mapping gaps
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum GapType {
    /// Requirement without implementation
    MissingImplementation,
    /// Implementation without requirement
    MissingRequirement,
    /// Partial implementation
    IncompleteImplementation,
    /// Outdated mapping
    OutdatedMapping,
    /// Quality gap
    QualityGap,
    /// Test coverage gap
    TestGap,
}

/// Recommendation for improving mappings
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MappingRecommendation {
    /// Recommendation type
    pub recommendation_type: RecommendationType,
    /// Description
    pub description: String,
    /// Priority
    pub priority: Priority,
    /// Affected items
    pub affected_items: Vec<String>,
    /// Expected impact
    pub expected_impact: String,
    /// Effort estimate
    pub effort_estimate: EffortLevel,
}

/// Types of recommendations
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RecommendationType {
    CreateImplementation,
    CreateRequirement,
    UpdateMapping,
    ImproveQuality,
    AddTests,
    UpdateDocumentation,
    RefactorCode,
    ValidateMapping,
}

/// Effort estimation levels
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum EffortLevel {
    Small,   // < 1 day
    Medium,  // 1-3 days
    Large,   // 1-2 weeks
    XLarge,  // > 2 weeks
}

impl IntentMappingSystem {
    /// Create a new intent mapping system
    pub fn new() -> Self {
        Self {
            requirements: Vec::new(),
            implementations: Vec::new(),
            mappings: Vec::new(),
            traceability: TraceabilityMatrix::new(),
            config: MappingConfig::default(),
        }
    }

    /// Create system with custom configuration
    pub fn with_config(config: MappingConfig) -> Self {
        Self {
            requirements: Vec::new(),
            implementations: Vec::new(),
            mappings: Vec::new(),
            traceability: TraceabilityMatrix::new(),
            config,
        }
    }

    /// Helper function to create intent mapping without excessive cloning
    fn create_intent_mapping(
        id_prefix: &str,
        requirement_id: &str,
        implementation_id: &str,
        mapping_type: MappingType,
        confidence: f64,
        rationale: &str,
        validation_status: ValidationStatus,
    ) -> IntentMapping {
        IntentMapping {
            id: format!("{}_{}_{}", id_prefix, requirement_id, implementation_id),
            requirement_id: requirement_id.to_string(),
            implementation_id: implementation_id.to_string(),
            mapping_type,
            confidence,
            rationale: rationale.to_string(),
            validation_status,
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        }
    }

    /// Add a requirement to the system
    pub fn add_requirement(&mut self, requirement: Requirement) {
        self.requirements.push(requirement);
    }

    /// Add multiple requirements
    pub fn add_requirements(&mut self, requirements: Vec<Requirement>) {
        self.requirements.extend(requirements);
    }

    /// Extract implementations from analysis result
    pub fn extract_implementations(&mut self, analysis: &AnalysisResult) -> Result<()> {
        self.implementations.clear();
        
        for file in &analysis.files {
            let implementation = self.create_implementation_from_file(file)?;
            self.implementations.push(implementation);
        }
        
        Ok(())
    }

    /// Perform intent-to-implementation mapping analysis
    pub fn analyze_mappings(&mut self) -> Result<MappingAnalysisResult> {
        // Generate automatic mappings
        self.generate_automatic_mappings()?;

        // Build traceability matrix
        self.build_traceability_matrix();

        // Identify gaps
        let gaps = self.identify_gaps()?;

        // Generate recommendations
        let recommendations = self.generate_recommendations(&gaps)?;

        Ok(MappingAnalysisResult {
            total_requirements: self.requirements.len(),
            total_implementations: self.implementations.len(),
            mappings: self.mappings.clone(),
            traceability: self.traceability.clone(),
            gaps,
            recommendations,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    /// Validate existing mappings
    pub fn validate_mappings(&mut self) -> Result<Vec<IntentMapping>> {
        let mut validated_mappings = Vec::new();

        // Collect validation results first
        let mut validation_results = Vec::new();
        for mapping in &self.mappings {
            let validation_result = self.validate_mapping(mapping)?;
            validation_results.push(validation_result);
        }

        // Update mappings with validation results
        for (mapping, validation_result) in self.mappings.iter_mut().zip(validation_results.iter()) {
            mapping.validation_status = validation_result.clone();

            if *validation_result == ValidationStatus::Valid {
                validated_mappings.push(mapping.clone());
            }
        }

        Ok(validated_mappings)
    }

    /// Get traceability report
    pub fn get_traceability_report(&self) -> TraceabilityReport {
        let mut report = TraceabilityReport {
            forward_coverage: 0.0,
            backward_coverage: 0.0,
            orphaned_requirements: Vec::new(),
            orphaned_implementations: Vec::new(),
            mapping_quality_score: 0.0,
        };

        // Calculate forward coverage
        let requirements_with_impl = self.traceability.forward_trace.len();
        if !self.requirements.is_empty() {
            report.forward_coverage = requirements_with_impl as f64 / self.requirements.len() as f64;
        }

        // Calculate backward coverage
        let implementations_with_req = self.traceability.backward_trace.len();
        if !self.implementations.is_empty() {
            report.backward_coverage = implementations_with_req as f64 / self.implementations.len() as f64;
        }

        // Find orphaned items
        for req in &self.requirements {
            if !self.traceability.forward_trace.contains_key(&req.id) {
                report.orphaned_requirements.push(req.id.clone());
            }
        }

        for impl_item in &self.implementations {
            if !self.traceability.backward_trace.contains_key(&impl_item.id) {
                report.orphaned_implementations.push(impl_item.id.clone());
            }
        }

        // Calculate overall quality score
        let valid_mappings = self.mappings.iter()
            .filter(|m| m.validation_status == ValidationStatus::Valid)
            .count();

        if !self.mappings.is_empty() {
            report.mapping_quality_score = valid_mappings as f64 / self.mappings.len() as f64;
        }

        report
    }

    // Private implementation methods

    /// Create implementation from file info
    fn create_implementation_from_file(&self, file: &FileInfo) -> Result<Implementation> {
        let mut code_elements = Vec::new();

        for symbol in &file.symbols {
            let element = CodeElement {
                name: symbol.name.clone(),
                element_type: symbol.kind.clone(),
                line_range: (symbol.start_line, symbol.end_line),
                complexity: 1.0, // Default complexity
                test_coverage: 0.0, // Default coverage
            };
            code_elements.push(element);
        }

        let implementation = Implementation {
            id: format!("impl_{}", file.path.display()),
            implementation_type: self.infer_implementation_type(&file.language),
            file_path: file.path.clone(),
            code_elements,
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics {
                coverage: 0.0,
                complexity: 1.0,
                maintainability: 0.8,
                performance: 0.8,
                security: 0.8,
            },
            documentation: None,
        };

        Ok(implementation)
    }

    /// Infer implementation type from language
    fn infer_implementation_type(&self, language: &str) -> ImplementationType {
        match language.to_lowercase().as_str() {
            "rust" | "c" | "cpp" | "c++" => ImplementationType::Module,
            "python" | "javascript" | "typescript" => ImplementationType::Module,
            "sql" => ImplementationType::Database,
            "yaml" | "json" | "toml" => ImplementationType::Configuration,
            "md" | "markdown" | "rst" => ImplementationType::Documentation,
            _ => ImplementationType::Module,
        }
    }

    /// Generate automatic mappings using various strategies
    fn generate_automatic_mappings(&mut self) -> Result<()> {
        self.mappings.clear();

        // Strategy 1: Keyword-based matching
        self.generate_keyword_mappings()?;

        // Strategy 2: Semantic similarity matching
        if self.config.enable_semantic_analysis {
            self.generate_semantic_mappings()?;
        }

        // Strategy 3: Pattern-based matching
        self.generate_pattern_mappings()?;

        Ok(())
    }

    /// Generate mappings based on keyword matching
    fn generate_keyword_mappings(&mut self) -> Result<()> {
        for requirement in &self.requirements {
            let req_keywords = self.extract_keywords(&requirement.description);

            for implementation in &self.implementations {
                let impl_keywords = self.extract_implementation_keywords(implementation);
                let similarity = self.calculate_keyword_similarity(&req_keywords, &impl_keywords);

                if similarity >= self.config.confidence_threshold {
                    let validation_status = if similarity >= self.config.auto_validation_threshold {
                        ValidationStatus::Valid
                    } else {
                        ValidationStatus::NotValidated
                    };

                    let mapping = Self::create_intent_mapping(
                        "map",
                        &requirement.id,
                        &implementation.id,
                        MappingType::Direct,
                        similarity,
                        "Keyword-based matching",
                        validation_status,
                    );

                    self.mappings.push(mapping);
                }
            }
        }

        Ok(())
    }

    /// Generate mappings based on semantic similarity
    fn generate_semantic_mappings(&mut self) -> Result<()> {
        // Simplified semantic matching based on text similarity
        for requirement in &self.requirements {
            for implementation in &self.implementations {
                let semantic_score = self.calculate_semantic_similarity(
                    &requirement.description,
                    &self.get_implementation_description(implementation)
                );

                if semantic_score >= self.config.confidence_threshold {
                    // Check if mapping already exists
                    let exists = self.mappings.iter().any(|m|
                        m.requirement_id == requirement.id &&
                        m.implementation_id == implementation.id
                    );

                    if !exists {
                        let mapping = Self::create_intent_mapping(
                            "sem",
                            &requirement.id,
                            &implementation.id,
                            MappingType::Inferred,
                            semantic_score,
                            "Semantic similarity matching",
                            ValidationStatus::NeedsReview,
                        );

                        self.mappings.push(mapping);
                    }
                }
            }
        }

        Ok(())
    }

    /// Generate mappings based on common patterns
    fn generate_pattern_mappings(&mut self) -> Result<()> {
        // Pattern 1: User story to API endpoint
        for requirement in &self.requirements {
            if requirement.requirement_type == RequirementType::UserStory {
                for implementation in &self.implementations {
                    if implementation.implementation_type == ImplementationType::API {
                        let pattern_score = self.calculate_pattern_match(requirement, implementation);

                        if pattern_score >= self.config.confidence_threshold {
                            let mapping = IntentMapping {
                                id: format!("pat_{}_{}", requirement.id, implementation.id),
                                requirement_id: requirement.id.clone(),
                                implementation_id: implementation.id.clone(),
                                mapping_type: MappingType::Derived,
                                confidence: pattern_score,
                                rationale: "Pattern-based matching (User Story -> API)".to_string(),
                                validation_status: ValidationStatus::NeedsReview,
                                last_updated: std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap_or_default()
                                    .as_secs(),
                            };

                            self.mappings.push(mapping);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Build traceability matrix
    fn build_traceability_matrix(&mut self) {
        self.traceability = TraceabilityMatrix::new();

        for mapping in &self.mappings {
            // Forward traceability
            self.traceability.forward_trace
                .entry(mapping.requirement_id.to_string())
                .or_insert_with(Vec::new)
                .push(mapping.implementation_id.to_string());

            // Backward traceability
            self.traceability.backward_trace
                .entry(mapping.implementation_id.to_string())
                .or_insert_with(Vec::new)
                .push(mapping.requirement_id.to_string());
        }

        // Calculate coverage metrics
        let req_coverage = if self.requirements.is_empty() {
            0.0
        } else {
            self.traceability.forward_trace.len() as f64 / self.requirements.len() as f64
        };

        let impl_coverage = if self.implementations.is_empty() {
            0.0
        } else {
            self.traceability.backward_trace.len() as f64 / self.implementations.len() as f64
        };

        let orphaned_reqs = self.requirements.len() - self.traceability.forward_trace.len();
        let orphaned_impls = self.implementations.len() - self.traceability.backward_trace.len();

        self.traceability.coverage_metrics = CoverageMetrics {
            requirement_coverage: req_coverage,
            implementation_coverage: impl_coverage,
            orphaned_requirements: orphaned_reqs,
            orphaned_implementations: orphaned_impls,
        };
    }

    /// Identify gaps in mappings
    fn identify_gaps(&self) -> Result<Vec<MappingGap>> {
        let mut gaps = Vec::new();

        // Find requirements without implementations
        for requirement in &self.requirements {
            if !self.traceability.forward_trace.contains_key(&requirement.id) {
                gaps.push(MappingGap {
                    gap_type: GapType::MissingImplementation,
                    description: format!("Requirement '{}' has no implementation", requirement.id),
                    affected_items: vec![requirement.id.clone()],
                    severity: requirement.priority.clone(),
                    suggested_actions: vec![
                        "Create implementation".to_string(),
                        "Review requirement validity".to_string(),
                    ],
                });
            }
        }

        // Find implementations without requirements
        for implementation in &self.implementations {
            if !self.traceability.backward_trace.contains_key(&implementation.id) {
                gaps.push(MappingGap {
                    gap_type: GapType::MissingRequirement,
                    description: format!("Implementation '{}' has no requirement", implementation.id),
                    affected_items: vec![implementation.id.clone()],
                    severity: Priority::Medium,
                    suggested_actions: vec![
                        "Create requirement".to_string(),
                        "Review implementation necessity".to_string(),
                    ],
                });
            }
        }

        // Find quality gaps
        for implementation in &self.implementations {
            if implementation.quality_metrics.coverage < COVERAGE_THRESHOLD {
                gaps.push(MappingGap {
                    gap_type: GapType::TestGap,
                    description: format!("Implementation '{}' has low test coverage", implementation.id),
                    affected_items: vec![implementation.id.clone()],
                    severity: Priority::High,
                    suggested_actions: vec![
                        "Add unit tests".to_string(),
                        "Add integration tests".to_string(),
                    ],
                });
            }
        }

        Ok(gaps)
    }

    /// Generate recommendations
    fn generate_recommendations(&self, gaps: &[MappingGap]) -> Result<Vec<MappingRecommendation>> {
        let mut recommendations = Vec::new();

        for gap in gaps {
            match gap.gap_type {
                GapType::MissingImplementation => {
                    recommendations.push(MappingRecommendation {
                        recommendation_type: RecommendationType::CreateImplementation,
                        description: format!("Implement missing functionality for requirement"),
                        priority: gap.severity.clone(),
                        affected_items: gap.affected_items.clone(),
                        expected_impact: "Improved requirement coverage".to_string(),
                        effort_estimate: EffortLevel::Large,
                    });
                }
                GapType::MissingRequirement => {
                    recommendations.push(MappingRecommendation {
                        recommendation_type: RecommendationType::CreateRequirement,
                        description: format!("Document requirement for existing implementation"),
                        priority: Priority::Medium,
                        affected_items: gap.affected_items.clone(),
                        expected_impact: "Improved traceability".to_string(),
                        effort_estimate: EffortLevel::Small,
                    });
                }
                GapType::TestGap => {
                    recommendations.push(MappingRecommendation {
                        recommendation_type: RecommendationType::AddTests,
                        description: format!("Improve test coverage"),
                        priority: Priority::High,
                        affected_items: gap.affected_items.clone(),
                        expected_impact: "Improved quality and reliability".to_string(),
                        effort_estimate: EffortLevel::Medium,
                    });
                }
                _ => {}
            }
        }

        Ok(recommendations)
    }

    /// Validate a single mapping
    fn validate_mapping(&self, mapping: &IntentMapping) -> Result<ValidationStatus> {
        // Find the requirement and implementation
        let requirement = self.requirements.iter()
            .find(|r| r.id == mapping.requirement_id);
        let implementation = self.implementations.iter()
            .find(|i| i.id == mapping.implementation_id);

        let (req, impl_item) = match (requirement, implementation) {
            (Some(req), Some(impl_item)) => (req, impl_item),
            _ => return Ok(ValidationStatus::Invalid),
        };

        // Validation criteria
        let mut validation_score = 0.0;

        // Check confidence threshold
        if mapping.confidence >= self.config.auto_validation_threshold {
            validation_score += VALIDATION_CONFIDENCE_WEIGHT;
        }

        // Check requirement status
        if matches!(req.status, RequirementStatus::Approved | RequirementStatus::InProgress) {
            validation_score += VALIDATION_REQUIREMENT_WEIGHT;
        }

        // Check implementation status
        if matches!(impl_item.status, ImplementationStatus::Complete | ImplementationStatus::Tested) {
            validation_score += VALIDATION_IMPLEMENTATION_WEIGHT;
        }

        // Check quality metrics
        if impl_item.quality_metrics.coverage > QUALITY_COVERAGE_THRESHOLD {
            validation_score += VALIDATION_QUALITY_WEIGHT;
        }

        if validation_score >= VALIDATION_VALID_THRESHOLD {
            Ok(ValidationStatus::Valid)
        } else if validation_score >= VALIDATION_REVIEW_THRESHOLD {
            Ok(ValidationStatus::NeedsReview)
        } else {
            Ok(ValidationStatus::Invalid)
        }
    }

    // Helper methods for text analysis

    /// Extract keywords from text
    fn extract_keywords(&self, text: &str) -> Vec<String> {
        text.to_lowercase()
            .split_whitespace()
            .filter(|word| word.len() > 3)
            .filter(|word| !self.is_stop_word(word))
            .map(|word| word.trim_matches(|c: char| !c.is_alphanumeric()).to_string())
            .filter(|word| !word.is_empty())
            .collect()
    }

    /// Extract keywords from implementation
    fn extract_implementation_keywords(&self, implementation: &Implementation) -> Vec<String> {
        let mut keywords = Vec::new();

        // Add file path components
        if let Some(file_name) = implementation.file_path.file_stem() {
            if let Some(name_str) = file_name.to_str() {
                keywords.extend(self.extract_keywords(name_str));
            }
        }

        // Add code element names
        for element in &implementation.code_elements {
            keywords.extend(self.extract_keywords(&element.name));
        }

        keywords
    }

    /// Calculate keyword similarity
    fn calculate_keyword_similarity(&self, keywords1: &[String], keywords2: &[String]) -> f64 {
        if keywords1.is_empty() || keywords2.is_empty() {
            return 0.0;
        }

        let set1: HashSet<_> = keywords1.iter().collect();
        let set2: HashSet<_> = keywords2.iter().collect();

        let intersection = set1.intersection(&set2).count();
        let union = set1.union(&set2).count();

        if union == 0 {
            0.0
        } else {
            intersection as f64 / union as f64
        }
    }

    /// Calculate semantic similarity (simplified)
    fn calculate_semantic_similarity(&self, text1: &str, text2: &str) -> f64 {
        // Simplified semantic similarity using word overlap
        let words1 = self.extract_keywords(text1);
        let words2 = self.extract_keywords(text2);

        self.calculate_keyword_similarity(&words1, &words2)
    }

    /// Get implementation description
    fn get_implementation_description(&self, implementation: &Implementation) -> String {
        let mut description = String::new();

        if let Some(file_name) = implementation.file_path.file_name() {
            if let Some(name_str) = file_name.to_str() {
                description.push_str(name_str);
                description.push(' ');
            }
        }

        for element in &implementation.code_elements {
            description.push_str(&element.name);
            description.push(' ');
            description.push_str(&element.element_type);
            description.push(' ');
        }

        description
    }

    /// Calculate pattern match score
    fn calculate_pattern_match(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        let mut score = 0.0;

        // Type-based matching
        match (&requirement.requirement_type, &implementation.implementation_type) {
            (RequirementType::UserStory, ImplementationType::API) => score += USER_STORY_API_WEIGHT,
            (RequirementType::Functional, ImplementationType::Function) => score += FUNCTIONAL_FUNCTION_WEIGHT,
            (RequirementType::Technical, ImplementationType::Module) => score += TECHNICAL_MODULE_WEIGHT,
            (RequirementType::Security, _) => score += SECURITY_WEIGHT,
            _ => {}
        }

        // Keyword matching
        let req_keywords = self.extract_keywords(&requirement.description);
        let impl_keywords = self.extract_implementation_keywords(implementation);
        let keyword_sim = self.calculate_keyword_similarity(&req_keywords, &impl_keywords);

        score += keyword_sim * KEYWORD_SIMILARITY_WEIGHT;

        score.min(1.0)
    }

    /// Check if word is a stop word
    fn is_stop_word(&self, word: &str) -> bool {
        matches!(word, "the" | "and" | "or" | "but" | "in" | "on" | "at" | "to" | "for" | "of" | "with" | "by" | "a" | "an" | "is" | "are" | "was" | "were" | "be" | "been" | "have" | "has" | "had" | "do" | "does" | "did" | "will" | "would" | "could" | "should" | "may" | "might" | "can" | "this" | "that" | "these" | "those")
    }

    // Public getter methods for testing

    /// Get requirements (for testing)
    pub fn requirements(&self) -> &[Requirement] {
        &self.requirements
    }

    /// Get implementations (for testing)
    pub fn implementations(&self) -> &[Implementation] {
        &self.implementations
    }

    /// Get mappings (for testing)
    pub fn mappings(&self) -> &[IntentMapping] {
        &self.mappings
    }

    /// Get configuration (for testing)
    pub fn config(&self) -> &MappingConfig {
        &self.config
    }

    /// Get traceability matrix (for testing)
    pub fn traceability(&self) -> &TraceabilityMatrix {
        &self.traceability
    }

    /// Add implementation directly (for testing)
    pub fn add_implementation(&mut self, implementation: Implementation) {
        self.implementations.push(implementation);
    }

    /// Add mapping directly (for testing)
    pub fn add_mapping(&mut self, mapping: IntentMapping) {
        self.mappings.push(mapping);
    }

    /// Build traceability matrix (for testing)
    pub fn build_traceability_matrix_public(&mut self) {
        self.build_traceability_matrix();
    }

    /// Identify gaps (for testing)
    pub fn identify_gaps_public(&self) -> Result<Vec<MappingGap>> {
        self.identify_gaps()
    }

    /// Generate recommendations (for testing)
    pub fn generate_recommendations_public(&self, gaps: &[MappingGap]) -> Result<Vec<MappingRecommendation>> {
        self.generate_recommendations(gaps)
    }

    /// Validate mapping (for testing)
    pub fn validate_mapping_public(&self, mapping: &IntentMapping) -> Result<ValidationStatus> {
        self.validate_mapping(mapping)
    }

    /// Extract keywords (for testing)
    pub fn extract_keywords_public(&self, text: &str) -> Vec<String> {
        self.extract_keywords(text)
    }

    /// Calculate keyword similarity (for testing)
    pub fn calculate_keyword_similarity_public(&self, keywords1: &[String], keywords2: &[String]) -> f64 {
        self.calculate_keyword_similarity(keywords1, keywords2)
    }

    /// Extract implementation keywords (for testing)
    pub fn extract_implementation_keywords_public(&self, implementation: &Implementation) -> Vec<String> {
        self.extract_implementation_keywords(implementation)
    }

    /// Calculate pattern match (for testing)
    pub fn calculate_pattern_match_public(&self, requirement: &Requirement, implementation: &Implementation) -> f64 {
        self.calculate_pattern_match(requirement, implementation)
    }
}

/// Traceability report
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TraceabilityReport {
    /// Forward coverage percentage
    pub forward_coverage: f64,
    /// Backward coverage percentage
    pub backward_coverage: f64,
    /// Orphaned requirements
    pub orphaned_requirements: Vec<String>,
    /// Orphaned implementations
    pub orphaned_implementations: Vec<String>,
    /// Overall mapping quality score
    pub mapping_quality_score: f64,
}

impl TraceabilityMatrix {
    fn new() -> Self {
        Self {
            forward_trace: HashMap::new(),
            backward_trace: HashMap::new(),
            coverage_metrics: CoverageMetrics {
                requirement_coverage: 0.0,
                implementation_coverage: 0.0,
                orphaned_requirements: 0,
                orphaned_implementations: 0,
            },
        }
    }
}

impl Default for IntentMappingSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for QualityMetrics {
    fn default() -> Self {
        Self {
            coverage: DEFAULT_COVERAGE,
            complexity: DEFAULT_COMPLEXITY,
            maintainability: DEFAULT_MAINTAINABILITY,
            performance: DEFAULT_PERFORMANCE,
            security: DEFAULT_SECURITY,
        }
    }
}

impl std::fmt::Display for RequirementType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequirementType::Functional => write!(f, "functional"),
            RequirementType::NonFunctional => write!(f, "non-functional"),
            RequirementType::Business => write!(f, "business"),
            RequirementType::Technical => write!(f, "technical"),
            RequirementType::UserStory => write!(f, "user-story"),
            RequirementType::Epic => write!(f, "epic"),
            RequirementType::Feature => write!(f, "feature"),
            RequirementType::BugFix => write!(f, "bug-fix"),
            RequirementType::Performance => write!(f, "performance"),
            RequirementType::Security => write!(f, "security"),
        }
    }
}

impl std::fmt::Display for ImplementationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ImplementationType::Function => write!(f, "function"),
            ImplementationType::Class => write!(f, "class"),
            ImplementationType::Module => write!(f, "module"),
            ImplementationType::Interface => write!(f, "interface"),
            ImplementationType::Database => write!(f, "database"),
            ImplementationType::API => write!(f, "api"),
            ImplementationType::Configuration => write!(f, "configuration"),
            ImplementationType::Test => write!(f, "test"),
            ImplementationType::Documentation => write!(f, "documentation"),
            ImplementationType::Infrastructure => write!(f, "infrastructure"),
        }
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Priority::Low => write!(f, "low"),
            Priority::Medium => write!(f, "medium"),
            Priority::High => write!(f, "high"),
            Priority::Critical => write!(f, "critical"),
        }
    }
}

impl std::fmt::Display for MappingType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MappingType::Direct => write!(f, "direct"),
            MappingType::OneToMany => write!(f, "one-to-many"),
            MappingType::ManyToOne => write!(f, "many-to-one"),
            MappingType::Partial => write!(f, "partial"),
            MappingType::Derived => write!(f, "derived"),
            MappingType::Inferred => write!(f, "inferred"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_intent_mapping_system_creation() {
        let system = IntentMappingSystem::new();
        assert_eq!(system.requirements().len(), 0);
        assert_eq!(system.implementations().len(), 0);
        assert_eq!(system.mappings().len(), 0);
        assert_eq!(system.config().confidence_threshold, DEFAULT_CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn test_intent_mapping_system_with_config() {
        let mut config = MappingConfig::default();
        config.confidence_threshold = 0.9;
        config.enable_nlp = false;

        let system = IntentMappingSystem::with_config(config.clone());
        assert_eq!(system.config().confidence_threshold, 0.9);
        assert!(!system.config().enable_nlp);
    }

    #[test]
    fn test_mapping_config_default() {
        let config = MappingConfig::default();
        assert_eq!(config.confidence_threshold, DEFAULT_CONFIDENCE_THRESHOLD);
        assert_eq!(config.max_mapping_distance, DEFAULT_MAX_MAPPING_DISTANCE);
        assert_eq!(config.auto_validation_threshold, DEFAULT_AUTO_VALIDATION_THRESHOLD);
        assert!(config.enable_nlp);
        assert!(config.enable_semantic_analysis);
    }

    #[test]
    fn test_requirement_creation() {
        let requirement = Requirement {
            id: "REQ-001".to_string(),
            requirement_type: RequirementType::UserStory,
            description: "As a user, I want to log in".to_string(),
            priority: Priority::High,
            acceptance_criteria: vec![
                "User can enter credentials".to_string(),
                "System validates credentials".to_string(),
            ],
            stakeholders: vec!["Product Owner".to_string(), "Development Team".to_string()],
            tags: vec!["authentication".to_string(), "security".to_string()],
            status: RequirementStatus::Approved,
        };

        assert_eq!(requirement.id, "REQ-001");
        assert!(matches!(requirement.requirement_type, RequirementType::UserStory));
        assert!(matches!(requirement.priority, Priority::High));
        assert!(matches!(requirement.status, RequirementStatus::Approved));
        assert_eq!(requirement.acceptance_criteria.len(), 2);
        assert_eq!(requirement.stakeholders.len(), 2);
        assert_eq!(requirement.tags.len(), 2);
    }

    #[test]
    fn test_requirement_type_variants() {
        let types = vec![
            RequirementType::Functional,
            RequirementType::NonFunctional,
            RequirementType::Business,
            RequirementType::Technical,
            RequirementType::UserStory,
            RequirementType::Epic,
            RequirementType::Feature,
            RequirementType::BugFix,
            RequirementType::Performance,
            RequirementType::Security,
        ];

        assert_eq!(types.len(), 10);
        assert!(types.contains(&RequirementType::UserStory));
        assert!(types.contains(&RequirementType::Security));
    }

    #[test]
    fn test_priority_ordering() {
        assert!(Priority::Critical > Priority::High);
        assert!(Priority::High > Priority::Medium);
        assert!(Priority::Medium > Priority::Low);
    }

    #[test]
    fn test_requirement_status_variants() {
        let statuses = vec![
            RequirementStatus::Draft,
            RequirementStatus::Approved,
            RequirementStatus::InProgress,
            RequirementStatus::Implemented,
            RequirementStatus::Tested,
            RequirementStatus::Deployed,
            RequirementStatus::Rejected,
        ];

        assert_eq!(statuses.len(), 7);
        assert!(statuses.contains(&RequirementStatus::Approved));
        assert!(statuses.contains(&RequirementStatus::Implemented));
    }

    #[test]
    fn test_implementation_creation() {
        let implementation = Implementation {
            id: "IMPL-001".to_string(),
            implementation_type: ImplementationType::Function,
            file_path: PathBuf::from("src/auth.rs"),
            code_elements: vec![
                CodeElement {
                    name: "login".to_string(),
                    element_type: "function".to_string(),
                    line_range: (10, 25),
                    complexity: 2.5,
                    test_coverage: 0.85,
                }
            ],
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics::default(),
            documentation: Some("User authentication function".to_string()),
        };

        assert_eq!(implementation.id, "IMPL-001");
        assert!(matches!(implementation.implementation_type, ImplementationType::Function));
        assert_eq!(implementation.file_path, PathBuf::from("src/auth.rs"));
        assert!(matches!(implementation.status, ImplementationStatus::Complete));
        assert_eq!(implementation.code_elements.len(), 1);
        assert!(implementation.documentation.is_some());
    }

    #[test]
    fn test_implementation_type_variants() {
        let types = vec![
            ImplementationType::Function,
            ImplementationType::Class,
            ImplementationType::Module,
            ImplementationType::Interface,
            ImplementationType::Database,
            ImplementationType::API,
            ImplementationType::Configuration,
            ImplementationType::Test,
            ImplementationType::Documentation,
            ImplementationType::Infrastructure,
        ];

        assert_eq!(types.len(), 10);
        assert!(types.contains(&ImplementationType::Function));
        assert!(types.contains(&ImplementationType::API));
    }

    #[test]
    fn test_code_element_creation() {
        let element = CodeElement {
            name: "authenticate_user".to_string(),
            element_type: "function".to_string(),
            line_range: (15, 30),
            complexity: 3.2,
            test_coverage: 0.92,
        };

        assert_eq!(element.name, "authenticate_user");
        assert_eq!(element.element_type, "function");
        assert_eq!(element.line_range, (15, 30));
        assert_eq!(element.complexity, 3.2);
        assert_eq!(element.test_coverage, 0.92);
    }

    #[test]
    fn test_implementation_status_variants() {
        let statuses = vec![
            ImplementationStatus::NotStarted,
            ImplementationStatus::InProgress,
            ImplementationStatus::Complete,
            ImplementationStatus::Tested,
            ImplementationStatus::Deployed,
            ImplementationStatus::Deprecated,
        ];

        assert_eq!(statuses.len(), 6);
        assert!(statuses.contains(&ImplementationStatus::Complete));
        assert!(statuses.contains(&ImplementationStatus::Tested));
    }

    #[test]
    fn test_quality_metrics_creation() {
        let metrics = QualityMetrics {
            coverage: 0.85,
            complexity: 2.3,
            maintainability: 0.78,
            performance: 0.91,
            security: 0.88,
        };

        assert_eq!(metrics.coverage, 0.85);
        assert_eq!(metrics.complexity, 2.3);
        assert_eq!(metrics.maintainability, 0.78);
        assert_eq!(metrics.performance, 0.91);
        assert_eq!(metrics.security, 0.88);
    }

    #[test]
    fn test_quality_metrics_default() {
        let metrics = QualityMetrics::default();
        assert_eq!(metrics.coverage, DEFAULT_COVERAGE);
        assert_eq!(metrics.complexity, DEFAULT_COMPLEXITY);
        assert_eq!(metrics.maintainability, DEFAULT_MAINTAINABILITY);
        assert_eq!(metrics.performance, DEFAULT_PERFORMANCE);
        assert_eq!(metrics.security, DEFAULT_SECURITY);
    }

    #[test]
    fn test_intent_mapping_creation() {
        let mapping = IntentMapping {
            id: "MAP-001".to_string(),
            requirement_id: "REQ-001".to_string(),
            implementation_id: "IMPL-001".to_string(),
            mapping_type: MappingType::Direct,
            confidence: 0.92,
            rationale: "Direct keyword match".to_string(),
            validation_status: ValidationStatus::Valid,
            last_updated: 1234567890,
        };

        assert_eq!(mapping.id, "MAP-001");
        assert_eq!(mapping.requirement_id, "REQ-001");
        assert_eq!(mapping.implementation_id, "IMPL-001");
        assert!(matches!(mapping.mapping_type, MappingType::Direct));
        assert_eq!(mapping.confidence, 0.92);
        assert!(matches!(mapping.validation_status, ValidationStatus::Valid));
    }

    #[test]
    fn test_mapping_type_variants() {
        let types = vec![
            MappingType::Direct,
            MappingType::OneToMany,
            MappingType::ManyToOne,
            MappingType::Partial,
            MappingType::Derived,
            MappingType::Inferred,
        ];

        assert_eq!(types.len(), 6);
        assert!(types.contains(&MappingType::Direct));
        assert!(types.contains(&MappingType::Inferred));
    }

    #[test]
    fn test_validation_status_variants() {
        let statuses = vec![
            ValidationStatus::NotValidated,
            ValidationStatus::Valid,
            ValidationStatus::Invalid,
            ValidationStatus::NeedsReview,
            ValidationStatus::Outdated,
        ];

        assert_eq!(statuses.len(), 5);
        assert!(statuses.contains(&ValidationStatus::Valid));
        assert!(statuses.contains(&ValidationStatus::NeedsReview));
    }

    #[test]
    fn test_traceability_matrix_creation() {
        let matrix = TraceabilityMatrix::new();
        assert!(matrix.forward_trace.is_empty());
        assert!(matrix.backward_trace.is_empty());
        assert_eq!(matrix.coverage_metrics.requirement_coverage, 0.0);
        assert_eq!(matrix.coverage_metrics.implementation_coverage, 0.0);
        assert_eq!(matrix.coverage_metrics.orphaned_requirements, 0);
        assert_eq!(matrix.coverage_metrics.orphaned_implementations, 0);
    }

    #[test]
    fn test_coverage_metrics_creation() {
        let metrics = CoverageMetrics {
            requirement_coverage: 0.85,
            implementation_coverage: 0.92,
            orphaned_requirements: 3,
            orphaned_implementations: 1,
        };

        assert_eq!(metrics.requirement_coverage, 0.85);
        assert_eq!(metrics.implementation_coverage, 0.92);
        assert_eq!(metrics.orphaned_requirements, 3);
        assert_eq!(metrics.orphaned_implementations, 1);
    }

    fn create_test_requirement() -> Requirement {
        Requirement {
            id: "REQ-TEST-001".to_string(),
            requirement_type: RequirementType::UserStory,
            description: "As a user, I want to authenticate securely".to_string(),
            priority: Priority::High,
            acceptance_criteria: vec![
                "User can enter username and password".to_string(),
                "System validates credentials".to_string(),
                "User is redirected on success".to_string(),
            ],
            stakeholders: vec!["Product Owner".to_string()],
            tags: vec!["authentication".to_string(), "security".to_string()],
            status: RequirementStatus::Approved,
        }
    }

    fn create_test_implementation() -> Implementation {
        Implementation {
            id: "IMPL-TEST-001".to_string(),
            implementation_type: ImplementationType::Function,
            file_path: PathBuf::from("src/auth.rs"),
            code_elements: vec![
                CodeElement {
                    name: "authenticate".to_string(),
                    element_type: "function".to_string(),
                    line_range: (10, 25),
                    complexity: 2.0,
                    test_coverage: 0.9,
                }
            ],
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics {
                coverage: 0.9,
                complexity: 2.0,
                maintainability: 0.8,
                performance: 0.85,
                security: 0.9,
            },
            documentation: Some("Authentication function".to_string()),
        }
    }

    #[test]
    fn test_add_requirement() {
        let mut system = IntentMappingSystem::new();
        let requirement = create_test_requirement();

        system.add_requirement(requirement.clone());
        assert_eq!(system.requirements().len(), 1);
        assert_eq!(system.requirements()[0].id, requirement.id);
    }

    #[test]
    fn test_add_multiple_requirements() {
        let mut system = IntentMappingSystem::new();
        let requirements = vec![
            create_test_requirement(),
            Requirement {
                id: "REQ-TEST-002".to_string(),
                requirement_type: RequirementType::Functional,
                description: "System should validate input".to_string(),
                priority: Priority::Medium,
                acceptance_criteria: vec!["Input is validated".to_string()],
                stakeholders: vec!["Developer".to_string()],
                tags: vec!["validation".to_string()],
                status: RequirementStatus::Draft,
            }
        ];

        system.add_requirements(requirements);
        assert_eq!(system.requirements().len(), 2);
    }

    #[test]
    fn test_add_implementation() {
        let mut system = IntentMappingSystem::new();
        let implementation = create_test_implementation();

        system.add_implementation(implementation.clone());
        assert_eq!(system.implementations().len(), 1);
        assert_eq!(system.implementations()[0].id, implementation.id);
    }

    #[test]
    fn test_extract_keywords() {
        let system = IntentMappingSystem::new();
        let text = "As a user, I want to authenticate securely with the system";
        let keywords = system.extract_keywords_public(text);

        assert!(keywords.contains(&"user".to_string()));
        assert!(keywords.contains(&"authenticate".to_string()));
        assert!(keywords.contains(&"securely".to_string()));
        assert!(keywords.contains(&"system".to_string()));

        // Should not contain stop words
        assert!(!keywords.contains(&"as".to_string()));
        assert!(!keywords.contains(&"a".to_string()));
        assert!(!keywords.contains(&"to".to_string()));
        assert!(!keywords.contains(&"with".to_string()));
        assert!(!keywords.contains(&"the".to_string()));
    }

    #[test]
    fn test_calculate_keyword_similarity() {
        let system = IntentMappingSystem::new();
        let keywords1 = vec!["user".to_string(), "authenticate".to_string(), "security".to_string()];
        let keywords2 = vec!["user".to_string(), "login".to_string(), "security".to_string()];

        let similarity = system.calculate_keyword_similarity_public(&keywords1, &keywords2);
        assert!(similarity > 0.0);
        assert!(similarity <= 1.0);

        // Test identical keywords
        let identical_similarity = system.calculate_keyword_similarity_public(&keywords1, &keywords1);
        assert_eq!(identical_similarity, 1.0);

        // Test no overlap
        let keywords3 = vec!["database".to_string(), "query".to_string()];
        let no_overlap_similarity = system.calculate_keyword_similarity_public(&keywords1, &keywords3);
        assert_eq!(no_overlap_similarity, 0.0);
    }

    #[test]
    fn test_extract_implementation_keywords() {
        let system = IntentMappingSystem::new();
        let implementation = create_test_implementation();

        let keywords = system.extract_implementation_keywords_public(&implementation);
        assert!(keywords.contains(&"auth".to_string()));
        assert!(keywords.contains(&"authenticate".to_string()));
    }

    #[test]
    fn test_build_traceability_matrix() {
        let mut system = IntentMappingSystem::new();
        let requirement = create_test_requirement();
        let implementation = create_test_implementation();

        system.add_requirement(requirement.clone());
        system.add_implementation(implementation.clone());

        let mapping = IntentMapping {
            id: "MAP-TEST-001".to_string(),
            requirement_id: requirement.id.clone(),
            implementation_id: implementation.id.clone(),
            mapping_type: MappingType::Direct,
            confidence: 0.9,
            rationale: "Test mapping".to_string(),
            validation_status: ValidationStatus::Valid,
            last_updated: 1234567890,
        };

        system.add_mapping(mapping);
        system.build_traceability_matrix_public();

        let traceability = system.traceability();
        assert!(traceability.forward_trace.contains_key(&requirement.id));
        assert!(traceability.backward_trace.contains_key(&implementation.id));
    }

    #[test]
    fn test_identify_gaps() {
        let mut system = IntentMappingSystem::new();

        // Add requirement without implementation
        let orphaned_requirement = Requirement {
            id: "REQ-ORPHANED".to_string(),
            requirement_type: RequirementType::Functional,
            description: "Orphaned requirement".to_string(),
            priority: Priority::Medium,
            acceptance_criteria: vec!["Should be implemented".to_string()],
            stakeholders: vec!["Developer".to_string()],
            tags: vec!["orphaned".to_string()],
            status: RequirementStatus::Approved,
        };

        // Add implementation without requirement
        let orphaned_implementation = Implementation {
            id: "IMPL-ORPHANED".to_string(),
            implementation_type: ImplementationType::Function,
            file_path: PathBuf::from("src/orphaned.rs"),
            code_elements: vec![],
            status: ImplementationStatus::Complete,
            quality_metrics: QualityMetrics::default(),
            documentation: None,
        };

        system.add_requirement(orphaned_requirement);
        system.add_implementation(orphaned_implementation);
        system.build_traceability_matrix_public();

        let gaps = system.identify_gaps_public().unwrap();
        assert!(gaps.len() >= 2); // At least one missing implementation and one missing requirement

        let missing_impl_gaps: Vec<_> = gaps.iter()
            .filter(|g| g.gap_type == GapType::MissingImplementation)
            .collect();
        assert!(!missing_impl_gaps.is_empty());

        let missing_req_gaps: Vec<_> = gaps.iter()
            .filter(|g| g.gap_type == GapType::MissingRequirement)
            .collect();
        assert!(!missing_req_gaps.is_empty());
    }

    #[test]
    fn test_generate_recommendations() {
        let system = IntentMappingSystem::new();
        let gaps = vec![
            MappingGap {
                gap_type: GapType::MissingImplementation,
                description: "Missing implementation for requirement".to_string(),
                affected_items: vec!["REQ-001".to_string()],
                severity: Priority::High,
                suggested_actions: vec!["Create implementation".to_string()],
            },
            MappingGap {
                gap_type: GapType::TestGap,
                description: "Low test coverage".to_string(),
                affected_items: vec!["IMPL-001".to_string()],
                severity: Priority::Medium,
                suggested_actions: vec!["Add tests".to_string()],
            }
        ];

        let recommendations = system.generate_recommendations_public(&gaps).unwrap();
        assert_eq!(recommendations.len(), 2);

        let create_impl_recs: Vec<_> = recommendations.iter()
            .filter(|r| r.recommendation_type == RecommendationType::CreateImplementation)
            .collect();
        assert_eq!(create_impl_recs.len(), 1);

        let add_test_recs: Vec<_> = recommendations.iter()
            .filter(|r| r.recommendation_type == RecommendationType::AddTests)
            .collect();
        assert_eq!(add_test_recs.len(), 1);
    }

    #[test]
    fn test_display_implementations() {
        assert_eq!(format!("{}", RequirementType::UserStory), "user-story");
        assert_eq!(format!("{}", RequirementType::Security), "security");
        assert_eq!(format!("{}", ImplementationType::Function), "function");
        assert_eq!(format!("{}", ImplementationType::API), "api");
        assert_eq!(format!("{}", Priority::High), "high");
        assert_eq!(format!("{}", Priority::Critical), "critical");
        assert_eq!(format!("{}", MappingType::Direct), "direct");
        assert_eq!(format!("{}", MappingType::OneToMany), "one-to-many");
    }
}
