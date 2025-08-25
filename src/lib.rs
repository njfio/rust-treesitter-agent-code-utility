//! # Rust Tree-sitter Library
//!
//! A comprehensive Rust library for processing source code using tree-sitter.
//! This library provides high-level abstractions for parsing, navigating, and
//! querying syntax trees across multiple programming languages.
//!
//! ## Features
//!
//! - Multi-language parsing support (Rust, JavaScript, Python, C, C++)
//! - Incremental parsing for efficient updates
//! - Syntax tree navigation utilities
//! - Query system for pattern matching
//! - Thread-safe parser management
//! - Memory-efficient tree handling
//!
//! ## Quick Start
//!
//! ```rust
//! use rust_tree_sitter::{Parser, Language};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let parser = Parser::new(Language::Rust)?;
//! let source = "fn main() { println!(\"Hello, world!\"); }";
//! let tree = parser.parse(source, None)?;
//!
//! println!("Root node: {}", tree.root_node().kind());
//! # Ok(())
//! # }
//! ```

/// AI service layer and provider integrations
pub mod ai;
/// Advanced AI-powered code analysis capabilities
pub mod advanced_ai_analysis;
/// Advanced security analysis with OWASP compliance
pub mod advanced_security;
/// AI-powered code explanation and insights
pub mod ai_analysis;
/// Utility functions for code analysis
pub mod analysis_utils;
/// Common analysis functionality and helpers
pub mod analysis_common;
/// Control flow graph construction and analysis
pub mod control_flow;
/// Code complexity metrics and analysis
pub mod complexity_analysis;
/// Taint analysis for security vulnerability detection
pub mod taint_analysis;
/// SQL injection vulnerability detection
pub mod sql_injection_detector;
/// Command injection vulnerability detection
pub mod command_injection_detector;
/// Symbol table construction and management
pub mod symbol_table;
/// Semantic context analysis and data flow
pub mod semantic_context;
/// Main codebase analyzer functionality
pub mod analyzer;
/// AST transformation and refactoring engine
pub mod ast_transformation;
/// Command-line interface implementation
pub mod cli;
/// Code evolution tracking and analysis
pub mod code_evolution;
/// Code mapping and visualization utilities
pub mod code_map;
/// Configuration constants and defaults
pub mod constants;
/// Dependency analysis and vulnerability scanning
pub mod dependency_analysis;
/// Enhanced security analysis with compliance checking
// #[cfg(any(feature = "net", feature = "db"))]
// pub mod enhanced_security; // TODO: Fix infrastructure dependency
/// Error types and handling
pub mod error;
/// File caching for performance optimization
pub mod file_cache;
/// Infrastructure and configuration management
// #[cfg(any(feature = "net", feature = "db"))]
// pub mod infrastructure; // TODO: Fix sqlx dependency issues
/// Intent mapping between requirements and implementation
#[cfg(feature = "ml")]
pub mod intent_mapping;
#[cfg(not(feature = "ml"))]
pub mod intent_mapping_stub;
#[cfg(not(feature = "ml"))]
pub use intent_mapping_stub as intent_mapping;
/// Text embeddings and semantic similarity
#[cfg(feature = "ml")]
pub mod embeddings;
/// Memory allocation tracking and analysis
pub mod memory_tracker;
/// Programming language support and parsers
pub mod languages;
/// Tree-sitter parser integration
pub mod parser;
/// Performance analysis and optimization detection
pub mod performance_analysis;
/// Code querying and pattern matching
pub mod query;
/// Automated reasoning and inference engine
pub mod reasoning_engine;
/// Code refactoring suggestions and analysis
pub mod refactoring;
/// Security analysis and vulnerability detection
// pub mod security; // TODO: Fix infrastructure dependency
/// Semantic graph construction and querying
pub mod semantic_graph;
/// Smart refactoring with AI assistance
pub mod smart_refactoring;
/// Test coverage analysis and gap detection
pub mod test_coverage;
/// Syntax tree manipulation and traversal
pub mod tree;

// Re-export commonly used types

// Core analysis types
pub use analyzer::{CodebaseAnalyzer, AnalysisConfig, AnalysisDepth, AnalysisResult, FileInfo, Symbol};
pub use error::{Error, Result};
pub use languages::Language;
pub use parser::{Parser, ParseOptions, create_edit};
pub use query::{Query, QueryCapture, QueryMatch, QueryBuilder};
pub use tree::{Node, SyntaxTree, TreeCursor, TreeEdit};

// Basic analysis modules
pub use ai_analysis::{AIAnalyzer, AIAnalysisResult, AIConfig, CodebaseExplanation, FileExplanation, SymbolExplanation};
pub use complexity_analysis::{ComplexityAnalyzer, ComplexityMetrics, HalsteadMetrics};
pub use dependency_analysis::{DependencyAnalyzer, DependencyAnalysisResult, DependencyConfig, Dependency, PackageManager};
pub use performance_analysis::{PerformanceAnalyzer, PerformanceAnalysisResult, PerformanceConfig, PerformanceHotspot};
pub use refactoring::{RefactoringAnalyzer, RefactoringResult, RefactoringSuggestion, RefactoringConfig};
pub use test_coverage::{TestCoverageAnalyzer, TestCoverageResult, TestCoverageConfig, MissingTest};

// Security analysis
// pub use security::OwaspDetector; // TODO: Fix infrastructure dependency
// #[cfg(any(feature = "net", feature = "db"))]
// pub use security::{VulnerabilityDatabase, SecretsDetector}; // TODO: Fix infrastructure dependency
// #[cfg(any(feature = "net", feature = "db"))]
// pub use enhanced_security::{EnhancedSecurityScanner, EnhancedSecurityResult, EnhancedSecurityConfig}; // TODO: Fix infrastructure dependency
pub use advanced_security::{AdvancedSecurityAnalyzer as SecurityScanner, AdvancedSecurityResult as SecurityScanResult, SecurityVulnerability, AdvancedSecurityConfig as SecurityConfig, SecuritySeverity};

// AI service layer
pub use ai::{AIService, AIServiceBuilder, AIConfig as AIServiceConfig, AIProvider, AIFeature, AIRequest, AIResponse, AIError, AIResult};

// Advanced features
pub use advanced_ai_analysis::{AdvancedAIAnalyzer, AdvancedAIResult, AdvancedAIConfig, SemanticAnalysis, ArchitecturePattern};
pub use smart_refactoring::{SmartRefactoringEngine, SmartRefactoringResult, SmartRefactoringConfig, CodeSmellFix};
pub use ast_transformation::{
    AstTransformationEngine, TransformationConfig, Transformation, TransformationType,
    TransformationResult, SemanticValidator, ValidationResult, ValidationConfig,
    TransformationLocation, Position, TransformationMetadata, TransformationImpact,
    ExtractedVariableAnalysis, VariableInfo, ImpactScope
};
pub use code_map::{CallGraph, ModuleGraph, build_call_graph, build_module_graph};

// Specialized analysis tools
pub use control_flow::{ControlFlowGraph, CfgBuilder, CfgNodeType};
pub use taint_analysis::{TaintAnalyzer, TaintFlow, TaintSource, TaintSink, VulnerabilityType};
pub use sql_injection_detector::{SqlInjectionDetector, SqlInjectionVulnerability, SqlInjectionType};
pub use command_injection_detector::{CommandInjectionDetector, CommandInjectionVulnerability, CommandInjectionType};
pub use symbol_table::{SymbolTableAnalyzer, SymbolTable, SymbolDefinition, SymbolReference, SymbolAnalysisResult, Scope, ScopeType, SymbolType, ReferenceType};
pub use semantic_context::{SemanticContextAnalyzer, SemanticContext, DataFlowAnalysis, SecuritySemanticContext, ValidationPoint, SanitizationPoint, TrustLevel};
pub use semantic_graph::{SemanticGraphQuery, GraphNode, GraphEdge, NodeType, RelationshipType, QueryResult, QueryConfig, GraphStatistics};

// Advanced AI features
pub use code_evolution::{CodeEvolutionTracker, EvolutionAnalysisResult, EvolutionConfig, ChangePattern, PatternType, EvolutionMetrics, FileInsight, EvolutionRecommendation, ChangeType};
#[cfg(feature = "ml")]
pub use intent_mapping::{
    IntentMappingSystem, MappingAnalysisResult, MappingConfig, Requirement, Implementation,
    IntentMapping, TraceabilityMatrix, TraceabilityReport, RequirementType, ImplementationType,
    Priority as IntentPriority, RequirementStatus, ImplementationStatus, QualityMetrics,
    CodeElement, MappingType, ValidationStatus, GapType, RecommendationType, MappingGap,
    MappingRecommendation
};
#[cfg(not(feature = "ml"))]
pub use intent_mapping::IntentMappingSystem;
pub use reasoning_engine::{
    AutomatedReasoningEngine, ReasoningResult, ReasoningConfig, Fact, Rule, KnowledgeBase,
    InferenceEngine, ConstraintSolver, TheoremProver, ReasoningInsight, InsightType
};
pub use memory_tracker::{
    MemoryTracker, MemoryTrackingResult, MemoryTrackingConfig, AllocationHotspot,
    MemoryLeakCandidate, AllocationPattern, FragmentationAnalysis, MemorySnapshot,
    AllocationCallStack, AllocationType, LeakType, UsagePattern, AllocationLocation,
    LifetimeStatistics, AllocationImpact, MemoryStatistics
};

// Utilities
pub use file_cache::{FileCache, CacheStats};

// Re-export tree-sitter types that users might need
pub use tree_sitter::{InputEdit, Point, Range};

// Re-export common types from constants
pub use constants::common::RiskLevel;

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Supported language information
#[derive(Debug, Clone)]
pub struct LanguageInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub file_extensions: &'static [&'static str],
}

/// Get information about all supported languages
pub fn supported_languages() -> Vec<LanguageInfo> {
    vec![
        LanguageInfo {
            name: "Rust",
            version: "0.21.0",
            file_extensions: &["rs"],
        },
        LanguageInfo {
            name: "JavaScript",
            version: "0.21.0",
            file_extensions: &["js", "mjs", "jsx"],
        },
        LanguageInfo {
            name: "Python",
            version: "0.21.0",
            file_extensions: &["py", "pyi"],
        },
        LanguageInfo {
            name: "C",
            version: "0.21.0",
            file_extensions: &["c", "h"],
        },
        LanguageInfo {
            name: "C++",
            version: "0.22.0",
            file_extensions: &["cpp", "cxx", "cc", "hpp", "hxx"],
        },
        LanguageInfo {
            name: "TypeScript",
            version: "0.21.0",
            file_extensions: &["ts", "tsx", "mts", "cts"],
        },
        LanguageInfo {
            name: "Go",
            version: "0.21.0",
            file_extensions: &["go"],
        },
    ]
}

/// Detect language from file extension
pub fn detect_language_from_extension(extension: &str) -> Option<Language> {
    match extension.to_lowercase().as_str() {
        "rs" => Some(Language::Rust),
        "js" | "mjs" | "jsx" => Some(Language::JavaScript),
        "ts" | "tsx" | "mts" | "cts" => Some(Language::TypeScript),
        "py" | "pyi" => Some(Language::Python),
        "c" | "h" => Some(Language::C),
        "cpp" | "cxx" | "cc" | "hpp" | "hxx" => Some(Language::Cpp),
        "go" => Some(Language::Go),
        _ => None,
    }
}

/// Detect language from file path
pub fn detect_language_from_path(path: &str) -> Option<Language> {
    std::path::Path::new(path)
        .extension()
        .and_then(|ext| ext.to_str())
        .and_then(detect_language_from_extension)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_language_detection() {
        assert_eq!(detect_language_from_extension("rs"), Some(Language::Rust));
        assert_eq!(detect_language_from_extension("js"), Some(Language::JavaScript));
        assert_eq!(detect_language_from_extension("ts"), Some(Language::TypeScript));
        assert_eq!(detect_language_from_extension("py"), Some(Language::Python));
        assert_eq!(detect_language_from_extension("go"), Some(Language::Go));
        assert_eq!(detect_language_from_extension("unknown"), None);
    }

    #[test]
    fn test_path_detection() {
        assert_eq!(detect_language_from_path("main.rs"), Some(Language::Rust));
        assert_eq!(detect_language_from_path("src/lib.rs"), Some(Language::Rust));
        assert_eq!(detect_language_from_path("script.py"), Some(Language::Python));
        assert_eq!(detect_language_from_path("unknown.txt"), None);
    }

    #[test]
    fn test_supported_languages() {
        let languages = supported_languages();
        assert!(!languages.is_empty());
        assert!(languages.iter().any(|lang| lang.name == "Rust"));
    }
}
