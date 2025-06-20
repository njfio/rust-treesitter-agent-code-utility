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

pub mod advanced_ai_analysis;
pub mod advanced_security;
pub mod ai_analysis;
pub mod analysis_utils;
pub mod control_flow;
pub mod complexity_analysis;
pub mod taint_analysis;
pub mod sql_injection_detector;
pub mod command_injection_detector;
pub mod symbol_table;
pub mod semantic_context;
pub mod analyzer;
pub mod cli;
pub mod code_evolution;
pub mod code_map;
pub mod constants;
pub mod dependency_analysis;
pub mod enhanced_security;
pub mod error;
pub mod file_cache;
pub mod infrastructure;
pub mod intent_mapping;
pub mod languages;
pub mod parser;
pub mod performance_analysis;
pub mod query;
pub mod reasoning_engine;
pub mod refactoring;
pub mod security;
pub mod semantic_graph;
pub mod smart_refactoring;
pub mod test_coverage;
pub mod tree;

// Re-export commonly used types
pub use advanced_ai_analysis::{AdvancedAIAnalyzer, AdvancedAIResult, AdvancedAIConfig, SemanticAnalysis, ArchitecturePattern};
pub use advanced_security::{AdvancedSecurityAnalyzer, AdvancedSecurityResult, AdvancedSecurityConfig, SecurityVulnerability as AdvancedSecurityVulnerability};
pub use ai_analysis::{AIAnalyzer, AIAnalysisResult, AIConfig, CodebaseExplanation, FileExplanation, SymbolExplanation};
pub use analyzer::{CodebaseAnalyzer, AnalysisConfig, AnalysisDepth, AnalysisResult, FileInfo, Symbol};
pub use dependency_analysis::{DependencyAnalyzer, DependencyAnalysisResult, DependencyConfig, Dependency, PackageManager};
pub use error::{Error, Result};
pub use file_cache::{FileCache, CacheStats};
pub use languages::Language;
pub use parser::{Parser, ParseOptions, create_edit};
pub use performance_analysis::{PerformanceAnalyzer, PerformanceAnalysisResult, PerformanceConfig, PerformanceHotspot};
pub use query::{Query, QueryCapture, QueryMatch, QueryBuilder};
pub use refactoring::{RefactoringAnalyzer, RefactoringResult, RefactoringSuggestion, RefactoringConfig};
pub use security::{VulnerabilityDatabase, SecretsDetector, OwaspDetector};
pub use enhanced_security::{EnhancedSecurityScanner, EnhancedSecurityResult, EnhancedSecurityConfig};
pub use advanced_security::{AdvancedSecurityAnalyzer as SecurityScanner, AdvancedSecurityResult as SecurityScanResult, SecurityVulnerability, AdvancedSecurityConfig as SecurityConfig, SecuritySeverity};
pub use smart_refactoring::{SmartRefactoringEngine, SmartRefactoringResult, SmartRefactoringConfig, CodeSmellFix};
pub use test_coverage::{TestCoverageAnalyzer, TestCoverageResult, TestCoverageConfig, MissingTest};
pub use code_map::{CallGraph, ModuleGraph, build_call_graph, build_module_graph};
pub use tree::{Node, SyntaxTree, TreeCursor, TreeEdit};
pub use control_flow::{ControlFlowGraph, CfgBuilder, CfgNodeType};
pub use complexity_analysis::{ComplexityAnalyzer, ComplexityMetrics, HalsteadMetrics};
pub use taint_analysis::{TaintAnalyzer, TaintFlow, TaintSource, TaintSink, VulnerabilityType};
pub use sql_injection_detector::{SqlInjectionDetector, SqlInjectionVulnerability, SqlInjectionType};
pub use command_injection_detector::{CommandInjectionDetector, CommandInjectionVulnerability, CommandInjectionType};
pub use symbol_table::{SymbolTableAnalyzer, SymbolTable, SymbolDefinition, SymbolReference, SymbolAnalysisResult, Scope, ScopeType, SymbolType, ReferenceType};
pub use semantic_context::{SemanticContextAnalyzer, SemanticContext, DataFlowAnalysis, SecuritySemanticContext, ValidationPoint, SanitizationPoint, TrustLevel};
pub use semantic_graph::{SemanticGraphQuery, GraphNode, GraphEdge, NodeType, RelationshipType, QueryResult, QueryConfig, GraphStatistics};
pub use code_evolution::{CodeEvolutionTracker, EvolutionAnalysisResult, EvolutionConfig, ChangePattern, PatternType, EvolutionMetrics, FileInsight, EvolutionRecommendation, ChangeType, RiskLevel};
pub use intent_mapping::{
    IntentMappingSystem, MappingAnalysisResult, MappingConfig, Requirement, Implementation,
    IntentMapping, TraceabilityMatrix, TraceabilityReport, RequirementType, ImplementationType,
    Priority as IntentPriority, RequirementStatus, ImplementationStatus, QualityMetrics,
    CodeElement, MappingType, ValidationStatus, GapType, RecommendationType, MappingGap,
    MappingRecommendation
};
pub use reasoning_engine::{
    AutomatedReasoningEngine, ReasoningResult, ReasoningConfig, Fact, Rule, KnowledgeBase,
    InferenceEngine, ConstraintSolver, TheoremProver, ReasoningInsight, InsightType
};

// Re-export tree-sitter types that users might need
pub use tree_sitter::{InputEdit, Point, Range};

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
