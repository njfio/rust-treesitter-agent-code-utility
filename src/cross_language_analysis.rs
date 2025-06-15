//! Cross-Language Semantic Analysis
//!
//! This module provides advanced semantic analysis capabilities for polyglot codebases,
//! enabling understanding of relationships and dependencies across different programming languages.
//!
//! ## Features
//!
//! - Cross-language symbol resolution and dependency tracking
//! - FFI (Foreign Function Interface) analysis for Rust/C/Python interop
//! - Multi-language architecture pattern detection
//! - Polyglot refactoring suggestions and impact analysis
//! - Cross-language test coverage analysis
//! - Language boundary security analysis

use crate::{AnalysisResult, Result, Symbol, Language};
use crate::error::Error;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use serde::{Serialize, Deserialize};

#[cfg(feature = "serde")]
use serde::{Serialize as SerdeSerialize, Deserialize as SerdeDeserialize};

/// Cross-language semantic analyzer
#[derive(Debug)]
pub struct CrossLanguageAnalyzer {
    pub config: CrossLanguageConfig,
    symbol_registry: SymbolRegistry,
    dependency_graph: DependencyGraph,
}

/// Configuration for cross-language analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
pub struct CrossLanguageConfig {
    /// Enable FFI analysis
    pub enable_ffi_analysis: bool,
    /// Enable cross-language dependency tracking
    pub enable_dependency_tracking: bool,
    /// Enable architecture pattern detection
    pub enable_architecture_analysis: bool,
    /// Maximum depth for dependency resolution
    pub max_dependency_depth: usize,
    /// Languages to include in analysis
    pub included_languages: Vec<Language>,
    /// FFI patterns to detect
    pub ffi_patterns: Vec<FfiPattern>,
}

/// FFI pattern configuration
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
pub struct FfiPattern {
    /// Source language
    pub source_language: Language,
    /// Target language
    pub target_language: Language,
    /// Pattern type (binding, wrapper, direct_call)
    pub pattern_type: FfiPatternType,
    /// File patterns to match
    pub file_patterns: Vec<String>,
    /// Symbol patterns to match
    pub symbol_patterns: Vec<String>,
}

/// Types of FFI patterns
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(SerdeSerialize, SerdeDeserialize))]
pub enum FfiPatternType {
    /// Language bindings (e.g., Python bindings for Rust)
    Binding,
    /// Wrapper functions
    Wrapper,
    /// Direct function calls
    DirectCall,
    /// Shared library interface
    SharedLibrary,
    /// WebAssembly interface
    WebAssembly,
}

/// Registry of symbols across all languages
#[derive(Debug, Default)]
pub struct SymbolRegistry {
    /// Symbols organized by language
    symbols_by_language: HashMap<Language, Vec<CrossLanguageSymbol>>,
    /// Symbol lookup by name
    symbol_lookup: HashMap<String, Vec<SymbolReference>>,
    /// FFI bindings
    ffi_bindings: Vec<FfiBinding>,
}

/// Enhanced symbol with cross-language metadata
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CrossLanguageSymbol {
    /// Base symbol information
    pub symbol: Symbol,
    /// Language of the symbol
    pub language: Language,
    /// File path
    pub file_path: PathBuf,
    /// Cross-language references
    pub cross_references: Vec<CrossReference>,
    /// FFI metadata
    pub ffi_metadata: Option<FfiMetadata>,
    /// Semantic tags
    pub semantic_tags: Vec<String>,
}

/// Reference to a symbol from another language
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CrossReference {
    /// Source language making the reference
    pub source_language: Language,
    /// Source file path
    pub source_file: PathBuf,
    /// Source line number
    pub source_line: usize,
    /// Reference type
    pub reference_type: ReferenceType,
    /// Confidence level (0.0 to 1.0)
    pub confidence: f64,
}

/// Types of cross-language references
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ReferenceType {
    /// Function call
    FunctionCall,
    /// Type usage
    TypeUsage,
    /// Import/include
    Import,
    /// FFI binding
    FfiBinding,
    /// Configuration reference
    Configuration,
    /// Documentation reference
    Documentation,
}

/// FFI-specific metadata
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FfiMetadata {
    /// FFI pattern type
    pub pattern_type: FfiPatternType,
    /// Binding file (e.g., .pyi, .h, .rs)
    pub binding_file: Option<PathBuf>,
    /// ABI compatibility information
    pub abi_info: AbiInfo,
    /// Safety annotations
    pub safety_annotations: Vec<String>,
}

/// ABI (Application Binary Interface) information
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AbiInfo {
    /// Calling convention
    pub calling_convention: String,
    /// Parameter types
    pub parameter_types: Vec<String>,
    /// Return type
    pub return_type: String,
    /// Memory management requirements
    pub memory_management: Vec<String>,
}

/// FFI binding between languages
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FfiBinding {
    /// Source symbol
    pub source_symbol: SymbolReference,
    /// Target symbol
    pub target_symbol: SymbolReference,
    /// Binding type
    pub binding_type: FfiPatternType,
    /// Binding quality metrics
    pub quality_metrics: BindingQualityMetrics,
}

/// Reference to a symbol
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SymbolReference {
    /// Symbol name
    pub name: String,
    /// Language
    pub language: Language,
    /// File path
    pub file_path: PathBuf,
    /// Line number
    pub line: usize,
}

/// Quality metrics for FFI bindings
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BindingQualityMetrics {
    /// Type safety score (0.0 to 1.0)
    pub type_safety: f64,
    /// Memory safety score (0.0 to 1.0)
    pub memory_safety: f64,
    /// Performance impact score (0.0 to 1.0)
    pub performance_impact: f64,
    /// Maintainability score (0.0 to 1.0)
    pub maintainability: f64,
}

/// Cross-language dependency graph
#[derive(Debug, Default)]
pub struct DependencyGraph {
    /// Nodes in the graph (files)
    nodes: HashMap<PathBuf, DependencyNode>,
    /// Edges in the graph (dependencies)
    edges: Vec<DependencyEdge>,
    /// Language boundaries
    language_boundaries: Vec<LanguageBoundary>,
}

/// Node in the dependency graph
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DependencyNode {
    /// File path
    pub file_path: PathBuf,
    /// Language
    pub language: Language,
    /// Symbols exported by this file
    pub exported_symbols: Vec<String>,
    /// Symbols imported by this file
    pub imported_symbols: Vec<String>,
    /// Module/package name
    pub module_name: Option<String>,
}

/// Edge in the dependency graph
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DependencyEdge {
    /// Source file
    pub source: PathBuf,
    /// Target file
    pub target: PathBuf,
    /// Dependency type
    pub dependency_type: DependencyType,
    /// Strength of dependency (0.0 to 1.0)
    pub strength: f64,
}

/// Types of dependencies
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum DependencyType {
    /// Direct import/include
    Direct,
    /// Indirect dependency
    Indirect,
    /// FFI dependency
    Ffi,
    /// Configuration dependency
    Configuration,
    /// Build system dependency
    BuildSystem,
}

/// Language boundary in the codebase
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct LanguageBoundary {
    /// Source language
    pub source_language: Language,
    /// Target language
    pub target_language: Language,
    /// Boundary type
    pub boundary_type: BoundaryType,
    /// Files involved in the boundary
    pub files: Vec<PathBuf>,
    /// Complexity score
    pub complexity_score: f64,
}

/// Types of language boundaries
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum BoundaryType {
    /// FFI boundary
    Ffi,
    /// Build system boundary
    BuildSystem,
    /// Configuration boundary
    Configuration,
    /// Data format boundary (JSON, XML, etc.)
    DataFormat,
    /// Protocol boundary (HTTP, gRPC, etc.)
    Protocol,
}

impl Default for CrossLanguageConfig {
    fn default() -> Self {
        Self {
            enable_ffi_analysis: true,
            enable_dependency_tracking: true,
            enable_architecture_analysis: true,
            max_dependency_depth: 10,
            included_languages: vec![
                Language::Rust,
                Language::Python,
                Language::JavaScript,
                Language::TypeScript,
                Language::C,
                Language::Cpp,
                Language::Go,
            ],
            ffi_patterns: Self::default_ffi_patterns(),
        }
    }
}

impl CrossLanguageConfig {
    /// Get default FFI patterns for common language combinations
    fn default_ffi_patterns() -> Vec<FfiPattern> {
        vec![
            // Rust-Python FFI
            FfiPattern {
                source_language: Language::Python,
                target_language: Language::Rust,
                pattern_type: FfiPatternType::Binding,
                file_patterns: vec!["*.pyi".to_string(), "*_rust.py".to_string()],
                symbol_patterns: vec!["@ffi.def_extern".to_string(), "lib.".to_string()],
            },
            // Rust-C FFI
            FfiPattern {
                source_language: Language::C,
                target_language: Language::Rust,
                pattern_type: FfiPatternType::DirectCall,
                file_patterns: vec!["*.h".to_string(), "bindings.rs".to_string()],
                symbol_patterns: vec!["extern \"C\"".to_string(), "#[no_mangle]".to_string()],
            },
            // JavaScript-WebAssembly
            FfiPattern {
                source_language: Language::JavaScript,
                target_language: Language::Rust,
                pattern_type: FfiPatternType::WebAssembly,
                file_patterns: vec!["*.wasm".to_string(), "*_bg.js".to_string()],
                symbol_patterns: vec!["wasm_bindgen".to_string(), "WebAssembly.".to_string()],
            },
        ]
    }
}

impl CrossLanguageAnalyzer {
    /// Create a new cross-language analyzer
    pub fn new(config: CrossLanguageConfig) -> Self {
        Self {
            config,
            symbol_registry: SymbolRegistry::default(),
            dependency_graph: DependencyGraph::default(),
        }
    }

    /// Create analyzer with default configuration
    pub fn with_default_config() -> Self {
        Self::new(CrossLanguageConfig::default())
    }

    /// Analyze cross-language relationships in a codebase
    pub fn analyze(&mut self, analysis_results: &[AnalysisResult]) -> Result<CrossLanguageAnalysisResult> {
        // Step 1: Build symbol registry from all analysis results
        self.build_symbol_registry(analysis_results)?;

        // Step 2: Detect FFI patterns and bindings
        let ffi_analysis = if self.config.enable_ffi_analysis {
            Some(self.analyze_ffi_patterns()?)
        } else {
            None
        };

        // Step 3: Build dependency graph
        let dependency_analysis = if self.config.enable_dependency_tracking {
            Some(self.build_dependency_graph(analysis_results)?)
        } else {
            None
        };

        // Step 4: Analyze architecture patterns
        let architecture_analysis = if self.config.enable_architecture_analysis {
            Some(self.analyze_architecture_patterns()?)
        } else {
            None
        };

        // Step 5: Generate recommendations
        let recommendations = self.generate_recommendations()?;

        Ok(CrossLanguageAnalysisResult {
            ffi_analysis,
            dependency_analysis,
            architecture_analysis,
            recommendations,
            symbol_registry_stats: self.get_symbol_registry_stats(),
            language_distribution: self.calculate_language_distribution(),
        })
    }

    /// Build symbol registry from analysis results
    fn build_symbol_registry(&mut self, analysis_results: &[AnalysisResult]) -> Result<()> {
        for result in analysis_results {
            for file_info in &result.files {
                let language = Language::from_extension(&file_info.path)?;

                for symbol in &file_info.symbols {
                    let cross_lang_symbol = CrossLanguageSymbol {
                        symbol: symbol.clone(),
                        language,
                        file_path: file_info.path.clone(),
                        cross_references: Vec::new(),
                        ffi_metadata: None,
                        semantic_tags: self.generate_semantic_tags(symbol, &language),
                    };

                    // Add to language-specific collection
                    self.symbol_registry.symbols_by_language
                        .entry(language)
                        .or_insert_with(Vec::new)
                        .push(cross_lang_symbol);

                    // Add to lookup table
                    let symbol_ref = SymbolReference {
                        name: symbol.name.clone(),
                        language,
                        file_path: file_info.path.clone(),
                        line: symbol.start_line,
                    };

                    self.symbol_registry.symbol_lookup
                        .entry(symbol.name.clone())
                        .or_insert_with(Vec::new)
                        .push(symbol_ref);
                }
            }
        }

        // Detect cross-references
        self.detect_cross_references()?;

        Ok(())
    }

    /// Generate semantic tags for a symbol
    fn generate_semantic_tags(&self, symbol: &Symbol, language: &Language) -> Vec<String> {
        let mut tags = Vec::new();

        // Add language-specific tags
        match language {
            Language::Rust => {
                if symbol.name.contains("unsafe") {
                    tags.push("unsafe".to_string());
                }
                if symbol.name.contains("extern") {
                    tags.push("ffi".to_string());
                }
                if symbol.name.starts_with("test_") {
                    tags.push("test".to_string());
                }
            }
            Language::Python => {
                if symbol.name.starts_with("_") {
                    tags.push("private".to_string());
                }
                if symbol.name.starts_with("test_") {
                    tags.push("test".to_string());
                }
                if symbol.kind == "async_function" {
                    tags.push("async".to_string());
                }
            }
            Language::JavaScript | Language::TypeScript => {
                if symbol.name.starts_with("test") || symbol.name.contains("Test") {
                    tags.push("test".to_string());
                }
                if symbol.kind == "async_function" {
                    tags.push("async".to_string());
                }
            }
            _ => {}
        }

        // Add general tags based on symbol properties
        if symbol.is_public {
            tags.push("public".to_string());
        } else {
            tags.push("private".to_string());
        }

        if symbol.documentation.is_some() {
            tags.push("documented".to_string());
        }

        tags
    }

    /// Detect cross-references between symbols
    fn detect_cross_references(&mut self) -> Result<()> {
        // This is a simplified implementation - in practice, this would involve
        // sophisticated pattern matching and static analysis

        // Collect all cross-references first to avoid borrowing issues
        let mut all_cross_refs: Vec<(Language, usize, CrossReference)> = Vec::new();

        for (language, symbols) in &self.symbol_registry.symbols_by_language {
            for (symbol_idx, symbol) in symbols.iter().enumerate() {
                // Look for potential references in other languages
                for (other_language, other_symbols) in &self.symbol_registry.symbols_by_language {
                    if language == other_language {
                        continue;
                    }

                    for other_symbol in other_symbols {
                        if Self::symbols_might_be_related(&symbol.symbol, &other_symbol.symbol) {
                            let cross_ref = CrossReference {
                                source_language: *other_language,
                                source_file: other_symbol.file_path.clone(),
                                source_line: other_symbol.symbol.start_line,
                                reference_type: Self::determine_reference_type(&symbol.symbol, &other_symbol.symbol),
                                confidence: Self::calculate_reference_confidence(&symbol.symbol, &other_symbol.symbol),
                            };

                            all_cross_refs.push((*language, symbol_idx, cross_ref));
                        }
                    }
                }
            }
        }

        // Now apply the cross-references
        for (language, symbol_idx, cross_ref) in all_cross_refs {
            if let Some(symbols) = self.symbol_registry.symbols_by_language.get_mut(&language) {
                if let Some(symbol) = symbols.get_mut(symbol_idx) {
                    symbol.cross_references.push(cross_ref);
                }
            }
        }

        Ok(())
    }

    /// Check if two symbols might be related
    fn symbols_might_be_related(symbol1: &Symbol, symbol2: &Symbol) -> bool {
        // Simple heuristics - could be much more sophisticated
        symbol1.name == symbol2.name ||
        symbol1.name.to_lowercase() == symbol2.name.to_lowercase() ||
        symbol1.name.contains(&symbol2.name) ||
        symbol2.name.contains(&symbol1.name)
    }

    /// Determine the type of reference between symbols
    fn determine_reference_type(_symbol1: &Symbol, _symbol2: &Symbol) -> ReferenceType {
        // Simplified - would analyze actual code patterns
        ReferenceType::FunctionCall
    }

    /// Calculate confidence level for a cross-reference
    fn calculate_reference_confidence(symbol1: &Symbol, symbol2: &Symbol) -> f64 {
        let mut confidence: f64 = 0.0;

        // Exact name match
        if symbol1.name == symbol2.name {
            confidence += 0.8;
        } else if symbol1.name.to_lowercase() == symbol2.name.to_lowercase() {
            confidence += 0.6;
        } else if symbol1.name.contains(&symbol2.name) || symbol2.name.contains(&symbol1.name) {
            confidence += 0.4;
        }

        // Same symbol type
        if symbol1.kind == symbol2.kind {
            confidence += 0.2;
        }

        confidence.min(1.0)
    }

    /// Analyze FFI patterns in the codebase
    fn analyze_ffi_patterns(&mut self) -> Result<FfiAnalysisResult> {
        let mut detected_patterns = Vec::new();
        let mut bindings = Vec::new();

        for pattern in &self.config.ffi_patterns {
            let matches = self.find_ffi_pattern_matches(pattern)?;
            detected_patterns.extend(matches);
        }

        // Analyze binding quality
        for binding in &self.symbol_registry.ffi_bindings {
            let quality = self.analyze_binding_quality(binding)?;
            bindings.push(FfiBindingAnalysis {
                binding: binding.clone(),
                quality_analysis: quality,
                recommendations: self.generate_ffi_recommendations(binding)?,
            });
        }

        Ok(FfiAnalysisResult {
            detected_patterns,
            bindings,
            pattern_summary: self.summarize_ffi_patterns(),
        })
    }

    /// Find matches for a specific FFI pattern
    fn find_ffi_pattern_matches(&self, pattern: &FfiPattern) -> Result<Vec<FfiPatternMatch>> {
        let mut matches = Vec::new();

        // Search through symbols of the source language
        if let Some(symbols) = self.symbol_registry.symbols_by_language.get(&pattern.source_language) {
            for symbol in symbols {
                if self.symbol_matches_ffi_pattern(symbol, pattern) {
                    matches.push(FfiPatternMatch {
                        pattern_type: pattern.pattern_type.clone(),
                        source_symbol: SymbolReference {
                            name: symbol.symbol.name.clone(),
                            language: symbol.language,
                            file_path: symbol.file_path.clone(),
                            line: symbol.symbol.start_line,
                        },
                        target_language: pattern.target_language,
                        confidence: 0.8, // Simplified confidence calculation
                        metadata: HashMap::new(),
                    });
                }
            }
        }

        Ok(matches)
    }

    /// Check if a symbol matches an FFI pattern
    fn symbol_matches_ffi_pattern(&self, symbol: &CrossLanguageSymbol, pattern: &FfiPattern) -> bool {
        // Check file patterns
        let file_name = symbol.file_path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");

        let file_matches = pattern.file_patterns.iter().any(|pat| {
            // Simple glob-like matching
            if pat.contains('*') {
                let prefix = pat.trim_end_matches('*');
                let suffix = pat.trim_start_matches('*');
                file_name.starts_with(prefix) || file_name.ends_with(suffix)
            } else {
                file_name == pat
            }
        });

        // Check symbol patterns
        let symbol_matches = pattern.symbol_patterns.iter().any(|pat| {
            symbol.symbol.name.contains(pat)
        });

        file_matches || symbol_matches
    }

    /// Build dependency graph from analysis results
    fn build_dependency_graph(&mut self, analysis_results: &[AnalysisResult]) -> Result<DependencyAnalysisResult> {
        // Build nodes
        for result in analysis_results {
            for file_info in &result.files {
                let language = Language::from_extension(&file_info.path)?;

                let node = DependencyNode {
                    file_path: file_info.path.clone(),
                    language,
                    exported_symbols: file_info.exports.clone(),
                    imported_symbols: file_info.imports.clone(),
                    module_name: self.extract_module_name(&file_info.path, &language),
                };

                self.dependency_graph.nodes.insert(file_info.path.clone(), node);
            }
        }

        // Build edges
        self.build_dependency_edges()?;

        // Detect language boundaries
        self.detect_language_boundaries()?;

        Ok(DependencyAnalysisResult {
            total_files: self.dependency_graph.nodes.len(),
            total_dependencies: self.dependency_graph.edges.len(),
            language_boundaries: self.dependency_graph.language_boundaries.clone(),
            circular_dependencies: self.detect_circular_dependencies()?,
            dependency_metrics: self.calculate_dependency_metrics()?,
        })
    }

    /// Extract module name from file path
    fn extract_module_name(&self, path: &Path, language: &Language) -> Option<String> {
        match language {
            Language::Rust => {
                // For Rust, use the file stem or parent directory name
                path.file_stem()
                    .and_then(|s| s.to_str())
                    .map(|s| s.to_string())
            }
            Language::Python => {
                // For Python, convert path to module notation
                let parts: Vec<String> = path.iter()
                    .filter_map(|p| p.to_str())
                    .map(|s| s.to_string())
                    .collect();

                // Remove file extension from the last part
                let mut module_parts = parts;
                if let Some(last) = module_parts.last().cloned() {
                    if let Some(stem) = Path::new(&last).file_stem().and_then(|s| s.to_str()) {
                        let last_idx = module_parts.len() - 1;
                        module_parts[last_idx] = stem.to_string();
                    }
                }

                Some(module_parts.join("."))
            }
            Language::JavaScript | Language::TypeScript => {
                // For JS/TS, use relative path
                path.to_str().map(|s| s.to_string())
            }
            _ => None,
        }
    }

    /// Build dependency edges between files
    fn build_dependency_edges(&mut self) -> Result<()> {
        let nodes: Vec<_> = self.dependency_graph.nodes.values().cloned().collect();

        for source_node in &nodes {
            for target_node in &nodes {
                if source_node.file_path == target_node.file_path {
                    continue;
                }

                // Check if source imports from target
                let dependency_strength = self.calculate_dependency_strength(source_node, target_node);

                if dependency_strength > 0.0 {
                    let dependency_type = if source_node.language != target_node.language {
                        DependencyType::Ffi
                    } else {
                        DependencyType::Direct
                    };

                    let edge = DependencyEdge {
                        source: source_node.file_path.clone(),
                        target: target_node.file_path.clone(),
                        dependency_type,
                        strength: dependency_strength,
                    };

                    self.dependency_graph.edges.push(edge);
                }
            }
        }

        Ok(())
    }

    /// Calculate dependency strength between two nodes
    fn calculate_dependency_strength(&self, source: &DependencyNode, target: &DependencyNode) -> f64 {
        let mut strength: f64 = 0.0;

        // Check for direct imports
        for import in &source.imported_symbols {
            if target.exported_symbols.contains(import) {
                strength += 0.5;
            }
        }

        // Check for module-level dependencies
        if let (Some(source_module), Some(target_module)) = (&source.module_name, &target.module_name) {
            if source_module.contains(target_module) || target_module.contains(source_module) {
                strength += 0.3;
            }
        }

        strength.min(1.0)
    }

    /// Detect language boundaries in the codebase
    fn detect_language_boundaries(&mut self) -> Result<()> {
        let mut boundaries = Vec::new();

        // Find edges that cross language boundaries
        for edge in &self.dependency_graph.edges {
            if let (Some(source_node), Some(target_node)) = (
                self.dependency_graph.nodes.get(&edge.source),
                self.dependency_graph.nodes.get(&edge.target)
            ) {
                if source_node.language != target_node.language {
                    let boundary_type = match edge.dependency_type {
                        DependencyType::Ffi => BoundaryType::Ffi,
                        DependencyType::Configuration => BoundaryType::Configuration,
                        DependencyType::BuildSystem => BoundaryType::BuildSystem,
                        _ => BoundaryType::DataFormat,
                    };

                    // Check if boundary already exists
                    let existing_boundary = boundaries.iter_mut().find(|b: &&mut LanguageBoundary| {
                        b.source_language == source_node.language &&
                        b.target_language == target_node.language &&
                        b.boundary_type == boundary_type
                    });

                    if let Some(boundary) = existing_boundary {
                        boundary.files.push(edge.source.clone());
                        boundary.files.push(edge.target.clone());
                        boundary.complexity_score += edge.strength;
                    } else {
                        boundaries.push(LanguageBoundary {
                            source_language: source_node.language,
                            target_language: target_node.language,
                            boundary_type,
                            files: vec![edge.source.clone(), edge.target.clone()],
                            complexity_score: edge.strength,
                        });
                    }
                }
            }
        }

        self.dependency_graph.language_boundaries = boundaries;
        Ok(())
    }

    /// Detect circular dependencies
    fn detect_circular_dependencies(&self) -> Result<Vec<CircularDependency>> {
        let mut circular_deps = Vec::new();
        let mut visited = HashSet::new();
        let mut rec_stack = HashSet::new();

        for node_path in self.dependency_graph.nodes.keys() {
            if !visited.contains(node_path) {
                self.dfs_detect_cycle(
                    node_path,
                    &mut visited,
                    &mut rec_stack,
                    &mut circular_deps,
                    &mut Vec::new(),
                )?;
            }
        }

        Ok(circular_deps)
    }

    /// DFS helper for cycle detection
    fn dfs_detect_cycle(
        &self,
        current: &PathBuf,
        visited: &mut HashSet<PathBuf>,
        rec_stack: &mut HashSet<PathBuf>,
        circular_deps: &mut Vec<CircularDependency>,
        path: &mut Vec<PathBuf>,
    ) -> Result<()> {
        visited.insert(current.clone());
        rec_stack.insert(current.clone());
        path.push(current.clone());

        // Find all dependencies of current node
        for edge in &self.dependency_graph.edges {
            if edge.source == *current {
                if rec_stack.contains(&edge.target) {
                    // Found a cycle
                    let cycle_start = path.iter().position(|p| *p == edge.target).unwrap_or(0);
                    let cycle_path = path[cycle_start..].to_vec();

                    circular_deps.push(CircularDependency {
                        files: cycle_path,
                        severity: self.calculate_cycle_severity(&edge.target, current),
                        impact_analysis: "Circular dependency detected".to_string(),
                    });
                } else if !visited.contains(&edge.target) {
                    self.dfs_detect_cycle(&edge.target, visited, rec_stack, circular_deps, path)?;
                }
            }
        }

        rec_stack.remove(current);
        path.pop();
        Ok(())
    }

    /// Calculate severity of a circular dependency
    fn calculate_cycle_severity(&self, _start: &PathBuf, _end: &PathBuf) -> CycleSeverity {
        // Simplified - would analyze actual impact
        CycleSeverity::Medium
    }

    /// Calculate dependency metrics
    fn calculate_dependency_metrics(&self) -> Result<DependencyMetrics> {
        let total_files = self.dependency_graph.nodes.len();
        let total_edges = self.dependency_graph.edges.len();

        let cross_language_edges = self.dependency_graph.edges.iter()
            .filter(|edge| {
                if let (Some(source), Some(target)) = (
                    self.dependency_graph.nodes.get(&edge.source),
                    self.dependency_graph.nodes.get(&edge.target)
                ) {
                    source.language != target.language
                } else {
                    false
                }
            })
            .count();

        let coupling_score = if total_files > 0 {
            total_edges as f64 / total_files as f64
        } else {
            0.0
        };

        let cross_language_ratio = if total_edges > 0 {
            cross_language_edges as f64 / total_edges as f64
        } else {
            0.0
        };

        Ok(DependencyMetrics {
            total_files,
            total_dependencies: total_edges,
            cross_language_dependencies: cross_language_edges,
            coupling_score,
            cross_language_ratio,
            modularity_score: self.calculate_modularity_score(),
        })
    }

    /// Calculate modularity score
    fn calculate_modularity_score(&self) -> f64 {
        // Simplified modularity calculation
        let language_groups: HashMap<Language, usize> = self.dependency_graph.nodes
            .values()
            .fold(HashMap::new(), |mut acc, node| {
                *acc.entry(node.language).or_insert(0) += 1;
                acc
            });

        let total_files = self.dependency_graph.nodes.len() as f64;
        let language_diversity = language_groups.len() as f64;

        if total_files > 0.0 && language_diversity > 1.0 {
            1.0 - (language_diversity / total_files)
        } else {
            1.0
        }
    }

    /// Analyze architecture patterns
    fn analyze_architecture_patterns(&self) -> Result<ArchitectureAnalysisResult> {
        let patterns = self.detect_architecture_patterns()?;
        let anti_patterns = self.detect_anti_patterns()?;
        let recommendations = self.generate_architecture_recommendations(&patterns, &anti_patterns)?;

        Ok(ArchitectureAnalysisResult {
            detected_patterns: patterns,
            anti_patterns,
            recommendations,
            architecture_score: self.calculate_architecture_score(),
        })
    }

    /// Detect architecture patterns
    fn detect_architecture_patterns(&self) -> Result<Vec<ArchitecturePattern>> {
        let mut patterns = Vec::new();

        // Detect layered architecture
        if self.has_layered_architecture() {
            patterns.push(ArchitecturePattern {
                pattern_type: ArchitecturePatternType::Layered,
                confidence: 0.8,
                description: "Layered architecture detected with clear separation of concerns".to_string(),
                files_involved: self.get_layered_architecture_files(),
            });
        }

        // Detect microservices pattern
        if self.has_microservices_pattern() {
            patterns.push(ArchitecturePattern {
                pattern_type: ArchitecturePatternType::Microservices,
                confidence: 0.7,
                description: "Microservices architecture with language boundaries".to_string(),
                files_involved: self.get_microservices_files(),
            });
        }

        // Detect FFI bridge pattern
        if self.has_ffi_bridge_pattern() {
            patterns.push(ArchitecturePattern {
                pattern_type: ArchitecturePatternType::FfiBridge,
                confidence: 0.9,
                description: "FFI bridge pattern for cross-language integration".to_string(),
                files_involved: self.get_ffi_bridge_files(),
            });
        }

        Ok(patterns)
    }

    /// Check for layered architecture
    fn has_layered_architecture(&self) -> bool {
        // Simplified check - look for common layer patterns
        let layer_keywords = ["controller", "service", "repository", "model", "view"];
        let files_with_layers = self.dependency_graph.nodes.keys()
            .filter(|path| {
                let path_str = path.to_string_lossy().to_lowercase();
                layer_keywords.iter().any(|keyword| path_str.contains(keyword))
            })
            .count();

        files_with_layers >= 3 // At least 3 different layers
    }

    /// Check for microservices pattern
    fn has_microservices_pattern(&self) -> bool {
        // Look for multiple language boundaries and service-like structure
        self.dependency_graph.language_boundaries.len() >= 2 &&
        self.dependency_graph.nodes.len() >= 5
    }

    /// Check for FFI bridge pattern
    fn has_ffi_bridge_pattern(&self) -> bool {
        // Look for FFI-specific patterns
        self.dependency_graph.language_boundaries.iter()
            .any(|boundary| boundary.boundary_type == BoundaryType::Ffi)
    }

    /// Get files involved in layered architecture
    fn get_layered_architecture_files(&self) -> Vec<PathBuf> {
        let layer_keywords = ["controller", "service", "repository", "model", "view"];
        self.dependency_graph.nodes.keys()
            .filter(|path| {
                let path_str = path.to_string_lossy().to_lowercase();
                layer_keywords.iter().any(|keyword| path_str.contains(keyword))
            })
            .cloned()
            .collect()
    }

    /// Get files involved in microservices
    fn get_microservices_files(&self) -> Vec<PathBuf> {
        // Return files that are part of language boundaries
        self.dependency_graph.language_boundaries.iter()
            .flat_map(|boundary| boundary.files.iter())
            .cloned()
            .collect()
    }

    /// Get files involved in FFI bridges
    fn get_ffi_bridge_files(&self) -> Vec<PathBuf> {
        self.dependency_graph.language_boundaries.iter()
            .filter(|boundary| boundary.boundary_type == BoundaryType::Ffi)
            .flat_map(|boundary| boundary.files.iter())
            .cloned()
            .collect()
    }

    /// Detect anti-patterns in the architecture
    fn detect_anti_patterns(&self) -> Result<Vec<AntiPattern>> {
        let mut anti_patterns = Vec::new();

        // Detect circular dependencies
        let circular_deps = self.detect_circular_dependencies()?;
        if !circular_deps.is_empty() {
            anti_patterns.push(AntiPattern {
                pattern_type: AntiPatternType::CircularDependency,
                severity: AntiPatternSeverity::High,
                description: format!("Found {} circular dependencies", circular_deps.len()),
                affected_files: circular_deps.into_iter()
                    .flat_map(|cd| cd.files)
                    .collect(),
                remediation_steps: vec![
                    "Break circular dependencies by introducing interfaces".to_string(),
                    "Consider dependency inversion principle".to_string(),
                    "Refactor to use event-driven architecture".to_string(),
                ],
            });
        }

        // Detect god objects (files with too many symbols)
        let god_objects = self.detect_god_objects();
        if !god_objects.is_empty() {
            anti_patterns.push(AntiPattern {
                pattern_type: AntiPatternType::GodObject,
                severity: AntiPatternSeverity::Medium,
                description: format!("Found {} files with excessive symbols", god_objects.len()),
                affected_files: god_objects,
                remediation_steps: vec![
                    "Split large files into smaller, focused modules".to_string(),
                    "Apply single responsibility principle".to_string(),
                    "Extract related functionality into separate files".to_string(),
                ],
            });
        }

        // Detect tight coupling
        if self.has_tight_coupling() {
            anti_patterns.push(AntiPattern {
                pattern_type: AntiPatternType::TightCoupling,
                severity: AntiPatternSeverity::Medium,
                description: "High coupling detected between modules".to_string(),
                affected_files: self.get_tightly_coupled_files(),
                remediation_steps: vec![
                    "Introduce abstractions to reduce coupling".to_string(),
                    "Use dependency injection".to_string(),
                    "Apply facade pattern for complex subsystems".to_string(),
                ],
            });
        }

        Ok(anti_patterns)
    }

    /// Detect god objects (files with too many symbols)
    fn detect_god_objects(&self) -> Vec<PathBuf> {
        const MAX_SYMBOLS_PER_FILE: usize = 50;

        self.symbol_registry.symbols_by_language.values()
            .flat_map(|symbols| symbols.iter())
            .fold(HashMap::new(), |mut acc: HashMap<PathBuf, usize>, symbol| {
                *acc.entry(symbol.file_path.clone()).or_insert(0) += 1;
                acc
            })
            .into_iter()
            .filter(|(_, count)| *count > MAX_SYMBOLS_PER_FILE)
            .map(|(path, _)| path)
            .collect()
    }

    /// Check for tight coupling
    fn has_tight_coupling(&self) -> bool {
        let metrics = self.calculate_dependency_metrics().unwrap_or_default();
        metrics.coupling_score > 3.0 // Arbitrary threshold
    }

    /// Get tightly coupled files
    fn get_tightly_coupled_files(&self) -> Vec<PathBuf> {
        // Find files with high number of dependencies
        let mut file_dependency_count: HashMap<PathBuf, usize> = HashMap::new();

        for edge in &self.dependency_graph.edges {
            *file_dependency_count.entry(edge.source.clone()).or_insert(0) += 1;
        }

        file_dependency_count.into_iter()
            .filter(|(_, count)| *count > 5) // Arbitrary threshold
            .map(|(path, _)| path)
            .collect()
    }

    /// Generate architecture recommendations
    fn generate_architecture_recommendations(
        &self,
        patterns: &[ArchitecturePattern],
        anti_patterns: &[AntiPattern],
    ) -> Result<Vec<ArchitectureRecommendation>> {
        let mut recommendations = Vec::new();

        // Recommendations based on detected patterns
        for pattern in patterns {
            match pattern.pattern_type {
                ArchitecturePatternType::Layered => {
                    recommendations.push(ArchitectureRecommendation {
                        recommendation_type: RecommendationType::Enhancement,
                        priority: RecommendationPriority::Medium,
                        title: "Strengthen Layered Architecture".to_string(),
                        description: "Consider adding clear interfaces between layers".to_string(),
                        implementation_steps: vec![
                            "Define clear contracts between layers".to_string(),
                            "Add validation at layer boundaries".to_string(),
                            "Consider using dependency injection".to_string(),
                        ],
                        estimated_effort: EffortLevel::Medium,
                        impact: ImpactLevel::High,
                    });
                }
                ArchitecturePatternType::Microservices => {
                    recommendations.push(ArchitectureRecommendation {
                        recommendation_type: RecommendationType::Enhancement,
                        priority: RecommendationPriority::Low,
                        title: "Optimize Microservices Communication".to_string(),
                        description: "Consider optimizing inter-service communication".to_string(),
                        implementation_steps: vec![
                            "Implement circuit breaker pattern".to_string(),
                            "Add service discovery".to_string(),
                            "Consider event-driven architecture".to_string(),
                        ],
                        estimated_effort: EffortLevel::High,
                        impact: ImpactLevel::Medium,
                    });
                }
                ArchitecturePatternType::FfiBridge => {
                    recommendations.push(ArchitectureRecommendation {
                        recommendation_type: RecommendationType::Security,
                        priority: RecommendationPriority::High,
                        title: "Secure FFI Boundaries".to_string(),
                        description: "Ensure FFI boundaries are secure and well-tested".to_string(),
                        implementation_steps: vec![
                            "Add comprehensive error handling".to_string(),
                            "Implement input validation".to_string(),
                            "Add integration tests".to_string(),
                        ],
                        estimated_effort: EffortLevel::Medium,
                        impact: ImpactLevel::High,
                    });
                }
                ArchitecturePatternType::EventDriven => {
                    recommendations.push(ArchitectureRecommendation {
                        recommendation_type: RecommendationType::Enhancement,
                        priority: RecommendationPriority::Medium,
                        title: "Optimize Event-Driven Architecture".to_string(),
                        description: "Consider improving event handling and messaging".to_string(),
                        implementation_steps: vec![
                            "Implement event sourcing".to_string(),
                            "Add event replay capabilities".to_string(),
                            "Consider CQRS pattern".to_string(),
                        ],
                        estimated_effort: EffortLevel::High,
                        impact: ImpactLevel::High,
                    });
                }
                ArchitecturePatternType::Pipeline => {
                    recommendations.push(ArchitectureRecommendation {
                        recommendation_type: RecommendationType::Performance,
                        priority: RecommendationPriority::Medium,
                        title: "Optimize Pipeline Performance".to_string(),
                        description: "Consider improving pipeline throughput and reliability".to_string(),
                        implementation_steps: vec![
                            "Add parallel processing".to_string(),
                            "Implement backpressure handling".to_string(),
                            "Add monitoring and metrics".to_string(),
                        ],
                        estimated_effort: EffortLevel::Medium,
                        impact: ImpactLevel::Medium,
                    });
                }
                ArchitecturePatternType::Hexagonal => {
                    recommendations.push(ArchitectureRecommendation {
                        recommendation_type: RecommendationType::Enhancement,
                        priority: RecommendationPriority::Low,
                        title: "Strengthen Hexagonal Architecture".to_string(),
                        description: "Consider improving port and adapter isolation".to_string(),
                        implementation_steps: vec![
                            "Define clear port interfaces".to_string(),
                            "Implement adapter pattern consistently".to_string(),
                            "Add integration testing for adapters".to_string(),
                        ],
                        estimated_effort: EffortLevel::Medium,
                        impact: ImpactLevel::Medium,
                    });
                }
            }
        }

        // Recommendations based on anti-patterns
        for anti_pattern in anti_patterns {
            let recommendation = match anti_pattern.pattern_type {
                AntiPatternType::CircularDependency => ArchitectureRecommendation {
                    recommendation_type: RecommendationType::Refactoring,
                    priority: RecommendationPriority::High,
                    title: "Resolve Circular Dependencies".to_string(),
                    description: anti_pattern.description.clone(),
                    implementation_steps: anti_pattern.remediation_steps.clone(),
                    estimated_effort: EffortLevel::High,
                    impact: ImpactLevel::High,
                },
                AntiPatternType::GodObject => ArchitectureRecommendation {
                    recommendation_type: RecommendationType::Refactoring,
                    priority: RecommendationPriority::Medium,
                    title: "Break Down Large Files".to_string(),
                    description: anti_pattern.description.clone(),
                    implementation_steps: anti_pattern.remediation_steps.clone(),
                    estimated_effort: EffortLevel::Medium,
                    impact: ImpactLevel::Medium,
                },
                AntiPatternType::TightCoupling => ArchitectureRecommendation {
                    recommendation_type: RecommendationType::Refactoring,
                    priority: RecommendationPriority::Medium,
                    title: "Reduce Coupling".to_string(),
                    description: anti_pattern.description.clone(),
                    implementation_steps: anti_pattern.remediation_steps.clone(),
                    estimated_effort: EffortLevel::Medium,
                    impact: ImpactLevel::High,
                },
                AntiPatternType::DeadCode => ArchitectureRecommendation {
                    recommendation_type: RecommendationType::Refactoring,
                    priority: RecommendationPriority::Low,
                    title: "Remove Dead Code".to_string(),
                    description: anti_pattern.description.clone(),
                    implementation_steps: anti_pattern.remediation_steps.clone(),
                    estimated_effort: EffortLevel::Low,
                    impact: ImpactLevel::Medium,
                },
                AntiPatternType::DuplicateCode => ArchitectureRecommendation {
                    recommendation_type: RecommendationType::Refactoring,
                    priority: RecommendationPriority::Medium,
                    title: "Eliminate Code Duplication".to_string(),
                    description: anti_pattern.description.clone(),
                    implementation_steps: anti_pattern.remediation_steps.clone(),
                    estimated_effort: EffortLevel::Medium,
                    impact: ImpactLevel::Medium,
                },
            };
            recommendations.push(recommendation);
        }

        Ok(recommendations)
    }

    /// Calculate overall architecture score
    fn calculate_architecture_score(&self) -> f64 {
        let mut score = 100.0;

        // Deduct points for anti-patterns
        let circular_deps = self.detect_circular_dependencies().unwrap_or_default();
        score -= circular_deps.len() as f64 * 10.0;

        let god_objects = self.detect_god_objects();
        score -= god_objects.len() as f64 * 5.0;

        if self.has_tight_coupling() {
            score -= 15.0;
        }

        // Add points for good patterns
        let metrics = self.calculate_dependency_metrics().unwrap_or_default();
        if metrics.modularity_score > 0.8 {
            score += 10.0;
        }

        score.max(0.0).min(100.0)
    }

    /// Generate general recommendations
    fn generate_recommendations(&self) -> Result<Vec<CrossLanguageRecommendation>> {
        let mut recommendations = Vec::new();

        // Always add basic cross-language recommendations
        recommendations.push(CrossLanguageRecommendation {
            category: RecommendationCategory::Documentation,
            priority: RecommendationPriority::Medium,
            title: "Improve Cross-Language Documentation".to_string(),
            description: "Ensure comprehensive documentation for cross-language interfaces".to_string(),
            action_items: vec![
                "Document API contracts between languages".to_string(),
                "Add examples for cross-language usage".to_string(),
                "Maintain up-to-date interface documentation".to_string(),
            ],
            estimated_impact: ImpactLevel::Medium,
        });

        // Language distribution recommendations
        let lang_dist = self.calculate_language_distribution();
        if lang_dist.len() > 3 {
            recommendations.push(CrossLanguageRecommendation {
                category: RecommendationCategory::Architecture,
                priority: RecommendationPriority::Medium,
                title: "Consider Language Consolidation".to_string(),
                description: format!("Project uses {} languages which may increase complexity", lang_dist.len()),
                action_items: vec![
                    "Evaluate if all languages are necessary".to_string(),
                    "Consider consolidating similar functionality".to_string(),
                    "Document language choice rationale".to_string(),
                ],
                estimated_impact: ImpactLevel::Medium,
            });
        } else if lang_dist.len() > 1 {
            recommendations.push(CrossLanguageRecommendation {
                category: RecommendationCategory::Testing,
                priority: RecommendationPriority::Medium,
                title: "Enhance Cross-Language Testing".to_string(),
                description: "Multiple languages detected - ensure comprehensive testing".to_string(),
                action_items: vec![
                    "Add integration tests for language boundaries".to_string(),
                    "Test error handling across languages".to_string(),
                    "Validate data serialization/deserialization".to_string(),
                ],
                estimated_impact: ImpactLevel::Medium,
            });
        }

        // FFI recommendations
        if !self.symbol_registry.ffi_bindings.is_empty() {
            recommendations.push(CrossLanguageRecommendation {
                category: RecommendationCategory::Security,
                priority: RecommendationPriority::High,
                title: "Review FFI Security".to_string(),
                description: "FFI bindings detected - ensure proper security measures".to_string(),
                action_items: vec![
                    "Audit FFI boundary security".to_string(),
                    "Add comprehensive error handling".to_string(),
                    "Implement input validation".to_string(),
                ],
                estimated_impact: ImpactLevel::High,
            });
        }

        Ok(recommendations)
    }

    /// Get symbol registry statistics
    fn get_symbol_registry_stats(&self) -> SymbolRegistryStats {
        let total_symbols = self.symbol_registry.symbols_by_language.values()
            .map(|symbols| symbols.len())
            .sum();

        let cross_references = self.symbol_registry.symbols_by_language.values()
            .flat_map(|symbols| symbols.iter())
            .map(|symbol| symbol.cross_references.len())
            .sum();

        SymbolRegistryStats {
            total_symbols,
            symbols_by_language: self.symbol_registry.symbols_by_language.iter()
                .map(|(lang, symbols)| (*lang, symbols.len()))
                .collect(),
            cross_references,
            ffi_bindings: self.symbol_registry.ffi_bindings.len(),
        }
    }

    /// Calculate language distribution
    fn calculate_language_distribution(&self) -> HashMap<Language, f64> {
        let total_symbols = self.symbol_registry.symbols_by_language.values()
            .map(|symbols| symbols.len())
            .sum::<usize>() as f64;

        if total_symbols == 0.0 {
            return HashMap::new();
        }

        self.symbol_registry.symbols_by_language.iter()
            .map(|(lang, symbols)| (*lang, symbols.len() as f64 / total_symbols))
            .collect()
    }

    /// Analyze binding quality
    fn analyze_binding_quality(&self, _binding: &FfiBinding) -> Result<BindingQualityAnalysis> {
        // Simplified implementation
        Ok(BindingQualityAnalysis {
            type_safety_score: 0.8,
            memory_safety_score: 0.7,
            performance_score: 0.9,
            maintainability_score: 0.6,
            issues: vec![],
            recommendations: vec![
                "Add comprehensive error handling".to_string(),
                "Implement input validation".to_string(),
            ],
        })
    }

    /// Generate FFI recommendations
    fn generate_ffi_recommendations(&self, _binding: &FfiBinding) -> Result<Vec<String>> {
        Ok(vec![
            "Add comprehensive testing for FFI boundaries".to_string(),
            "Implement proper error handling".to_string(),
            "Document ABI compatibility requirements".to_string(),
        ])
    }

    /// Summarize FFI patterns
    fn summarize_ffi_patterns(&self) -> FfiPatternSummary {
        let patterns_by_type = self.symbol_registry.ffi_bindings.iter()
            .fold(HashMap::new(), |mut acc, binding| {
                *acc.entry(binding.binding_type.clone()).or_insert(0) += 1;
                acc
            });

        let most_common_pattern = patterns_by_type.iter()
            .max_by_key(|(_, count)| *count)
            .map(|(pattern, _)| pattern.clone());

        FfiPatternSummary {
            total_patterns: self.symbol_registry.ffi_bindings.len(),
            patterns_by_type,
            most_common_pattern,
        }
    }
}

impl Default for DependencyMetrics {
    fn default() -> Self {
        Self {
            total_files: 0,
            total_dependencies: 0,
            cross_language_dependencies: 0,
            coupling_score: 0.0,
            cross_language_ratio: 0.0,
            modularity_score: 1.0,
        }
    }
}

impl Language {
    /// Create language from file extension
    pub fn from_extension(path: &Path) -> Result<Language> {
        match path.extension().and_then(|ext| ext.to_str()) {
            Some("rs") => Ok(Language::Rust),
            Some("py") => Ok(Language::Python),
            Some("js") => Ok(Language::JavaScript),
            Some("ts") => Ok(Language::TypeScript),
            Some("c") | Some("h") => Ok(Language::C),
            Some("cpp") | Some("cc") | Some("cxx") | Some("hpp") | Some("hxx") => Ok(Language::Cpp),
            Some("go") => Ok(Language::Go),
            _ => Err(Error::UnsupportedLanguage(
                path.extension()
                    .and_then(|ext| ext.to_str())
                    .unwrap_or("unknown")
                    .to_string()
            )),
        }
    }
}

// Result types and supporting structures

/// Result of cross-language analysis
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CrossLanguageAnalysisResult {
    /// FFI analysis results
    pub ffi_analysis: Option<FfiAnalysisResult>,
    /// Dependency analysis results
    pub dependency_analysis: Option<DependencyAnalysisResult>,
    /// Architecture analysis results
    pub architecture_analysis: Option<ArchitectureAnalysisResult>,
    /// General recommendations
    pub recommendations: Vec<CrossLanguageRecommendation>,
    /// Symbol registry statistics
    pub symbol_registry_stats: SymbolRegistryStats,
    /// Language distribution
    pub language_distribution: HashMap<Language, f64>,
}

/// FFI analysis results
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FfiAnalysisResult {
    /// Detected FFI patterns
    pub detected_patterns: Vec<FfiPatternMatch>,
    /// FFI bindings analysis
    pub bindings: Vec<FfiBindingAnalysis>,
    /// Pattern summary
    pub pattern_summary: FfiPatternSummary,
}

/// FFI pattern match
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FfiPatternMatch {
    /// Pattern type
    pub pattern_type: FfiPatternType,
    /// Source symbol
    pub source_symbol: SymbolReference,
    /// Target language
    pub target_language: Language,
    /// Confidence level
    pub confidence: f64,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// FFI binding analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FfiBindingAnalysis {
    /// The binding
    pub binding: FfiBinding,
    /// Quality analysis
    pub quality_analysis: BindingQualityAnalysis,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// Binding quality analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct BindingQualityAnalysis {
    /// Type safety score
    pub type_safety_score: f64,
    /// Memory safety score
    pub memory_safety_score: f64,
    /// Performance score
    pub performance_score: f64,
    /// Maintainability score
    pub maintainability_score: f64,
    /// Identified issues
    pub issues: Vec<String>,
    /// Recommendations
    pub recommendations: Vec<String>,
}

/// FFI pattern summary
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FfiPatternSummary {
    /// Total number of patterns
    pub total_patterns: usize,
    /// Patterns by type
    pub patterns_by_type: HashMap<FfiPatternType, usize>,
    /// Most common pattern
    pub most_common_pattern: Option<FfiPatternType>,
}

/// Dependency analysis results
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DependencyAnalysisResult {
    /// Total number of files
    pub total_files: usize,
    /// Total number of dependencies
    pub total_dependencies: usize,
    /// Language boundaries
    pub language_boundaries: Vec<LanguageBoundary>,
    /// Circular dependencies
    pub circular_dependencies: Vec<CircularDependency>,
    /// Dependency metrics
    pub dependency_metrics: DependencyMetrics,
}

/// Circular dependency
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CircularDependency {
    /// Files involved in the cycle
    pub files: Vec<PathBuf>,
    /// Severity of the cycle
    pub severity: CycleSeverity,
    /// Impact analysis
    pub impact_analysis: String,
}

/// Cycle severity levels
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum CycleSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Dependency metrics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct DependencyMetrics {
    /// Total number of files
    pub total_files: usize,
    /// Total number of dependencies
    pub total_dependencies: usize,
    /// Cross-language dependencies
    pub cross_language_dependencies: usize,
    /// Coupling score
    pub coupling_score: f64,
    /// Cross-language dependency ratio
    pub cross_language_ratio: f64,
    /// Modularity score
    pub modularity_score: f64,
}

/// Architecture analysis results
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ArchitectureAnalysisResult {
    /// Detected architecture patterns
    pub detected_patterns: Vec<ArchitecturePattern>,
    /// Detected anti-patterns
    pub anti_patterns: Vec<AntiPattern>,
    /// Architecture recommendations
    pub recommendations: Vec<ArchitectureRecommendation>,
    /// Overall architecture score
    pub architecture_score: f64,
}

/// Architecture pattern
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ArchitecturePattern {
    /// Pattern type
    pub pattern_type: ArchitecturePatternType,
    /// Confidence level
    pub confidence: f64,
    /// Description
    pub description: String,
    /// Files involved
    pub files_involved: Vec<PathBuf>,
}

/// Architecture pattern types
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ArchitecturePatternType {
    Layered,
    Microservices,
    FfiBridge,
    EventDriven,
    Pipeline,
    Hexagonal,
}

/// Anti-pattern
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AntiPattern {
    /// Anti-pattern type
    pub pattern_type: AntiPatternType,
    /// Severity
    pub severity: AntiPatternSeverity,
    /// Description
    pub description: String,
    /// Affected files
    pub affected_files: Vec<PathBuf>,
    /// Remediation steps
    pub remediation_steps: Vec<String>,
}

/// Anti-pattern types
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AntiPatternType {
    CircularDependency,
    GodObject,
    TightCoupling,
    DeadCode,
    DuplicateCode,
}

/// Anti-pattern severity
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AntiPatternSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// Architecture recommendation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ArchitectureRecommendation {
    /// Recommendation type
    pub recommendation_type: RecommendationType,
    /// Priority level
    pub priority: RecommendationPriority,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Implementation steps
    pub implementation_steps: Vec<String>,
    /// Estimated effort
    pub estimated_effort: EffortLevel,
    /// Expected impact
    pub impact: ImpactLevel,
}

/// Recommendation types
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RecommendationType {
    Enhancement,
    Refactoring,
    Security,
    Performance,
    Maintainability,
}

/// Cross-language recommendation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CrossLanguageRecommendation {
    /// Category
    pub category: RecommendationCategory,
    /// Priority
    pub priority: RecommendationPriority,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Action items
    pub action_items: Vec<String>,
    /// Estimated impact
    pub estimated_impact: ImpactLevel,
}

/// Recommendation categories
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RecommendationCategory {
    Architecture,
    Security,
    Performance,
    Maintainability,
    Testing,
    Documentation,
}

/// Recommendation priority levels
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RecommendationPriority {
    Low,
    Medium,
    High,
    Critical,
}

/// Effort levels
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum EffortLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Impact levels
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ImpactLevel {
    Low,
    Medium,
    High,
    VeryHigh,
}

/// Symbol registry statistics
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SymbolRegistryStats {
    /// Total number of symbols
    pub total_symbols: usize,
    /// Symbols by language
    pub symbols_by_language: HashMap<Language, usize>,
    /// Total cross-references
    pub cross_references: usize,
    /// Total FFI bindings
    pub ffi_bindings: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn test_cross_language_analyzer_creation() {
        let analyzer = CrossLanguageAnalyzer::with_default_config();
        assert!(analyzer.config.enable_ffi_analysis);
        assert!(analyzer.config.enable_dependency_tracking);
        assert!(analyzer.config.enable_architecture_analysis);
    }

    #[test]
    fn test_language_from_extension() {
        assert_eq!(Language::from_extension(&PathBuf::from("test.rs")).unwrap(), Language::Rust);
        assert_eq!(Language::from_extension(&PathBuf::from("test.py")).unwrap(), Language::Python);
        assert_eq!(Language::from_extension(&PathBuf::from("test.js")).unwrap(), Language::JavaScript);
        assert_eq!(Language::from_extension(&PathBuf::from("test.ts")).unwrap(), Language::TypeScript);
        assert_eq!(Language::from_extension(&PathBuf::from("test.c")).unwrap(), Language::C);
        assert_eq!(Language::from_extension(&PathBuf::from("test.cpp")).unwrap(), Language::Cpp);
        assert_eq!(Language::from_extension(&PathBuf::from("test.go")).unwrap(), Language::Go);
    }

    #[test]
    fn test_ffi_pattern_creation() {
        let pattern = FfiPattern {
            source_language: Language::Python,
            target_language: Language::Rust,
            pattern_type: FfiPatternType::Binding,
            file_patterns: vec!["*.pyi".to_string()],
            symbol_patterns: vec!["@ffi".to_string()],
        };

        assert_eq!(pattern.source_language, Language::Python);
        assert_eq!(pattern.target_language, Language::Rust);
        assert_eq!(pattern.pattern_type, FfiPatternType::Binding);
    }

    #[test]
    fn test_symbol_registry_default() {
        let registry = SymbolRegistry::default();
        assert!(registry.symbols_by_language.is_empty());
        assert!(registry.symbol_lookup.is_empty());
        assert!(registry.ffi_bindings.is_empty());
    }

    #[test]
    fn test_dependency_graph_default() {
        let graph = DependencyGraph::default();
        assert!(graph.nodes.is_empty());
        assert!(graph.edges.is_empty());
        assert!(graph.language_boundaries.is_empty());
    }

    #[test]
    fn test_cross_language_config_default() {
        let config = CrossLanguageConfig::default();
        assert!(config.enable_ffi_analysis);
        assert!(config.enable_dependency_tracking);
        assert!(config.enable_architecture_analysis);
        assert_eq!(config.max_dependency_depth, 10);
        assert!(!config.included_languages.is_empty());
        assert!(!config.ffi_patterns.is_empty());
    }
}
