//! Smart refactoring engine with automated code improvements
//! 
//! This module provides comprehensive automated refactoring including:
//! - Code smell detection with automated fixes
//! - Design pattern recommendations and implementation guidance
//! - Performance optimization suggestions with code transformations
//! - Modernization recommendations (language version upgrades, deprecated API usage)
//! - Architectural improvements with refactoring roadmaps

use crate::{AnalysisResult, Result};
use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Smart refactoring engine for automated code improvements
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SmartRefactoringEngine {
    /// Configuration for smart refactoring
    pub config: SmartRefactoringConfig,
}

/// Configuration for smart refactoring
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SmartRefactoringConfig {
    /// Enable code smell detection and fixes
    pub code_smell_fixes: bool,
    /// Enable design pattern recommendations
    pub pattern_recommendations: bool,
    /// Enable performance optimizations
    pub performance_optimizations: bool,
    /// Enable modernization suggestions
    pub modernization: bool,
    /// Enable architectural improvements
    pub architectural_improvements: bool,
    /// Minimum confidence threshold for suggestions
    pub min_confidence: f64,
    /// Maximum number of suggestions per category
    pub max_suggestions_per_category: usize,
}

/// Results of smart refactoring analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SmartRefactoringResult {
    /// Overall refactoring score (0-100)
    pub refactoring_score: u8,
    /// Total refactoring opportunities found
    pub total_opportunities: usize,
    /// Opportunities by category
    pub opportunities_by_category: HashMap<RefactoringCategory, usize>,
    /// Code smell fixes
    pub code_smell_fixes: Vec<CodeSmellFix>,
    /// Design pattern recommendations
    pub pattern_recommendations: Vec<PatternRecommendation>,
    /// Performance optimizations
    pub performance_optimizations: Vec<PerformanceOptimization>,
    /// Modernization suggestions
    pub modernization_suggestions: Vec<ModernizationSuggestion>,
    /// Architectural improvements
    pub architectural_improvements: Vec<ArchitecturalImprovement>,
    /// Refactoring roadmap
    pub refactoring_roadmap: RefactoringRoadmap,
    /// Impact analysis
    pub impact_analysis: ImpactAnalysis,
}

/// Categories of refactoring opportunities
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RefactoringCategory {
    CodeSmells,
    DesignPatterns,
    Performance,
    Modernization,
    Architecture,
}

/// A code smell fix with automated solution
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CodeSmellFix {
    /// Fix ID
    pub id: String,
    /// Code smell name
    pub smell_name: String,
    /// Smell description
    pub description: String,
    /// Smell category
    pub category: SmellCategory,
    /// Location of the smell
    pub location: RefactoringLocation,
    /// Current problematic code
    pub current_code: String,
    /// Suggested refactored code
    pub refactored_code: String,
    /// Explanation of the fix
    pub explanation: String,
    /// Benefits of applying the fix
    pub benefits: Vec<String>,
    /// Potential risks
    pub risks: Vec<String>,
    /// Confidence level
    pub confidence: f64,
    /// Estimated effort (hours)
    pub effort: f64,
    /// Automated fix available
    pub automated_fix: bool,
}

/// Categories of code smells
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SmellCategory {
    /// Long methods or functions
    LongMethod,
    /// Large classes or modules
    LargeClass,
    /// Duplicate code
    DuplicateCode,
    /// Long parameter lists
    LongParameterList,
    /// Feature envy
    FeatureEnvy,
    /// Data clumps
    DataClumps,
    /// Primitive obsession
    PrimitiveObsession,
    /// Switch statements
    SwitchStatements,
    /// Lazy class
    LazyClass,
    /// Speculative generality
    SpeculativeGenerality,
}

/// Location of refactoring opportunity
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RefactoringLocation {
    /// File path
    pub file: PathBuf,
    /// Function or method name
    pub function: Option<String>,
    /// Class or struct name
    pub class: Option<String>,
    /// Start line
    pub start_line: usize,
    /// End line
    pub end_line: usize,
    /// Scope description
    pub scope: String,
}

/// Design pattern recommendation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PatternRecommendation {
    /// Recommendation ID
    pub id: String,
    /// Pattern name
    pub pattern_name: String,
    /// Pattern type
    pub pattern_type: PatternType,
    /// Recommendation description
    pub description: String,
    /// Current code structure
    pub current_structure: String,
    /// Suggested pattern implementation
    pub suggested_implementation: String,
    /// Implementation steps
    pub implementation_steps: Vec<ImplementationStep>,
    /// Benefits of applying the pattern
    pub benefits: Vec<String>,
    /// When to apply this pattern
    pub applicability: String,
    /// Confidence level
    pub confidence: f64,
    /// Complexity of implementation
    pub complexity: ImplementationComplexity,
}

/// Types of design patterns
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PatternType {
    /// Creational patterns
    Creational,
    /// Structural patterns
    Structural,
    /// Behavioral patterns
    Behavioral,
    /// Architectural patterns
    Architectural,
}

/// Implementation step for a pattern
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ImplementationStep {
    /// Step number
    pub step: usize,
    /// Step description
    pub description: String,
    /// Code changes required
    pub code_changes: Vec<CodeChange>,
    /// Estimated time (hours)
    pub estimated_time: f64,
}

/// A code change for implementation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct CodeChange {
    /// Change type
    pub change_type: ChangeType,
    /// File to modify
    pub file: PathBuf,
    /// Current code
    pub current_code: String,
    /// New code
    pub new_code: String,
    /// Change description
    pub description: String,
}

/// Types of code changes
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ChangeType {
    /// Add new code
    Add,
    /// Modify existing code
    Modify,
    /// Remove code
    Remove,
    /// Move code to different location
    Move,
    /// Rename symbols
    Rename,
}

/// Implementation complexity levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ImplementationComplexity {
    Trivial,
    Simple,
    Moderate,
    Complex,
    VeryComplex,
}

/// Performance optimization suggestion
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PerformanceOptimization {
    /// Optimization ID
    pub id: String,
    /// Optimization name
    pub name: String,
    /// Optimization type
    pub optimization_type: OptimizationType,
    /// Description
    pub description: String,
    /// Current inefficient code
    pub current_code: String,
    /// Optimized code
    pub optimized_code: String,
    /// Performance improvement explanation
    pub improvement_explanation: String,
    /// Expected performance gain
    pub expected_gain: PerformanceGain,
    /// Implementation difficulty
    pub difficulty: ImplementationComplexity,
    /// Confidence level
    pub confidence: f64,
    /// Benchmarking suggestions
    pub benchmarking: Vec<String>,
}

/// Types of performance optimizations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OptimizationType {
    /// Algorithm optimization
    Algorithm,
    /// Data structure optimization
    DataStructure,
    /// Memory optimization
    Memory,
    /// I/O optimization
    IO,
    /// Concurrency optimization
    Concurrency,
    /// Caching optimization
    Caching,
    /// Loop optimization
    Loop,
}

/// Expected performance gain
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PerformanceGain {
    /// CPU performance improvement percentage
    pub cpu_improvement: f64,
    /// Memory usage reduction percentage
    pub memory_reduction: f64,
    /// Execution time reduction percentage
    pub time_reduction: f64,
    /// Throughput improvement percentage
    pub throughput_improvement: f64,
}

/// Modernization suggestion
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ModernizationSuggestion {
    /// Suggestion ID
    pub id: String,
    /// Modernization type
    pub modernization_type: ModernizationType,
    /// Description
    pub description: String,
    /// Current outdated code
    pub current_code: String,
    /// Modern equivalent
    pub modern_code: String,
    /// Benefits of modernization
    pub benefits: Vec<String>,
    /// Migration steps
    pub migration_steps: Vec<String>,
    /// Compatibility considerations
    pub compatibility: Vec<String>,
    /// Confidence level
    pub confidence: f64,
}

/// Types of modernization
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ModernizationType {
    /// Language version upgrade
    LanguageVersion,
    /// Deprecated API replacement
    DeprecatedAPI,
    /// Modern syntax adoption
    ModernSyntax,
    /// Library upgrade
    LibraryUpgrade,
    /// Best practices adoption
    BestPractices,
}

/// Architectural improvement suggestion
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ArchitecturalImprovement {
    /// Improvement ID
    pub id: String,
    /// Improvement name
    pub name: String,
    /// Improvement type
    pub improvement_type: ArchitecturalImprovementType,
    /// Description
    pub description: String,
    /// Current architecture issues
    pub current_issues: Vec<String>,
    /// Proposed solution
    pub proposed_solution: String,
    /// Implementation plan
    pub implementation_plan: Vec<ImplementationPhase>,
    /// Benefits
    pub benefits: Vec<String>,
    /// Risks and challenges
    pub risks: Vec<String>,
    /// Estimated effort (person-days)
    pub effort_estimate: f64,
}

/// Types of architectural improvements
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ArchitecturalImprovementType {
    /// Modularization
    Modularization,
    /// Separation of concerns
    SeparationOfConcerns,
    /// Dependency injection
    DependencyInjection,
    /// Event-driven architecture
    EventDriven,
    /// Microservices migration
    Microservices,
    /// API design improvement
    APIDesign,
}

/// Implementation phase for architectural improvements
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ImplementationPhase {
    /// Phase number
    pub phase: usize,
    /// Phase name
    pub name: String,
    /// Phase description
    pub description: String,
    /// Deliverables
    pub deliverables: Vec<String>,
    /// Estimated duration (days)
    pub duration: f64,
    /// Dependencies on other phases
    pub dependencies: Vec<usize>,
}

/// Refactoring roadmap
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RefactoringRoadmap {
    /// Total estimated effort (person-days)
    pub total_effort: f64,
    /// Recommended phases
    pub phases: Vec<RefactoringPhase>,
    /// Priority matrix
    pub priority_matrix: PriorityMatrix,
    /// Success metrics
    pub success_metrics: Vec<SuccessMetric>,
}

/// A phase in the refactoring roadmap
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RefactoringPhase {
    /// Phase number
    pub phase: usize,
    /// Phase name
    pub name: String,
    /// Phase description
    pub description: String,
    /// Refactoring items in this phase
    pub items: Vec<RefactoringItem>,
    /// Estimated duration (days)
    pub duration: f64,
    /// Expected benefits
    pub benefits: Vec<String>,
}

/// A refactoring item
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RefactoringItem {
    /// Item ID
    pub id: String,
    /// Item name
    pub name: String,
    /// Item type
    pub item_type: RefactoringCategory,
    /// Priority level
    pub priority: Priority,
    /// Estimated effort (hours)
    pub effort: f64,
}

/// Priority levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum Priority {
    Critical,
    High,
    Medium,
    Low,
}

/// Priority matrix for refactoring decisions
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PriorityMatrix {
    /// High impact, low effort items (quick wins)
    pub quick_wins: Vec<String>,
    /// High impact, high effort items (major projects)
    pub major_projects: Vec<String>,
    /// Low impact, low effort items (fill-ins)
    pub fill_ins: Vec<String>,
    /// Low impact, high effort items (questionable)
    pub questionable: Vec<String>,
}

/// Success metric for measuring refactoring progress
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SuccessMetric {
    /// Metric name
    pub name: String,
    /// Metric description
    pub description: String,
    /// Current value
    pub current_value: f64,
    /// Target value
    pub target_value: f64,
    /// Measurement method
    pub measurement_method: String,
}

/// Impact analysis of refactoring changes
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ImpactAnalysis {
    /// Overall impact score (0-100)
    pub overall_impact: u8,
    /// Code quality impact
    pub quality_impact: QualityImpact,
    /// Performance impact
    pub performance_impact: PerformanceImpact,
    /// Maintainability impact
    pub maintainability_impact: MaintainabilityImpact,
    /// Risk assessment
    pub risk_assessment: RiskAssessment,
}

/// Quality impact assessment
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct QualityImpact {
    /// Readability improvement (0-100)
    pub readability_improvement: u8,
    /// Testability improvement (0-100)
    pub testability_improvement: u8,
    /// Reusability improvement (0-100)
    pub reusability_improvement: u8,
}

/// Performance impact assessment
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PerformanceImpact {
    /// Expected performance improvement (0-100)
    pub performance_improvement: u8,
    /// Memory usage improvement (0-100)
    pub memory_improvement: u8,
    /// Scalability improvement (0-100)
    pub scalability_improvement: u8,
}

/// Maintainability impact assessment
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MaintainabilityImpact {
    /// Code complexity reduction (0-100)
    pub complexity_reduction: u8,
    /// Documentation improvement (0-100)
    pub documentation_improvement: u8,
    /// Modularity improvement (0-100)
    pub modularity_improvement: u8,
}

/// Risk assessment for refactoring
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RiskAssessment {
    /// Overall risk level
    pub overall_risk: RiskLevel,
    /// Identified risks
    pub risks: Vec<RefactoringRisk>,
    /// Mitigation strategies
    pub mitigation_strategies: Vec<String>,
}

/// Risk levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// A refactoring risk
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RefactoringRisk {
    /// Risk name
    pub name: String,
    /// Risk description
    pub description: String,
    /// Risk level
    pub level: RiskLevel,
    /// Probability (0-1)
    pub probability: f64,
    /// Impact if occurs (0-10)
    pub impact: f64,
    /// Mitigation strategies
    pub mitigation: Vec<String>,
}

impl Default for SmartRefactoringConfig {
    fn default() -> Self {
        Self {
            code_smell_fixes: true,
            pattern_recommendations: true,
            performance_optimizations: true,
            modernization: true,
            architectural_improvements: true,
            min_confidence: 0.7,
            max_suggestions_per_category: 10,
        }
    }
}

impl SmartRefactoringEngine {
    /// Create a new smart refactoring engine with default configuration
    pub fn new() -> Self {
        Self {
            config: SmartRefactoringConfig::default(),
        }
    }
    
    /// Create a new smart refactoring engine with custom configuration
    pub fn with_config(config: SmartRefactoringConfig) -> Self {
        Self { config }
    }
    
    /// Perform comprehensive refactoring analysis
    pub fn analyze(&self, analysis_result: &AnalysisResult) -> Result<SmartRefactoringResult> {
        let mut opportunities_by_category = HashMap::new();
        
        // Detect and fix code smells
        let code_smell_fixes = if self.config.code_smell_fixes {
            let fixes = self.detect_code_smell_fixes(analysis_result)?;
            opportunities_by_category.insert(RefactoringCategory::CodeSmells, fixes.len());
            fixes
        } else {
            Vec::new()
        };
        
        // Generate design pattern recommendations
        let pattern_recommendations = if self.config.pattern_recommendations {
            let recommendations = self.generate_pattern_recommendations(analysis_result)?;
            opportunities_by_category.insert(RefactoringCategory::DesignPatterns, recommendations.len());
            recommendations
        } else {
            Vec::new()
        };
        
        // Generate performance optimizations
        let performance_optimizations = if self.config.performance_optimizations {
            let optimizations = self.generate_performance_optimizations(analysis_result)?;
            opportunities_by_category.insert(RefactoringCategory::Performance, optimizations.len());
            optimizations
        } else {
            Vec::new()
        };
        
        // Generate modernization suggestions
        let modernization_suggestions = if self.config.modernization {
            let suggestions = self.generate_modernization_suggestions(analysis_result)?;
            opportunities_by_category.insert(RefactoringCategory::Modernization, suggestions.len());
            suggestions
        } else {
            Vec::new()
        };
        
        // Generate architectural improvements
        let architectural_improvements = if self.config.architectural_improvements {
            let improvements = self.generate_architectural_improvements(analysis_result)?;
            opportunities_by_category.insert(RefactoringCategory::Architecture, improvements.len());
            improvements
        } else {
            Vec::new()
        };
        
        // Create refactoring roadmap
        let refactoring_roadmap = self.create_refactoring_roadmap(
            &code_smell_fixes,
            &pattern_recommendations,
            &performance_optimizations,
            &modernization_suggestions,
            &architectural_improvements,
        )?;
        
        // Perform impact analysis
        let impact_analysis = self.analyze_impact(
            &code_smell_fixes,
            &performance_optimizations,
            &architectural_improvements,
        )?;
        
        let total_opportunities = code_smell_fixes.len() + pattern_recommendations.len() + 
                                 performance_optimizations.len() + modernization_suggestions.len() + 
                                 architectural_improvements.len();
        
        let refactoring_score = self.calculate_refactoring_score(&impact_analysis, total_opportunities);
        
        Ok(SmartRefactoringResult {
            refactoring_score,
            total_opportunities,
            opportunities_by_category,
            code_smell_fixes,
            pattern_recommendations,
            performance_optimizations,
            modernization_suggestions,
            architectural_improvements,
            refactoring_roadmap,
            impact_analysis,
        })
    }

    /// Detect code smells and generate automated fixes
    fn detect_code_smell_fixes(&self, analysis_result: &AnalysisResult) -> Result<Vec<CodeSmellFix>> {
        let mut fixes = Vec::new();

        for file in &analysis_result.files {
            // Detect long methods
            for symbol in &file.symbols {
                if symbol.kind == "function" {
                    let estimated_length = symbol.end_line.saturating_sub(symbol.start_line) + 1;

                    if estimated_length > 30 {
                        fixes.push(CodeSmellFix {
                            id: format!("LONG_METHOD_{}_{}", file.path.display(), symbol.name),
                            smell_name: "Long Method".to_string(),
                            description: format!("Method '{}' is {} lines long, exceeding recommended limit", symbol.name, estimated_length),
                            category: SmellCategory::LongMethod,
                            location: RefactoringLocation {
                                file: file.path.clone(),
                                function: Some(symbol.name.clone()),
                                class: None,
                                start_line: symbol.start_line,
                                end_line: symbol.end_line,
                                scope: "function".to_string(),
                            },
                            current_code: format!("fn {}() {{\n    // {} lines of code\n}}", symbol.name, estimated_length),
                            refactored_code: format!(
                                "fn {}() {{\n    {}();\n    {}();\n}}\n\nfn {}_part1() {{\n    // First part of logic\n}}\n\nfn {}_part2() {{\n    // Second part of logic\n}}",
                                symbol.name, symbol.name, symbol.name, symbol.name, symbol.name
                            ),
                            explanation: "Break down the long method into smaller, focused methods with single responsibilities".to_string(),
                            benefits: vec![
                                "Improved readability".to_string(),
                                "Better testability".to_string(),
                                "Easier maintenance".to_string(),
                                "Enhanced reusability".to_string(),
                            ],
                            risks: vec![
                                "May increase number of methods".to_string(),
                                "Requires careful extraction of logic".to_string(),
                            ],
                            confidence: 0.85,
                            effort: 2.0,
                            automated_fix: false,
                        });
                    }
                }
            }

            // Detect large files (large class smell)
            if file.lines > 500 {
                fixes.push(CodeSmellFix {
                    id: format!("LARGE_FILE_{}", file.path.display()),
                    smell_name: "Large Class/File".to_string(),
                    description: format!("File '{}' has {} lines, which may indicate too many responsibilities", file.path.display(), file.lines),
                    category: SmellCategory::LargeClass,
                    location: RefactoringLocation {
                        file: file.path.clone(),
                        function: None,
                        class: None,
                        start_line: 1,
                        end_line: file.lines,
                        scope: "file".to_string(),
                    },
                    current_code: format!("// Large file with {} lines", file.lines),
                    refactored_code: "// Split into multiple focused modules:\n// - module1.rs (core functionality)\n// - module2.rs (utilities)\n// - module3.rs (data structures)".to_string(),
                    explanation: "Split the large file into smaller, cohesive modules following the Single Responsibility Principle".to_string(),
                    benefits: vec![
                        "Better organization".to_string(),
                        "Improved maintainability".to_string(),
                        "Easier navigation".to_string(),
                        "Better separation of concerns".to_string(),
                    ],
                    risks: vec![
                        "May require significant restructuring".to_string(),
                        "Need to manage module dependencies".to_string(),
                    ],
                    confidence: 0.8,
                    effort: 8.0,
                    automated_fix: false,
                });
            }

            // Detect potential duplicate code (simplified)
            let function_names: Vec<_> = file.symbols.iter()
                .filter(|s| s.kind == "function")
                .map(|s| &s.name)
                .collect();

            for (i, name1) in function_names.iter().enumerate() {
                for name2 in function_names.iter().skip(i + 1) {
                    if name1.len() > 5 && name2.len() > 5 &&
                       self.calculate_similarity(name1, name2) > 0.7 {
                        fixes.push(CodeSmellFix {
                            id: format!("DUPLICATE_CODE_{}_{}_{}", file.path.display(), name1, name2),
                            smell_name: "Duplicate Code".to_string(),
                            description: format!("Functions '{}' and '{}' appear to have similar implementations", name1, name2),
                            category: SmellCategory::DuplicateCode,
                            location: RefactoringLocation {
                                file: file.path.clone(),
                                function: Some(format!("{}, {}", name1, name2)),
                                class: None,
                                start_line: 1,
                                end_line: file.lines,
                                scope: "functions".to_string(),
                            },
                            current_code: format!("fn {}() {{ /* similar code */ }}\nfn {}() {{ /* similar code */ }}", name1, name2),
                            refactored_code: format!("fn common_logic() {{ /* extracted common code */ }}\nfn {}() {{ common_logic(); /* specific code */ }}\nfn {}() {{ common_logic(); /* specific code */ }}", name1, name2),
                            explanation: "Extract common functionality into a shared function to eliminate duplication".to_string(),
                            benefits: vec![
                                "Reduced code duplication".to_string(),
                                "Easier maintenance".to_string(),
                                "Single source of truth".to_string(),
                                "Reduced bug potential".to_string(),
                            ],
                            risks: vec![
                                "May introduce coupling".to_string(),
                                "Need to ensure extracted logic is truly common".to_string(),
                            ],
                            confidence: 0.7,
                            effort: 3.0,
                            automated_fix: false,
                        });
                        break; // Only report one duplicate per function
                    }
                }
            }
        }

        // Limit results based on configuration
        fixes.truncate(self.config.max_suggestions_per_category);
        Ok(fixes)
    }

    /// Calculate similarity between two strings (simplified)
    fn calculate_similarity(&self, s1: &str, s2: &str) -> f64 {
        let len1 = s1.len();
        let len2 = s2.len();
        let max_len = len1.max(len2);

        if max_len == 0 {
            return 1.0;
        }

        let common_chars = s1.chars()
            .filter(|c| s2.contains(*c))
            .count();

        common_chars as f64 / max_len as f64
    }

    /// Generate design pattern recommendations
    fn generate_pattern_recommendations(&self, analysis_result: &AnalysisResult) -> Result<Vec<PatternRecommendation>> {
        let mut recommendations = Vec::new();

        // Analyze for Factory pattern opportunities
        let mut creation_methods = 0;
        for file in &analysis_result.files {
            for symbol in &file.symbols {
                if symbol.kind == "function" &&
                   (symbol.name.starts_with("create") || symbol.name.starts_with("new") || symbol.name.contains("build")) {
                    creation_methods += 1;
                }
            }
        }

        if creation_methods > 3 {
            recommendations.push(PatternRecommendation {
                id: "FACTORY_PATTERN_OPPORTUNITY".to_string(),
                pattern_name: "Factory Pattern".to_string(),
                pattern_type: PatternType::Creational,
                description: "Multiple object creation methods detected. Consider implementing Factory pattern for centralized object creation.".to_string(),
                current_structure: "Scattered object creation methods across multiple files".to_string(),
                suggested_implementation: "Centralized Factory class with create methods for different object types".to_string(),
                implementation_steps: vec![
                    ImplementationStep {
                        step: 1,
                        description: "Create a Factory trait or interface".to_string(),
                        code_changes: vec![
                            CodeChange {
                                change_type: ChangeType::Add,
                                file: PathBuf::from("src/factory.rs"),
                                current_code: "".to_string(),
                                new_code: "trait ObjectFactory {\n    fn create_object(&self, object_type: ObjectType) -> Box<dyn Object>;\n}".to_string(),
                                description: "Define factory interface".to_string(),
                            }
                        ],
                        estimated_time: 1.0,
                    },
                    ImplementationStep {
                        step: 2,
                        description: "Implement concrete factory".to_string(),
                        code_changes: vec![
                            CodeChange {
                                change_type: ChangeType::Add,
                                file: PathBuf::from("src/factory.rs"),
                                current_code: "".to_string(),
                                new_code: "struct ConcreteFactory;\n\nimpl ObjectFactory for ConcreteFactory {\n    fn create_object(&self, object_type: ObjectType) -> Box<dyn Object> {\n        match object_type {\n            ObjectType::TypeA => Box::new(ObjectA::new()),\n            ObjectType::TypeB => Box::new(ObjectB::new()),\n        }\n    }\n}".to_string(),
                                description: "Implement factory logic".to_string(),
                            }
                        ],
                        estimated_time: 2.0,
                    },
                ],
                benefits: vec![
                    "Centralized object creation".to_string(),
                    "Easier to maintain and extend".to_string(),
                    "Reduced coupling".to_string(),
                    "Consistent object initialization".to_string(),
                ],
                applicability: "When you have multiple related object creation methods scattered across the codebase".to_string(),
                confidence: 0.8,
                complexity: ImplementationComplexity::Moderate,
            });
        }

        // Analyze for Observer pattern opportunities
        let mut event_related_code = 0;
        for file in &analysis_result.files {
            let file_content = std::fs::read_to_string(&file.path).unwrap_or_default();
            if file_content.to_lowercase().contains("event") ||
               file_content.to_lowercase().contains("notify") ||
               file_content.to_lowercase().contains("listener") {
                event_related_code += 1;
            }
        }

        if event_related_code > 2 {
            recommendations.push(PatternRecommendation {
                id: "OBSERVER_PATTERN_OPPORTUNITY".to_string(),
                pattern_name: "Observer Pattern".to_string(),
                pattern_type: PatternType::Behavioral,
                description: "Event-related code detected. Consider implementing Observer pattern for loose coupling between components.".to_string(),
                current_structure: "Direct coupling between event producers and consumers".to_string(),
                suggested_implementation: "Observer pattern with Subject and Observer interfaces".to_string(),
                implementation_steps: vec![
                    ImplementationStep {
                        step: 1,
                        description: "Define Observer trait".to_string(),
                        code_changes: vec![
                            CodeChange {
                                change_type: ChangeType::Add,
                                file: PathBuf::from("src/observer.rs"),
                                current_code: "".to_string(),
                                new_code: "trait Observer {\n    fn update(&self, event: &Event);\n}".to_string(),
                                description: "Define observer interface".to_string(),
                            }
                        ],
                        estimated_time: 0.5,
                    },
                    ImplementationStep {
                        step: 2,
                        description: "Implement Subject with observer management".to_string(),
                        code_changes: vec![
                            CodeChange {
                                change_type: ChangeType::Add,
                                file: PathBuf::from("src/observer.rs"),
                                current_code: "".to_string(),
                                new_code: "struct Subject {\n    observers: Vec<Box<dyn Observer>>,\n}\n\nimpl Subject {\n    fn attach(&mut self, observer: Box<dyn Observer>) {\n        self.observers.push(observer);\n    }\n    \n    fn notify(&self, event: &Event) {\n        for observer in &self.observers {\n            observer.update(event);\n        }\n    }\n}".to_string(),
                                description: "Implement subject with observer management".to_string(),
                            }
                        ],
                        estimated_time: 2.0,
                    },
                ],
                benefits: vec![
                    "Loose coupling between components".to_string(),
                    "Dynamic subscription/unsubscription".to_string(),
                    "Easier to add new observers".to_string(),
                    "Better separation of concerns".to_string(),
                ],
                applicability: "When you have one-to-many dependencies between objects and want to notify multiple objects about state changes".to_string(),
                confidence: 0.75,
                complexity: ImplementationComplexity::Moderate,
            });
        }

        recommendations.truncate(self.config.max_suggestions_per_category);
        Ok(recommendations)
    }

    /// Generate performance optimizations
    fn generate_performance_optimizations(&self, analysis_result: &AnalysisResult) -> Result<Vec<PerformanceOptimization>> {
        let mut optimizations = Vec::new();

        for file in &analysis_result.files {
            // Check for potential string concatenation in loops
            if let Ok(content) = std::fs::read_to_string(&file.path) {
                if content.contains("for") && content.contains("+") && content.contains("String") {
                    optimizations.push(PerformanceOptimization {
                        id: format!("STRING_CONCAT_LOOP_{}", file.path.display()),
                        name: "String Concatenation in Loop".to_string(),
                        optimization_type: OptimizationType::Algorithm,
                        description: "String concatenation in loop detected. This can be inefficient for large datasets.".to_string(),
                        current_code: "let mut result = String::new();\nfor item in items {\n    result = result + &item.to_string();\n}".to_string(),
                        optimized_code: "let mut result = String::with_capacity(estimated_size);\nfor item in items {\n    result.push_str(&item.to_string());\n}\n// Or use: items.iter().map(|i| i.to_string()).collect::<Vec<_>>().join(\"\")".to_string(),
                        improvement_explanation: "Using push_str() or pre-allocating capacity avoids repeated memory allocations".to_string(),
                        expected_gain: PerformanceGain {
                            cpu_improvement: 30.0,
                            memory_reduction: 25.0,
                            time_reduction: 40.0,
                            throughput_improvement: 35.0,
                        },
                        difficulty: ImplementationComplexity::Simple,
                        confidence: 0.9,
                        benchmarking: vec![
                            "Benchmark with different string sizes".to_string(),
                            "Measure memory allocations".to_string(),
                            "Test with various loop iterations".to_string(),
                        ],
                    });
                }

                // Check for potential vector reallocation
                if content.contains("Vec::new()") && content.contains("push") {
                    optimizations.push(PerformanceOptimization {
                        id: format!("VECTOR_REALLOCATION_{}", file.path.display()),
                        name: "Vector Reallocation".to_string(),
                        optimization_type: OptimizationType::Memory,
                        description: "Vector created without capacity hint may cause multiple reallocations.".to_string(),
                        current_code: "let mut vec = Vec::new();\nfor i in 0..1000 {\n    vec.push(i);\n}".to_string(),
                        optimized_code: "let mut vec = Vec::with_capacity(1000);\nfor i in 0..1000 {\n    vec.push(i);\n}\n// Or use: (0..1000).collect::<Vec<_>>()".to_string(),
                        improvement_explanation: "Pre-allocating capacity prevents multiple reallocations and copying".to_string(),
                        expected_gain: PerformanceGain {
                            cpu_improvement: 20.0,
                            memory_reduction: 15.0,
                            time_reduction: 25.0,
                            throughput_improvement: 20.0,
                        },
                        difficulty: ImplementationComplexity::Trivial,
                        confidence: 0.85,
                        benchmarking: vec![
                            "Measure allocation count".to_string(),
                            "Compare execution times".to_string(),
                            "Test with different vector sizes".to_string(),
                        ],
                    });
                }

                // Check for nested loops (potential O(n²) complexity)
                let loop_count = content.matches("for").count();
                if loop_count > 1 && content.contains("for") {
                    optimizations.push(PerformanceOptimization {
                        id: format!("NESTED_LOOPS_{}", file.path.display()),
                        name: "Nested Loop Optimization".to_string(),
                        optimization_type: OptimizationType::Algorithm,
                        description: "Nested loops detected. Consider algorithmic improvements to reduce complexity.".to_string(),
                        current_code: "for i in 0..n {\n    for j in 0..m {\n        // O(n*m) operation\n    }\n}".to_string(),
                        optimized_code: "// Option 1: Use HashMap for O(1) lookups\nlet lookup: HashMap<_, _> = data.iter().enumerate().collect();\nfor item in items {\n    if let Some(value) = lookup.get(&item.key) {\n        // O(n) operation\n    }\n}\n\n// Option 2: Sort and use binary search\ndata.sort();\nfor item in items {\n    if data.binary_search(&item).is_ok() {\n        // O(n log n) operation\n    }\n}".to_string(),
                        improvement_explanation: "Replace nested loops with more efficient data structures or algorithms".to_string(),
                        expected_gain: PerformanceGain {
                            cpu_improvement: 60.0,
                            memory_reduction: 10.0,
                            time_reduction: 70.0,
                            throughput_improvement: 65.0,
                        },
                        difficulty: ImplementationComplexity::Complex,
                        confidence: 0.7,
                        benchmarking: vec![
                            "Measure time complexity with different input sizes".to_string(),
                            "Profile CPU usage".to_string(),
                            "Compare algorithmic approaches".to_string(),
                        ],
                    });
                }
            }
        }

        optimizations.truncate(self.config.max_suggestions_per_category);
        Ok(optimizations)
    }

    /// Generate modernization suggestions
    fn generate_modernization_suggestions(&self, analysis_result: &AnalysisResult) -> Result<Vec<ModernizationSuggestion>> {
        let mut suggestions = Vec::new();

        for file in &analysis_result.files {
            if let Ok(content) = std::fs::read_to_string(&file.path) {
                // Check for deprecated Rust patterns
                if file.path.extension().map_or(false, |ext| ext == "rs") {
                    // Check for old-style error handling
                    if content.contains("unwrap()") && !content.contains("expect(") {
                        suggestions.push(ModernizationSuggestion {
                            id: format!("MODERN_ERROR_HANDLING_{}", file.path.display()),
                            modernization_type: ModernizationType::BestPractices,
                            description: "Replace unwrap() with more descriptive error handling".to_string(),
                            current_code: "let value = some_operation().unwrap();".to_string(),
                            modern_code: "let value = some_operation().expect(\"Failed to perform operation\");\n// Or better:\nlet value = some_operation().map_err(|e| format!(\"Operation failed: {}\", e))?;".to_string(),
                            benefits: vec![
                                "Better error messages".to_string(),
                                "Easier debugging".to_string(),
                                "More robust error handling".to_string(),
                            ],
                            migration_steps: vec![
                                "Identify all unwrap() calls".to_string(),
                                "Replace with expect() and descriptive messages".to_string(),
                                "Consider proper error propagation with ?".to_string(),
                            ],
                            compatibility: vec![
                                "No breaking changes".to_string(),
                                "Improves runtime error reporting".to_string(),
                            ],
                            confidence: 0.9,
                        });
                    }

                    // Check for old-style string formatting
                    if content.contains("format!") && content.contains("{}") && !content.contains("println!") {
                        suggestions.push(ModernizationSuggestion {
                            id: format!("MODERN_STRING_FORMAT_{}", file.path.display()),
                            modernization_type: ModernizationType::ModernSyntax,
                            description: "Consider using named parameters in format strings for clarity".to_string(),
                            current_code: "format!(\"Hello {} from {}\", name, location)".to_string(),
                            modern_code: "format!(\"Hello {name} from {location}\", name = name, location = location)".to_string(),
                            benefits: vec![
                                "Improved readability".to_string(),
                                "Self-documenting code".to_string(),
                                "Easier maintenance".to_string(),
                            ],
                            migration_steps: vec![
                                "Identify format! calls with positional parameters".to_string(),
                                "Replace with named parameters".to_string(),
                                "Update format strings accordingly".to_string(),
                            ],
                            compatibility: vec![
                                "Requires Rust 1.58+".to_string(),
                                "No runtime performance impact".to_string(),
                            ],
                            confidence: 0.8,
                        });
                    }
                }

                // Check for JavaScript/TypeScript modernization opportunities
                if file.path.extension().map_or(false, |ext| ext == "js" || ext == "ts") {
                    // Check for var usage
                    if content.contains("var ") {
                        suggestions.push(ModernizationSuggestion {
                            id: format!("MODERN_JS_VAR_{}", file.path.display()),
                            modernization_type: ModernizationType::ModernSyntax,
                            description: "Replace 'var' with 'let' or 'const' for better scoping".to_string(),
                            current_code: "var name = 'John';\nvar age = 30;".to_string(),
                            modern_code: "const name = 'John';\nlet age = 30;".to_string(),
                            benefits: vec![
                                "Block scoping instead of function scoping".to_string(),
                                "Prevents accidental reassignment".to_string(),
                                "Better error detection".to_string(),
                            ],
                            migration_steps: vec![
                                "Replace 'var' with 'const' for values that don't change".to_string(),
                                "Replace 'var' with 'let' for values that do change".to_string(),
                                "Test for any scoping issues".to_string(),
                            ],
                            compatibility: vec![
                                "Requires ES6+ support".to_string(),
                                "May require transpilation for older browsers".to_string(),
                            ],
                            confidence: 0.95,
                        });
                    }

                    // Check for function declarations vs arrow functions
                    if content.contains("function(") && !content.contains("=>") {
                        suggestions.push(ModernizationSuggestion {
                            id: format!("MODERN_JS_ARROW_{}", file.path.display()),
                            modernization_type: ModernizationType::ModernSyntax,
                            description: "Consider using arrow functions for callbacks and short functions".to_string(),
                            current_code: "array.map(function(item) { return item * 2; })".to_string(),
                            modern_code: "array.map(item => item * 2)".to_string(),
                            benefits: vec![
                                "Shorter syntax".to_string(),
                                "Lexical 'this' binding".to_string(),
                                "More functional programming style".to_string(),
                            ],
                            migration_steps: vec![
                                "Identify callback functions".to_string(),
                                "Replace with arrow function syntax".to_string(),
                                "Check 'this' binding behavior".to_string(),
                            ],
                            compatibility: vec![
                                "Requires ES6+ support".to_string(),
                                "Different 'this' binding behavior".to_string(),
                            ],
                            confidence: 0.8,
                        });
                    }
                }
            }
        }

        suggestions.truncate(self.config.max_suggestions_per_category);
        Ok(suggestions)
    }

    /// Generate architectural improvements
    fn generate_architectural_improvements(&self, analysis_result: &AnalysisResult) -> Result<Vec<ArchitecturalImprovement>> {
        let mut improvements = Vec::new();

        // Analyze project structure for modularization opportunities
        if analysis_result.total_files > 20 {
            let _has_clear_modules = false;
            let mut module_dirs = 0;

            for file in &analysis_result.files {
                if file.path.parent().map_or(false, |p| p.file_name().is_some()) {
                    module_dirs += 1;
                }
            }

            if module_dirs < analysis_result.total_files / 4 {
                improvements.push(ArchitecturalImprovement {
                    id: "MODULARIZATION_OPPORTUNITY".to_string(),
                    name: "Improve Modularization".to_string(),
                    improvement_type: ArchitecturalImprovementType::Modularization,
                    description: "Large codebase with limited modular organization detected".to_string(),
                    current_issues: vec![
                        "Files not organized into logical modules".to_string(),
                        "Potential for tight coupling".to_string(),
                        "Difficult navigation and maintenance".to_string(),
                    ],
                    proposed_solution: "Reorganize code into domain-specific modules with clear boundaries".to_string(),
                    implementation_plan: vec![
                        ImplementationPhase {
                            phase: 1,
                            name: "Analysis and Planning".to_string(),
                            description: "Analyze current dependencies and identify module boundaries".to_string(),
                            deliverables: vec![
                                "Dependency analysis report".to_string(),
                                "Proposed module structure".to_string(),
                                "Migration plan".to_string(),
                            ],
                            duration: 3.0,
                            dependencies: vec![],
                        },
                        ImplementationPhase {
                            phase: 2,
                            name: "Core Module Creation".to_string(),
                            description: "Create core modules and move related functionality".to_string(),
                            deliverables: vec![
                                "Core module structure".to_string(),
                                "Moved core functionality".to_string(),
                                "Updated imports and exports".to_string(),
                            ],
                            duration: 5.0,
                            dependencies: vec![1],
                        },
                        ImplementationPhase {
                            phase: 3,
                            name: "Interface Definition".to_string(),
                            description: "Define clear interfaces between modules".to_string(),
                            deliverables: vec![
                                "Module interfaces".to_string(),
                                "API documentation".to_string(),
                                "Integration tests".to_string(),
                            ],
                            duration: 4.0,
                            dependencies: vec![2],
                        },
                    ],
                    benefits: vec![
                        "Better code organization".to_string(),
                        "Improved maintainability".to_string(),
                        "Easier testing and debugging".to_string(),
                        "Better team collaboration".to_string(),
                    ],
                    risks: vec![
                        "Temporary disruption during migration".to_string(),
                        "Potential for circular dependencies".to_string(),
                        "Need for comprehensive testing".to_string(),
                    ],
                    effort_estimate: 12.0,
                });
            }
        }

        // Check for separation of concerns issues
        let mut business_logic_files = 0;
        let mut ui_files = 0;
        let mut data_files = 0;

        for file in &analysis_result.files {
            let file_name = file.path.file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("")
                .to_lowercase();

            if file_name.contains("service") || file_name.contains("business") || file_name.contains("logic") {
                business_logic_files += 1;
            } else if file_name.contains("ui") || file_name.contains("view") || file_name.contains("component") {
                ui_files += 1;
            } else if file_name.contains("data") || file_name.contains("repository") || file_name.contains("db") {
                data_files += 1;
            }
        }

        if business_logic_files == 0 || ui_files == 0 || data_files == 0 {
            improvements.push(ArchitecturalImprovement {
                id: "SEPARATION_OF_CONCERNS".to_string(),
                name: "Improve Separation of Concerns".to_string(),
                improvement_type: ArchitecturalImprovementType::SeparationOfConcerns,
                description: "Code appears to mix different concerns (business logic, UI, data access)".to_string(),
                current_issues: vec![
                    "Mixed responsibilities in files".to_string(),
                    "Tight coupling between layers".to_string(),
                    "Difficult to test individual components".to_string(),
                ],
                proposed_solution: "Implement layered architecture with clear separation of concerns".to_string(),
                implementation_plan: vec![
                    ImplementationPhase {
                        phase: 1,
                        name: "Layer Identification".to_string(),
                        description: "Identify and separate different layers of the application".to_string(),
                        deliverables: vec![
                            "Layer definitions".to_string(),
                            "Responsibility mapping".to_string(),
                            "Interface specifications".to_string(),
                        ],
                        duration: 4.0,
                        dependencies: vec![],
                    },
                    ImplementationPhase {
                        phase: 2,
                        name: "Data Layer Separation".to_string(),
                        description: "Extract data access logic into dedicated layer".to_string(),
                        deliverables: vec![
                            "Data access layer".to_string(),
                            "Repository interfaces".to_string(),
                            "Data models".to_string(),
                        ],
                        duration: 6.0,
                        dependencies: vec![1],
                    },
                    ImplementationPhase {
                        phase: 3,
                        name: "Business Logic Layer".to_string(),
                        description: "Create dedicated business logic layer".to_string(),
                        deliverables: vec![
                            "Business services".to_string(),
                            "Domain models".to_string(),
                            "Business rules".to_string(),
                        ],
                        duration: 8.0,
                        dependencies: vec![2],
                    },
                ],
                benefits: vec![
                    "Better testability".to_string(),
                    "Easier maintenance".to_string(),
                    "Improved reusability".to_string(),
                    "Better team collaboration".to_string(),
                ],
                risks: vec![
                    "Increased complexity initially".to_string(),
                    "Need for interface management".to_string(),
                    "Potential performance overhead".to_string(),
                ],
                effort_estimate: 18.0,
            });
        }

        improvements.truncate(self.config.max_suggestions_per_category);
        Ok(improvements)
    }

    /// Create refactoring roadmap
    fn create_refactoring_roadmap(
        &self,
        code_smell_fixes: &[CodeSmellFix],
        pattern_recommendations: &[PatternRecommendation],
        performance_optimizations: &[PerformanceOptimization],
        modernization_suggestions: &[ModernizationSuggestion],
        architectural_improvements: &[ArchitecturalImprovement],
    ) -> Result<RefactoringRoadmap> {
        let mut refactoring_items = Vec::new();

        // Convert all suggestions to refactoring items
        for fix in code_smell_fixes {
            refactoring_items.push(RefactoringItem {
                id: fix.id.clone(),
                name: fix.smell_name.clone(),
                item_type: RefactoringCategory::CodeSmells,
                priority: if fix.confidence > 0.8 { Priority::High } else { Priority::Medium },
                effort: fix.effort,
            });
        }

        for recommendation in pattern_recommendations {
            let effort = recommendation.implementation_steps.iter()
                .map(|step| step.estimated_time)
                .sum();
            refactoring_items.push(RefactoringItem {
                id: recommendation.id.clone(),
                name: recommendation.pattern_name.clone(),
                item_type: RefactoringCategory::DesignPatterns,
                priority: Priority::Medium,
                effort,
            });
        }

        for optimization in performance_optimizations {
            refactoring_items.push(RefactoringItem {
                id: optimization.id.clone(),
                name: optimization.name.clone(),
                item_type: RefactoringCategory::Performance,
                priority: if optimization.expected_gain.time_reduction > 50.0 { Priority::High } else { Priority::Medium },
                effort: match optimization.difficulty {
                    ImplementationComplexity::Trivial => 0.5,
                    ImplementationComplexity::Simple => 1.0,
                    ImplementationComplexity::Moderate => 3.0,
                    ImplementationComplexity::Complex => 8.0,
                    ImplementationComplexity::VeryComplex => 16.0,
                },
            });
        }

        for suggestion in modernization_suggestions {
            refactoring_items.push(RefactoringItem {
                id: suggestion.id.clone(),
                name: format!("{:?}", suggestion.modernization_type),
                item_type: RefactoringCategory::Modernization,
                priority: Priority::Low,
                effort: 2.0,
            });
        }

        for improvement in architectural_improvements {
            refactoring_items.push(RefactoringItem {
                id: improvement.id.clone(),
                name: improvement.name.clone(),
                item_type: RefactoringCategory::Architecture,
                priority: Priority::Critical,
                effort: improvement.effort_estimate * 8.0, // Convert days to hours
            });
        }

        // Sort by priority and effort
        refactoring_items.sort_by(|a, b| {
            match (&a.priority, &b.priority) {
                (Priority::Critical, Priority::Critical) => a.effort.partial_cmp(&b.effort).unwrap_or(std::cmp::Ordering::Equal),
                (Priority::Critical, _) => std::cmp::Ordering::Less,
                (_, Priority::Critical) => std::cmp::Ordering::Greater,
                (Priority::High, Priority::High) => a.effort.partial_cmp(&b.effort).unwrap_or(std::cmp::Ordering::Equal),
                (Priority::High, _) => std::cmp::Ordering::Less,
                (_, Priority::High) => std::cmp::Ordering::Greater,
                _ => a.effort.partial_cmp(&b.effort).unwrap_or(std::cmp::Ordering::Equal),
            }
        });

        // Create phases
        let mut phases = Vec::new();
        let mut current_phase_items = Vec::new();
        let mut current_phase_effort = 0.0;
        let max_phase_effort = 40.0; // 40 hours per phase (1 week)

        for item in refactoring_items {
            if current_phase_effort + item.effort > max_phase_effort && !current_phase_items.is_empty() {
                phases.push(RefactoringPhase {
                    phase: phases.len() + 1,
                    name: format!("Phase {}", phases.len() + 1),
                    description: "Refactoring phase with prioritized improvements".to_string(),
                    items: current_phase_items.clone(),
                    duration: current_phase_effort / 8.0, // Convert to days
                    benefits: vec!["Improved code quality".to_string()],
                });
                current_phase_items.clear();
                current_phase_effort = 0.0;
            }

            current_phase_effort += item.effort;
            current_phase_items.push(item);
        }

        // Add remaining items as final phase
        if !current_phase_items.is_empty() {
            phases.push(RefactoringPhase {
                phase: phases.len() + 1,
                name: format!("Phase {}", phases.len() + 1),
                description: "Final refactoring phase".to_string(),
                items: current_phase_items,
                duration: current_phase_effort / 8.0,
                benefits: vec!["Completed refactoring goals".to_string()],
            });
        }

        let total_effort = phases.iter().map(|p| p.duration).sum();

        // Create priority matrix
        let priority_matrix = PriorityMatrix {
            quick_wins: code_smell_fixes.iter()
                .filter(|f| f.effort < 2.0 && f.confidence > 0.8)
                .map(|f| f.smell_name.clone())
                .collect(),
            major_projects: architectural_improvements.iter()
                .map(|i| i.name.clone())
                .collect(),
            fill_ins: modernization_suggestions.iter()
                .map(|s| format!("{:?}", s.modernization_type))
                .collect(),
            questionable: Vec::new(),
        };

        // Define success metrics
        let success_metrics = vec![
            SuccessMetric {
                name: "Code Quality Score".to_string(),
                description: "Overall code quality improvement".to_string(),
                current_value: 70.0,
                target_value: 85.0,
                measurement_method: "Automated code analysis tools".to_string(),
            },
            SuccessMetric {
                name: "Technical Debt Reduction".to_string(),
                description: "Reduction in technical debt items".to_string(),
                current_value: 100.0,
                target_value: 30.0,
                measurement_method: "Count of identified issues".to_string(),
            },
        ];

        Ok(RefactoringRoadmap {
            total_effort,
            phases,
            priority_matrix,
            success_metrics,
        })
    }

    /// Analyze impact of refactoring changes
    fn analyze_impact(
        &self,
        code_smell_fixes: &[CodeSmellFix],
        performance_optimizations: &[PerformanceOptimization],
        architectural_improvements: &[ArchitecturalImprovement],
    ) -> Result<ImpactAnalysis> {
        // Calculate quality impact
        let readability_improvement = if code_smell_fixes.is_empty() { 0 } else { 75 };
        let testability_improvement = if architectural_improvements.is_empty() { 0 } else { 80 };
        let reusability_improvement = if code_smell_fixes.len() > 2 { 70 } else { 40 };

        let quality_impact = QualityImpact {
            readability_improvement,
            testability_improvement,
            reusability_improvement,
        };

        // Calculate performance impact
        let avg_performance_gain = if performance_optimizations.is_empty() {
            0.0
        } else {
            performance_optimizations.iter()
                .map(|opt| opt.expected_gain.time_reduction)
                .sum::<f64>() / performance_optimizations.len() as f64
        };

        let performance_impact = PerformanceImpact {
            performance_improvement: avg_performance_gain as u8,
            memory_improvement: (avg_performance_gain * 0.6) as u8,
            scalability_improvement: if architectural_improvements.is_empty() { 0 } else { 85 },
        };

        // Calculate maintainability impact
        let complexity_reduction = if code_smell_fixes.is_empty() { 0 } else { 60 };
        let documentation_improvement = 50; // Moderate improvement expected
        let modularity_improvement = if architectural_improvements.is_empty() { 0 } else { 90 };

        let maintainability_impact = MaintainabilityImpact {
            complexity_reduction,
            documentation_improvement,
            modularity_improvement,
        };

        // Assess risks
        let mut risks = Vec::new();

        if !architectural_improvements.is_empty() {
            risks.push(RefactoringRisk {
                name: "Architectural Changes".to_string(),
                description: "Large-scale architectural changes may introduce instability".to_string(),
                level: RiskLevel::Medium,
                probability: 0.3,
                impact: 7.0,
                mitigation: vec![
                    "Implement changes incrementally".to_string(),
                    "Comprehensive testing at each step".to_string(),
                    "Maintain rollback capabilities".to_string(),
                ],
            });
        }

        if performance_optimizations.len() > 3 {
            risks.push(RefactoringRisk {
                name: "Performance Optimization Complexity".to_string(),
                description: "Multiple performance optimizations may interact unexpectedly".to_string(),
                level: RiskLevel::Low,
                probability: 0.2,
                impact: 4.0,
                mitigation: vec![
                    "Benchmark each optimization individually".to_string(),
                    "Monitor performance metrics continuously".to_string(),
                ],
            });
        }

        let overall_risk = if risks.iter().any(|r| matches!(r.level, RiskLevel::High | RiskLevel::Critical)) {
            RiskLevel::High
        } else if risks.iter().any(|r| matches!(r.level, RiskLevel::Medium)) {
            RiskLevel::Medium
        } else {
            RiskLevel::Low
        };

        let risk_assessment = RiskAssessment {
            overall_risk,
            risks,
            mitigation_strategies: vec![
                "Implement changes in small, testable increments".to_string(),
                "Maintain comprehensive test coverage".to_string(),
                "Use feature flags for gradual rollout".to_string(),
                "Monitor system metrics closely".to_string(),
            ],
        };

        // Calculate overall impact
        let overall_impact = ((readability_improvement + testability_improvement + reusability_improvement) as f64 / 3.0) as u8;

        Ok(ImpactAnalysis {
            overall_impact,
            quality_impact,
            performance_impact,
            maintainability_impact,
            risk_assessment,
        })
    }

    /// Calculate refactoring score
    fn calculate_refactoring_score(&self, impact_analysis: &ImpactAnalysis, total_opportunities: usize) -> u8 {
        let impact_score = impact_analysis.overall_impact as f64 * 0.6;
        let opportunity_score = (total_opportunities.min(20) as f64 / 20.0) * 40.0;

        (impact_score + opportunity_score).min(100.0) as u8
    }
}

// Display implementations
impl std::fmt::Display for RefactoringCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RefactoringCategory::CodeSmells => write!(f, "Code Smells"),
            RefactoringCategory::DesignPatterns => write!(f, "Design Patterns"),
            RefactoringCategory::Performance => write!(f, "Performance"),
            RefactoringCategory::Modernization => write!(f, "Modernization"),
            RefactoringCategory::Architecture => write!(f, "Architecture"),
        }
    }
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Priority::Critical => write!(f, "Critical"),
            Priority::High => write!(f, "High"),
            Priority::Medium => write!(f, "Medium"),
            Priority::Low => write!(f, "Low"),
        }
    }
}

impl std::fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "Low"),
            RiskLevel::Medium => write!(f, "Medium"),
            RiskLevel::High => write!(f, "High"),
            RiskLevel::Critical => write!(f, "Critical"),
        }
    }
}
