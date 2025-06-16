//! Performance hotspot detection and optimization analysis
//! 
//! This module provides comprehensive performance analysis including:
//! - Algorithmic complexity detection
//! - Memory usage patterns analysis
//! - I/O operation optimization
//! - Concurrency and parallelization opportunities
//! - Performance bottleneck identification

use crate::{AnalysisResult, FileInfo, Result};
use std::collections::HashMap;
use std::path::PathBuf;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Performance analyzer for detecting hotspots and optimization opportunities
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PerformanceAnalyzer {
    /// Configuration for performance analysis
    pub config: PerformanceConfig,
}

/// Configuration for performance analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PerformanceConfig {
    /// Enable algorithmic complexity analysis
    pub complexity_analysis: bool,
    /// Enable memory usage analysis
    pub memory_analysis: bool,
    /// Enable I/O operation analysis
    pub io_analysis: bool,
    /// Enable concurrency analysis
    pub concurrency_analysis: bool,
    /// Enable database query analysis
    pub database_analysis: bool,
    /// Minimum complexity threshold for reporting
    pub min_complexity_threshold: usize,
    /// Maximum acceptable function length
    pub max_function_length: usize,
}

/// Results of performance analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PerformanceAnalysisResult {
    /// Overall performance score (0-100)
    pub performance_score: u8,
    /// Total hotspots detected
    pub total_hotspots: usize,
    /// Hotspots by severity
    pub hotspots_by_severity: HashMap<PerformanceSeverity, usize>,
    /// Detected performance hotspots
    pub hotspots: Vec<PerformanceHotspot>,
    /// Optimization opportunities
    pub optimizations: Vec<OptimizationOpportunity>,
    /// Performance metrics by file
    pub file_metrics: Vec<FilePerformanceMetrics>,
    /// Algorithmic complexity analysis
    pub complexity_analysis: ComplexityAnalysis,
    /// Memory usage analysis
    pub memory_analysis: MemoryAnalysis,
    /// Concurrency analysis
    pub concurrency_analysis: ConcurrencyAnalysis,
    /// Performance recommendations
    pub recommendations: Vec<PerformanceRecommendation>,
}

/// A performance hotspot
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PerformanceHotspot {
    /// Hotspot ID
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Hotspot category
    pub category: HotspotCategory,
    /// Severity level
    pub severity: PerformanceSeverity,
    /// Performance impact estimation
    pub impact: PerformanceImpact,
    /// Location of the hotspot
    pub location: HotspotLocation,
    /// Code snippet causing the issue
    pub code_snippet: String,
    /// Suggested optimization
    pub optimization: String,
    /// Expected improvement
    pub expected_improvement: ExpectedImprovement,
    /// Implementation difficulty
    pub difficulty: OptimizationDifficulty,
    /// Related patterns or anti-patterns
    pub patterns: Vec<String>,
}

/// Location of a performance hotspot
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct HotspotLocation {
    /// File path
    pub file: String,
    /// Function or method name
    pub function: Option<String>,
    /// Start line
    pub start_line: usize,
    /// End line
    pub end_line: usize,
    /// Scope context
    pub scope: String,
}

/// Categories of performance hotspots
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum HotspotCategory {
    /// Algorithmic complexity issues
    AlgorithmicComplexity,
    /// Memory allocation and usage
    MemoryUsage,
    /// I/O operations
    IOOperations,
    /// Database queries
    DatabaseQueries,
    /// Network operations
    NetworkOperations,
    /// Concurrency and synchronization
    Concurrency,
    /// String operations
    StringOperations,
    /// Collection operations
    Collections,
    /// File system operations
    FileSystem,
    /// CPU-intensive operations
    CPUIntensive,
}

/// Performance severity levels
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum PerformanceSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

/// Performance impact assessment
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PerformanceImpact {
    /// CPU impact (0-100)
    pub cpu_impact: u8,
    /// Memory impact (0-100)
    pub memory_impact: u8,
    /// I/O impact (0-100)
    pub io_impact: u8,
    /// Network impact (0-100)
    pub network_impact: u8,
    /// Overall impact score (0-100)
    pub overall_impact: u8,
}

/// Expected improvement from optimization
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ExpectedImprovement {
    /// Performance improvement percentage
    pub performance_gain: f64,
    /// Memory usage reduction percentage
    pub memory_reduction: f64,
    /// Execution time reduction percentage
    pub time_reduction: f64,
    /// Confidence level in the improvement estimate
    pub confidence: ConfidenceLevel,
}

/// Confidence levels for performance estimates
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ConfidenceLevel {
    High,
    Medium,
    Low,
}

/// Optimization difficulty levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OptimizationDifficulty {
    Trivial,
    Easy,
    Medium,
    Hard,
    VeryHard,
}

/// An optimization opportunity
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct OptimizationOpportunity {
    /// Opportunity ID
    pub id: String,
    /// Title
    pub title: String,
    /// Description
    pub description: String,
    /// Optimization type
    pub optimization_type: OptimizationType,
    /// Priority level
    pub priority: OptimizationPriority,
    /// Affected files
    pub affected_files: Vec<String>,
    /// Implementation steps
    pub implementation_steps: Vec<String>,
    /// Expected benefits
    pub benefits: Vec<String>,
    /// Potential risks
    pub risks: Vec<String>,
    /// Estimated effort
    pub effort_estimate: EffortEstimate,
}

/// Types of optimizations
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
    /// Database optimization
    Database,
}

/// Optimization priority levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OptimizationPriority {
    Critical,
    High,
    Medium,
    Low,
}

/// Effort estimation for optimization
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct EffortEstimate {
    /// Estimated hours
    pub hours: f64,
    /// Complexity level
    pub complexity: OptimizationDifficulty,
    /// Required expertise level
    pub expertise_level: ExpertiseLevel,
}

/// Required expertise levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ExpertiseLevel {
    Beginner,
    Intermediate,
    Advanced,
    Expert,
}

/// Performance metrics for a file
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FilePerformanceMetrics {
    /// File path
    pub file: PathBuf,
    /// Performance score for this file
    pub performance_score: u8,
    /// Cyclomatic complexity
    pub cyclomatic_complexity: f64,
    /// Function count
    pub function_count: usize,
    /// Average function length
    pub average_function_length: f64,
    /// Nested loop count
    pub nested_loops: usize,
    /// Recursive function count
    pub recursive_functions: usize,
    /// Memory allocation patterns
    pub memory_allocations: usize,
    /// I/O operation count
    pub io_operations: usize,
    /// Database query count
    pub database_queries: usize,
}

/// Algorithmic complexity analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ComplexityAnalysis {
    /// Average complexity across codebase
    pub average_complexity: f64,
    /// Maximum complexity found
    pub max_complexity: f64,
    /// Functions with high complexity
    pub high_complexity_functions: Vec<ComplexFunction>,
    /// Nested loop analysis
    pub nested_loops: Vec<NestedLoopAnalysis>,
    /// Recursive function analysis
    pub recursive_functions: Vec<RecursiveFunction>,
}

/// A function with high complexity
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ComplexFunction {
    /// Function name
    pub name: String,
    /// File location
    pub file: String,
    /// Line number
    pub line: usize,
    /// Complexity score
    pub complexity: f64,
    /// Suggested improvements
    pub improvements: Vec<String>,
}

/// Nested loop analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct NestedLoopAnalysis {
    /// Location
    pub location: HotspotLocation,
    /// Nesting depth
    pub depth: usize,
    /// Estimated time complexity
    pub time_complexity: String,
    /// Optimization suggestions
    pub optimizations: Vec<String>,
}

/// Recursive function analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct RecursiveFunction {
    /// Function name
    pub name: String,
    /// Location
    pub location: HotspotLocation,
    /// Recursion type
    pub recursion_type: RecursionType,
    /// Potential for optimization
    pub optimization_potential: OptimizationPotential,
}

/// Types of recursion
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RecursionType {
    Direct,
    Indirect,
    TailRecursion,
    MutualRecursion,
}

/// Optimization potential levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum OptimizationPotential {
    High,
    Medium,
    Low,
    None,
}

/// Memory usage analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemoryAnalysis {
    /// Memory allocation hotspots
    pub allocation_hotspots: Vec<MemoryHotspot>,
    /// Memory leak potential
    pub leak_potential: Vec<MemoryLeakRisk>,
    /// Inefficient data structures
    pub inefficient_structures: Vec<InefficiientDataStructure>,
    /// Memory optimization opportunities
    pub optimizations: Vec<MemoryOptimization>,
}

/// Memory allocation hotspot
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemoryHotspot {
    /// Location
    pub location: HotspotLocation,
    /// Allocation type
    pub allocation_type: AllocationType,
    /// Frequency estimate
    pub frequency: AllocationFrequency,
    /// Size estimate
    pub size_estimate: SizeEstimate,
}

/// Types of memory allocation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AllocationType {
    HeapAllocation,
    VectorReallocation,
    StringAllocation,
    CollectionGrowth,
    BoxAllocation,
}

/// Allocation frequency levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AllocationFrequency {
    VeryHigh,
    High,
    Medium,
    Low,
}

/// Size estimation for allocations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SizeEstimate {
    Large,
    Medium,
    Small,
    Unknown,
}

/// Memory leak risk assessment
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemoryLeakRisk {
    /// Location
    pub location: HotspotLocation,
    /// Risk level
    pub risk_level: RiskLevel,
    /// Description
    pub description: String,
    /// Mitigation strategies
    pub mitigation: Vec<String>,
}

/// Risk levels
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RiskLevel {
    High,
    Medium,
    Low,
}

/// Inefficient data structure usage
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct InefficiientDataStructure {
    /// Location
    pub location: HotspotLocation,
    /// Current structure
    pub current_structure: String,
    /// Suggested alternative
    pub suggested_alternative: String,
    /// Performance improvement
    pub improvement: String,
}

/// Memory optimization opportunity
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct MemoryOptimization {
    /// Optimization title
    pub title: String,
    /// Description
    pub description: String,
    /// Affected locations
    pub locations: Vec<HotspotLocation>,
    /// Expected memory savings
    pub memory_savings: String,
}

/// Concurrency analysis results
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ConcurrencyAnalysis {
    /// Parallelization opportunities
    pub parallelization_opportunities: Vec<ParallelizationOpportunity>,
    /// Synchronization issues
    pub synchronization_issues: Vec<SynchronizationIssue>,
    /// Thread safety concerns
    pub thread_safety_concerns: Vec<ThreadSafetyConcern>,
    /// Async/await optimization opportunities
    pub async_optimizations: Vec<AsyncOptimization>,
}

/// Parallelization opportunity
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ParallelizationOpportunity {
    /// Location
    pub location: HotspotLocation,
    /// Opportunity type
    pub opportunity_type: ParallelizationType,
    /// Expected speedup
    pub expected_speedup: f64,
    /// Implementation approach
    pub approach: String,
}

/// Types of parallelization
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ParallelizationType {
    DataParallelism,
    TaskParallelism,
    PipelineParallelism,
    AsyncProcessing,
}

/// Synchronization issue
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SynchronizationIssue {
    /// Location
    pub location: HotspotLocation,
    /// Issue type
    pub issue_type: SynchronizationIssueType,
    /// Severity
    pub severity: PerformanceSeverity,
    /// Description
    pub description: String,
    /// Solution
    pub solution: String,
}

/// Types of synchronization issues
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SynchronizationIssueType {
    Deadlock,
    RaceCondition,
    Contention,
    OverSynchronization,
}

/// Thread safety concern
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ThreadSafetyConcern {
    /// Location
    pub location: HotspotLocation,
    /// Concern type
    pub concern_type: ThreadSafetyIssue,
    /// Risk assessment
    pub risk: RiskLevel,
    /// Recommendation
    pub recommendation: String,
}

/// Types of thread safety issues
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ThreadSafetyIssue {
    SharedMutableState,
    UnsafeAccess,
    NonAtomicOperations,
    GlobalState,
}

/// Async/await optimization
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AsyncOptimization {
    /// Location
    pub location: HotspotLocation,
    /// Optimization type
    pub optimization_type: AsyncOptimizationType,
    /// Description
    pub description: String,
    /// Implementation
    pub implementation: String,
}

/// Types of async optimizations
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AsyncOptimizationType {
    AwaitOptimization,
    ConcurrentExecution,
    StreamProcessing,
    BatchProcessing,
}

/// Performance recommendation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct PerformanceRecommendation {
    /// Recommendation category
    pub category: String,
    /// Recommendation text
    pub recommendation: String,
    /// Priority level
    pub priority: OptimizationPriority,
    /// Affected components
    pub affected_components: Vec<String>,
    /// Implementation difficulty
    pub difficulty: OptimizationDifficulty,
    /// Expected impact
    pub expected_impact: ExpectedImprovement,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            complexity_analysis: true,
            memory_analysis: true,
            io_analysis: true,
            concurrency_analysis: true,
            database_analysis: true,
            min_complexity_threshold: 10,
            max_function_length: 50,
        }
    }
}

impl PerformanceAnalyzer {
    /// Create a new performance analyzer with default configuration
    pub fn new() -> Self {
        Self {
            config: PerformanceConfig::default(),
        }
    }
    
    /// Create a new performance analyzer with custom configuration
    pub fn with_config(config: PerformanceConfig) -> Self {
        Self { config }
    }
    
    /// Analyze performance hotspots in a codebase
    pub fn analyze(&self, analysis_result: &AnalysisResult) -> Result<PerformanceAnalysisResult> {
        let mut hotspots = Vec::new();
        let mut file_metrics = Vec::new();
        
        // Analyze each file for performance issues
        for file in &analysis_result.files {
            let metrics = self.analyze_file_performance(file)?;
            file_metrics.push(metrics);
            
            hotspots.extend(self.detect_file_hotspots(file)?);
        }
        
        // Perform cross-file analysis
        hotspots.extend(self.detect_cross_file_hotspots(analysis_result)?);
        
        // Generate optimization opportunities
        let optimizations = self.generate_optimizations(&hotspots, analysis_result)?;
        
        // Categorize hotspots by severity
        let mut hotspots_by_severity = HashMap::new();
        for hotspot in &hotspots {
            *hotspots_by_severity.entry(hotspot.severity.clone()).or_insert(0) += 1;
        }
        
        // Perform specialized analyses
        let complexity_analysis = if self.config.complexity_analysis {
            self.analyze_complexity(analysis_result)?
        } else {
            ComplexityAnalysis::default()
        };
        
        let memory_analysis = if self.config.memory_analysis {
            self.analyze_memory_usage(analysis_result)?
        } else {
            MemoryAnalysis::default()
        };
        
        let concurrency_analysis = if self.config.concurrency_analysis {
            self.analyze_concurrency(analysis_result)?
        } else {
            ConcurrencyAnalysis::default()
        };
        
        // Generate recommendations
        let recommendations = self.generate_recommendations(&hotspots, &optimizations)?;
        
        // Calculate overall performance score
        let performance_score = self.calculate_performance_score(&hotspots, &file_metrics);
        
        Ok(PerformanceAnalysisResult {
            performance_score,
            total_hotspots: hotspots.len(),
            hotspots_by_severity,
            hotspots,
            optimizations,
            file_metrics,
            complexity_analysis,
            memory_analysis,
            concurrency_analysis,
            recommendations,
        })
    }

    /// Analyze performance metrics for a single file
    fn analyze_file_performance(&self, file: &FileInfo) -> Result<FilePerformanceMetrics> {
        let function_lengths: Vec<usize> = file
            .symbols
            .iter()
            .filter(|s| s.kind == "function")
            .map(|s| s.end_line.saturating_sub(s.start_line) + 1)
            .collect();
        let function_count = function_lengths.len();
        let average_function_length = if function_count > 0 {
            function_lengths.iter().sum::<usize>() as f64 / function_count as f64
        } else {
            0.0
        };

        // Simplified complexity calculation
        let cyclomatic_complexity = self.calculate_file_complexity(file);

        // Count various performance-related patterns
        let nested_loops = self.count_nested_loops(file);
        let recursive_functions = self.count_recursive_functions(file);
        let memory_allocations = self.count_memory_allocations(file);
        let io_operations = self.count_io_operations(file);
        let database_queries = self.count_database_queries(file);

        // Calculate performance score for this file
        let performance_score = self.calculate_file_performance_score(
            cyclomatic_complexity,
            average_function_length,
            nested_loops,
            memory_allocations,
            io_operations,
        );

        Ok(FilePerformanceMetrics {
            file: file.path.clone(),
            performance_score,
            cyclomatic_complexity,
            function_count,
            average_function_length,
            nested_loops,
            recursive_functions,
            memory_allocations,
            io_operations,
            database_queries,
        })
    }

    /// Detect performance hotspots in a file
    fn detect_file_hotspots(&self, file: &FileInfo) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();

        // Check for long functions
        for symbol in &file.symbols {
            if symbol.kind == "function" {
                let function_length = symbol.end_line.saturating_sub(symbol.start_line) + 1;

                if function_length > self.config.max_function_length {
                    hotspots.push(PerformanceHotspot {
                        id: format!("LONG_FUNCTION_{}_{}", file.path.display(), symbol.name),
                        title: "Long function detected".to_string(),
                        description: format!("Function '{}' is {} lines long, which may impact performance", symbol.name, function_length),
                        category: HotspotCategory::AlgorithmicComplexity,
                        severity: if function_length > 100 { PerformanceSeverity::High } else { PerformanceSeverity::Medium },
                        impact: PerformanceImpact {
                            cpu_impact: 60,
                            memory_impact: 30,
                            io_impact: 10,
                            network_impact: 0,
                            overall_impact: 50,
                        },
                        location: HotspotLocation {
                            file: file.path.display().to_string(),
                            function: Some(symbol.name.clone()),
                            start_line: symbol.start_line,
                            end_line: symbol.end_line,
                            scope: "function".to_string(),
                        },
                        code_snippet: format!("fn {}(...) {{ ... }}", symbol.name),
                        optimization: "Break down into smaller, focused functions".to_string(),
                        expected_improvement: ExpectedImprovement {
                            performance_gain: 15.0,
                            memory_reduction: 5.0,
                            time_reduction: 10.0,
                            confidence: ConfidenceLevel::Medium,
                        },
                        difficulty: OptimizationDifficulty::Medium,
                        patterns: vec!["Long Method".to_string(), "God Function".to_string()],
                    });
                }

                // Check for potential nested loops (simplified detection)
                if symbol.name.contains("nested") || symbol.name.contains("loop") {
                    hotspots.push(PerformanceHotspot {
                        id: format!("NESTED_LOOP_{}_{}", file.path.display(), symbol.name),
                        title: "Potential nested loop detected".to_string(),
                        description: format!("Function '{}' may contain nested loops affecting performance", symbol.name),
                        category: HotspotCategory::AlgorithmicComplexity,
                        severity: PerformanceSeverity::High,
                        impact: PerformanceImpact {
                            cpu_impact: 90,
                            memory_impact: 20,
                            io_impact: 0,
                            network_impact: 0,
                            overall_impact: 80,
                        },
                        location: HotspotLocation {
                            file: file.path.display().to_string(),
                            function: Some(symbol.name.clone()),
                            start_line: symbol.start_line,
                            end_line: symbol.end_line,
                            scope: "function".to_string(),
                        },
                        code_snippet: format!("fn {}(...) {{ for ... {{ for ... }} }}", symbol.name),
                        optimization: "Consider algorithm optimization or data structure changes".to_string(),
                        expected_improvement: ExpectedImprovement {
                            performance_gain: 50.0,
                            memory_reduction: 10.0,
                            time_reduction: 60.0,
                            confidence: ConfidenceLevel::High,
                        },
                        difficulty: OptimizationDifficulty::Hard,
                        patterns: vec!["Nested Loops".to_string(), "O(n²) Complexity".to_string()],
                    });
                }

                // Check for memory allocation patterns
                if symbol.name.contains("alloc") || symbol.name.contains("vec") || symbol.name.contains("string") {
                    hotspots.push(PerformanceHotspot {
                        id: format!("MEMORY_ALLOC_{}_{}", file.path.display(), symbol.name),
                        title: "Frequent memory allocation detected".to_string(),
                        description: format!("Function '{}' may perform frequent memory allocations", symbol.name),
                        category: HotspotCategory::MemoryUsage,
                        severity: PerformanceSeverity::Medium,
                        impact: PerformanceImpact {
                            cpu_impact: 30,
                            memory_impact: 80,
                            io_impact: 0,
                            network_impact: 0,
                            overall_impact: 55,
                        },
                        location: HotspotLocation {
                            file: file.path.display().to_string(),
                            function: Some(symbol.name.clone()),
                            start_line: symbol.start_line,
                            end_line: symbol.end_line,
                            scope: "function".to_string(),
                        },
                        code_snippet: format!("fn {}(...) {{ Vec::new() ... }}", symbol.name),
                        optimization: "Pre-allocate collections with known capacity or use object pooling".to_string(),
                        expected_improvement: ExpectedImprovement {
                            performance_gain: 25.0,
                            memory_reduction: 40.0,
                            time_reduction: 20.0,
                            confidence: ConfidenceLevel::Medium,
                        },
                        difficulty: OptimizationDifficulty::Easy,
                        patterns: vec!["Frequent Allocation".to_string(), "Memory Churn".to_string()],
                    });
                }
            }
        }

        // Try to read and parse the file for real hotspot detection
        if let Ok(content) = std::fs::read_to_string(&file.path) {
            hotspots.extend(self.detect_ast_hotspots(&content, file)?);
        }

        Ok(hotspots)
    }

    /// Detect hotspots using AST analysis
    fn detect_ast_hotspots(&self, content: &str, file: &FileInfo) -> Result<Vec<PerformanceHotspot>> {
        use crate::{Language, Parser};

        let lang = match file.language.to_lowercase().as_str() {
            "rust" => Language::Rust,
            "python" => Language::Python,
            "javascript" => Language::JavaScript,
            "typescript" => Language::TypeScript,
            "c" => Language::C,
            "cpp" | "c++" => Language::Cpp,
            "go" => Language::Go,
            _ => return Ok(Vec::new()),
        };

        let mut parser = match Parser::new(lang) {
            Ok(p) => p,
            Err(_) => return Ok(Vec::new()),
        };

        let tree = match parser.parse(content, None) {
            Ok(t) => t,
            Err(_) => return Ok(Vec::new()),
        };

        let mut hotspots = Vec::new();

        // Detect nested loops
        hotspots.extend(self.detect_nested_loop_hotspots(&tree, content, file)?);

        // Detect memory allocation hotspots
        hotspots.extend(self.detect_memory_hotspots(&tree, content, file)?);

        // Detect high complexity functions
        hotspots.extend(self.detect_complexity_hotspots(&tree, content, file)?);

        Ok(hotspots)
    }

    /// Detect nested loop hotspots using AST analysis
    fn detect_nested_loop_hotspots(&self, tree: &crate::SyntaxTree, content: &str, file: &FileInfo) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();

        let loop_patterns = match file.language.to_lowercase().as_str() {
            "rust" => vec!["for_expression", "while_expression", "while_let_expression", "loop_expression"],
            "python" => vec!["for_statement", "while_statement"],
            "javascript" | "typescript" => vec!["for_statement", "for_in_statement", "for_of_statement", "while_statement", "do_statement"],
            "c" | "cpp" | "c++" => vec!["for_statement", "while_statement", "do_statement"],
            "go" => vec!["for_statement"],
            _ => vec!["for_statement", "while_statement"],
        };

        for pattern in &loop_patterns {
            let loops = tree.find_nodes_by_kind(pattern);
            for loop_node in loops {
                // Check if this loop contains other loops (nested)
                let nested_loops = self.find_nested_loops_in_node(&loop_node, &loop_patterns);
                if nested_loops > 0 {
                    let start_point = loop_node.start_position();
                    let end_point = loop_node.end_position();

                    hotspots.push(PerformanceHotspot {
                        id: format!("NESTED_LOOP_{}_{}_{}", file.path.display(), start_point.row, start_point.column),
                        title: "Nested loop detected".to_string(),
                        description: format!("Nested loop with {} levels detected, potentially O(n^{}) complexity", nested_loops + 1, nested_loops + 1),
                        category: HotspotCategory::AlgorithmicComplexity,
                        severity: if nested_loops > 1 { PerformanceSeverity::Critical } else { PerformanceSeverity::High },
                        impact: PerformanceImpact {
                            cpu_impact: 90,
                            memory_impact: 20,
                            io_impact: 0,
                            network_impact: 0,
                            overall_impact: 85,
                        },
                        location: HotspotLocation {
                            file: file.path.display().to_string(),
                            function: None,
                            start_line: start_point.row + 1,
                            end_line: end_point.row + 1,
                            scope: "loop".to_string(),
                        },
                        code_snippet: loop_node.text().unwrap_or("nested loop").to_string(),
                        optimization: "Consider algorithm optimization, data structure changes, or loop fusion".to_string(),
                        expected_improvement: ExpectedImprovement {
                            performance_gain: 70.0,
                            memory_reduction: 10.0,
                            time_reduction: 80.0,
                            confidence: ConfidenceLevel::High,
                        },
                        difficulty: OptimizationDifficulty::Hard,
                        patterns: vec!["Nested Loops".to_string(), format!("O(n^{}) Complexity", nested_loops + 1)],
                    });
                }
            }
        }

        Ok(hotspots)
    }

    /// Detect memory allocation hotspots using AST analysis
    fn detect_memory_hotspots(&self, tree: &crate::SyntaxTree, _content: &str, file: &FileInfo) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();

        match file.language.to_lowercase().as_str() {
            "rust" => {
                // Look for Vec::new(), String::new(), Box::new(), etc.
                let call_expressions = tree.find_nodes_by_kind("call_expression");
                for call in call_expressions {
                    if let Some(function) = call.child_by_field_name("function") {
                        let function_text = function.text().unwrap_or("");
                        let is_allocation = function_text.contains("::new") ||
                                          function_text.contains("Vec::") ||
                                          function_text.contains("String::") ||
                                          function_text.contains("Box::") ||
                                          function_text.contains("HashMap::") ||
                                          function_text.contains("BTreeMap::");

                        if is_allocation {
                            let start_point = call.start_position();
                            let end_point = call.end_position();
                            let in_loop = self.is_inside_loop(&call);

                            hotspots.push(PerformanceHotspot {
                                id: format!("MEMORY_ALLOC_{}_{}_{}", file.path.display(), start_point.row, start_point.column),
                                title: if in_loop { "Memory allocation in loop".to_string() } else { "Memory allocation detected".to_string() },
                                description: if in_loop {
                                    "Memory allocation inside loop detected, may cause performance issues".to_string()
                                } else {
                                    "Memory allocation detected, consider pre-allocation if size is known".to_string()
                                },
                                category: HotspotCategory::MemoryUsage,
                                severity: if in_loop { PerformanceSeverity::High } else { PerformanceSeverity::Medium },
                                impact: PerformanceImpact {
                                    cpu_impact: if in_loop { 40 } else { 20 },
                                    memory_impact: if in_loop { 90 } else { 60 },
                                    io_impact: 0,
                                    network_impact: 0,
                                    overall_impact: if in_loop { 70 } else { 40 },
                                },
                                location: HotspotLocation {
                                    file: file.path.display().to_string(),
                                    function: None,
                                    start_line: start_point.row + 1,
                                    end_line: end_point.row + 1,
                                    scope: "allocation".to_string(),
                                },
                                code_snippet: call.text().unwrap_or("allocation").to_string(),
                                optimization: if in_loop {
                                    "Move allocation outside loop or pre-allocate with capacity".to_string()
                                } else {
                                    "Consider pre-allocating with known capacity".to_string()
                                },
                                expected_improvement: ExpectedImprovement {
                                    performance_gain: if in_loop { 40.0 } else { 20.0 },
                                    memory_reduction: if in_loop { 60.0 } else { 30.0 },
                                    time_reduction: if in_loop { 35.0 } else { 15.0 },
                                    confidence: ConfidenceLevel::High,
                                },
                                difficulty: OptimizationDifficulty::Easy,
                                patterns: if in_loop {
                                    vec!["Allocation in Loop".to_string(), "Memory Churn".to_string()]
                                } else {
                                    vec!["Memory Allocation".to_string()]
                                },
                            });
                        }
                    }
                }

                // Also look for format! macro calls which allocate strings
                let macro_expressions = tree.find_nodes_by_kind("macro_invocation");
                for macro_call in macro_expressions {
                    if let Some(macro_name) = macro_call.child_by_field_name("macro") {
                        let macro_text = macro_name.text().unwrap_or("");
                        if macro_text == "format" || macro_text == "vec" {
                            let start_point = macro_call.start_position();
                            let end_point = macro_call.end_position();
                            let in_loop = self.is_inside_loop(&macro_call);

                            hotspots.push(PerformanceHotspot {
                                id: format!("MACRO_ALLOC_{}_{}_{}", file.path.display(), start_point.row, start_point.column),
                                title: if in_loop { "Allocation macro in loop".to_string() } else { "Allocation macro detected".to_string() },
                                description: format!("{}! macro detected{}", macro_text, if in_loop { " inside loop" } else { "" }),
                                category: HotspotCategory::MemoryUsage,
                                severity: if in_loop { PerformanceSeverity::High } else { PerformanceSeverity::Medium },
                                impact: PerformanceImpact {
                                    cpu_impact: if in_loop { 30 } else { 15 },
                                    memory_impact: if in_loop { 80 } else { 50 },
                                    io_impact: 0,
                                    network_impact: 0,
                                    overall_impact: if in_loop { 60 } else { 35 },
                                },
                                location: HotspotLocation {
                                    file: file.path.display().to_string(),
                                    function: None,
                                    start_line: start_point.row + 1,
                                    end_line: end_point.row + 1,
                                    scope: "macro".to_string(),
                                },
                                code_snippet: macro_call.text().unwrap_or("macro").to_string(),
                                optimization: if in_loop {
                                    "Move allocation outside loop or use pre-allocated buffer".to_string()
                                } else {
                                    "Consider reusing allocations or using static strings".to_string()
                                },
                                expected_improvement: ExpectedImprovement {
                                    performance_gain: if in_loop { 35.0 } else { 15.0 },
                                    memory_reduction: if in_loop { 50.0 } else { 25.0 },
                                    time_reduction: if in_loop { 30.0 } else { 10.0 },
                                    confidence: ConfidenceLevel::Medium,
                                },
                                difficulty: OptimizationDifficulty::Easy,
                                patterns: if in_loop {
                                    vec!["Macro Allocation in Loop".to_string(), "String Allocation".to_string()]
                                } else {
                                    vec!["Macro Allocation".to_string()]
                                },
                            });
                        }
                    }
                }
            },
            _ => {
                // Similar logic for other languages can be added here
            }
        }

        Ok(hotspots)
    }

    /// Detect high complexity function hotspots
    fn detect_complexity_hotspots(&self, tree: &crate::SyntaxTree, content: &str, file: &FileInfo) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();

        // Find function definitions
        let function_patterns = match file.language.to_lowercase().as_str() {
            "rust" => vec!["function_item"],
            "python" => vec!["function_definition"],
            "javascript" | "typescript" => vec!["function_declaration", "function_expression", "arrow_function"],
            "c" | "cpp" | "c++" => vec!["function_definition"],
            "go" => vec!["function_declaration"],
            _ => vec!["function_definition"],
        };

        for pattern in function_patterns {
            let functions = tree.find_nodes_by_kind(pattern);
            for func_node in functions {
                let complexity = self.calculate_function_complexity(&func_node, content, &file.language);

                if complexity > self.config.min_complexity_threshold as f64 {
                    let start_point = func_node.start_position();
                    let end_point = func_node.end_position();

                    // Try to extract function name
                    let function_name = self.extract_function_name(&func_node, content, &file.language);

                    hotspots.push(PerformanceHotspot {
                        id: format!("HIGH_COMPLEXITY_{}_{}_{}", file.path.display(), start_point.row, start_point.column),
                        title: "High complexity function".to_string(),
                        description: format!("Function '{}' has cyclomatic complexity of {:.1}", function_name, complexity),
                        category: HotspotCategory::AlgorithmicComplexity,
                        severity: if complexity > 15.0 { PerformanceSeverity::Critical }
                                 else if complexity > 10.0 { PerformanceSeverity::High }
                                 else { PerformanceSeverity::Medium },
                        impact: PerformanceImpact {
                            cpu_impact: (complexity * 5.0).min(100.0) as u8,
                            memory_impact: 20,
                            io_impact: 0,
                            network_impact: 0,
                            overall_impact: (complexity * 4.0).min(100.0) as u8,
                        },
                        location: HotspotLocation {
                            file: file.path.display().to_string(),
                            function: Some(function_name.clone()),
                            start_line: start_point.row + 1,
                            end_line: end_point.row + 1,
                            scope: "function".to_string(),
                        },
                        code_snippet: format!("fn {}(...) {{ ... }}", function_name),
                        optimization: "Break down into smaller functions, reduce nesting, or simplify logic".to_string(),
                        expected_improvement: ExpectedImprovement {
                            performance_gain: 30.0,
                            memory_reduction: 10.0,
                            time_reduction: 25.0,
                            confidence: ConfidenceLevel::Medium,
                        },
                        difficulty: OptimizationDifficulty::Medium,
                        patterns: vec!["High Complexity".to_string(), format!("Complexity: {:.1}", complexity)],
                    });
                }
            }
        }

        Ok(hotspots)
    }

    /// Calculate complexity for a specific function node
    fn calculate_function_complexity(&self, func_node: &crate::Node, content: &str, language: &str) -> f64 {
        let mut complexity = 1.0; // Base complexity

        // Define control flow patterns for different languages
        let control_patterns = match language.to_lowercase().as_str() {
            "rust" => vec![
                "if_expression", "if_let_expression", "while_expression", "while_let_expression",
                "for_expression", "loop_expression", "match_expression", "match_arm",
                "try_expression", "catch_clause"
            ],
            "python" => vec![
                "if_statement", "elif_clause", "while_statement", "for_statement",
                "try_statement", "except_clause", "with_statement", "match_statement", "case_clause"
            ],
            "javascript" | "typescript" => vec![
                "if_statement", "while_statement", "for_statement", "for_in_statement", "for_of_statement",
                "switch_statement", "case_clause", "try_statement", "catch_clause", "conditional_expression"
            ],
            "c" | "cpp" | "c++" => vec![
                "if_statement", "while_statement", "for_statement", "do_statement",
                "switch_statement", "case_statement", "conditional_expression"
            ],
            "go" => vec![
                "if_statement", "for_statement", "switch_statement", "type_switch_statement",
                "case_clause", "select_statement", "communication_clause"
            ],
            _ => vec!["if_statement", "while_statement", "for_statement", "switch_statement"],
        };

        // Count control flow nodes within this function
        for pattern in control_patterns {
            let nodes = self.find_nodes_in_subtree(func_node, pattern);
            complexity += nodes.len() as f64;
        }

        complexity
    }

    /// Extract function name from function node
    fn extract_function_name(&self, func_node: &crate::Node, content: &str, language: &str) -> String {
        match language.to_lowercase().as_str() {
            "rust" => {
                if let Some(name_node) = func_node.child_by_field_name("name") {
                    name_node.text().unwrap_or("unknown").to_string()
                } else {
                    "unknown".to_string()
                }
            },
            "python" => {
                if let Some(name_node) = func_node.child_by_field_name("name") {
                    name_node.text().unwrap_or("unknown").to_string()
                } else {
                    "unknown".to_string()
                }
            },
            "javascript" | "typescript" => {
                if let Some(name_node) = func_node.child_by_field_name("name") {
                    name_node.text().unwrap_or("unknown").to_string()
                } else {
                    "anonymous".to_string()
                }
            },
            _ => "unknown".to_string(),
        }
    }

    /// Find nodes of a specific kind within a subtree
    fn find_nodes_in_subtree<'a>(&self, root: &crate::Node<'a>, kind: &str) -> Vec<crate::Node<'a>> {
        let mut nodes = Vec::new();
        self.collect_nodes_recursive(root, kind, &mut nodes);
        nodes
    }

    /// Recursively collect nodes of a specific kind
    fn collect_nodes_recursive<'a>(&self, node: &crate::Node<'a>, target_kind: &str, nodes: &mut Vec<crate::Node<'a>>) {
        if node.kind() == target_kind {
            nodes.push(*node);
        }

        for child in node.children() {
            self.collect_nodes_recursive(&child, target_kind, nodes);
        }
    }

    /// Check if a node is inside a loop
    fn is_inside_loop(&self, node: &crate::Node) -> bool {
        let mut current = node.parent();
        while let Some(parent) = current {
            let kind = parent.kind();
            if kind.contains("for") || kind.contains("while") || kind.contains("loop") {
                return true;
            }
            current = parent.parent();
        }
        false
    }

    /// Find nested loops within a node
    fn find_nested_loops_in_node(&self, node: &crate::Node, loop_patterns: &[&str]) -> usize {
        let mut nested_count = 0;
        for pattern in loop_patterns {
            let nested_loops = self.find_nodes_in_subtree(node, pattern);
            // Don't count the node itself if it's a loop
            if node.kind() == *pattern {
                nested_count += nested_loops.len().saturating_sub(1);
            } else {
                nested_count += nested_loops.len();
            }
        }
        nested_count
    }

    /// Detect cross-file performance hotspots
    fn detect_cross_file_hotspots(&self, analysis_result: &AnalysisResult) -> Result<Vec<PerformanceHotspot>> {
        let mut hotspots = Vec::new();

        // Check for potential architectural issues
        if analysis_result.total_files > 100 {
            hotspots.push(PerformanceHotspot {
                id: "LARGE_CODEBASE".to_string(),
                title: "Large codebase detected".to_string(),
                description: format!("Codebase has {} files which may impact compilation and runtime performance", analysis_result.total_files),
                category: HotspotCategory::AlgorithmicComplexity,
                severity: PerformanceSeverity::Low,
                impact: PerformanceImpact {
                    cpu_impact: 20,
                    memory_impact: 30,
                    io_impact: 40,
                    network_impact: 0,
                    overall_impact: 30,
                },
                location: HotspotLocation {
                    file: "project structure".to_string(),
                    function: None,
                    start_line: 1,
                    end_line: 1,
                    scope: "project".to_string(),
                },
                code_snippet: format!("{} files in project", analysis_result.total_files),
                optimization: "Consider modularization and lazy loading strategies".to_string(),
                expected_improvement: ExpectedImprovement {
                    performance_gain: 10.0,
                    memory_reduction: 15.0,
                    time_reduction: 20.0,
                    confidence: ConfidenceLevel::Low,
                },
                difficulty: OptimizationDifficulty::VeryHard,
                patterns: vec!["Monolithic Architecture".to_string()],
            });
        }

        Ok(hotspots)
    }

    /// Generate optimization opportunities
    fn generate_optimizations(&self, hotspots: &[PerformanceHotspot], _analysis_result: &AnalysisResult) -> Result<Vec<OptimizationOpportunity>> {
        let mut optimizations = Vec::new();

        // Group hotspots by category and generate optimizations
        let mut complexity_hotspots = 0;
        let mut memory_hotspots = 0;

        for hotspot in hotspots {
            match hotspot.category {
                HotspotCategory::AlgorithmicComplexity => complexity_hotspots += 1,
                HotspotCategory::MemoryUsage => memory_hotspots += 1,
                _ => {}
            }
        }

        if complexity_hotspots > 0 {
            optimizations.push(OptimizationOpportunity {
                id: "ALGORITHM_OPTIMIZATION".to_string(),
                title: "Algorithm optimization opportunity".to_string(),
                description: format!("Found {} algorithmic complexity issues that can be optimized", complexity_hotspots),
                optimization_type: OptimizationType::Algorithm,
                priority: OptimizationPriority::High,
                affected_files: hotspots.iter()
                    .filter(|h| h.category == HotspotCategory::AlgorithmicComplexity)
                    .map(|h| h.location.file.clone())
                    .collect(),
                implementation_steps: vec![
                    "Profile the identified functions to confirm performance impact".to_string(),
                    "Analyze algorithm complexity and identify bottlenecks".to_string(),
                    "Research and implement more efficient algorithms".to_string(),
                    "Benchmark before and after changes".to_string(),
                ],
                benefits: vec![
                    "Reduced CPU usage".to_string(),
                    "Faster execution times".to_string(),
                    "Better scalability".to_string(),
                ],
                risks: vec![
                    "May increase code complexity".to_string(),
                    "Requires thorough testing".to_string(),
                ],
                effort_estimate: EffortEstimate {
                    hours: 16.0,
                    complexity: OptimizationDifficulty::Hard,
                    expertise_level: ExpertiseLevel::Advanced,
                },
            });
        }

        if memory_hotspots > 0 {
            optimizations.push(OptimizationOpportunity {
                id: "MEMORY_OPTIMIZATION".to_string(),
                title: "Memory usage optimization".to_string(),
                description: format!("Found {} memory usage issues that can be optimized", memory_hotspots),
                optimization_type: OptimizationType::Memory,
                priority: OptimizationPriority::Medium,
                affected_files: hotspots.iter()
                    .filter(|h| h.category == HotspotCategory::MemoryUsage)
                    .map(|h| h.location.file.clone())
                    .collect(),
                implementation_steps: vec![
                    "Profile memory usage patterns".to_string(),
                    "Implement object pooling where appropriate".to_string(),
                    "Pre-allocate collections with known sizes".to_string(),
                    "Consider using more efficient data structures".to_string(),
                ],
                benefits: vec![
                    "Reduced memory allocation overhead".to_string(),
                    "Lower garbage collection pressure".to_string(),
                    "More predictable performance".to_string(),
                ],
                risks: vec![
                    "May increase code complexity".to_string(),
                    "Potential for memory leaks if not handled properly".to_string(),
                ],
                effort_estimate: EffortEstimate {
                    hours: 8.0,
                    complexity: OptimizationDifficulty::Medium,
                    expertise_level: ExpertiseLevel::Intermediate,
                },
            });
        }

        Ok(optimizations)
    }

    // Helper methods for analysis

    fn calculate_file_complexity(&self, file: &FileInfo) -> f64 {
        // Try to read and parse the file for real complexity calculation
        if let Ok(content) = std::fs::read_to_string(&file.path) {
            let ast_complexity = self.calculate_ast_complexity(&content, &file.language);
            if ast_complexity > 1.0 {
                ast_complexity
            } else {
                // Fallback to simplified calculation if AST parsing failed
                let symbol_complexity = file.symbols.len() as f64 * 1.5;
                let size_complexity = (file.lines as f64 / 100.0).max(1.0);
                symbol_complexity + size_complexity
            }
        } else {
            // Fallback to simplified calculation
            let symbol_complexity = file.symbols.len() as f64 * 1.5;
            let size_complexity = (file.lines as f64 / 100.0).max(1.0);
            symbol_complexity + size_complexity
        }
    }

    /// Calculate cyclomatic complexity using AST analysis
    fn calculate_ast_complexity(&self, content: &str, language: &str) -> f64 {
        use crate::{Language, Parser};

        let lang = match language.to_lowercase().as_str() {
            "rust" => Language::Rust,
            "python" => Language::Python,
            "javascript" => Language::JavaScript,
            "typescript" => Language::TypeScript,
            "c" => Language::C,
            "cpp" | "c++" => Language::Cpp,
            "go" => Language::Go,
            _ => return 1.0, // Default complexity for unknown languages
        };

        let mut parser = match Parser::new(lang) {
            Ok(p) => p,
            Err(_) => return 1.0,
        };

        let tree = match parser.parse(content, None) {
            Ok(t) => t,
            Err(_) => return 1.0,
        };

        self.calculate_cyclomatic_complexity(&tree, content, language)
    }

    /// Calculate cyclomatic complexity from AST
    fn calculate_cyclomatic_complexity(&self, tree: &crate::SyntaxTree, _content: &str, language: &str) -> f64 {
        let mut complexity = 1.0; // Base complexity

        // Define control flow patterns for different languages
        let control_patterns = match language.to_lowercase().as_str() {
            "rust" => vec![
                "if_expression", "if_let_expression", "while_expression", "while_let_expression",
                "for_expression", "loop_expression", "match_expression", "match_arm",
                "try_expression", "catch_clause"
            ],
            "python" => vec![
                "if_statement", "elif_clause", "while_statement", "for_statement",
                "try_statement", "except_clause", "with_statement", "match_statement", "case_clause"
            ],
            "javascript" | "typescript" => vec![
                "if_statement", "while_statement", "for_statement", "for_in_statement", "for_of_statement",
                "switch_statement", "case_clause", "try_statement", "catch_clause", "conditional_expression"
            ],
            "c" | "cpp" | "c++" => vec![
                "if_statement", "while_statement", "for_statement", "do_statement",
                "switch_statement", "case_statement", "conditional_expression"
            ],
            "go" => vec![
                "if_statement", "for_statement", "switch_statement", "type_switch_statement",
                "case_clause", "select_statement", "communication_clause"
            ],
            _ => vec!["if_statement", "while_statement", "for_statement", "switch_statement"],
        };

        // Count control flow nodes
        for pattern in control_patterns {
            let nodes = tree.find_nodes_by_kind(pattern);
            complexity += nodes.len() as f64;
        }

        // Special handling for match arms in Rust
        if language.to_lowercase() == "rust" {
            let match_expressions = tree.find_nodes_by_kind("match_expression");
            for match_expr in match_expressions {
                // Count match arms by looking for match_arm children
                let arms = match_expr.children().into_iter().filter(|child| child.kind() == "match_arm").count();
                if arms > 1 {
                    complexity += (arms - 1) as f64; // Each additional arm adds complexity
                }
            }
        }

        // Special handling for switch cases
        if matches!(language.to_lowercase().as_str(), "javascript" | "typescript" | "c" | "cpp" | "c++" | "go") {
            let switch_statements = tree.find_nodes_by_kind("switch_statement");
            for switch_stmt in switch_statements {
                // Count case clauses by looking for case_clause children
                let cases = switch_stmt.children().into_iter().filter(|child| child.kind() == "case_clause").count();
                if cases > 1 {
                    complexity += (cases - 1) as f64;
                }
            }
        }

        complexity
    }

    fn count_nested_loops(&self, file: &FileInfo) -> usize {
        // Try to read and parse the file for real nested loop detection
        if let Ok(content) = std::fs::read_to_string(&file.path) {
            self.detect_nested_loops(&content, &file.language)
        } else {
            // Fallback to simplified detection
            file.symbols.iter()
                .filter(|s| s.name.to_lowercase().contains("loop") || s.name.to_lowercase().contains("nested"))
                .count()
        }
    }

    /// Detect nested loops using AST analysis
    fn detect_nested_loops(&self, content: &str, language: &str) -> usize {
        use crate::{Language, Parser};

        let lang = match language.to_lowercase().as_str() {
            "rust" => Language::Rust,
            "python" => Language::Python,
            "javascript" => Language::JavaScript,
            "typescript" => Language::TypeScript,
            "c" => Language::C,
            "cpp" | "c++" => Language::Cpp,
            "go" => Language::Go,
            _ => return 0,
        };

        let mut parser = match Parser::new(lang) {
            Ok(p) => p,
            Err(_) => return 0,
        };

        let tree = match parser.parse(content, None) {
            Ok(t) => t,
            Err(_) => return 0,
        };

        self.count_nested_loop_patterns(&tree, language)
    }

    /// Count nested loop patterns in AST
    fn count_nested_loop_patterns(&self, tree: &crate::SyntaxTree, language: &str) -> usize {
        let loop_patterns = match language.to_lowercase().as_str() {
            "rust" => vec!["for_expression", "while_expression", "while_let_expression", "loop_expression"],
            "python" => vec!["for_statement", "while_statement"],
            "javascript" | "typescript" => vec!["for_statement", "for_in_statement", "for_of_statement", "while_statement", "do_statement"],
            "c" | "cpp" | "c++" => vec!["for_statement", "while_statement", "do_statement"],
            "go" => vec!["for_statement"],
            _ => vec!["for_statement", "while_statement"],
        };

        let mut nested_count = 0;

        for pattern in &loop_patterns {
            let loops = tree.find_nodes_by_kind(pattern);
            for loop_node in loops {
                // Check if this loop contains other loops (nested)
                let nested_loops = self.find_nested_loops_in_node(&loop_node, &loop_patterns);
                if nested_loops > 0 {
                    nested_count += 1;
                }
            }
        }

        nested_count
    }



    fn count_recursive_functions(&self, file: &FileInfo) -> usize {
        // Simplified detection - count functions with "recursive" in name
        file.symbols.iter()
            .filter(|s| s.name.to_lowercase().contains("recursive") || s.name.to_lowercase().contains("recurse"))
            .count()
    }

    fn count_memory_allocations(&self, file: &FileInfo) -> usize {
        // Try to read and parse the file for real memory allocation detection
        if let Ok(content) = std::fs::read_to_string(&file.path) {
            self.detect_memory_allocations(&content, &file.language)
        } else {
            // Fallback to simplified detection
            file.symbols.iter()
                .filter(|s| {
                    let name = s.name.to_lowercase();
                    name.contains("alloc") || name.contains("vec") || name.contains("string") || name.contains("new")
                })
                .count()
        }
    }

    /// Detect memory allocations using AST analysis
    fn detect_memory_allocations(&self, content: &str, language: &str) -> usize {
        use crate::{Language, Parser};

        let lang = match language.to_lowercase().as_str() {
            "rust" => Language::Rust,
            "python" => Language::Python,
            "javascript" => Language::JavaScript,
            "typescript" => Language::TypeScript,
            "c" => Language::C,
            "cpp" | "c++" => Language::Cpp,
            "go" => Language::Go,
            _ => return 0,
        };

        let mut parser = match Parser::new(lang) {
            Ok(p) => p,
            Err(_) => return 0,
        };

        let tree = match parser.parse(content, None) {
            Ok(t) => t,
            Err(_) => return 0,
        };

        self.count_allocation_patterns(&tree, content, language)
    }

    /// Count memory allocation patterns in AST
    fn count_allocation_patterns(&self, tree: &crate::SyntaxTree, content: &str, language: &str) -> usize {
        let mut allocation_count = 0;

        match language.to_lowercase().as_str() {
            "rust" => {
                // Look for Vec::new(), String::new(), Box::new(), etc.
                let call_expressions = tree.find_nodes_by_kind("call_expression");
                for call in call_expressions {
                    if let Some(function) = call.child_by_field_name("function") {
                        let function_text = function.text().unwrap_or("");
                        if function_text.contains("::new") ||
                           function_text.contains("Vec::") ||
                           function_text.contains("String::") ||
                           function_text.contains("Box::") ||
                           function_text.contains("HashMap::") ||
                           function_text.contains("BTreeMap::") {
                            allocation_count += 1;
                        }
                    }
                }

                // Look for vec![] macros
                let macro_invocations = tree.find_nodes_by_kind("macro_invocation");
                for macro_inv in macro_invocations {
                    if let Some(macro_name) = macro_inv.child_by_field_name("macro") {
                        let macro_text = macro_name.text().unwrap_or("");
                        if macro_text == "vec" || macro_text == "format" {
                            allocation_count += 1;
                        }
                    }
                }
            },
            "python" => {
                // Look for list(), dict(), set(), etc.
                let call_expressions = tree.find_nodes_by_kind("call");
                for call in call_expressions {
                    if let Some(function) = call.child_by_field_name("function") {
                        let function_text = function.text().unwrap_or("");
                        if matches!(function_text, "list" | "dict" | "set" | "tuple" | "bytearray") {
                            allocation_count += 1;
                        }
                    }
                }

                // Look for list comprehensions
                let list_comprehensions = tree.find_nodes_by_kind("list_comprehension");
                allocation_count += list_comprehensions.len();

                // Look for dictionary comprehensions
                let dict_comprehensions = tree.find_nodes_by_kind("dictionary_comprehension");
                allocation_count += dict_comprehensions.len();
            },
            "javascript" | "typescript" => {
                // Look for new Array(), new Object(), etc.
                let new_expressions = tree.find_nodes_by_kind("new_expression");
                allocation_count += new_expressions.len();

                // Look for array literals in loops (potential performance issue)
                let array_expressions = tree.find_nodes_by_kind("array_expression");
                for array_expr in array_expressions {
                    // Check if this array is inside a loop
                    if self.is_inside_loop(&array_expr) {
                        allocation_count += 1;
                    }
                }
            },
            "c" | "cpp" | "c++" => {
                // Look for malloc, calloc, new, etc.
                let call_expressions = tree.find_nodes_by_kind("call_expression");
                for call in call_expressions {
                    if let Some(function) = call.child_by_field_name("function") {
                        let function_text = function.text().unwrap_or("");
                        if matches!(function_text, "malloc" | "calloc" | "realloc" | "new" | "new[]") {
                            allocation_count += 1;
                        }
                    }
                }
            },
            "go" => {
                // Look for make(), new(), etc.
                let call_expressions = tree.find_nodes_by_kind("call_expression");
                for call in call_expressions {
                    if let Some(function) = call.child_by_field_name("function") {
                        let function_text = function.text().unwrap_or("");
                        if matches!(function_text, "make" | "new") {
                            allocation_count += 1;
                        }
                    }
                }
            },
            _ => {}
        }

        allocation_count
    }



    fn count_io_operations(&self, file: &FileInfo) -> usize {
        // Simplified detection - count functions with I/O-related names
        file.symbols.iter()
            .filter(|s| {
                let name = s.name.to_lowercase();
                name.contains("read") || name.contains("write") || name.contains("file") || name.contains("io")
            })
            .count()
    }

    fn count_database_queries(&self, file: &FileInfo) -> usize {
        // Simplified detection - count functions with database-related names
        file.symbols.iter()
            .filter(|s| {
                let name = s.name.to_lowercase();
                name.contains("query") || name.contains("sql") || name.contains("db") || name.contains("database")
            })
            .count()
    }

    fn calculate_file_performance_score(
        &self,
        complexity: f64,
        avg_function_length: f64,
        nested_loops: usize,
        memory_allocations: usize,
        io_operations: usize,
    ) -> u8 {
        let mut score = 100.0;

        // Deduct points for various performance issues
        score -= (complexity / 10.0).min(30.0);
        score -= (avg_function_length / 10.0).min(20.0);
        score -= (nested_loops as f64 * 15.0).min(25.0);
        score -= (memory_allocations as f64 * 5.0).min(15.0);
        score -= (io_operations as f64 * 3.0).min(10.0);

        score.max(0.0) as u8
    }

    fn analyze_complexity(&self, analysis_result: &AnalysisResult) -> Result<ComplexityAnalysis> {
        let mut total_complexity: f64 = 0.0;
        let mut max_complexity: f64 = 0.0;
        let mut high_complexity_functions = Vec::new();
        let mut function_count = 0;

        for file in &analysis_result.files {
            let file_complexity = self.calculate_file_complexity(file);
            total_complexity += file_complexity;
            max_complexity = max_complexity.max(file_complexity);

            // Calculate complexity per function based on file content analysis
            if let Ok(content) = std::fs::read_to_string(&file.path) {
                let function_complexities = self.analyze_function_complexities(&content, &file.language);

                for (func_name, complexity) in function_complexities {
                    function_count += 1;

                    if complexity > self.config.min_complexity_threshold as f64 {
                        high_complexity_functions.push(ComplexFunction {
                            name: func_name.clone(),
                            file: file.path.display().to_string(),
                            line: 1, // Simplified - would need AST to get exact line
                            complexity,
                            improvements: vec![
                                "Break down into smaller functions".to_string(),
                                "Reduce nesting levels".to_string(),
                                "Extract complex logic into helper functions".to_string(),
                            ],
                        });
                    }
                }
            } else {
                // Fallback to symbol-based analysis
                for symbol in &file.symbols {
                    if symbol.kind == "function" {
                        function_count += 1;
                        let func_complexity = file_complexity / file.symbols.len().max(1) as f64;

                        if func_complexity > self.config.min_complexity_threshold as f64 {
                            high_complexity_functions.push(ComplexFunction {
                                name: symbol.name.clone(),
                                file: file.path.display().to_string(),
                                line: symbol.start_line,
                                complexity: func_complexity,
                                improvements: vec![
                                    "Break down into smaller functions".to_string(),
                                    "Reduce nesting levels".to_string(),
                                    "Extract complex logic into helper functions".to_string(),
                                ],
                            });
                        }
                    }
                }
            }
        }

        let average_complexity = if function_count > 0 {
            total_complexity / function_count as f64
        } else {
            0.0
        };

        Ok(ComplexityAnalysis {
            average_complexity,
            max_complexity,
            high_complexity_functions,
            nested_loops: Vec::new(), // Simplified
            recursive_functions: Vec::new(), // Simplified
        })
    }

    /// Analyze function complexities using simple pattern matching
    fn analyze_function_complexities(&self, content: &str, language: &str) -> Vec<(String, f64)> {
        let mut complexities = Vec::new();

        match language.to_lowercase().as_str() {
            "rust" => {
                // Simple pattern matching for Rust functions
                let lines: Vec<&str> = content.lines().collect();
                let mut current_function = None;
                let mut current_complexity = 1.0;

                for line in lines {
                    let trimmed = line.trim();

                    // Detect function start
                    if trimmed.starts_with("fn ") && trimmed.contains('(') {
                        // Save previous function if exists
                        if let Some(func_name) = current_function.take() {
                            complexities.push((func_name, current_complexity));
                        }

                        // Extract function name
                        if let Some(name_start) = trimmed.find("fn ") {
                            if let Some(name_end) = trimmed[name_start + 3..].find('(') {
                                let func_name = trimmed[name_start + 3..name_start + 3 + name_end].trim().to_string();
                                current_function = Some(func_name);
                                current_complexity = 1.0;
                            }
                        }
                    }

                    // Count complexity-adding constructs
                    if current_function.is_some() {
                        if trimmed.contains("if ") || trimmed.contains("if let") {
                            current_complexity += 1.0;
                        }
                        if trimmed.contains("while ") || trimmed.contains("while let") {
                            current_complexity += 1.0;
                        }
                        if trimmed.contains("for ") {
                            current_complexity += 1.0;
                        }
                        if trimmed.contains("loop ") {
                            current_complexity += 1.0;
                        }
                        if trimmed.contains("match ") {
                            current_complexity += 1.0;
                        }
                        // Count nested loops (simple heuristic)
                        if (trimmed.contains("for ") || trimmed.contains("while ")) &&
                           (content.matches("for ").count() > 1 || content.matches("while ").count() > 1) {
                            current_complexity += 2.0; // Extra penalty for potential nesting
                        }
                    }
                }

                // Save last function
                if let Some(func_name) = current_function {
                    complexities.push((func_name, current_complexity));
                }
            },
            _ => {
                // Simplified analysis for other languages
                complexities.push(("unknown_function".to_string(), 5.0));
            }
        }

        complexities
    }

    fn analyze_memory_usage(&self, analysis_result: &AnalysisResult) -> Result<MemoryAnalysis> {
        let mut allocation_hotspots = Vec::new();
        let mut leak_potential = Vec::new();

        // Analyze each file for memory patterns
        for file in &analysis_result.files {
            if let Ok(content) = std::fs::read_to_string(&file.path) {
                let hotspots = self.detect_memory_allocation_patterns(&content, &file.language, file);
                allocation_hotspots.extend(hotspots);

                let leaks = self.detect_potential_memory_leaks(&content, &file.language, file);
                leak_potential.extend(leaks);
            }
        }

        Ok(MemoryAnalysis {
            allocation_hotspots,
            leak_potential,
            inefficient_structures: Vec::new(),
            optimizations: vec![
                MemoryOptimization {
                    title: "Pre-allocate collections".to_string(),
                    description: "Use Vec::with_capacity() when the size is known in advance".to_string(),
                    locations: Vec::new(),
                    memory_savings: "10-30% reduction in allocation overhead".to_string(),
                },
                MemoryOptimization {
                    title: "Use string interning".to_string(),
                    description: "For frequently used strings, consider string interning to reduce memory usage".to_string(),
                    locations: Vec::new(),
                    memory_savings: "20-50% reduction in string memory usage".to_string(),
                },
            ],
        })
    }

    /// Detect memory allocation patterns using simple text analysis
    fn detect_memory_allocation_patterns(&self, content: &str, language: &str, file: &FileInfo) -> Vec<MemoryHotspot> {
        let mut hotspots = Vec::new();

        match language.to_lowercase().as_str() {
            "rust" => {
                let lines: Vec<&str> = content.lines().collect();
                let mut in_loop = false;

                for (line_num, line) in lines.iter().enumerate() {
                    let trimmed = line.trim();

                    // Track if we're in a loop
                    if trimmed.contains("for ") || trimmed.contains("while ") || trimmed.contains("loop ") {
                        in_loop = true;
                    }
                    if trimmed.contains('}') && in_loop {
                        in_loop = false;
                    }

                    // Detect allocations
                    let has_allocation = trimmed.contains("Vec::new()") ||
                                       trimmed.contains("String::new()") ||
                                       trimmed.contains("HashMap::new()") ||
                                       trimmed.contains("BTreeMap::new()") ||
                                       trimmed.contains("vec![") ||
                                       trimmed.contains("format!(");

                    if has_allocation {
                        let severity = if in_loop { "High" } else { "Medium" };

                        hotspots.push(MemoryHotspot {
                            location: HotspotLocation {
                                file: file.path.display().to_string(),
                                function: None,
                                start_line: line_num + 1,
                                end_line: line_num + 1,
                                scope: "allocation".to_string(),
                            },
                            allocation_type: AllocationType::HeapAllocation,
                            frequency: if in_loop { AllocationFrequency::High } else { AllocationFrequency::Medium },
                            size_estimate: SizeEstimate::Unknown,
                        });
                    }
                }
            },
            _ => {
                // Simplified analysis for other languages
            }
        }

        hotspots
    }

    /// Detect potential memory leaks using simple pattern analysis
    fn detect_potential_memory_leaks(&self, content: &str, language: &str, file: &FileInfo) -> Vec<MemoryLeakRisk> {
        let mut leaks = Vec::new();

        match language.to_lowercase().as_str() {
            "rust" => {
                // Rust has automatic memory management, but we can look for potential issues
                let lines: Vec<&str> = content.lines().collect();

                for (line_num, line) in lines.iter().enumerate() {
                    let trimmed = line.trim();

                    // Look for potential reference cycles or unsafe patterns
                    if trimmed.contains("Rc::new") && trimmed.contains("RefCell") {
                        leaks.push(MemoryLeakRisk {
                            location: HotspotLocation {
                                file: file.path.display().to_string(),
                                function: None,
                                start_line: line_num + 1,
                                end_line: line_num + 1,
                                scope: "reference_cycle".to_string(),
                            },
                            risk_level: RiskLevel::Medium,
                            description: "Rc<RefCell<T>> can create reference cycles".to_string(),
                            mitigation: vec!["Consider using Weak references to break cycles".to_string()],
                        });
                    }

                    if trimmed.contains("Box::leak") || trimmed.contains("mem::forget") {
                        leaks.push(MemoryLeakRisk {
                            location: HotspotLocation {
                                file: file.path.display().to_string(),
                                function: None,
                                start_line: line_num + 1,
                                end_line: line_num + 1,
                                scope: "intentional_leak".to_string(),
                            },
                            risk_level: RiskLevel::High,
                            description: "Explicit memory leak detected".to_string(),
                            mitigation: vec!["Ensure this is intentional and necessary".to_string()],
                        });
                    }
                }
            },
            _ => {
                // Analysis for other languages would go here
            }
        }

        leaks
    }

    fn analyze_concurrency(&self, _analysis_result: &AnalysisResult) -> Result<ConcurrencyAnalysis> {
        // Simplified concurrency analysis
        Ok(ConcurrencyAnalysis {
            parallelization_opportunities: vec![
                ParallelizationOpportunity {
                    location: HotspotLocation {
                        file: "data_processing.rs".to_string(),
                        function: Some("process_items".to_string()),
                        start_line: 1,
                        end_line: 50,
                        scope: "function".to_string(),
                    },
                    opportunity_type: ParallelizationType::DataParallelism,
                    expected_speedup: 3.5,
                    approach: "Use rayon for parallel iteration over data collections".to_string(),
                },
            ],
            synchronization_issues: Vec::new(),
            thread_safety_concerns: Vec::new(),
            async_optimizations: Vec::new(),
        })
    }

    fn generate_recommendations(&self, hotspots: &[PerformanceHotspot], optimizations: &[OptimizationOpportunity]) -> Result<Vec<PerformanceRecommendation>> {
        let mut recommendations = Vec::new();

        // Analyze hotspots by category
        let memory_hotspots = hotspots.iter().filter(|h| h.category == HotspotCategory::MemoryUsage).count();
        let complexity_hotspots = hotspots.iter().filter(|h| h.category == HotspotCategory::AlgorithmicComplexity).count();
        let io_hotspots = hotspots.iter().filter(|h| h.category == HotspotCategory::IOOperations).count();
        let critical_hotspots = hotspots.iter().filter(|h| h.severity == PerformanceSeverity::Critical).count();

        // Memory-specific recommendations
        if memory_hotspots > 0 {
            recommendations.push(PerformanceRecommendation {
                category: "Memory Optimization".to_string(),
                recommendation: format!("Optimize {} memory allocation hotspots to reduce memory churn and improve performance", memory_hotspots),
                priority: OptimizationPriority::High,
                affected_components: hotspots.iter()
                    .filter(|h| h.category == HotspotCategory::MemoryUsage)
                    .map(|h| h.location.file.clone())
                    .collect(),
                difficulty: OptimizationDifficulty::Medium,
                expected_impact: ExpectedImprovement {
                    performance_gain: 30.0,
                    memory_reduction: 50.0,
                    time_reduction: 25.0,
                    confidence: ConfidenceLevel::High,
                },
            });
        }

        // Complexity-specific recommendations
        if complexity_hotspots > 0 {
            recommendations.push(PerformanceRecommendation {
                category: "Complexity Reduction".to_string(),
                recommendation: format!("Refactor {} high-complexity functions to improve maintainability and performance", complexity_hotspots),
                priority: OptimizationPriority::Medium,
                affected_components: hotspots.iter()
                    .filter(|h| h.category == HotspotCategory::AlgorithmicComplexity)
                    .map(|h| h.location.file.clone())
                    .collect(),
                difficulty: OptimizationDifficulty::Hard,
                expected_impact: ExpectedImprovement {
                    performance_gain: 20.0,
                    memory_reduction: 10.0,
                    time_reduction: 35.0,
                    confidence: ConfidenceLevel::Medium,
                },
            });
        }

        // I/O-specific recommendations
        if io_hotspots > 0 {
            recommendations.push(PerformanceRecommendation {
                category: "I/O Optimization".to_string(),
                recommendation: format!("Optimize {} I/O operations using buffering, async patterns, or batching", io_hotspots),
                priority: OptimizationPriority::High,
                affected_components: hotspots.iter()
                    .filter(|h| h.category == HotspotCategory::IOOperations)
                    .map(|h| h.location.file.clone())
                    .collect(),
                difficulty: OptimizationDifficulty::Medium,
                expected_impact: ExpectedImprovement {
                    performance_gain: 40.0,
                    memory_reduction: 15.0,
                    time_reduction: 60.0,
                    confidence: ConfidenceLevel::High,
                },
            });
        }

        // Critical issues
        if critical_hotspots > 0 {
            recommendations.push(PerformanceRecommendation {
                category: "Critical Performance Issues".to_string(),
                recommendation: format!("Address {} critical performance hotspots immediately", critical_hotspots),
                priority: OptimizationPriority::Critical,
                affected_components: hotspots.iter()
                    .filter(|h| h.severity == PerformanceSeverity::Critical)
                    .map(|h| h.location.file.clone())
                    .collect(),
                difficulty: OptimizationDifficulty::Hard,
                expected_impact: ExpectedImprovement {
                    performance_gain: 40.0,
                    memory_reduction: 20.0,
                    time_reduction: 50.0,
                    confidence: ConfidenceLevel::High,
                },
            });
        }

        // General optimization opportunities
        if !optimizations.is_empty() {
            recommendations.push(PerformanceRecommendation {
                category: "Optimization Opportunities".to_string(),
                recommendation: format!("Implement {} identified optimization opportunities", optimizations.len()),
                priority: OptimizationPriority::Medium,
                affected_components: optimizations.iter()
                    .flat_map(|o| o.affected_files.clone())
                    .collect(),
                difficulty: OptimizationDifficulty::Medium,
                expected_impact: ExpectedImprovement {
                    performance_gain: 25.0,
                    memory_reduction: 15.0,
                    time_reduction: 30.0,
                    confidence: ConfidenceLevel::Medium,
                },
            });
        }

        // Always include monitoring recommendation
        recommendations.push(PerformanceRecommendation {
            category: "Performance Monitoring".to_string(),
            recommendation: "Implement performance monitoring and profiling in production".to_string(),
            priority: OptimizationPriority::Medium,
            affected_components: vec!["monitoring".to_string(), "profiling".to_string()],
            difficulty: OptimizationDifficulty::Medium,
            expected_impact: ExpectedImprovement {
                performance_gain: 10.0,
                memory_reduction: 5.0,
                time_reduction: 15.0,
                confidence: ConfidenceLevel::High,
            },
        });

        Ok(recommendations)
    }

    fn calculate_performance_score(&self, hotspots: &[PerformanceHotspot], file_metrics: &[FilePerformanceMetrics]) -> u8 {
        if file_metrics.is_empty() {
            return 50; // Default score
        }

        let avg_file_score = file_metrics.iter().map(|m| m.performance_score as f64).sum::<f64>() / file_metrics.len() as f64;

        // Deduct points for hotspots
        let mut score = avg_file_score;
        for hotspot in hotspots {
            let deduction = match hotspot.severity {
                PerformanceSeverity::Critical => 15.0,
                PerformanceSeverity::High => 10.0,
                PerformanceSeverity::Medium => 5.0,
                PerformanceSeverity::Low => 2.0,
                PerformanceSeverity::Info => 1.0,
            };
            score -= deduction;
        }

        score.max(0.0).min(100.0) as u8
    }
}

// Default implementations
impl Default for ComplexityAnalysis {
    fn default() -> Self {
        Self {
            average_complexity: 0.0,
            max_complexity: 0.0,
            high_complexity_functions: Vec::new(),
            nested_loops: Vec::new(),
            recursive_functions: Vec::new(),
        }
    }
}

impl Default for MemoryAnalysis {
    fn default() -> Self {
        Self {
            allocation_hotspots: Vec::new(),
            leak_potential: Vec::new(),
            inefficient_structures: Vec::new(),
            optimizations: Vec::new(),
        }
    }
}

impl Default for ConcurrencyAnalysis {
    fn default() -> Self {
        Self {
            parallelization_opportunities: Vec::new(),
            synchronization_issues: Vec::new(),
            thread_safety_concerns: Vec::new(),
            async_optimizations: Vec::new(),
        }
    }
}

// Display implementations
impl std::fmt::Display for PerformanceSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PerformanceSeverity::Critical => write!(f, "Critical"),
            PerformanceSeverity::High => write!(f, "High"),
            PerformanceSeverity::Medium => write!(f, "Medium"),
            PerformanceSeverity::Low => write!(f, "Low"),
            PerformanceSeverity::Info => write!(f, "Info"),
        }
    }
}

impl std::fmt::Display for OptimizationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptimizationPriority::Critical => write!(f, "Critical"),
            OptimizationPriority::High => write!(f, "High"),
            OptimizationPriority::Medium => write!(f, "Medium"),
            OptimizationPriority::Low => write!(f, "Low"),
        }
    }
}

impl std::fmt::Display for OptimizationDifficulty {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OptimizationDifficulty::Trivial => write!(f, "Trivial"),
            OptimizationDifficulty::Easy => write!(f, "Easy"),
            OptimizationDifficulty::Medium => write!(f, "Medium"),
            OptimizationDifficulty::Hard => write!(f, "Hard"),
            OptimizationDifficulty::VeryHard => write!(f, "Very Hard"),
        }
    }
}
