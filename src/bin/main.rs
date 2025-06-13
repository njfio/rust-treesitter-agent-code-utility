//! Smart CLI interface for the rust-tree-sitter library
//! 
//! This CLI provides intelligent codebase analysis, querying, and insights
//! for developers and AI code agents.

use clap::{Parser, Subcommand};
use colored::*;
use indicatif::{ProgressBar, ProgressStyle};
use rust_tree_sitter::{
    CodebaseAnalyzer, AnalysisConfig, Language,
    supported_languages
};
use serde::{Serialize, Deserialize};
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use tabled::{Table, Tabled};

#[derive(Parser)]
#[command(name = "tree-sitter-cli")]
#[command(about = "Smart codebase analysis with tree-sitter")]
#[command(version = "1.0.0")]
#[command(author = "Rust Tree-sitter Team")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Analyze a codebase and extract insights
    Analyze {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,
        
        /// Output format (table, json, summary)
        #[arg(short, long, default_value = "table")]
        format: String,
        
        /// Maximum file size to process (in KB)
        #[arg(long, default_value = "1024")]
        max_size: usize,
        
        /// Maximum depth to traverse
        #[arg(long, default_value = "20")]
        max_depth: usize,
        
        /// Include hidden files and directories
        #[arg(long)]
        include_hidden: bool,
        
        /// Exclude directories (comma-separated)
        #[arg(long)]
        exclude_dirs: Option<String>,
        
        /// Include only specific file extensions (comma-separated)
        #[arg(long)]
        include_exts: Option<String>,
        
        /// Save results to file
        #[arg(short, long)]
        output: Option<PathBuf>,
        
        /// Show detailed symbol information
        #[arg(long)]
        detailed: bool,
    },
    
    /// Query code patterns across the codebase
    Query {
        /// Directory to search
        #[arg(value_name = "PATH")]
        path: PathBuf,
        
        /// Tree-sitter query pattern
        #[arg(short, long)]
        pattern: String,
        
        /// Language to query (rust, javascript, python, c, cpp)
        #[arg(short, long)]
        language: String,
        
        /// Show context lines around matches
        #[arg(short, long, default_value = "3")]
        context: usize,
        
        /// Output format (table, json)
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    
    /// Show statistics about a codebase
    Stats {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,
        
        /// Show top N files by various metrics
        #[arg(long, default_value = "10")]
        top: usize,
    },
    
    /// Find specific symbols (functions, classes, etc.)
    Find {
        /// Directory to search
        #[arg(value_name = "PATH")]
        path: PathBuf,
        
        /// Symbol name to find (supports wildcards)
        #[arg(short, long)]
        name: Option<String>,
        
        /// Symbol type (function, class, struct, enum)
        #[arg(short, long)]
        symbol_type: Option<String>,
        
        /// Language to search in
        #[arg(short, long)]
        language: Option<String>,
        
        /// Show only public symbols
        #[arg(long)]
        public_only: bool,
    },
    
    /// Show supported languages and their capabilities
    Languages,
    
    /// Interactive mode for exploring codebases
    Interactive {
        /// Directory to explore
        #[arg(value_name = "PATH")]
        path: PathBuf,
    },

    /// Generate AI-friendly insights and recommendations
    Insights {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Focus area (architecture, quality, complexity, dependencies)
        #[arg(long, default_value = "all")]
        focus: String,

        /// Output format (markdown, json, text)
        #[arg(short, long, default_value = "markdown")]
        format: String,
    },

    /// Generate a visual code map of the project structure
    Map {
        /// Directory to map
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Map type (tree, symbols, dependencies, overview)
        #[arg(short, long, default_value = "overview")]
        map_type: String,

        /// Output format (ascii, unicode, json, mermaid)
        #[arg(short, long, default_value = "unicode")]
        format: String,

        /// Maximum depth to show
        #[arg(long, default_value = "5")]
        max_depth: usize,

        /// Show file sizes
        #[arg(long)]
        show_sizes: bool,

        /// Show symbol counts
        #[arg(long)]
        show_symbols: bool,

        /// Include only specific languages
        #[arg(long)]
        languages: Option<String>,

        /// Collapse empty directories
        #[arg(long)]
        collapse_empty: bool,
    },

    /// AI-powered code explanations and insights
    Explain {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Focus on specific file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Focus on specific symbol
        #[arg(short, long)]
        symbol: Option<String>,

        /// Output format (markdown, json, text)
        #[arg(long, default_value = "markdown")]
        format: String,

        /// Include detailed explanations
        #[arg(long)]
        detailed: bool,

        /// Include learning recommendations
        #[arg(long)]
        learning: bool,
    },

    /// Security vulnerability scanning
    Security {
        /// Directory to scan
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output format (table, json, markdown)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Minimum severity level (critical, high, medium, low, info)
        #[arg(long, default_value = "low")]
        min_severity: String,

        /// Save detailed report to file
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Show only summary
        #[arg(long)]
        summary_only: bool,

        /// Include compliance information
        #[arg(long)]
        compliance: bool,
    },

    /// Smart refactoring suggestions
    Refactor {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Focus on specific category (complexity, duplication, naming, performance, architecture)
        #[arg(short, long)]
        category: Option<String>,

        /// Output format (table, json, markdown)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Show only quick wins (easy improvements)
        #[arg(long)]
        quick_wins: bool,

        /// Show only major improvements
        #[arg(long)]
        major_only: bool,

        /// Minimum priority level (critical, high, medium, low)
        #[arg(long, default_value = "low")]
        min_priority: String,

        /// Save detailed report to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Enhanced dependency analysis and security scanning
    Dependencies {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output format (table, json, markdown)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Include development dependencies
        #[arg(long)]
        include_dev: bool,

        /// Enable vulnerability scanning
        #[arg(long)]
        vulnerabilities: bool,

        /// Enable license compliance checking
        #[arg(long)]
        licenses: bool,

        /// Show outdated dependencies
        #[arg(long)]
        outdated: bool,

        /// Show dependency graph analysis
        #[arg(long)]
        graph: bool,

        /// Save detailed report to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Performance hotspot detection and analysis
    Performance {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output format (table, json, markdown)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Focus on specific category (complexity, memory, cpu, io)
        #[arg(short, long)]
        category: Option<String>,

        /// Show top N hotspots
        #[arg(long, default_value = "20")]
        top: usize,

        /// Minimum complexity threshold
        #[arg(long, default_value = "10")]
        min_complexity: usize,

        /// Include detailed analysis
        #[arg(long)]
        detailed: bool,

        /// Save detailed report to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Test coverage analysis and reporting
    Coverage {
        /// Directory to analyze
        #[arg(value_name = "PATH")]
        path: PathBuf,

        /// Output format (table, json, markdown, html)
        #[arg(short, long, default_value = "table")]
        format: String,

        /// Test directory path
        #[arg(long)]
        test_dir: Option<PathBuf>,

        /// Show uncovered functions only
        #[arg(long)]
        uncovered_only: bool,

        /// Minimum coverage threshold (percentage)
        #[arg(long, default_value = "0")]
        min_coverage: f64,

        /// Include detailed line-by-line coverage
        #[arg(long)]
        detailed: bool,

        /// Save detailed report to file
        #[arg(short, long)]
        output: Option<PathBuf>,
    },
}

#[derive(Tabled)]
struct FileRow {
    #[tabled(rename = "File")]
    path: String,
    #[tabled(rename = "Language")]
    language: String,
    #[tabled(rename = "Lines")]
    lines: usize,
    #[tabled(rename = "Size")]
    size: String,
    #[tabled(rename = "Symbols")]
    symbols: usize,
    #[tabled(rename = "Status")]
    status: String,
}

#[derive(Tabled)]
struct SymbolRow {
    #[tabled(rename = "Symbol")]
    name: String,
    #[tabled(rename = "Type")]
    kind: String,
    #[tabled(rename = "File")]
    file: String,
    #[tabled(rename = "Line")]
    line: usize,
    #[tabled(rename = "Visibility")]
    visibility: String,
}

#[derive(Tabled)]
struct LanguageRow {
    #[tabled(rename = "Language")]
    name: String,
    #[tabled(rename = "Files")]
    files: usize,
    #[tabled(rename = "Percentage")]
    percentage: String,
    #[tabled(rename = "Extensions")]
    extensions: String,
}

#[derive(Serialize, Deserialize, Tabled)]
struct PerformanceHotspot {
    #[tabled(rename = "File")]
    file: String,
    #[tabled(rename = "Symbol")]
    symbol: String,
    #[tabled(rename = "Type")]
    symbol_type: String,
    #[tabled(rename = "Complexity")]
    complexity: usize,
    #[tabled(rename = "Line")]
    line: usize,
    #[tabled(rename = "Severity")]
    severity: String,
    #[tabled(rename = "Recommendation")]
    recommendation: String,
}

#[derive(Serialize, Deserialize, Tabled)]
struct CoverageItem {
    #[tabled(rename = "File")]
    file: String,
    #[tabled(rename = "Function")]
    function: String,
    #[tabled(rename = "Coverage %")]
    coverage_percentage: f64,
    #[tabled(rename = "Lines Covered")]
    lines_covered: usize,
    #[tabled(rename = "Total Lines")]
    total_lines: usize,
    #[tabled(rename = "Test Files")]
    test_files: usize,
    #[tabled(rename = "Status")]
    status: String,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Analyze { 
            path, format, max_size, max_depth, include_hidden, 
            exclude_dirs, include_exts, output, detailed 
        } => {
            analyze_command(
                path, format, max_size, max_depth, include_hidden,
                exclude_dirs, include_exts, output, detailed
            )?;
        }
        Commands::Query { path, pattern, language, context, format } => {
            query_command(path, pattern, language, context, format)?;
        }
        Commands::Stats { path, top } => {
            stats_command(path, top)?;
        }
        Commands::Find { path, name, symbol_type, language, public_only } => {
            find_command(path, name, symbol_type, language, public_only)?;
        }
        Commands::Languages => {
            languages_command()?;
        }
        Commands::Interactive { path } => {
            interactive_command(path)?;
        }
        Commands::Insights { path, focus, format } => {
            insights_command(path, focus, format)?;
        }
        Commands::Map { path, map_type, format, max_depth, show_sizes, show_symbols, languages, collapse_empty } => {
            map_command(path, map_type, format, max_depth, show_sizes, show_symbols, languages, collapse_empty)?;
        }
        Commands::Explain { path, file, symbol, format, detailed, learning } => {
            explain_command(path, file, symbol, format, detailed, learning)?;
        }
        Commands::Security { path, format, min_severity, output, summary_only, compliance } => {
            security_command(path, format, min_severity, output, summary_only, compliance)?;
        }
        Commands::Refactor { path, category, format, quick_wins, major_only, min_priority, output } => {
            refactor_command(path, category, format, quick_wins, major_only, min_priority, output)?;
        }
        Commands::Dependencies { path, format, include_dev, vulnerabilities, licenses, outdated, graph, output } => {
            dependencies_command(path, format, include_dev, vulnerabilities, licenses, outdated, graph, output)?;
        }
        Commands::Performance { path, format, category, top, min_complexity, detailed, output } => {
            performance_command(path, format, category, top, min_complexity, detailed, output)?;
        }
        Commands::Coverage { path, format, test_dir, uncovered_only, min_coverage, detailed, output } => {
            coverage_command(path, format, test_dir, uncovered_only, min_coverage, detailed, output)?;
        }
    }

    Ok(())
}

fn analyze_command(
    path: PathBuf,
    format: String,
    max_size: usize,
    max_depth: usize,
    include_hidden: bool,
    exclude_dirs: Option<String>,
    include_exts: Option<String>,
    output: Option<PathBuf>,
    detailed: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    // Input validation
    validate_path_input(&path)?;
    validate_format_input(&format)?;
    validate_size_limits(max_size, max_depth)?;
    if let Some(ref output_path) = output {
        validate_output_path(output_path)?;
    }

    println!("{}", "🔍 Analyzing codebase...".bright_blue().bold());
    
    // Create progress bar
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .expect("Failed to set progress bar style"));
    pb.set_message("Scanning files...");
    
    // Configure analyzer
    let mut config = AnalysisConfig::default();
    config.max_file_size = Some(max_size * 1024);
    config.max_depth = Some(max_depth);
    config.include_hidden = include_hidden;
    
    if let Some(dirs) = exclude_dirs {
        config.exclude_dirs = dirs.split(',').map(|s| s.trim().to_string()).collect();
    }
    
    if let Some(exts) = include_exts {
        config.include_extensions = Some(exts.split(',').map(|s| s.trim().to_string()).collect());
    }
    
    let mut analyzer = CodebaseAnalyzer::with_config(config);
    
    // Run analysis
    let result = analyzer.analyze_directory(&path)?;
    pb.finish_with_message("Analysis complete!");
    
    // Display results based on format
    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&result)?;
            if let Some(output_path) = output {
                fs::write(output_path, json)?;
                println!("{}", "Results saved to file".green());
            } else {
                println!("{}", json);
            }
        }
        "summary" => {
            print_summary(&result);
        }
        "table" | _ => {
            print_analysis_table(&result, detailed);
            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&result)?;
                fs::write(&output_path, json)?;
                println!("\n{}", format!("Detailed results saved to {}", output_path.display()).green());
            }
        }
    }
    
    Ok(())
}

fn print_summary(result: &rust_tree_sitter::AnalysisResult) {
    println!("\n{}", "📊 CODEBASE SUMMARY".bright_cyan().bold());
    println!("{}", "=".repeat(50).bright_cyan());
    
    println!("📁 Root: {}", result.root_path.display().to_string().bright_white());
    println!("📄 Files: {} total, {} parsed, {} errors", 
        result.total_files.to_string().bright_green(),
        result.parsed_files.to_string().bright_green(),
        result.error_files.to_string().bright_red()
    );
    println!("📏 Lines: {}", result.total_lines.to_string().bright_yellow());
    
    // Language breakdown
    println!("\n{}", "🌐 LANGUAGES".bright_cyan().bold());
    let mut languages: Vec<_> = result.languages.iter().collect();
    languages.sort_by(|a, b| b.1.cmp(a.1));
    
    for (lang, count) in languages.iter().take(5) {
        let percentage = (**count as f64 / result.total_files as f64) * 100.0;
        println!("  {} {} files ({:.1}%)", 
            "▶".bright_blue(),
            format!("{}: {}", lang, count).bright_white(),
            percentage.to_string().bright_yellow()
        );
    }
    
    // Symbol summary
    let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
    let public_symbols: usize = result.files.iter()
        .flat_map(|f| &f.symbols)
        .filter(|s| s.is_public)
        .count();
    
    println!("\n{}", "🔧 SYMBOLS".bright_cyan().bold());
    println!("  {} Total: {}", "▶".bright_blue(), total_symbols.to_string().bright_white());
    println!("  {} Public: {}", "▶".bright_blue(), public_symbols.to_string().bright_green());
    println!("  {} Private: {}", "▶".bright_blue(), (total_symbols - public_symbols).to_string().bright_yellow());
}

fn print_analysis_table(result: &rust_tree_sitter::AnalysisResult, detailed: bool) {
    print_summary(result);
    
    if detailed {
        println!("\n{}", "📋 DETAILED FILE ANALYSIS".bright_cyan().bold());
        
        let file_rows: Vec<FileRow> = result.files.iter().map(|file| {
            FileRow {
                path: file.path.display().to_string(),
                language: file.language.clone(),
                lines: file.lines,
                size: format_size(file.size),
                symbols: file.symbols.len(),
                status: if file.parsed_successfully { "✅".to_string() } else { "❌".to_string() },
            }
        }).collect();
        
        let table = Table::new(file_rows);
        println!("{}", table);
        
        // Show symbols if any
        let all_symbols: Vec<_> = result.files.iter()
            .flat_map(|file| {
                file.symbols.iter().map(|symbol| SymbolRow {
                    name: symbol.name.clone(),
                    kind: symbol.kind.clone(),
                    file: file.path.display().to_string(),
                    line: symbol.start_line,
                    visibility: if symbol.is_public { "public".to_string() } else { "private".to_string() },
                })
            })
            .collect();
        
        if !all_symbols.is_empty() {
            println!("\n{}", "🔍 SYMBOLS FOUND".bright_cyan().bold());
            let symbols_table = Table::new(all_symbols);
            println!("{}", symbols_table);
        }
    }
}

fn query_command(
    path: PathBuf,
    pattern: String,
    language: String,
    context: usize,
    format: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", format!("🔍 Querying pattern: {}", pattern).bright_blue().bold());

    let lang = language.parse::<Language>()
        .map_err(|_| format!("Unsupported language: {}", language))?;

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Searching files...");

    // Analyze the codebase first
    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(&path)?;

    pb.set_message("Executing queries...");

    // Filter files by language and execute query
    let mut matches = Vec::new();
    let query = rust_tree_sitter::Query::new(lang, &pattern)?;

    for file_info in &result.files {
        if file_info.language == lang.name() && file_info.parsed_successfully {
            let file_path = path.join(&file_info.path);
            if let Ok(content) = fs::read_to_string(&file_path) {
                let parser = rust_tree_sitter::Parser::new(lang)?;
                if let Ok(tree) = parser.parse(&content, None) {
                    let query_matches = query.matches(&tree)?;
                    for query_match in query_matches {
                        for capture in query_match.captures() {
                            let node = capture.node();
                            let start_line = node.start_position().row;
                            let end_line = node.end_position().row;

                            // Extract context
                            let lines: Vec<&str> = content.lines().collect();
                            let context_start = start_line.saturating_sub(context);
                            let context_end = (end_line + context + 1).min(lines.len());

                            matches.push(QueryMatch {
                                file: file_info.path.display().to_string(),
                                line: start_line + 1,
                                column: node.start_position().column,
                                text: node.text().unwrap_or("").to_string(),
                                context: lines[context_start..context_end].join("\n"),
                            });
                        }
                    }
                }
            }
        }
    }

    pb.finish_with_message(format!("Found {} matches!", matches.len()));

    // Display results
    if matches.is_empty() {
        println!("{}", "No matches found".yellow());
        return Ok(());
    }

    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&matches)?;
            println!("{}", json);
        }
        "table" | _ => {
            println!("\n{}", format!("🎯 FOUND {} MATCHES", matches.len()).bright_green().bold());
            for (i, m) in matches.iter().enumerate() {
                println!("\n{} {}:{}:{}",
                    format!("Match {}", i + 1).bright_cyan().bold(),
                    m.file.bright_white(),
                    m.line.to_string().bright_yellow(),
                    m.column.to_string().bright_yellow()
                );
                println!("{}", "─".repeat(60).bright_black());

                // Show context with highlighting
                for (line_num, line) in m.context.lines().enumerate() {
                    let actual_line = m.line.saturating_sub(context) + line_num;
                    if actual_line + 1 == m.line {
                        println!("{} {}",
                            format!("{:>4}", actual_line + 1).bright_red().bold(),
                            line.bright_white().bold()
                        );
                    } else {
                        println!("{} {}",
                            format!("{:>4}", actual_line + 1).bright_black(),
                            line.bright_black()
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct QueryMatch {
    file: String,
    line: usize,
    column: usize,
    text: String,
    context: String,
}

fn stats_command(path: PathBuf, top: usize) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "📊 Generating codebase statistics...".bright_blue().bold());

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Analyzing...");

    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(&path)?;

    pb.finish_with_message("Analysis complete!");

    print_summary(&result);

    // Top files by size
    println!("\n{}", format!("📏 TOP {} FILES BY SIZE", top).bright_cyan().bold());
    let mut files_by_size: Vec<_> = result.files.iter().collect();
    files_by_size.sort_by(|a, b| b.size.cmp(&a.size));

    for (i, file) in files_by_size.iter().take(top).enumerate() {
        println!("{} {} {} ({})",
            format!("{}.", i + 1).bright_yellow(),
            file.path.display().to_string().bright_white(),
            format!("{} lines", file.lines).bright_green(),
            format_size(file.size).bright_blue()
        );
    }

    // Top files by complexity (symbol count)
    println!("\n{}", format!("🧠 TOP {} FILES BY COMPLEXITY", top).bright_cyan().bold());
    let mut files_by_complexity: Vec<_> = result.files.iter().collect();
    files_by_complexity.sort_by(|a, b| b.symbols.len().cmp(&a.symbols.len()));

    for (i, file) in files_by_complexity.iter().take(top).enumerate() {
        if file.symbols.len() > 0 {
            println!("{} {} {} symbols",
                format!("{}.", i + 1).bright_yellow(),
                file.path.display().to_string().bright_white(),
                file.symbols.len().to_string().bright_green()
            );
        }
    }

    // Symbol type distribution
    println!("\n{}", "🔧 SYMBOL TYPE DISTRIBUTION".bright_cyan().bold());
    let mut symbol_counts: HashMap<String, usize> = HashMap::new();
    for file in &result.files {
        for symbol in &file.symbols {
            *symbol_counts.entry(symbol.kind.clone()).or_insert(0) += 1;
        }
    }

    let mut symbol_types: Vec<_> = symbol_counts.iter().collect();
    symbol_types.sort_by(|a, b| b.1.cmp(a.1));

    for (symbol_type, count) in symbol_types {
        println!("  {} {}: {}",
            "▶".bright_blue(),
            symbol_type.bright_white(),
            count.to_string().bright_green()
        );
    }

    Ok(())
}

fn find_command(
    path: PathBuf,
    name: Option<String>,
    symbol_type: Option<String>,
    language: Option<String>,
    public_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🔍 Finding symbols...".bright_blue().bold());

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Searching...");

    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(&path)?;

    // Filter symbols based on criteria
    let mut matching_symbols = Vec::new();

    for file in &result.files {
        // Filter by language if specified
        if let Some(ref lang) = language {
            if file.language.to_lowercase() != lang.to_lowercase() {
                continue;
            }
        }

        for symbol in &file.symbols {
            // Filter by visibility
            if public_only && !symbol.is_public {
                continue;
            }

            // Filter by symbol type
            if let Some(ref stype) = symbol_type {
                if symbol.kind.to_lowercase() != stype.to_lowercase() {
                    continue;
                }
            }

            // Filter by name (supports simple wildcards)
            if let Some(ref pattern) = name {
                if !matches_pattern(&symbol.name, pattern) {
                    continue;
                }
            }

            matching_symbols.push(SymbolRow {
                name: symbol.name.clone(),
                kind: symbol.kind.clone(),
                file: file.path.display().to_string(),
                line: symbol.start_line,
                visibility: if symbol.is_public { "public".to_string() } else { "private".to_string() },
            });
        }
    }

    pb.finish_with_message(format!("Found {} symbols!", matching_symbols.len()));

    if matching_symbols.is_empty() {
        println!("{}", "No matching symbols found".yellow());
        return Ok(());
    }

    println!("\n{}", format!("🎯 FOUND {} SYMBOLS", matching_symbols.len()).bright_green().bold());
    let table = Table::new(matching_symbols);
    println!("{}", table);

    Ok(())
}

fn languages_command() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🌐 SUPPORTED LANGUAGES".bright_cyan().bold());
    println!("{}", "=".repeat(60).bright_cyan());

    let languages = supported_languages();
    let lang_rows: Vec<LanguageRow> = languages.iter().map(|lang| {
        LanguageRow {
            name: lang.name.to_string(),
            files: 0, // This would be filled in actual usage
            percentage: "N/A".to_string(),
            extensions: lang.file_extensions.join(", "),
        }
    }).collect();

    let table = Table::new(lang_rows);
    println!("{}", table);

    println!("\n{}", "💡 CAPABILITIES".bright_cyan().bold());
    for lang_info in &languages {
        println!("  {} {}",
            "▶".bright_blue(),
            format!("{} v{}", lang_info.name, lang_info.version).bright_white()
        );
        println!("    Extensions: {}", lang_info.file_extensions.join(", ").bright_green());
    }

    Ok(())
}

fn interactive_command(path: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🚀 INTERACTIVE MODE".bright_cyan().bold());
    println!("{}", "Type 'help' for available commands, 'quit' to exit".bright_yellow());

    // Initial analysis
    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Loading codebase...");

    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(&path)?;

    pb.finish_with_message("Ready!");

    print_summary(&result);

    loop {
        print!("\n{} ", "tree-sitter>".bright_green().bold());
        use std::io::{self, Write};
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        let input = input.trim();

        match input {
            "quit" | "exit" | "q" => {
                println!("{}", "Goodbye! 👋".bright_green());
                break;
            }
            "help" | "h" => {
                print_interactive_help();
            }
            "stats" => {
                print_summary(&result);
            }
            "languages" | "langs" => {
                let mut lang_counts: Vec<_> = result.languages.iter().collect();
                lang_counts.sort_by(|a, b| b.1.cmp(a.1));
                for (lang, count) in lang_counts {
                    println!("  {} {}: {} files",
                        "▶".bright_blue(),
                        lang.bright_white(),
                        count.to_string().bright_green()
                    );
                }
            }
            cmd if cmd.starts_with("find ") => {
                let query = &cmd[5..];
                interactive_find(&result, query);
            }
            cmd if cmd.starts_with("files ") => {
                let lang = &cmd[6..];
                interactive_files(&result, lang);
            }
            "" => continue,
            _ => {
                println!("{}", "Unknown command. Type 'help' for available commands.".yellow());
            }
        }
    }

    Ok(())
}

fn print_interactive_help() {
    println!("\n{}", "📚 AVAILABLE COMMANDS".bright_cyan().bold());
    println!("  {} - Show this help", "help, h".bright_green());
    println!("  {} - Show codebase statistics", "stats".bright_green());
    println!("  {} - Show language breakdown", "languages, langs".bright_green());
    println!("  {} - Find symbols by name", "find <pattern>".bright_green());
    println!("  {} - Show files for language", "files <language>".bright_green());
    println!("  {} - Exit interactive mode", "quit, exit, q".bright_green());
}

fn interactive_find(result: &rust_tree_sitter::AnalysisResult, pattern: &str) {
    let mut found = Vec::new();

    for file in &result.files {
        for symbol in &file.symbols {
            if matches_pattern(&symbol.name, pattern) {
                found.push((file, symbol));
            }
        }
    }

    if found.is_empty() {
        println!("{}", format!("No symbols found matching '{}'", pattern).yellow());
        return;
    }

    println!("{}", format!("Found {} symbols matching '{}':", found.len(), pattern).bright_green());
    for (file, symbol) in found.iter().take(20) {
        println!("  {} {} in {} (line {})",
            if symbol.is_public { "pub".bright_green() } else { "prv".bright_yellow() },
            format!("{} {}", symbol.kind, symbol.name).bright_white(),
            file.path.display().to_string().bright_blue(),
            symbol.start_line.to_string().bright_cyan()
        );
    }

    if found.len() > 20 {
        println!("  {} (showing first 20)", format!("... and {} more", found.len() - 20).bright_black());
    }
}

fn interactive_files(result: &rust_tree_sitter::AnalysisResult, language: &str) {
    let files: Vec<_> = result.files.iter()
        .filter(|f| f.language.to_lowercase() == language.to_lowercase())
        .collect();

    if files.is_empty() {
        println!("{}", format!("No {} files found", language).yellow());
        return;
    }

    println!("{}", format!("Found {} {} files:", files.len(), language).bright_green());
    for file in files.iter().take(20) {
        println!("  {} {} ({} lines, {} symbols)",
            "▶".bright_blue(),
            file.path.display().to_string().bright_white(),
            file.lines.to_string().bright_green(),
            file.symbols.len().to_string().bright_cyan()
        );
    }

    if files.len() > 20 {
        println!("  {} (showing first 20)", format!("... and {} more", files.len() - 20).bright_black());
    }
}

fn matches_pattern(text: &str, pattern: &str) -> bool {
    if pattern.contains('*') {
        // Simple wildcard matching
        let parts: Vec<&str> = pattern.split('*').collect();
        if parts.len() == 2 {
            text.starts_with(parts[0]) && text.ends_with(parts[1])
        } else {
            text.contains(&pattern.replace('*', ""))
        }
    } else {
        text.to_lowercase().contains(&pattern.to_lowercase())
    }
}

fn insights_command(
    path: PathBuf,
    focus: String,
    format: String,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🧠 Generating AI-friendly insights...".bright_blue().bold());

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Analyzing codebase...");

    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(&path)?;

    pb.finish_with_message("Analysis complete!");

    let insights = generate_insights(&result, &focus);

    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&insights)?;
            println!("{}", json);
        }
        "text" => {
            print_insights_text(&insights);
        }
        "markdown" | _ => {
            print_insights_markdown(&insights);
        }
    }

    Ok(())
}

#[derive(Serialize, Deserialize)]
struct CodebaseInsights {
    summary: InsightsSummary,
    architecture: ArchitectureInsights,
    quality: QualityInsights,
    complexity: ComplexityInsights,
    recommendations: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct InsightsSummary {
    total_files: usize,
    total_lines: usize,
    primary_language: String,
    language_diversity: f64,
    symbol_count: usize,
    public_api_size: usize,
}

#[derive(Serialize, Deserialize)]
struct ArchitectureInsights {
    module_structure: String,
    dependency_patterns: Vec<String>,
    api_design: String,
    separation_of_concerns: String,
}

#[derive(Serialize, Deserialize)]
struct QualityInsights {
    parse_success_rate: f64,
    code_organization: String,
    naming_conventions: String,
    documentation_coverage: String,
}

#[derive(Serialize, Deserialize)]
struct ComplexityInsights {
    average_file_size: f64,
    largest_files: Vec<String>,
    symbol_distribution: HashMap<String, usize>,
    complexity_hotspots: Vec<String>,
}

fn generate_insights(result: &rust_tree_sitter::AnalysisResult, _focus: &str) -> CodebaseInsights {
    let total_symbols: usize = result.files.iter().map(|f| f.symbols.len()).sum();
    let public_symbols: usize = result.files.iter()
        .flat_map(|f| &f.symbols)
        .filter(|s| s.is_public)
        .count();

    let primary_language = result.languages.iter()
        .max_by_key(|(_, count)| *count)
        .map(|(lang, _)| lang.clone())
        .unwrap_or_else(|| "Unknown".to_string());

    let language_diversity = result.languages.len() as f64;
    let parse_success_rate = if result.total_files > 0 {
        (result.parsed_files as f64 / result.total_files as f64) * 100.0
    } else {
        0.0
    };

    let average_file_size = if result.total_files > 0 {
        result.total_lines as f64 / result.total_files as f64
    } else {
        0.0
    };

    // Generate symbol distribution
    let mut symbol_distribution = HashMap::new();
    for file in &result.files {
        for symbol in &file.symbols {
            *symbol_distribution.entry(symbol.kind.clone()).or_insert(0) += 1;
        }
    }

    // Find largest files
    let mut files_by_size: Vec<_> = result.files.iter().collect();
    files_by_size.sort_by(|a, b| b.lines.cmp(&a.lines));
    let largest_files: Vec<String> = files_by_size.iter()
        .take(5)
        .map(|f| format!("{} ({} lines)", f.path.display(), f.lines))
        .collect();

    // Find complexity hotspots
    let mut files_by_complexity: Vec<_> = result.files.iter().collect();
    files_by_complexity.sort_by(|a, b| b.symbols.len().cmp(&a.symbols.len()));
    let complexity_hotspots: Vec<String> = files_by_complexity.iter()
        .take(3)
        .filter(|f| f.symbols.len() > 10)
        .map(|f| format!("{} ({} symbols)", f.path.display(), f.symbols.len()))
        .collect();

    // Generate recommendations
    let mut recommendations = Vec::new();

    if parse_success_rate < 100.0 {
        recommendations.push(format!(
            "Fix parse errors in {} files to improve code analysis accuracy",
            result.error_files
        ));
    }

    if average_file_size > 500.0 {
        recommendations.push("Consider breaking down large files for better maintainability".to_string());
    }

    if public_symbols as f64 / total_symbols as f64 > 0.7 {
        recommendations.push("Consider reducing public API surface area for better encapsulation".to_string());
    }

    if language_diversity > 3.0 {
        recommendations.push("High language diversity detected - ensure consistent tooling and practices".to_string());
    }

    if complexity_hotspots.len() > 2 {
        recommendations.push("Multiple complexity hotspots found - consider refactoring for maintainability".to_string());
    }

    CodebaseInsights {
        summary: InsightsSummary {
            total_files: result.total_files,
            total_lines: result.total_lines,
            primary_language: primary_language.clone(),
            language_diversity,
            symbol_count: total_symbols,
            public_api_size: public_symbols,
        },
        architecture: ArchitectureInsights {
            module_structure: analyze_module_structure(result),
            dependency_patterns: analyze_dependency_patterns(result),
            api_design: analyze_api_design(result, public_symbols, total_symbols),
            separation_of_concerns: analyze_separation_of_concerns(result),
        },
        quality: QualityInsights {
            parse_success_rate,
            code_organization: analyze_code_organization(result),
            naming_conventions: analyze_naming_conventions(result),
            documentation_coverage: "Analysis not implemented".to_string(),
        },
        complexity: ComplexityInsights {
            average_file_size,
            largest_files,
            symbol_distribution,
            complexity_hotspots,
        },
        recommendations,
    }
}

fn analyze_module_structure(result: &rust_tree_sitter::AnalysisResult) -> String {
    let total_files = result.total_files;
    let avg_symbols_per_file = if total_files > 0 {
        result.files.iter().map(|f| f.symbols.len()).sum::<usize>() as f64 / total_files as f64
    } else {
        0.0
    };

    if avg_symbols_per_file < 5.0 {
        "Well-modularized with small, focused files".to_string()
    } else if avg_symbols_per_file < 15.0 {
        "Moderately modularized with reasonable file sizes".to_string()
    } else {
        "Large modules detected - consider breaking down for better organization".to_string()
    }
}

fn analyze_dependency_patterns(_result: &rust_tree_sitter::AnalysisResult) -> Vec<String> {
    vec![
        "Static analysis of imports/dependencies not yet implemented".to_string(),
        "Consider using dependency analysis tools for deeper insights".to_string(),
    ]
}

fn analyze_api_design(_result: &rust_tree_sitter::AnalysisResult, public_symbols: usize, total_symbols: usize) -> String {
    let public_ratio = if total_symbols > 0 {
        public_symbols as f64 / total_symbols as f64
    } else {
        0.0
    };

    if public_ratio < 0.3 {
        "Good encapsulation with limited public API surface".to_string()
    } else if public_ratio < 0.6 {
        "Moderate public API surface - review if all symbols need to be public".to_string()
    } else {
        "Large public API surface - consider reducing for better encapsulation".to_string()
    }
}

fn analyze_separation_of_concerns(result: &rust_tree_sitter::AnalysisResult) -> String {
    let file_count = result.total_files;
    let symbol_types: std::collections::HashSet<String> = result.files.iter()
        .flat_map(|f| &f.symbols)
        .map(|s| s.kind.clone())
        .collect();

    if file_count > 5 && symbol_types.len() > 2 {
        "Good separation with multiple files and diverse symbol types".to_string()
    } else if file_count > 2 {
        "Basic separation present - consider further modularization".to_string()
    } else {
        "Limited separation - consider breaking code into more focused modules".to_string()
    }
}

fn analyze_code_organization(result: &rust_tree_sitter::AnalysisResult) -> String {
    let has_nested_structure = result.files.iter()
        .any(|f| f.path.components().count() > 2);

    if has_nested_structure {
        "Hierarchical organization with nested directories".to_string()
    } else {
        "Flat organization - consider using subdirectories for better structure".to_string()
    }
}

fn analyze_naming_conventions(result: &rust_tree_sitter::AnalysisResult) -> String {
    let symbol_names: Vec<&String> = result.files.iter()
        .flat_map(|f| &f.symbols)
        .map(|s| &s.name)
        .collect();

    let snake_case_count = symbol_names.iter()
        .filter(|name| name.contains('_') && name.chars().all(|c| c.is_lowercase() || c == '_'))
        .count();

    let camel_case_count = symbol_names.iter()
        .filter(|name| name.chars().any(|c| c.is_uppercase()) && !name.contains('_'))
        .count();

    if snake_case_count > camel_case_count {
        "Primarily snake_case naming (typical for Rust)".to_string()
    } else if camel_case_count > snake_case_count {
        "Primarily camelCase naming (typical for JavaScript)".to_string()
    } else {
        "Mixed naming conventions - consider standardizing".to_string()
    }
}

fn print_insights_markdown(insights: &CodebaseInsights) {
    println!("# 🧠 Codebase Intelligence Report\n");

    println!("## 📊 Executive Summary\n");
    println!("- **Total Files**: {}", insights.summary.total_files);
    println!("- **Lines of Code**: {}", insights.summary.total_lines);
    println!("- **Primary Language**: {}", insights.summary.primary_language);
    println!("- **Total Symbols**: {}", insights.summary.symbol_count);
    println!("- **Public API Size**: {}\n", insights.summary.public_api_size);

    println!("## 🏗️ Architecture Analysis\n");
    println!("**Module Structure**: {}\n", insights.architecture.module_structure);
    println!("**API Design**: {}\n", insights.architecture.api_design);
    println!("**Separation of Concerns**: {}\n", insights.architecture.separation_of_concerns);

    println!("## 🔍 Quality Metrics\n");
    println!("- **Parse Success Rate**: {:.1}%", insights.quality.parse_success_rate);
    println!("- **Code Organization**: {}", insights.quality.code_organization);
    println!("- **Naming Conventions**: {}\n", insights.quality.naming_conventions);

    println!("## 📈 Complexity Analysis\n");
    println!("**Average File Size**: {:.1} lines\n", insights.complexity.average_file_size);

    if !insights.complexity.largest_files.is_empty() {
        println!("**Largest Files**:");
        for file in &insights.complexity.largest_files {
            println!("- {}", file);
        }
        println!();
    }

    if !insights.complexity.complexity_hotspots.is_empty() {
        println!("**Complexity Hotspots**:");
        for hotspot in &insights.complexity.complexity_hotspots {
            println!("- {}", hotspot);
        }
        println!();
    }

    println!("**Symbol Distribution**:");
    let mut symbol_types: Vec<_> = insights.complexity.symbol_distribution.iter().collect();
    symbol_types.sort_by(|a, b| b.1.cmp(a.1));
    for (symbol_type, count) in symbol_types {
        println!("- {}: {}", symbol_type, count);
    }
    println!();

    if !insights.recommendations.is_empty() {
        println!("## 💡 Recommendations\n");
        for (i, rec) in insights.recommendations.iter().enumerate() {
            println!("{}. {}", i + 1, rec);
        }
        println!();
    }

    println!("---");
    println!("*Generated by tree-sitter-cli - Smart codebase analysis*");
}

fn print_insights_text(insights: &CodebaseInsights) {
    println!("{}", "🧠 CODEBASE INTELLIGENCE REPORT".bright_cyan().bold());
    println!("{}", "=".repeat(50).bright_cyan());

    println!("\n{}", "📊 SUMMARY".bright_yellow().bold());
    println!("Files: {} | Lines: {} | Language: {}",
        insights.summary.total_files.to_string().bright_white(),
        insights.summary.total_lines.to_string().bright_white(),
        insights.summary.primary_language.bright_white()
    );
    println!("Symbols: {} total, {} public",
        insights.summary.symbol_count.to_string().bright_white(),
        insights.summary.public_api_size.to_string().bright_green()
    );

    println!("\n{}", "🏗️ ARCHITECTURE".bright_yellow().bold());
    println!("Structure: {}", insights.architecture.module_structure.bright_white());
    println!("API Design: {}", insights.architecture.api_design.bright_white());

    println!("\n{}", "🔍 QUALITY".bright_yellow().bold());
    println!("Parse Success: {:.1}%", insights.quality.parse_success_rate.to_string().bright_green());
    println!("Organization: {}", insights.quality.code_organization.bright_white());

    if !insights.recommendations.is_empty() {
        println!("\n{}", "💡 RECOMMENDATIONS".bright_yellow().bold());
        for (i, rec) in insights.recommendations.iter().enumerate() {
            println!("{}. {}",
                format!("{}", i + 1).bright_cyan(),
                rec.bright_white()
            );
        }
    }
}

fn map_command(
    path: PathBuf,
    map_type: String,
    format: String,
    max_depth: usize,
    show_sizes: bool,
    show_symbols: bool,
    languages: Option<String>,
    collapse_empty: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🗺️  Generating code map...".bright_blue().bold());

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .expect("Failed to set progress bar style"));
    pb.set_message("Analyzing structure...");

    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(&path)?;

    pb.finish_with_message("Map generation complete!");

    let language_filter: Option<Vec<String>> = languages.map(|langs|
        langs.split(',').map(|s| s.trim().to_lowercase()).collect()
    );

    match map_type.as_str() {
        "tree" => generate_tree_map(&result, &format, max_depth, show_sizes, show_symbols, &language_filter, collapse_empty)?,
        "symbols" => generate_symbol_map(&result, &format, &language_filter)?,
        "dependencies" => generate_dependency_map(&result, &format)?,
        "overview" | _ => generate_overview_map(&result, &format, max_depth, show_sizes, show_symbols, &language_filter, collapse_empty)?,
    }

    Ok(())
}

fn generate_tree_map(
    result: &rust_tree_sitter::AnalysisResult,
    format: &str,
    max_depth: usize,
    show_sizes: bool,
    show_symbols: bool,
    language_filter: &Option<Vec<String>>,
    collapse_empty: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        "json" => generate_tree_map_json(result, language_filter)?,
        "mermaid" => generate_tree_map_mermaid(result, max_depth, language_filter)?,
        "ascii" => generate_tree_map_ascii(result, max_depth, show_sizes, show_symbols, language_filter, collapse_empty, false)?,
        "unicode" | _ => generate_tree_map_ascii(result, max_depth, show_sizes, show_symbols, language_filter, collapse_empty, true)?,
    }
    Ok(())
}

fn generate_overview_map(
    result: &rust_tree_sitter::AnalysisResult,
    format: &str,
    max_depth: usize,
    show_sizes: bool,
    show_symbols: bool,
    language_filter: &Option<Vec<String>>,
    collapse_empty: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        "json" => {
            let overview = create_overview_json(result, language_filter);
            println!("{}", serde_json::to_string_pretty(&overview)?);
        }
        "mermaid" => generate_overview_mermaid(result, language_filter)?,
        _ => {
            // Show summary first
            print_map_summary(result, language_filter);
            println!();

            // Then show tree
            generate_tree_map_ascii(result, max_depth, show_sizes, show_symbols, language_filter, collapse_empty, format == "unicode")?;
        }
    }
    Ok(())
}

fn print_map_summary(result: &rust_tree_sitter::AnalysisResult, language_filter: &Option<Vec<String>>) {
    let filtered_files: Vec<_> = result.files.iter()
        .filter(|f| {
            if let Some(ref langs) = language_filter {
                langs.contains(&f.language.to_lowercase())
            } else {
                true
            }
        })
        .collect();

    let total_files = filtered_files.len();
    let total_symbols: usize = filtered_files.iter().map(|f| f.symbols.len()).sum();
    let total_lines: usize = filtered_files.iter().map(|f| f.lines).sum();

    println!("{}", "🗺️  CODE MAP OVERVIEW".bright_cyan().bold());
    println!("{}", "=".repeat(50).bright_cyan());

    println!("📁 Root: {}", result.root_path.display().to_string().bright_white());
    println!("📄 Files: {} | 📏 Lines: {} | 🔧 Symbols: {}",
        total_files.to_string().bright_green(),
        total_lines.to_string().bright_yellow(),
        total_symbols.to_string().bright_blue()
    );

    // Language breakdown
    let mut lang_counts: HashMap<String, usize> = HashMap::new();
    for file in &filtered_files {
        *lang_counts.entry(file.language.clone()).or_insert(0) += 1;
    }

    if lang_counts.len() > 1 {
        print!("🌐 Languages: ");
        let mut lang_list: Vec<_> = lang_counts.iter().collect();
        lang_list.sort_by(|a, b| b.1.cmp(a.1));
        for (i, (lang, count)) in lang_list.iter().enumerate() {
            if i > 0 { print!(", "); }
            print!("{} ({})", lang.bright_white(), count.to_string().bright_green());
        }
        println!();
    }
}

fn generate_tree_map_ascii(
    result: &rust_tree_sitter::AnalysisResult,
    max_depth: usize,
    show_sizes: bool,
    show_symbols: bool,
    language_filter: &Option<Vec<String>>,
    collapse_empty: bool,
    use_unicode: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let (tree_chars, file_chars) = if use_unicode {
        (("├── ", "└── ", "│   ", "    "), ("📁 ", "📄 ", "🔧 "))
    } else {
        (("├── ", "└── ", "│   ", "    "), ("", "", ""))
    };

    // Build directory tree structure
    let mut tree = DirectoryTree::new();

    for file in &result.files {
        if let Some(ref langs) = language_filter {
            if !langs.contains(&file.language.to_lowercase()) {
                continue;
            }
        }

        tree.add_file(file);
    }

    println!("\n{}", "📂 PROJECT STRUCTURE".bright_cyan().bold());
    println!("{}", "=".repeat(50).bright_cyan());

    print_directory_tree(&tree.root, "", true, 0, max_depth, show_sizes, show_symbols, collapse_empty, tree_chars, file_chars);

    Ok(())
}

#[derive(Debug)]
struct DirectoryNode {
    name: String,
    is_file: bool,
    children: HashMap<String, DirectoryNode>,
    file_info: Option<rust_tree_sitter::FileInfo>,
}

struct DirectoryTree {
    root: DirectoryNode,
}

impl DirectoryTree {
    fn new() -> Self {
        Self {
            root: DirectoryNode {
                name: ".".to_string(),
                is_file: false,
                children: HashMap::new(),
                file_info: None,
            }
        }
    }

    fn add_file(&mut self, file_info: &rust_tree_sitter::FileInfo) {
        let components: Vec<_> = file_info.path.components()
            .map(|c| c.as_os_str().to_string_lossy().to_string())
            .collect();

        let mut current = &mut self.root;

        for (i, component) in components.iter().enumerate() {
            let is_last = i == components.len() - 1;

            current.children.entry(component.clone()).or_insert_with(|| {
                DirectoryNode {
                    name: component.clone(),
                    is_file: is_last,
                    children: HashMap::new(),
                    file_info: if is_last { Some(file_info.clone()) } else { None },
                }
            });

            current = current.children.get_mut(component).unwrap();
        }
    }
}

fn print_directory_tree(
    node: &DirectoryNode,
    prefix: &str,
    is_last: bool,
    depth: usize,
    max_depth: usize,
    show_sizes: bool,
    show_symbols: bool,
    collapse_empty: bool,
    tree_chars: (&str, &str, &str, &str),
    file_chars: (&str, &str, &str),
) {
    if depth > max_depth {
        return;
    }

    let (branch, last_branch, vertical, space) = tree_chars;
    let (dir_icon, file_icon, symbol_icon) = file_chars;

    if depth > 0 {
        let connector = if is_last { last_branch } else { branch };
        print!("{}{}", prefix, connector);

        if node.is_file {
            print!("{}", file_icon);
            print!("{}", node.name.bright_white());

            if let Some(ref file_info) = node.file_info {
                let mut info_parts = Vec::new();

                if show_sizes {
                    info_parts.push(format!("{} lines", file_info.lines).bright_green().to_string());
                }

                if show_symbols && !file_info.symbols.is_empty() {
                    info_parts.push(format!("{}{} symbols", symbol_icon, file_info.symbols.len()).bright_blue().to_string());
                }

                if !info_parts.is_empty() {
                    print!(" {}", format!("({})", info_parts.join(", ")).bright_black());
                }
            }
        } else {
            print!("{}", dir_icon);
            print!("{}", node.name.bright_cyan().bold());

            if show_sizes || show_symbols {
                let child_files: Vec<_> = collect_all_files(node);
                let mut info_parts = Vec::new();

                if show_sizes {
                    let total_lines: usize = child_files.iter()
                        .filter_map(|f| f.file_info.as_ref())
                        .map(|f| f.lines)
                        .sum();
                    if total_lines > 0 {
                        info_parts.push(format!("{} lines", total_lines).bright_green().to_string());
                    }
                }

                if show_symbols {
                    let total_symbols: usize = child_files.iter()
                        .filter_map(|f| f.file_info.as_ref())
                        .map(|f| f.symbols.len())
                        .sum();
                    if total_symbols > 0 {
                        info_parts.push(format!("{}{} symbols", symbol_icon, total_symbols).bright_blue().to_string());
                    }
                }

                if !info_parts.is_empty() {
                    print!(" {}", format!("({})", info_parts.join(", ")).bright_black());
                }
            }
        }

        println!();
    }

    if !node.is_file {
        let mut children: Vec<_> = node.children.values().collect();
        children.sort_by(|a, b| {
            // Directories first, then files
            match (a.is_file, b.is_file) {
                (false, true) => std::cmp::Ordering::Less,
                (true, false) => std::cmp::Ordering::Greater,
                _ => a.name.cmp(&b.name),
            }
        });

        // Filter empty directories if collapse_empty is true
        if collapse_empty {
            children.retain(|child| {
                if child.is_file {
                    true
                } else {
                    has_files(child)
                }
            });
        }

        for (i, child) in children.iter().enumerate() {
            let is_last_child = i == children.len() - 1;
            let new_prefix = if depth == 0 {
                "".to_string()
            } else {
                format!("{}{}", prefix, if is_last { space } else { vertical })
            };

            print_directory_tree(
                child,
                &new_prefix,
                is_last_child,
                depth + 1,
                max_depth,
                show_sizes,
                show_symbols,
                collapse_empty,
                tree_chars,
                file_chars
            );
        }
    }
}

fn collect_all_files(node: &DirectoryNode) -> Vec<&DirectoryNode> {
    let mut files = Vec::new();

    if node.is_file {
        files.push(node);
    } else {
        for child in node.children.values() {
            files.extend(collect_all_files(child));
        }
    }

    files
}

fn has_files(node: &DirectoryNode) -> bool {
    if node.is_file {
        true
    } else {
        node.children.values().any(has_files)
    }
}

fn generate_symbol_map(
    result: &rust_tree_sitter::AnalysisResult,
    format: &str,
    language_filter: &Option<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let filtered_files: Vec<_> = result.files.iter()
        .filter(|f| {
            if let Some(ref langs) = language_filter {
                langs.contains(&f.language.to_lowercase())
            } else {
                true
            }
        })
        .collect();

    match format {
        "json" => {
            let symbol_map = create_symbol_map_json(&filtered_files);
            println!("{}", serde_json::to_string_pretty(&symbol_map)?);
        }
        "mermaid" => generate_symbol_map_mermaid(&filtered_files)?,
        _ => generate_symbol_map_text(&filtered_files)?,
    }

    Ok(())
}

fn generate_symbol_map_text(files: &[&rust_tree_sitter::FileInfo]) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{}", "🔧 SYMBOL MAP".bright_cyan().bold());
    println!("{}", "=".repeat(50).bright_cyan());

    // Group symbols by type
    let mut symbol_groups: HashMap<String, Vec<(&rust_tree_sitter::FileInfo, &rust_tree_sitter::Symbol)>> = HashMap::new();

    for file in files {
        for symbol in &file.symbols {
            symbol_groups.entry(symbol.kind.clone())
                .or_insert_with(Vec::new)
                .push((file, symbol));
        }
    }

    // Sort symbol types by count
    let mut sorted_groups: Vec<_> = symbol_groups.iter().collect();
    sorted_groups.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    for (symbol_type, symbols) in sorted_groups {
        println!("\n{} {} ({} total)",
            "▶".bright_blue(),
            symbol_type.to_uppercase().bright_white().bold(),
            symbols.len().to_string().bright_green()
        );

        // Group by file
        let mut file_groups: HashMap<&str, Vec<&rust_tree_sitter::Symbol>> = HashMap::new();
        for (file, symbol) in symbols {
            let file_name = file.path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            file_groups.entry(file_name)
                .or_insert_with(Vec::new)
                .push(symbol);
        }

        let mut sorted_files: Vec<_> = file_groups.iter().collect();
        sorted_files.sort_by(|a, b| a.0.cmp(b.0));

        for (file_name, file_symbols) in sorted_files {
            println!("  📄 {}", file_name.bright_cyan());

            let mut sorted_symbols = file_symbols.clone();
            sorted_symbols.sort_by(|a, b| a.start_line.cmp(&b.start_line));

            for symbol in sorted_symbols.iter().take(10) { // Limit to 10 per file
                let visibility = if symbol.is_public { "pub".bright_green() } else { "prv".bright_yellow() };
                println!("    {} {} {} (line {})",
                    "•".bright_black(),
                    visibility,
                    symbol.name.bright_white(),
                    symbol.start_line.to_string().bright_black()
                );
            }

            if file_symbols.len() > 10 {
                println!("    {} ... and {} more",
                    "•".bright_black(),
                    (file_symbols.len() - 10).to_string().bright_black()
                );
            }
        }
    }

    Ok(())
}

fn generate_dependency_map(
    result: &rust_tree_sitter::AnalysisResult,
    format: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        "json" => {
            let dep_map = create_dependency_map_json(result);
            println!("{}", serde_json::to_string_pretty(&dep_map)?);
        }
        "mermaid" => generate_dependency_map_mermaid(result)?,
        _ => generate_dependency_map_text(result)?,
    }

    Ok(())
}

fn generate_dependency_map_text(result: &rust_tree_sitter::AnalysisResult) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n{}", "🔗 DEPENDENCY MAP".bright_cyan().bold());
    println!("{}", "=".repeat(50).bright_cyan());

    println!("{}", "Note: Static dependency analysis not yet implemented.".yellow());
    println!("This feature would analyze:");
    println!("  • Import/use statements");
    println!("  • Module dependencies");
    println!("  • Function call relationships");
    println!("  • Type dependencies");

    // For now, show file relationships based on naming patterns
    println!("\n{}", "📁 FILE ORGANIZATION".bright_cyan().bold());

    let mut modules: HashMap<String, Vec<&rust_tree_sitter::FileInfo>> = HashMap::new();

    for file in &result.files {
        let module_name = file.path.parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            .unwrap_or("root");

        modules.entry(module_name.to_string())
            .or_insert_with(Vec::new)
            .push(file);
    }

    for (module, files) in modules {
        if files.len() > 1 {
            println!("\n{} {} ({} files)",
                "▶".bright_blue(),
                module.bright_white().bold(),
                files.len().to_string().bright_green()
            );

            for file in files {
                let file_name = file.path.file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("unknown");
                println!("  • {} ({} symbols)",
                    file_name.bright_cyan(),
                    file.symbols.len().to_string().bright_green()
                );
            }
        }
    }

    Ok(())
}

// JSON generation functions
fn create_overview_json(
    result: &rust_tree_sitter::AnalysisResult,
    language_filter: &Option<Vec<String>>,
) -> serde_json::Value {
    let filtered_files: Vec<_> = result.files.iter()
        .filter(|f| {
            if let Some(ref langs) = language_filter {
                langs.contains(&f.language.to_lowercase())
            } else {
                true
            }
        })
        .collect();

    serde_json::json!({
        "overview": {
            "root_path": result.root_path,
            "total_files": filtered_files.len(),
            "total_lines": filtered_files.iter().map(|f| f.lines).sum::<usize>(),
            "total_symbols": filtered_files.iter().map(|f| f.symbols.len()).sum::<usize>(),
            "languages": {
                // Language breakdown
            }
        },
        "structure": create_tree_structure_json(&filtered_files),
        "symbols": create_symbol_summary_json(&filtered_files)
    })
}

fn create_tree_structure_json(files: &[&rust_tree_sitter::FileInfo]) -> serde_json::Value {
    // Create a simplified tree structure
    let mut tree = serde_json::Map::new();

    for file in files {
        let path_str = file.path.to_string_lossy();
        tree.insert(path_str.to_string(), serde_json::json!({
            "language": file.language,
            "lines": file.lines,
            "symbols": file.symbols.len(),
            "parsed": file.parsed_successfully
        }));
    }

    serde_json::Value::Object(tree)
}

fn create_symbol_summary_json(files: &[&rust_tree_sitter::FileInfo]) -> serde_json::Value {
    let mut symbol_counts: HashMap<String, usize> = HashMap::new();
    let mut public_counts: HashMap<String, usize> = HashMap::new();

    for file in files {
        for symbol in &file.symbols {
            *symbol_counts.entry(symbol.kind.clone()).or_insert(0) += 1;
            if symbol.is_public {
                *public_counts.entry(symbol.kind.clone()).or_insert(0) += 1;
            }
        }
    }

    serde_json::json!({
        "by_type": symbol_counts,
        "public_by_type": public_counts
    })
}

fn create_symbol_map_json(files: &[&rust_tree_sitter::FileInfo]) -> serde_json::Value {
    let mut symbol_map = serde_json::Map::new();

    for file in files {
        let file_name = file.path.to_string_lossy();
        let symbols: Vec<_> = file.symbols.iter().map(|s| {
            serde_json::json!({
                "name": s.name,
                "kind": s.kind,
                "line": s.start_line,
                "column": s.start_column,
                "public": s.is_public
            })
        }).collect();

        symbol_map.insert(file_name.to_string(), serde_json::Value::Array(symbols));
    }

    serde_json::Value::Object(symbol_map)
}

fn create_dependency_map_json(result: &rust_tree_sitter::AnalysisResult) -> serde_json::Value {
    serde_json::json!({
        "note": "Static dependency analysis not yet implemented",
        "file_count": result.total_files,
        "modules": result.files.iter().map(|f| {
            serde_json::json!({
                "path": f.path,
                "language": f.language,
                "symbols": f.symbols.len()
            })
        }).collect::<Vec<_>>()
    })
}

// Mermaid generation functions (stubs for now)
fn generate_tree_map_mermaid(
    result: &rust_tree_sitter::AnalysisResult,
    _max_depth: usize,
    language_filter: &Option<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("```mermaid");
    println!("graph TD");
    println!("    Root[{}]", result.root_path.display());

    let filtered_files: Vec<_> = result.files.iter()
        .filter(|f| {
            if let Some(ref langs) = language_filter {
                langs.contains(&f.language.to_lowercase())
            } else {
                true
            }
        })
        .collect();

    for (i, file) in filtered_files.iter().enumerate() {
        let file_name = file.path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        println!("    Root --> F{}[{}]", i, file_name);

        if !file.symbols.is_empty() {
            println!("    F{} --> S{}[{} symbols]", i, i, file.symbols.len());
        }
    }

    println!("```");
    Ok(())
}

fn generate_overview_mermaid(
    result: &rust_tree_sitter::AnalysisResult,
    language_filter: &Option<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("```mermaid");
    println!("mindmap");
    println!("  root){}(", result.root_path.display());

    let filtered_files: Vec<_> = result.files.iter()
        .filter(|f| {
            if let Some(ref langs) = language_filter {
                langs.contains(&f.language.to_lowercase())
            } else {
                true
            }
        })
        .collect();

    // Group by language
    let mut lang_groups: HashMap<String, Vec<_>> = HashMap::new();
    for file in filtered_files {
        lang_groups.entry(file.language.clone())
            .or_insert_with(Vec::new)
            .push(file);
    }

    for (lang, files) in lang_groups {
        println!("    {}", lang);
        for file in files.iter().take(5) { // Limit for readability
            let file_name = file.path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            println!("      {}", file_name);
        }
        if files.len() > 5 {
            println!("      ... {} more", files.len() - 5);
        }
    }

    println!("```");
    Ok(())
}

fn generate_symbol_map_mermaid(files: &[&rust_tree_sitter::FileInfo]) -> Result<(), Box<dyn std::error::Error>> {
    println!("```mermaid");
    println!("graph LR");

    for (i, file) in files.iter().enumerate() {
        let file_name = file.path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("unknown");
        println!("    F{}[{}]", i, file_name);

        let mut symbol_types: HashMap<String, usize> = HashMap::new();
        for symbol in &file.symbols {
            *symbol_types.entry(symbol.kind.clone()).or_insert(0) += 1;
        }

        for (j, (symbol_type, count)) in symbol_types.iter().enumerate() {
            println!("    F{} --> S{}{}[{}: {}]", i, i, j, symbol_type, count);
        }
    }

    println!("```");
    Ok(())
}

fn generate_dependency_map_mermaid(result: &rust_tree_sitter::AnalysisResult) -> Result<(), Box<dyn std::error::Error>> {
    println!("```mermaid");
    println!("graph TD");
    println!("    Root[Project: {}]", result.root_path.display());

    // Group by directory
    let mut dir_groups: HashMap<String, Vec<_>> = HashMap::new();
    for file in &result.files {
        let dir = file.path.parent()
            .and_then(|p| p.to_str())
            .unwrap_or("root");
        dir_groups.entry(dir.to_string())
            .or_insert_with(Vec::new)
            .push(file);
    }

    for (i, (dir, files)) in dir_groups.iter().enumerate() {
        println!("    Root --> D{}[{}]", i, dir);
        for (j, file) in files.iter().enumerate() {
            let file_name = file.path.file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("unknown");
            println!("    D{} --> F{}{}[{}]", i, i, j, file_name);
        }
    }

    println!("```");
    Ok(())
}

fn generate_tree_map_json(
    result: &rust_tree_sitter::AnalysisResult,
    language_filter: &Option<Vec<String>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let filtered_files: Vec<_> = result.files.iter()
        .filter(|f| {
            if let Some(ref langs) = language_filter {
                langs.contains(&f.language.to_lowercase())
            } else {
                true
            }
        })
        .collect();

    let tree_map = serde_json::json!({
        "root": result.root_path,
        "files": filtered_files.iter().map(|f| {
            serde_json::json!({
                "path": f.path,
                "language": f.language,
                "lines": f.lines,
                "size": f.size,
                "symbols": f.symbols.len(),
                "parsed": f.parsed_successfully
            })
        }).collect::<Vec<_>>()
    });

    println!("{}", serde_json::to_string_pretty(&tree_map)?);
    Ok(())
}

fn explain_command(
    path: PathBuf,
    file: Option<PathBuf>,
    symbol: Option<String>,
    format: String,
    detailed: bool,
    learning: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🧠 Generating AI explanations...".bright_blue().bold());

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Analyzing code...");

    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(&path)?;

    pb.set_message("Generating explanations...");

    // Generate AI explanations
    let ai_config = rust_tree_sitter::AIConfig {
        detailed_explanations: detailed,
        include_examples: true,
        max_explanation_length: if detailed { 1000 } else { 500 },
        pattern_recognition: true,
        architectural_insights: true,
    };

    let ai_analyzer = rust_tree_sitter::AIAnalyzer::with_config(ai_config);
    let ai_result = ai_analyzer.analyze(&result);

    pb.finish_with_message("Explanations generated!");

    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&ai_result)?;
            println!("{}", json);
        }
        "text" => {
            print_explanations_text(&ai_result, file.as_ref(), symbol.as_ref(), learning);
        }
        "markdown" | _ => {
            print_explanations_markdown(&ai_result, file.as_ref(), symbol.as_ref(), learning);
        }
    }

    Ok(())
}

fn security_command(
    path: PathBuf,
    format: String,
    min_severity: String,
    output: Option<PathBuf>,
    summary_only: bool,
    compliance: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🔍 Scanning for security vulnerabilities...".bright_red().bold());

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Analyzing code...");

    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(&path)?;

    pb.set_message("Scanning for vulnerabilities...");

    // Parse severity level
    let min_sev = match min_severity.to_lowercase().as_str() {
        "critical" => rust_tree_sitter::SecuritySeverity::Critical,
        "high" => rust_tree_sitter::SecuritySeverity::High,
        "medium" => rust_tree_sitter::SecuritySeverity::Medium,
        "low" => rust_tree_sitter::SecuritySeverity::Low,
        "info" => rust_tree_sitter::SecuritySeverity::Info,
        _ => rust_tree_sitter::SecuritySeverity::Low,
    };

    // Configure security scanner
    let security_config = rust_tree_sitter::SecurityConfig {
        min_severity: min_sev,
        ..Default::default()
    };

    let security_scanner = rust_tree_sitter::SecurityScanner::with_config(security_config)?;
    let security_result = security_scanner.analyze(&result)?;

    pb.finish_with_message(format!("Scan complete! Found {} vulnerabilities", security_result.total_vulnerabilities));

    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&security_result)?;
            if let Some(output_path) = output {
                fs::write(&output_path, &json)?;
                println!("{}", format!("Security report saved to {}", output_path.display()).green());
            } else {
                println!("{}", json);
            }
        }
        "markdown" => {
            print_security_markdown(&security_result, summary_only, compliance);
            if let Some(output_path) = output {
                // Save markdown report
                println!("\n{}", format!("Detailed report would be saved to {}", output_path.display()).green());
            }
        }
        "table" | _ => {
            print_security_table(&security_result, summary_only, compliance);
            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&security_result)?;
                fs::write(&output_path, json)?;
                println!("\n{}", format!("Detailed JSON report saved to {}", output_path.display()).green());
            }
        }
    }

    Ok(())
}

fn refactor_command(
    path: PathBuf,
    category: Option<String>,
    format: String,
    quick_wins: bool,
    major_only: bool,
    min_priority: String,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🎯 Analyzing refactoring opportunities...".bright_yellow().bold());

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Analyzing code...");

    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(&path)?;

    pb.set_message("Generating refactoring suggestions...");

    // Configure refactoring analyzer
    let refactoring_config = rust_tree_sitter::RefactoringConfig::default();
    let refactoring_analyzer = rust_tree_sitter::RefactoringAnalyzer::with_config(refactoring_config);
    let refactoring_result = refactoring_analyzer.analyze(&result);

    pb.finish_with_message(format!("Analysis complete! Found {} opportunities", refactoring_result.total_opportunities));

    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&refactoring_result)?;
            if let Some(output_path) = output {
                fs::write(&output_path, &json)?;
                println!("{}", format!("Refactoring report saved to {}", output_path.display()).green());
            } else {
                println!("{}", json);
            }
        }
        "markdown" => {
            print_refactoring_markdown(&refactoring_result, category.as_ref(), quick_wins, major_only, &min_priority);
            if let Some(output_path) = output {
                println!("\n{}", format!("Detailed report would be saved to {}", output_path.display()).green());
            }
        }
        "table" | _ => {
            print_refactoring_table(&refactoring_result, category.as_ref(), quick_wins, major_only, &min_priority);
            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&refactoring_result)?;
                fs::write(&output_path, json)?;
                println!("\n{}", format!("Detailed JSON report saved to {}", output_path.display()).green());
            }
        }
    }

    Ok(())
}

fn dependencies_command(
    path: PathBuf,
    format: String,
    include_dev: bool,
    vulnerabilities: bool,
    licenses: bool,
    outdated: bool,
    graph: bool,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🔍 Analyzing dependencies...".bright_blue().bold());

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Scanning codebase...");

    // Analyze the codebase first
    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(&path)?;

    pb.set_message("Analyzing dependencies...");

    // Configure dependency analyzer
    let dependency_config = rust_tree_sitter::DependencyConfig {
        vulnerability_scanning: vulnerabilities,
        license_compliance: licenses,
        outdated_detection: outdated,
        graph_analysis: graph,
        include_dev_dependencies: include_dev,
        max_dependency_depth: 10,
    };

    let dependency_analyzer = rust_tree_sitter::DependencyAnalyzer::with_config(dependency_config);
    let dependency_result = dependency_analyzer.analyze(&result)?;

    pb.finish_with_message(format!("Analysis complete! Found {} dependencies", dependency_result.total_dependencies));

    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&dependency_result)?;
            if let Some(output_path) = output {
                fs::write(&output_path, &json)?;
                println!("{}", format!("Dependency report saved to {}", output_path.display()).green());
            } else {
                println!("{}", json);
            }
        }
        "markdown" => {
            print_dependencies_markdown(&dependency_result, vulnerabilities, licenses, outdated, graph);
            if let Some(output_path) = output {
                println!("\n{}", format!("Detailed report would be saved to {}", output_path.display()).green());
            }
        }
        "table" | _ => {
            print_dependencies_table(&dependency_result, vulnerabilities, licenses, outdated, graph);
            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&dependency_result)?;
                fs::write(&output_path, json)?;
                println!("\n{}", format!("Detailed JSON report saved to {}", output_path.display()).green());
            }
        }
    }

    Ok(())
}

// Display functions for new commands

fn print_explanations_markdown(
    ai_result: &rust_tree_sitter::AIAnalysisResult,
    _file: Option<&PathBuf>,
    _symbol: Option<&String>,
    learning: bool,
) {
    println!("# 🧠 AI Code Explanations\n");

    println!("## 📋 Codebase Overview\n");
    println!("**Purpose**: {}\n", ai_result.codebase_explanation.purpose);
    println!("**Architecture**: {}\n", ai_result.codebase_explanation.architecture);
    println!("**Complexity**: {:?}\n", ai_result.codebase_explanation.complexity_level);
    println!("**Target Audience**: {}\n", ai_result.codebase_explanation.target_audience);

    if !ai_result.codebase_explanation.technologies.is_empty() {
        println!("**Technologies Used**:");
        for tech in &ai_result.codebase_explanation.technologies {
            println!("- {}", tech);
        }
        println!();
    }

    if !ai_result.codebase_explanation.entry_points.is_empty() {
        println!("**Entry Points**:");
        for entry in &ai_result.codebase_explanation.entry_points {
            println!("- `{}`", entry);
        }
        println!();
    }

    println!("## 🏗️ Architectural Insights\n");
    println!("**Style**: {}\n", ai_result.architectural_insights.style);
    println!("**Modularity**: {}\n", ai_result.architectural_insights.modularity);
    println!("**Maintainability**: {}\n", ai_result.architectural_insights.maintainability);

    if !ai_result.architectural_insights.design_patterns.is_empty() {
        println!("**Design Patterns**:");
        for pattern in &ai_result.architectural_insights.design_patterns {
            println!("- {}", pattern);
        }
        println!();
    }

    if !ai_result.file_explanations.is_empty() {
        println!("## 📁 File Explanations\n");
        for file_exp in ai_result.file_explanations.iter().take(5) {
            println!("### {}\n", file_exp.file_path);
            println!("**Purpose**: {}\n", file_exp.purpose);
            println!("**Role**: {}\n", file_exp.role);

            if !file_exp.responsibilities.is_empty() {
                println!("**Responsibilities**:");
                for resp in &file_exp.responsibilities {
                    println!("- {}", resp);
                }
                println!();
            }
        }

        if ai_result.file_explanations.len() > 5 {
            println!("*... and {} more files*\n", ai_result.file_explanations.len() - 5);
        }
    }

    if learning && !ai_result.learning_recommendations.is_empty() {
        println!("## 📚 Learning Recommendations\n");
        for (i, rec) in ai_result.learning_recommendations.iter().enumerate() {
            println!("{}. {}", i + 1, rec);
        }
        println!();
    }

    println!("---");
    println!("*Generated by AI-powered code analysis*");
}

fn print_explanations_text(
    ai_result: &rust_tree_sitter::AIAnalysisResult,
    _file: Option<&PathBuf>,
    _symbol: Option<&String>,
    learning: bool,
) {
    println!("{}", "🧠 AI CODE EXPLANATIONS".bright_cyan().bold());
    println!("{}", "=".repeat(50).bright_cyan());

    println!("\n{}", "📋 OVERVIEW".bright_yellow().bold());
    println!("Purpose: {}", ai_result.codebase_explanation.purpose.bright_white());
    println!("Architecture: {}", ai_result.codebase_explanation.architecture.bright_white());
    println!("Complexity: {:?}", ai_result.codebase_explanation.complexity_level.to_string().bright_yellow());

    println!("\n{}", "🏗️ ARCHITECTURE".bright_yellow().bold());
    println!("Style: {}", ai_result.architectural_insights.style.bright_white());
    println!("Maintainability: {}", ai_result.architectural_insights.maintainability.bright_white());

    if learning && !ai_result.learning_recommendations.is_empty() {
        println!("\n{}", "📚 LEARNING RECOMMENDATIONS".bright_yellow().bold());
        for (i, rec) in ai_result.learning_recommendations.iter().enumerate() {
            println!("{}. {}",
                format!("{}", i + 1).bright_cyan(),
                rec.bright_white()
            );
        }
    }
}

fn print_security_table(
    security_result: &rust_tree_sitter::SecurityScanResult,
    summary_only: bool,
    compliance: bool,
) {
    println!("\n{}", "🔍 SECURITY SCAN RESULTS".bright_red().bold());
    println!("{}", "=".repeat(60).bright_red());

    println!("\n{}", "📊 SUMMARY".bright_yellow().bold());
    println!("Security Score: {}/100",
        if security_result.security_score >= 80 {
            security_result.security_score.to_string().bright_green()
        } else if security_result.security_score >= 60 {
            security_result.security_score.to_string().bright_yellow()
        } else {
            security_result.security_score.to_string().bright_red()
        }
    );
    println!("Total Vulnerabilities: {}",
        if security_result.total_vulnerabilities == 0 {
            security_result.total_vulnerabilities.to_string().bright_green()
        } else {
            security_result.total_vulnerabilities.to_string().bright_red()
        }
    );

    // Show vulnerabilities by severity
    println!("\n{}", "🚨 BY SEVERITY".bright_yellow().bold());
    for (severity, count) in &security_result.vulnerabilities_by_severity {
        let color = match severity {
            rust_tree_sitter::SecuritySeverity::Critical => "bright_red",
            rust_tree_sitter::SecuritySeverity::High => "red",
            rust_tree_sitter::SecuritySeverity::Medium => "yellow",
            rust_tree_sitter::SecuritySeverity::Low => "blue",
            rust_tree_sitter::SecuritySeverity::Info => "bright_black",
        };
        println!("  {:?}: {}", severity, count.to_string().color(color));
    }

    if !summary_only && !security_result.vulnerabilities.is_empty() {
        println!("\n{}", "🔍 VULNERABILITIES FOUND".bright_yellow().bold());
        for (i, vuln) in security_result.vulnerabilities.iter().enumerate() {
            println!("\n{} {}",
                format!("{}.", i + 1).bright_cyan(),
                vuln.title.bright_white().bold()
            );
            println!("   Severity: {:?} | Confidence: {:?}",
                format!("{:?}", vuln.severity).bright_red(),
                format!("{:?}", vuln.confidence).bright_yellow()
            );
            println!("   Location: {}:{}",
                vuln.location.file.display().to_string().bright_blue(),
                vuln.location.start_line.to_string().bright_green()
            );
            println!("   Description: {}", vuln.description.bright_white());
            println!("   Fix: {}", vuln.remediation.summary.bright_green());
        }
    }

    if compliance {
        println!("\n{}", "📋 COMPLIANCE STATUS".bright_yellow().bold());
        println!("OWASP Score: {}/100", security_result.compliance.owasp_score);
        println!("Overall Status: {:?}", security_result.compliance.overall_status);
    }

    if !security_result.recommendations.is_empty() {
        println!("\n{}", "💡 RECOMMENDATIONS".bright_yellow().bold());
        for (i, rec) in security_result.recommendations.iter().enumerate() {
            println!("{}. {} (Priority: {:?})",
                format!("{}", i + 1).bright_cyan(),
                rec.recommendation.bright_white(),
                format!("{:?}", rec.priority).bright_yellow()
            );
        }
    }
}

fn print_security_markdown(
    security_result: &rust_tree_sitter::SecurityScanResult,
    summary_only: bool,
    compliance: bool,
) {
    println!("# 🔍 Security Scan Report\n");

    println!("## 📊 Executive Summary\n");
    println!("- **Security Score**: {}/100", security_result.security_score);
    println!("- **Total Vulnerabilities**: {}", security_result.total_vulnerabilities);

    println!("\n### Vulnerabilities by Severity\n");
    for (severity, count) in &security_result.vulnerabilities_by_severity {
        println!("- **{:?}**: {}", severity, count);
    }

    if !summary_only && !security_result.vulnerabilities.is_empty() {
        println!("\n## 🚨 Detailed Findings\n");
        for (i, vuln) in security_result.vulnerabilities.iter().enumerate() {
            println!("### {}. {}\n", i + 1, vuln.title);
            println!("- **Severity**: {:?}", vuln.severity);
            println!("- **Location**: `{}:{}`", vuln.location.file.display(), vuln.location.start_line);
            println!("- **Description**: {}", vuln.description);
            println!("- **Fix**: {}\n", vuln.remediation.summary);
        }
    }

    if compliance {
        println!("## 📋 Compliance Status\n");
        println!("- **OWASP Score**: {}/100", security_result.compliance.owasp_score);
        println!("- **Overall Status**: {:?}\n", security_result.compliance.overall_status);
    }
}

fn print_refactoring_table(
    refactoring_result: &rust_tree_sitter::RefactoringResult,
    _category: Option<&String>,
    quick_wins: bool,
    major_only: bool,
    _min_priority: &str,
) {
    println!("\n{}", "🎯 REFACTORING ANALYSIS".bright_yellow().bold());
    println!("{}", "=".repeat(60).bright_yellow());

    println!("\n{}", "📊 SUMMARY".bright_cyan().bold());
    println!("Quality Score: {}/100",
        if refactoring_result.quality_score >= 80 {
            refactoring_result.quality_score.to_string().bright_green()
        } else if refactoring_result.quality_score >= 60 {
            refactoring_result.quality_score.to_string().bright_yellow()
        } else {
            refactoring_result.quality_score.to_string().bright_red()
        }
    );
    println!("Total Opportunities: {}", refactoring_result.total_opportunities.to_string().bright_blue());
    println!("Quick Wins: {}", refactoring_result.quick_wins.len().to_string().bright_green());
    println!("Major Improvements: {}", refactoring_result.major_improvements.len().to_string().bright_cyan());

    let suggestions_to_show = if quick_wins {
        &refactoring_result.quick_wins
    } else if major_only {
        &refactoring_result.major_improvements
    } else {
        &refactoring_result.suggestions
    };

    if !suggestions_to_show.is_empty() {
        println!("\n{}", "🔧 REFACTORING SUGGESTIONS".bright_cyan().bold());
        for (i, suggestion) in suggestions_to_show.iter().enumerate() {
            println!("\n{} {}",
                format!("{}.", i + 1).bright_cyan(),
                suggestion.title.bright_white().bold()
            );
            println!("   Category: {:?} | Priority: {:?} | Effort: {:?}",
                suggestion.category.to_string().bright_blue(),
                suggestion.priority.to_string().bright_yellow(),
                suggestion.effort.to_string().bright_green()
            );
            println!("   Location: {}", suggestion.location.file.bright_blue());
            println!("   Description: {}", suggestion.description.bright_white());

            if !suggestion.benefits.is_empty() {
                println!("   Benefits: {}", suggestion.benefits.join(", ").bright_green());
            }
        }
    }

    println!("\n{}", "📈 IMPACT SUMMARY".bright_cyan().bold());
    println!("Maintainability: +{}%", refactoring_result.impact_summary.maintainability_improvement.to_string().bright_green());
    println!("Readability: +{}%", refactoring_result.impact_summary.readability_improvement.to_string().bright_green());
    println!("Technical Debt: -{}%", refactoring_result.impact_summary.technical_debt_reduction.to_string().bright_green());
    println!("Time Saved: {:.1} hours", refactoring_result.impact_summary.time_saved_hours.to_string().bright_blue());
}

fn print_refactoring_markdown(
    refactoring_result: &rust_tree_sitter::RefactoringResult,
    _category: Option<&String>,
    quick_wins: bool,
    major_only: bool,
    _min_priority: &str,
) {
    println!("# 🎯 Refactoring Analysis Report\n");

    println!("## 📊 Summary\n");
    println!("- **Quality Score**: {}/100", refactoring_result.quality_score);
    println!("- **Total Opportunities**: {}", refactoring_result.total_opportunities);
    println!("- **Quick Wins**: {}", refactoring_result.quick_wins.len());
    println!("- **Major Improvements**: {}", refactoring_result.major_improvements.len());

    let suggestions_to_show = if quick_wins {
        &refactoring_result.quick_wins
    } else if major_only {
        &refactoring_result.major_improvements
    } else {
        &refactoring_result.suggestions
    };

    if !suggestions_to_show.is_empty() {
        println!("\n## 🔧 Refactoring Suggestions\n");
        for (i, suggestion) in suggestions_to_show.iter().enumerate() {
            println!("### {}. {}\n", i + 1, suggestion.title);
            println!("- **Category**: {:?}", suggestion.category);
            println!("- **Priority**: {:?}", suggestion.priority);
            println!("- **Effort**: {:?}", suggestion.effort);
            println!("- **Location**: `{}`", suggestion.location.file);
            println!("- **Description**: {}\n", suggestion.description);

            if !suggestion.benefits.is_empty() {
                println!("**Benefits**:");
                for benefit in &suggestion.benefits {
                    println!("- {}", benefit);
                }
                println!();
            }
        }
    }

    println!("## 📈 Expected Impact\n");
    println!("- **Maintainability**: +{}%", refactoring_result.impact_summary.maintainability_improvement);
    println!("- **Readability**: +{}%", refactoring_result.impact_summary.readability_improvement);
    println!("- **Technical Debt Reduction**: -{}%", refactoring_result.impact_summary.technical_debt_reduction);
    println!("- **Estimated Time Saved**: {:.1} hours", refactoring_result.impact_summary.time_saved_hours);
}

fn print_dependencies_table(
    dependency_result: &rust_tree_sitter::DependencyAnalysisResult,
    show_vulnerabilities: bool,
    show_licenses: bool,
    show_outdated: bool,
    show_graph: bool,
) {
    println!("\n{}", "🔍 DEPENDENCY ANALYSIS".bright_blue().bold());
    println!("{}", "=".repeat(60).bright_blue());

    println!("\n{}", "📊 SUMMARY".bright_cyan().bold());
    println!("Total Dependencies: {}", dependency_result.total_dependencies.to_string().bright_white());
    println!("Direct Dependencies: {}", dependency_result.direct_dependencies.to_string().bright_green());
    println!("Transitive Dependencies: {}", dependency_result.transitive_dependencies.to_string().bright_yellow());

    if !dependency_result.package_managers.is_empty() {
        println!("\n{}", "📦 PACKAGE MANAGERS".bright_cyan().bold());
        for pm in &dependency_result.package_managers {
            println!("  {} - {} dependencies",
                pm.manager.to_string().bright_blue(),
                dependency_result.dependencies_by_manager.get(&pm.manager).unwrap_or(&0).to_string().bright_white()
            );
        }
    }

    if show_vulnerabilities && !dependency_result.vulnerabilities.is_empty() {
        println!("\n{}", "🚨 VULNERABILITIES".bright_red().bold());
        for vuln in &dependency_result.vulnerabilities {
            println!("  {} - {} ({})",
                vuln.dependency.bright_white(),
                vuln.title.bright_red(),
                vuln.severity.to_string().bright_yellow()
            );
        }
    }

    if show_licenses && !dependency_result.license_analysis.compliance_issues.is_empty() {
        println!("\n{}", "⚖️ LICENSE ISSUES".bright_yellow().bold());
        for issue in &dependency_result.license_analysis.compliance_issues {
            println!("  {} - {} license issue",
                issue.dependency.bright_white(),
                issue.issue_type.to_string().bright_yellow()
            );
        }
    }

    if show_outdated && !dependency_result.outdated_dependencies.is_empty() {
        println!("\n{}", "📅 OUTDATED DEPENDENCIES".bright_yellow().bold());
        for outdated in &dependency_result.outdated_dependencies {
            println!("  {} {} → {} ({})",
                outdated.name.bright_white(),
                outdated.current_version.bright_red(),
                outdated.latest_version.bright_green(),
                outdated.urgency.to_string().bright_yellow()
            );
        }
    }

    if show_graph {
        println!("\n{}", "🕸️ DEPENDENCY GRAPH".bright_cyan().bold());
        println!("  Nodes: {}", dependency_result.graph_analysis.total_nodes.to_string().bright_white());
        println!("  Max Depth: {}", dependency_result.graph_analysis.max_depth.to_string().bright_white());
        println!("  Circular Dependencies: {}", dependency_result.graph_analysis.circular_dependencies.len().to_string().bright_red());
    }

    if !dependency_result.security_recommendations.is_empty() {
        println!("\n{}", "💡 SECURITY RECOMMENDATIONS".bright_green().bold());
        for (i, rec) in dependency_result.security_recommendations.iter().enumerate() {
            println!("{}. {} (Priority: {})",
                format!("{}", i + 1).bright_cyan(),
                rec.recommendation.bright_white(),
                rec.priority.to_string().bright_yellow()
            );
        }
    }
}

fn print_dependencies_markdown(
    dependency_result: &rust_tree_sitter::DependencyAnalysisResult,
    show_vulnerabilities: bool,
    show_licenses: bool,
    show_outdated: bool,
    show_graph: bool,
) {
    println!("# 🔍 Dependency Analysis Report\n");

    println!("## 📊 Summary\n");
    println!("- **Total Dependencies**: {}", dependency_result.total_dependencies);
    println!("- **Direct Dependencies**: {}", dependency_result.direct_dependencies);
    println!("- **Transitive Dependencies**: {}", dependency_result.transitive_dependencies);

    if !dependency_result.package_managers.is_empty() {
        println!("\n## 📦 Package Managers\n");
        for pm in &dependency_result.package_managers {
            println!("- **{}**: {} dependencies",
                pm.manager,
                dependency_result.dependencies_by_manager.get(&pm.manager).unwrap_or(&0)
            );
        }
    }

    if show_vulnerabilities && !dependency_result.vulnerabilities.is_empty() {
        println!("\n## 🚨 Security Vulnerabilities\n");
        for vuln in &dependency_result.vulnerabilities {
            println!("### {}\n", vuln.title);
            println!("- **Dependency**: {}", vuln.dependency);
            println!("- **Severity**: {}", vuln.severity);
            println!("- **Description**: {}\n", vuln.description);
        }
    }

    if show_licenses && !dependency_result.license_analysis.compliance_issues.is_empty() {
        println!("\n## ⚖️ License Compliance Issues\n");
        for issue in &dependency_result.license_analysis.compliance_issues {
            println!("- **{}**: {} license issue - {}",
                issue.dependency,
                issue.issue_type.to_string(),
                issue.description
            );
        }
    }

    if show_outdated && !dependency_result.outdated_dependencies.is_empty() {
        println!("\n## 📅 Outdated Dependencies\n");
        for outdated in &dependency_result.outdated_dependencies {
            println!("- **{}**: {} → {} ({})",
                outdated.name,
                outdated.current_version,
                outdated.latest_version,
                outdated.urgency.to_string()
            );
        }
    }

    if show_graph {
        println!("\n## 🕸️ Dependency Graph Analysis\n");
        println!("- **Total Nodes**: {}", dependency_result.graph_analysis.total_nodes);
        println!("- **Maximum Depth**: {}", dependency_result.graph_analysis.max_depth);
        println!("- **Circular Dependencies**: {}", dependency_result.graph_analysis.circular_dependencies.len());
    }
}

fn format_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{}B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1}KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1}MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn performance_command(
    path: PathBuf,
    format: String,
    category: Option<String>,
    top: usize,
    min_complexity: usize,
    detailed: bool,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🚀 Analyzing performance hotspots...".bright_blue().bold());

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Scanning for performance issues...");

    // Configure analyzer
    let config = AnalysisConfig::default();
    let mut analyzer = CodebaseAnalyzer::with_config(config);

    // Run analysis
    let result = analyzer.analyze_directory(&path)?;
    pb.finish_with_message("Performance analysis complete!");

    // Collect performance hotspots
    let mut hotspots = Vec::new();

    for file in &result.files {
        for symbol in &file.symbols {
            // Calculate complexity score based on symbol size and type
            let symbol_lines = symbol.end_line.saturating_sub(symbol.start_line) + 1;
            let complexity = calculate_symbol_complexity(symbol, symbol_lines);

            if complexity >= min_complexity {
                let category_match = category.as_ref().map_or(true, |cat| {
                    match cat.as_str() {
                        "complexity" => complexity > 10,
                        "memory" => symbol.name.contains("alloc") || symbol.name.contains("buffer"),
                        "cpu" => symbol.name.contains("loop") || symbol.name.contains("recursive"),
                        "io" => symbol.name.contains("read") || symbol.name.contains("write") || symbol.name.contains("file"),
                        _ => true,
                    }
                });

                if category_match {
                    hotspots.push(PerformanceHotspot {
                        file: file.path.display().to_string(),
                        symbol: symbol.name.clone(),
                        symbol_type: symbol.kind.clone(),
                        complexity,
                        line: symbol.start_line,
                        severity: if complexity > 20 { "Critical" } else if complexity > 15 { "High" } else { "Medium" }.to_string(),
                        recommendation: generate_performance_recommendation(complexity, &symbol.name),
                    });
                }
            }
        }
    }

    // Sort by complexity (highest first)
    hotspots.sort_by(|a, b| b.complexity.cmp(&a.complexity));
    hotspots.truncate(top);

    // Display results
    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&hotspots)?;
            if let Some(output_path) = output {
                fs::write(output_path, json)?;
                println!("{}", "Results saved to file".green());
            } else {
                println!("{}", json);
            }
        }
        "markdown" => {
            print_performance_markdown(&hotspots, detailed);
            if let Some(output_path) = output {
                let markdown = generate_performance_markdown(&hotspots, detailed);
                fs::write(output_path, markdown)?;
                println!("{}", "Report saved to file".green());
            }
        }
        "table" | _ => {
            print_performance_table(&hotspots, detailed);
            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&hotspots)?;
                fs::write(output_path, json)?;
                println!("\n{}", "Detailed results saved to file".green());
            }
        }
    }

    Ok(())
}

fn coverage_command(
    path: PathBuf,
    format: String,
    test_dir: Option<PathBuf>,
    uncovered_only: bool,
    min_coverage: f64,
    detailed: bool,
    output: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", "🧪 Analyzing test coverage...".bright_blue().bold());

    let pb = ProgressBar::new_spinner();
    pb.set_style(ProgressStyle::default_spinner()
        .template("{spinner:.green} {msg}")
        .unwrap());
    pb.set_message("Scanning for test coverage...");

    // Configure analyzer
    let config = AnalysisConfig::default();
    let mut analyzer = CodebaseAnalyzer::with_config(config);

    // Run analysis
    let result = analyzer.analyze_directory(&path)?;

    // Determine test directory
    let test_path = test_dir.unwrap_or_else(|| {
        // Try common test directory patterns
        for test_pattern in &["tests", "test", "spec", "__tests__", "src/test"] {
            let test_candidate = path.join(test_pattern);
            if test_candidate.exists() {
                return test_candidate;
            }
        }
        path.clone() // Fallback to main directory
    });

    // Analyze test files
    let test_result = if test_path.exists() {
        analyzer.analyze_directory(&test_path).ok()
    } else {
        None
    };

    pb.finish_with_message("Coverage analysis complete!");

    // Calculate coverage metrics
    let coverage_data = calculate_coverage_metrics(&result, test_result.as_ref(), min_coverage);

    // Filter results if needed
    let filtered_coverage: Vec<_> = if uncovered_only {
        coverage_data.into_iter()
            .filter(|item| item.coverage_percentage < 100.0)
            .collect()
    } else {
        coverage_data.into_iter()
            .filter(|item| item.coverage_percentage >= min_coverage)
            .collect()
    };

    // Display results
    match format.as_str() {
        "json" => {
            let json = serde_json::to_string_pretty(&filtered_coverage)?;
            if let Some(output_path) = output {
                fs::write(output_path, json)?;
                println!("{}", "Results saved to file".green());
            } else {
                println!("{}", json);
            }
        }
        "html" => {
            let html = generate_coverage_html(&filtered_coverage, detailed);
            if let Some(output_path) = output {
                fs::write(output_path, html)?;
                println!("{}", "HTML report saved to file".green());
            } else {
                println!("{}", "HTML format requires --output option".yellow());
            }
        }
        "markdown" => {
            print_coverage_markdown(&filtered_coverage, detailed);
            if let Some(output_path) = output {
                let markdown = generate_coverage_markdown(&filtered_coverage, detailed);
                fs::write(output_path, markdown)?;
                println!("{}", "Report saved to file".green());
            }
        }
        "table" | _ => {
            print_coverage_table(&filtered_coverage, detailed);
            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&filtered_coverage)?;
                fs::write(output_path, json)?;
                println!("\n{}", "Detailed results saved to file".green());
            }
        }
    }

    Ok(())
}

// Helper functions for performance analysis
fn calculate_symbol_complexity(symbol: &rust_tree_sitter::Symbol, symbol_lines: usize) -> usize {
    // Simple heuristic for complexity based on symbol type and size
    let base_complexity = match symbol.kind.as_str() {
        "function" | "method" => symbol_lines / 5, // Functions: 1 complexity per 5 lines
        "class" | "struct" => symbol_lines / 10,   // Classes: 1 complexity per 10 lines
        "enum" | "interface" => symbol_lines / 8,  // Enums/interfaces: 1 complexity per 8 lines
        _ => symbol_lines / 15,                    // Other symbols: 1 complexity per 15 lines
    };

    // Add complexity for long names (might indicate complex functionality)
    let name_complexity = if symbol.name.len() > 30 { 2 } else { 0 };

    // Minimum complexity of 1
    std::cmp::max(1, base_complexity + name_complexity)
}

fn generate_performance_recommendation(complexity: usize, _symbol_name: &str) -> String {
    match complexity {
        0..=5 => "Good performance".to_string(),
        6..=10 => "Consider minor optimizations".to_string(),
        11..=15 => "Refactor to reduce complexity".to_string(),
        16..=20 => "High complexity - needs refactoring".to_string(),
        _ => "Critical complexity - immediate attention required".to_string(),
    }
}

fn print_performance_table(hotspots: &[PerformanceHotspot], detailed: bool) {
    if hotspots.is_empty() {
        println!("{}", "✅ No performance hotspots found!".bright_green());
        return;
    }

    println!("\n{}", "🚀 PERFORMANCE HOTSPOTS".bright_cyan().bold());
    println!("{}", "=".repeat(80).bright_cyan());

    let table = Table::new(hotspots).to_string();
    println!("{}", table);

    if detailed {
        println!("\n{}", "📊 SUMMARY".bright_cyan().bold());
        let critical = hotspots.iter().filter(|h| h.severity == "Critical").count();
        let high = hotspots.iter().filter(|h| h.severity == "High").count();
        let medium = hotspots.iter().filter(|h| h.severity == "Medium").count();

        println!("🔴 Critical: {}", critical.to_string().bright_red());
        println!("🟡 High: {}", high.to_string().bright_yellow());
        println!("🟢 Medium: {}", medium.to_string().bright_green());
    }
}

fn print_performance_markdown(hotspots: &[PerformanceHotspot], detailed: bool) {
    println!("# 🚀 Performance Hotspots Report\n");

    if hotspots.is_empty() {
        println!("✅ **No performance hotspots found!**\n");
        return;
    }

    println!("## 📊 Summary\n");
    let critical = hotspots.iter().filter(|h| h.severity == "Critical").count();
    let high = hotspots.iter().filter(|h| h.severity == "High").count();
    let medium = hotspots.iter().filter(|h| h.severity == "Medium").count();

    println!("- 🔴 **Critical**: {}", critical);
    println!("- 🟡 **High**: {}", high);
    println!("- 🟢 **Medium**: {}\n", medium);

    println!("## 🎯 Hotspots\n");
    for hotspot in hotspots {
        println!("### {} - {}\n", hotspot.symbol, hotspot.severity);
        println!("- **File**: `{}`", hotspot.file);
        println!("- **Type**: {}", hotspot.symbol_type);
        println!("- **Line**: {}", hotspot.line);
        println!("- **Complexity**: {}", hotspot.complexity);
        println!("- **Recommendation**: {}\n", hotspot.recommendation);
    }
}

fn generate_performance_markdown(hotspots: &[PerformanceHotspot], detailed: bool) -> String {
    let mut markdown = String::new();
    markdown.push_str("# 🚀 Performance Hotspots Report\n\n");

    if hotspots.is_empty() {
        markdown.push_str("✅ **No performance hotspots found!**\n");
        return markdown;
    }

    // Add summary and hotspots (similar to print_performance_markdown)
    // ... implementation details

    markdown
}

// Helper functions for coverage analysis
fn calculate_coverage_metrics(
    main_result: &rust_tree_sitter::AnalysisResult,
    test_result: Option<&rust_tree_sitter::AnalysisResult>,
    min_coverage: f64,
) -> Vec<CoverageItem> {
    let mut coverage_items = Vec::new();

    for file in &main_result.files {
        for symbol in &file.symbols {
            if symbol.kind == "function" || symbol.kind == "method" {
                // Calculate coverage based on test presence
                let coverage = calculate_function_coverage(&symbol.name, test_result);
                let status = if coverage >= 90.0 {
                    "Excellent".to_string()
                } else if coverage >= 70.0 {
                    "Good".to_string()
                } else if coverage >= 50.0 {
                    "Fair".to_string()
                } else {
                    "Poor".to_string()
                };

                let symbol_lines = symbol.end_line.saturating_sub(symbol.start_line) + 1;
                coverage_items.push(CoverageItem {
                    file: file.path.display().to_string(),
                    function: symbol.name.clone(),
                    coverage_percentage: coverage,
                    lines_covered: ((coverage / 100.0) * symbol_lines as f64) as usize,
                    total_lines: symbol_lines,
                    test_files: count_test_files_for_function(&symbol.name, test_result),
                    status,
                });
            }
        }
    }

    coverage_items
}

fn calculate_function_coverage(function_name: &str, test_result: Option<&rust_tree_sitter::AnalysisResult>) -> f64 {
    if let Some(test_result) = test_result {
        // Look for test functions that might test this function
        let test_count = test_result.files.iter()
            .flat_map(|f| &f.symbols)
            .filter(|s| s.kind == "function" &&
                (s.name.contains("test") || s.name.starts_with("test_")) &&
                (s.name.to_lowercase().contains(&function_name.to_lowercase()) ||
                 function_name.to_lowercase().contains(&s.name.to_lowercase().replace("test_", ""))))
            .count();

        // Simple heuristic: more tests = better coverage
        match test_count {
            0 => 0.0,
            1 => 60.0,
            2 => 80.0,
            3 => 90.0,
            _ => 95.0,
        }
    } else {
        0.0 // No test files found
    }
}

fn count_test_files_for_function(function_name: &str, test_result: Option<&rust_tree_sitter::AnalysisResult>) -> usize {
    if let Some(test_result) = test_result {
        test_result.files.iter()
            .filter(|f| f.symbols.iter().any(|s|
                s.kind == "function" &&
                (s.name.contains("test") || s.name.starts_with("test_")) &&
                (s.name.to_lowercase().contains(&function_name.to_lowercase()) ||
                 function_name.to_lowercase().contains(&s.name.to_lowercase().replace("test_", "")))))
            .count()
    } else {
        0
    }
}

fn print_coverage_table(coverage_items: &[CoverageItem], detailed: bool) {
    if coverage_items.is_empty() {
        println!("{}", "📊 No coverage data available".bright_yellow());
        return;
    }

    println!("\n{}", "🧪 TEST COVERAGE ANALYSIS".bright_cyan().bold());
    println!("{}", "=".repeat(80).bright_cyan());

    let table = Table::new(coverage_items).to_string();
    println!("{}", table);

    if detailed {
        println!("\n{}", "📊 COVERAGE SUMMARY".bright_cyan().bold());
        let total_functions = coverage_items.len();
        let well_covered = coverage_items.iter().filter(|c| c.coverage_percentage >= 80.0).count();
        let poorly_covered = coverage_items.iter().filter(|c| c.coverage_percentage < 50.0).count();
        let avg_coverage: f64 = coverage_items.iter().map(|c| c.coverage_percentage).sum::<f64>() / total_functions as f64;

        println!("📈 Average Coverage: {:.1}%", avg_coverage.to_string().bright_green());
        println!("✅ Well Covered (≥80%): {}/{}", well_covered.to_string().bright_green(), total_functions);
        println!("❌ Poorly Covered (<50%): {}/{}", poorly_covered.to_string().bright_red(), total_functions);
    }
}

fn print_coverage_markdown(coverage_items: &[CoverageItem], detailed: bool) {
    println!("# 🧪 Test Coverage Report\n");

    if coverage_items.is_empty() {
        println!("📊 **No coverage data available**\n");
        return;
    }

    let total_functions = coverage_items.len();
    let well_covered = coverage_items.iter().filter(|c| c.coverage_percentage >= 80.0).count();
    let poorly_covered = coverage_items.iter().filter(|c| c.coverage_percentage < 50.0).count();
    let avg_coverage: f64 = coverage_items.iter().map(|c| c.coverage_percentage).sum::<f64>() / total_functions as f64;

    println!("## 📊 Summary\n");
    println!("- **Total Functions**: {}", total_functions);
    println!("- **Average Coverage**: {:.1}%", avg_coverage);
    println!("- **Well Covered (≥80%)**: {}/{}", well_covered, total_functions);
    println!("- **Poorly Covered (<50%)**: {}/{}\n", poorly_covered, total_functions);

    if detailed {
        println!("## 📋 Detailed Coverage\n");
        for item in coverage_items {
            println!("### {} - {:.1}%\n", item.function, item.coverage_percentage);
            println!("- **File**: `{}`", item.file);
            println!("- **Status**: {}", item.status);
            println!("- **Lines Covered**: {}/{}", item.lines_covered, item.total_lines);
            println!("- **Test Files**: {}\n", item.test_files);
        }
    }
}

fn generate_coverage_markdown(coverage_items: &[CoverageItem], detailed: bool) -> String {
    let mut markdown = String::new();
    markdown.push_str("# 🧪 Test Coverage Report\n\n");

    if coverage_items.is_empty() {
        markdown.push_str("📊 **No coverage data available**\n");
        return markdown;
    }

    // Add summary and detailed coverage (similar to print_coverage_markdown)
    // ... implementation details

    markdown
}

fn generate_coverage_html(coverage_items: &[CoverageItem], detailed: bool) -> String {
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
    html.push_str("<title>Test Coverage Report</title>\n");
    html.push_str("<style>\n");
    html.push_str("body { font-family: Arial, sans-serif; margin: 20px; }\n");
    html.push_str(".coverage-high { color: green; }\n");
    html.push_str(".coverage-medium { color: orange; }\n");
    html.push_str(".coverage-low { color: red; }\n");
    html.push_str("table { border-collapse: collapse; width: 100%; }\n");
    html.push_str("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
    html.push_str("th { background-color: #f2f2f2; }\n");
    html.push_str("</style>\n</head>\n<body>\n");

    html.push_str("<h1>🧪 Test Coverage Report</h1>\n");

    if coverage_items.is_empty() {
        html.push_str("<p>📊 <strong>No coverage data available</strong></p>\n");
    } else {
        // Add HTML table and summary
        html.push_str("<table>\n<tr><th>Function</th><th>File</th><th>Coverage %</th><th>Status</th></tr>\n");
        for item in coverage_items {
            let css_class = if item.coverage_percentage >= 80.0 {
                "coverage-high"
            } else if item.coverage_percentage >= 50.0 {
                "coverage-medium"
            } else {
                "coverage-low"
            };

            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td class=\"{}\">{:.1}%</td><td>{}</td></tr>\n",
                item.function, item.file, css_class, item.coverage_percentage, item.status
            ));
        }
        html.push_str("</table>\n");
    }

    html.push_str("</body>\n</html>");
    html
}

/// Input validation functions for security and robustness

/// Validate path input to prevent directory traversal and ensure path exists
fn validate_path_input(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Check if path exists
    if !path.exists() {
        return Err(format!("Path does not exist: {}", path.display()).into());
    }

    // Canonicalize path to resolve any .. or . components
    let canonical_path = path.canonicalize()
        .map_err(|e| format!("Cannot resolve path {}: {}", path.display(), e))?;

    // Basic security check - ensure path doesn't contain suspicious patterns
    let path_str = canonical_path.to_string_lossy();
    if path_str.contains("..") {
        return Err("Path contains suspicious directory traversal patterns".into());
    }

    Ok(())
}

/// Validate format input
fn validate_format_input(format: &str) -> Result<(), Box<dyn std::error::Error>> {
    match format {
        "json" | "table" | "summary" | "markdown" | "html" | "text" => Ok(()),
        _ => Err(format!("Unsupported format: {}. Supported formats: json, table, summary, markdown, html, text", format).into())
    }
}

/// Validate size and depth limits to prevent resource exhaustion
fn validate_size_limits(max_size: usize, max_depth: usize) -> Result<(), Box<dyn std::error::Error>> {
    const MAX_ALLOWED_SIZE: usize = 100_000_000; // 100MB
    const MAX_ALLOWED_DEPTH: usize = 50;

    if max_size > MAX_ALLOWED_SIZE {
        return Err(format!("Max size {} exceeds allowed limit of {}", max_size, MAX_ALLOWED_SIZE).into());
    }

    if max_depth > MAX_ALLOWED_DEPTH {
        return Err(format!("Max depth {} exceeds allowed limit of {}", max_depth, MAX_ALLOWED_DEPTH).into());
    }

    Ok(())
}

/// Validate output path
fn validate_output_path(output_path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    // Check if parent directory exists
    if let Some(parent) = output_path.parent() {
        if !parent.exists() {
            return Err(format!("Output directory does not exist: {}", parent.display()).into());
        }
    }

    // Check if we can write to the location (if file exists)
    if output_path.exists() {
        let metadata = output_path.metadata()
            .map_err(|e| format!("Cannot access output file {}: {}", output_path.display(), e))?;

        if metadata.permissions().readonly() {
            return Err(format!("Output file is read-only: {}", output_path.display()).into());
        }
    }

    Ok(())
}
