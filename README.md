# Rust Tree-sitter Agent Code Utility

A Rust library for parsing and analyzing source code using tree-sitter. Provides abstractions for parsing, navigating, and querying syntax trees across multiple programming languages with analysis capabilities for security, performance, and code quality.

Built for developers and AI systems that need code analysis tools and insights into code structure and quality.

## Table of Contents

- [Features](#features)
- [CLI Commands](#cli-commands)
- [Quick Start](#quick-start)
- [Library Usage](#library-usage)
- [Supported Languages](#supported-languages)
- [Test Coverage](#test-coverage)
- [Contributing](#contributing)
- [License](#license)

## Features

### Core Language Support

- **7 Programming Languages**: Rust, JavaScript, TypeScript, Python, C, C++, Go
- **Language Detection**: Automatic detection from file extensions and content analysis
- **Symbol Extraction**: Functions, classes, structs, methods, types, interfaces, implementations
- **Language Features**: Language-specific construct detection and analysis

### Analysis Capabilities

- **Codebase Analysis**: Directory analysis with file metrics, symbol extraction, and statistics
- **Security Scanning**: Pattern-based vulnerability detection with OWASP categorization and semantic context tracking
- **Performance Analysis**: Cyclomatic complexity calculation and optimization recommendations
- **Dependency Analysis**: Package manager file parsing (package.json, requirements.txt, Cargo.toml, go.mod)
- **Code Quality Analysis**: Code smell detection and refactoring suggestions
- **Intent Mapping**: Requirements to implementation mapping for development workflow
- **Semantic Context Tracking**: Advanced false positive reduction through contextual analysis

### Advanced Features

- **Semantic Context Tracking**: Multi-phase semantic analysis for 50% false positive reduction
- **Symbol Table Analysis**: Hierarchical scope management with comprehensive symbol tracking
- **Data Flow Analysis**: Reaching definitions, use-def chains, and taint flow tracking
- **Security Context Analysis**: Validation/sanitization point detection with trust level tracking
- **Semantic Knowledge Graphs**: Build and query relationships between code elements
- **Automated Reasoning**: Logic-based code analysis and inference capabilities
- **Smart Refactoring Engine**: Code improvement suggestions and automated refactoring

### CLI Interface

- **Available Commands**: analyze, security, refactor, dependencies, symbols, query, find, map, explain, insights, interactive
- **Output Formats**: JSON, table, markdown, summary
- **Progress Tracking**: Real-time progress indicators
- **Filtering**: Severity levels, file types, symbol types
- **Interactive Mode**: Real-time code exploration

## CLI Commands

### `analyze` - Codebase Analysis
Analyze directory structure, extract symbols, and generate statistics.

```bash
tree-sitter-cli analyze <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json, summary [default: table]
  -d, --detailed          Show detailed analysis
  --max-depth <DEPTH>     Maximum directory depth to analyze
```

**Example:**
```bash
tree-sitter-cli analyze ./src --format json
```

### `security` - Security Vulnerability Scanning

Pattern-based security analysis with vulnerability detection and compliance assessment.

```bash
tree-sitter-cli security <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>         Output format: table, json, markdown [default: table]
  --min-severity <SEVERITY>     Minimum severity: critical, high, medium, low, info [default: medium]
  --output <FILE>               Save detailed report to file
  --summary-only                Show summary only
  --compliance                  Include compliance assessment
  --depth <LEVEL>               Analysis depth: basic, deep, full [default: full]
```

**Example:**

```bash
tree-sitter-cli security ./src --min-severity high --format json
```

**Detection Capabilities:**

- **OWASP Patterns**: SQL injection, XSS, insecure deserialization, broken authentication
- **Code Injection**: Command injection, code execution vulnerabilities
- **Input Validation**: Missing validation patterns and sanitization
- **Authorization**: Missing access controls and privilege escalation
- **Cryptographic Issues**: Weak algorithms and insecure practices
- **Compliance Assessment**: OWASP and CWE compliance scoring

### `symbols` - Symbol Extraction
Extract and display code symbols (functions, classes, structs, etc.).

```bash
tree-sitter-cli symbols <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json [default: table]
```

**Example:**
```bash
tree-sitter-cli symbols ./src --format json
```

**Extracts:**
- Functions and methods
- Classes and structs
- Interfaces and traits
- Implementations
- Types and enums
- Visibility information
- Line numbers and locations

### `refactor` - Smart Refactoring Engine

Code improvement suggestions with refactoring capabilities.

```bash
tree-sitter-cli refactor <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json, markdown [default: table]
  --category <CATEGORY>    Focus category: all, code_smells, patterns, performance
  --quick-wins             Show only quick wins
  --major-only             Show only major improvements
  --min-priority <LEVEL>   Minimum priority: low, medium, high, critical
  --output <FILE>          Save detailed report to file
```

**Capabilities:**

- **Code Smell Detection**: Identify anti-patterns and code quality issues
- **Design Pattern Recommendations**: Suggest appropriate design patterns
- **Modernization Suggestions**: Update code to use modern language features
- **Performance Optimization**: Identify and suggest performance improvements
- **Complexity Reduction**: Simplify overly complex code structures

### `dependencies` - Dependency Analysis

Dependency analysis with package manager integration.

```bash
tree-sitter-cli dependencies <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json, markdown [default: table]
  --include-dev            Include development dependencies
  --vulnerabilities        Enable vulnerability scanning
  --licenses               Enable license compliance checking
  --outdated               Show outdated dependencies
  --graph                  Show dependency graph analysis
  --output <FILE>          Save detailed report to file
```

**Features:**

- **Multi-Language Support**: package.json (Node.js), requirements.txt (Python), Cargo.toml (Rust), go.mod (Go)
- **Dependency Tree**: Visualize dependency relationships
- **License Analysis**: Identify license information
- **Update Information**: Show outdated dependencies

### `query` - Code Querying

Code search and analysis using tree-sitter queries.

```bash
tree-sitter-cli query <PATH> [OPTIONS]

Options:
  -p, --pattern <PATTERN>  Tree-sitter query pattern
  -l, --language <LANG>    Target specific language
  -c, --context <LINES>    Show context lines around matches [default: 2]
  -f, --format <FORMAT>    Output format: table, json [default: table]
```

### `find` - Symbol Search

Find symbols and patterns across the codebase.

```bash
tree-sitter-cli find <PATH> [OPTIONS]

Options:
  --name <PATTERN>         Symbol name pattern
  --symbol-type <TYPE>     Symbol type filter
  --language <LANG>        Target specific language
  --public-only            Show only public symbols
```

### `map` - Code Structure Mapping

Generate visual maps of code structure and relationships.

```bash
tree-sitter-cli map <PATH> [OPTIONS]

Options:
  --map-type <TYPE>        Map type: overview, tree, symbols, dependencies
  -f, --format <FORMAT>    Output format: unicode, ascii, json, mermaid
  --max-depth <DEPTH>      Maximum depth to show
  --show-sizes             Show file sizes
  --show-symbols           Show symbol counts
  --languages <LANGS>      Filter by languages
  --collapse-empty         Collapse empty directories
```

### `explain` - Code Explanation

Generate explanations of code functionality and architecture.

```bash
tree-sitter-cli explain <PATH> [OPTIONS]

Options:
  --file <FILE>            Specific file to explain
  --symbol <SYMBOL>        Specific symbol to explain
  -f, --format <FORMAT>    Output format: markdown, json [default: markdown]
  --detailed               Include detailed analysis
  --learning               Include learning recommendations
```

### `insights` - Codebase Insights

Generate insights and recommendations for the codebase.

```bash
tree-sitter-cli insights <PATH> [OPTIONS]

Options:
  --focus <AREA>           Focus area: all, architecture, quality, complexity
  -f, --format <FORMAT>    Output format: markdown, json, text [default: markdown]
```

### `interactive` - Interactive Mode

Enter interactive mode for real-time code exploration.

```bash
tree-sitter-cli interactive <PATH>
```

### `stats` - Codebase Statistics

Show comprehensive statistics about the codebase.

```bash
tree-sitter-cli stats <PATH> [OPTIONS]

Options:
  --top <N>                Show top N files by various metrics [default: 10]
```

## Quick Start

### CLI Installation

```bash
# Clone the repository
git clone https://github.com/njfio/rust-treesitter-agent-code-utility.git
cd rust-treesitter-agent-code-utility

# Build the CLI tool
cargo build --release --bin tree-sitter-cli

# Run analysis on your code
./target/release/tree-sitter-cli analyze ./src
```

### Library Usage

Add this to your `Cargo.toml`:

```toml
[dependencies]
rust_tree_sitter = { git = "https://github.com/njfio/rust-treesitter-agent-code-utility.git" }
```

### Basic Parsing

```rust
use rust_tree_sitter::{Parser, Language};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a parser for Rust
    let mut parser = Parser::new(Language::Rust)?;

    // Parse some code
    let source = "fn main() { println!(\"Hello, world!\"); }";
    let tree = parser.parse(source, None)?;

    // Navigate the syntax tree
    let root = tree.root_node();
    println!("Root node: {}", root.kind());

    Ok(())
}
```

### Language Detection

```rust
use rust_tree_sitter::detect_language_from_extension;

// Detect language from extension
if let Some(lang) = detect_language_from_extension("py") {
    println!("Detected language: {}", lang.name());
}
```

### Codebase Analysis

```rust
use rust_tree_sitter::CodebaseAnalyzer;
use std::path::PathBuf;

// Create analyzer with error handling
let mut analyzer = CodebaseAnalyzer::new()?;

// Analyze directory
let result = analyzer.analyze_directory(&PathBuf::from("./src"))?;

// Access results
println!("Found {} files", result.files.len());
for file_info in &result.files {
    println!("📁 {} ({} symbols)", file_info.path.display(), file_info.symbols.len());
}
```

### Security Analysis

```rust
use rust_tree_sitter::{CodebaseAnalyzer, AdvancedSecurityAnalyzer};
use std::path::PathBuf;

// Analyze codebase
let mut analyzer = CodebaseAnalyzer::new()?;
let analysis = analyzer.analyze_directory(&PathBuf::from("./src"))?;

// Run security scan
let security_analyzer = AdvancedSecurityAnalyzer::new();
let security_result = security_analyzer.scan_analysis_result(&analysis)?;

println!("Security Score: {}/100", security_result.security_score);
println!("Found {} vulnerabilities", security_result.vulnerabilities.len());

// Display vulnerabilities
for vuln in &security_result.vulnerabilities {
    println!("🔒 {}: {} (line {})",
             vuln.severity, vuln.title, vuln.location.line);
}
```

### Intent Mapping

```rust
use rust_tree_sitter::{CodebaseAnalyzer, IntentMappingSystem, Requirement, RequirementType, Priority};
use std::path::PathBuf;

// Analyze codebase
let mut analyzer = CodebaseAnalyzer::new()?;
let analysis = analyzer.analyze_directory(&PathBuf::from("./src"))?;

// Create intent mapping system
let mut mapping_system = IntentMappingSystem::new();

// Add requirements
let requirement = Requirement {
    id: "REQ-001".to_string(),
    requirement_type: RequirementType::UserStory,
    description: "As a user, I want to authenticate securely".to_string(),
    priority: Priority::High,
    acceptance_criteria: vec![
        "User can enter credentials".to_string(),
        "System validates credentials".to_string(),
    ],
    stakeholders: vec!["Product Owner".to_string()],
    tags: vec!["authentication".to_string(), "security".to_string()],
};

mapping_system.add_requirement(requirement);

// Generate mappings
let mappings = mapping_system.generate_mappings(&analysis)?;
println!("Generated {} mappings", mappings.len());
```

### Performance Analysis

```rust
use rust_tree_sitter::{CodebaseAnalyzer, PerformanceAnalyzer};
use std::path::PathBuf;

// Analyze codebase
let mut analyzer = CodebaseAnalyzer::new()?;
let analysis = analyzer.analyze_directory(&PathBuf::from("./src"))?;

// Run performance analysis
let perf_analyzer = PerformanceAnalyzer::new();
let perf_result = perf_analyzer.analyze(&analysis)?;

println!("Performance Score: {}/100", perf_result.performance_score);
println!("Found {} hotspots", perf_result.hotspots.len());

for hotspot in &perf_result.hotspots {
    println!("⚡ {}: {} (severity: {:?})",
             hotspot.category, hotspot.location.file.display(), hotspot.severity);
}
```

### Semantic Context Analysis

```rust
use rust_tree_sitter::{SemanticContextAnalyzer, Language};
use std::path::PathBuf;

// Create semantic context analyzer
let mut semantic_analyzer = SemanticContextAnalyzer::new(Language::Rust)?;

// Parse and analyze code
let source = std::fs::read_to_string("src/main.rs")?;
let mut parser = Parser::new(Language::Rust)?;
let tree = parser.parse(&source, None)?;

// Perform comprehensive semantic analysis
let semantic_context = semantic_analyzer.analyze(&tree, &source)?;

// Access symbol table with scope information
println!("Found {} scopes", semantic_context.symbol_table.scopes.len());
println!("Found {} symbols", semantic_context.symbol_table.symbols.len());

// Access data flow analysis
println!("Reaching definitions: {}", semantic_context.data_flow.reaching_definitions.len());
println!("Use-def chains: {}", semantic_context.data_flow.use_def_chains.len());
println!("Taint flows: {}", semantic_context.data_flow.taint_flows.len());

// Access security context
let security_ctx = &semantic_context.security_context;
println!("Validation points: {}", security_ctx.validation_points.len());
println!("Sanitization points: {}", security_ctx.sanitization_points.len());
println!("Trust levels tracked: {}", security_ctx.trust_levels.len());

// Access call graph analysis
println!("Function calls: {}", semantic_context.call_graph.calls.len());
println!("Function definitions: {}", semantic_context.call_graph.functions.len());

// Access pattern detection
println!("Code patterns: {}", semantic_context.pattern_context.patterns.len());
println!("Anti-patterns: {}", semantic_context.pattern_context.anti_patterns.len());
```

## Supported Languages

| Language   | Extensions           | Symbol Extraction | Security Analysis | Status |
|------------|---------------------|-------------------|-------------------|---------|
| Rust       | `.rs`               | ✅ Functions, structs, impls, traits | ✅ Pattern-based | 🟢 Working |
| JavaScript | `.js`, `.mjs`, `.jsx` | ✅ Functions, classes, methods | ✅ Pattern-based | 🟢 Working |
| TypeScript | `.ts`, `.tsx`       | ✅ Functions, classes, interfaces, types | ✅ Pattern-based | 🟢 Working |
| Go         | `.go`               | ✅ Functions, structs, methods, interfaces | ✅ Pattern-based | 🟢 Working |
| Python     | `.py`, `.pyi`       | ✅ Functions, classes, methods | ✅ Pattern-based | 🟢 Working |
| C          | `.c`, `.h`          | ✅ Functions, structs, typedefs, macros | ✅ Pattern-based | 🟢 Working |
| C++        | `.cpp`, `.hpp`, etc | ✅ Functions, classes, namespaces, templates | ✅ Pattern-based | 🟢 Working |

### Symbol Types Extracted

- **Functions**: Regular functions, methods, constructors
- **Classes/Structs**: Class definitions, struct definitions, implementations
- **Types**: Interfaces, type aliases, enums, traits
- **Visibility**: Public, private, protected (language-dependent)
- **Location**: Line numbers, column positions
- **Documentation**: Extracted where available

### Security Vulnerability Detection

Pattern-based detection for:

- **SQL Injection**: Unsafe query construction
- **Command Injection**: Unsafe command execution
- **XSS**: Cross-site scripting patterns
- **Hardcoded Secrets**: API keys, passwords, tokens
- **Cryptographic Issues**: Weak algorithms, insecure practices
- **Input Validation**: Missing validation patterns
- **Authorization**: Missing access controls

## Test Coverage

### Current Test Status

- **330+ Total Tests Passing**: Comprehensive test suite covering all functionality
- **Core Parsing**: All parsing functionality working across 7 languages
- **Symbol Extraction**: Working for all supported languages with symbol detection
- **Security Analysis**: Pattern-based security scanning with OWASP categorization
- **Semantic Context Tracking**: 17 tests covering symbol tables, data flow, and security context
- **Performance Analysis**: Cyclomatic complexity calculation and optimization recommendations
- **Intent Mapping**: Requirements-to-implementation mapping with validation
- **Advanced Features**: Semantic analysis, automated reasoning, and code explanation
- **CLI Commands**: All commands working with comprehensive option support
- **Output Formats**: JSON, table, markdown, summary formats
- **Error Handling**: Robust Result<T,E> patterns throughout
- **Constants Management**: Centralized configuration with validation

### Test Categories

- **Unit Tests**: 313 tests covering individual components and functions
- **Integration Tests**: End-to-end testing of CLI commands and workflows
- **Error Handling Tests**: Comprehensive error condition and edge case testing
- **Configuration Tests**: Validation of all configuration options and defaults
- **Security Tests**: Vulnerability detection and pattern matching
- **Performance Tests**: Analysis accuracy and recommendation validation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.