# Rust Tree-sitter Agent Code Utility

A comprehensive Rust library for parsing and analyzing source code using tree-sitter. Provides advanced abstractions for parsing, navigating, and querying syntax trees across multiple programming languages with sophisticated analysis capabilities for security, performance, code quality, and AI-assisted development.

Built for developers, security researchers, and AI systems that need deep code analysis tools and insights into code structure, quality, and security posture.

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
- **Advanced Language Features**: Language-specific construct detection and analysis

### Enhanced Analysis Capabilities

- **Codebase Analysis**: Comprehensive directory analysis with file metrics, symbol extraction, and statistics
- **Advanced Security Scanning**: Multi-layered vulnerability detection with OWASP categorization, secrets detection, and dependency analysis
- **Performance Analysis**: Cyclomatic complexity calculation, hotspot detection, and optimization recommendations
- **Dependency Analysis**: Package manager file parsing with vulnerability scanning (package.json, requirements.txt, Cargo.toml, go.mod)
- **Code Quality Analysis**: Code smell detection, refactoring suggestions, and improvement recommendations
- **Intent Mapping**: AI-assisted mapping between requirements and implementation for development workflow optimization

### AI-Assisted Features

- **Semantic Knowledge Graphs**: Build and query semantic relationships between code elements
- **Automated Reasoning**: Logic-based code analysis and inference capabilities
- **Intent-to-Implementation Mapping**: Track requirements to code implementation relationships
- **Smart Refactoring Engine**: AI-powered code improvement suggestions and automated refactoring

### CLI Interface

- **Comprehensive Commands**: analyze, security, refactor, dependencies, symbols, query, find, map, explain, insights, interactive
- **Multiple Output Formats**: JSON, table, markdown, summary with detailed reporting
- **Progress Tracking**: Real-time progress indicators for long-running operations
- **Advanced Filtering**: Severity levels, file types, symbol types, confidence thresholds
- **Interactive Mode**: Real-time code exploration and analysis

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

### `security` - Advanced Security Vulnerability Scanning

Comprehensive security analysis with multi-layered vulnerability detection, secrets scanning, and dependency analysis.

```bash
tree-sitter-cli security <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>         Output format: table, json, markdown [default: table]
  --min-severity <SEVERITY>     Minimum severity: critical, high, medium, low, info [default: medium]
  --save-report <FILE>          Save detailed report to file
  --enable-secrets              Enable secrets detection
  --enable-dependencies         Enable dependency vulnerability scanning
  --confidence <THRESHOLD>      Minimum confidence threshold (0.0-1.0) [default: 0.7]
```

**Example:**

```bash
tree-sitter-cli security ./src --min-severity high --format json --enable-secrets
```

**Advanced Detection Capabilities:**

- **OWASP Top 10**: SQL injection, XSS, insecure deserialization, broken authentication
- **Secrets Detection**: API keys, passwords, tokens, certificates with entropy analysis
- **Dependency Vulnerabilities**: Known CVEs in project dependencies
- **Cryptographic Issues**: Weak algorithms, insecure practices, key management
- **Input Validation**: Missing validation patterns and sanitization
- **Authorization Flaws**: Missing access controls and privilege escalation
- **Code Injection**: Command injection, code execution vulnerabilities
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

AI-powered code improvement suggestions with automated refactoring capabilities.

```bash
tree-sitter-cli refactor <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json, markdown [default: table]
  --auto-apply             Automatically apply safe refactoring suggestions
  --complexity-threshold   Maximum complexity threshold for suggestions
```

**Advanced Capabilities:**

- **Code Smell Detection**: Identify anti-patterns and code quality issues
- **Design Pattern Recommendations**: Suggest appropriate design patterns
- **Modernization Suggestions**: Update code to use modern language features
- **Performance Optimization**: Identify and suggest performance improvements
- **Automated Refactoring**: Safe, automated code transformations
- **Complexity Reduction**: Simplify overly complex code structures

### `dependencies` - Enhanced Dependency Analysis

Comprehensive dependency analysis with vulnerability scanning and license compliance.

```bash
tree-sitter-cli dependencies <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json, markdown [default: table]
  --check-vulnerabilities  Check for known vulnerabilities in dependencies
  --license-compliance     Analyze license compatibility
  --outdated               Show outdated dependencies
```

**Enhanced Features:**

- **Multi-Language Support**: package.json (Node.js), requirements.txt (Python), Cargo.toml (Rust), go.mod (Go)
- **Vulnerability Scanning**: Check dependencies against known CVE databases
- **License Analysis**: Identify license conflicts and compliance issues
- **Dependency Tree**: Visualize dependency relationships and conflicts
- **Update Recommendations**: Suggest safe dependency updates

### `query` - Advanced Code Querying

Powerful code search and analysis using semantic queries.

```bash
tree-sitter-cli query <PATH> <QUERY> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json [default: table]
  --language <LANG>        Target specific language
  --context <LINES>        Show context lines around matches
```

**Example:**

```bash
tree-sitter-cli query ./src "function.*authenticate" --language rust
```

### `find` - Semantic Code Search

Find code patterns, symbols, and relationships across the codebase.

```bash
tree-sitter-cli find <PATH> <PATTERN> [OPTIONS]

Options:
  -t, --type <TYPE>        Search type: symbol, pattern, reference
  --case-sensitive         Case-sensitive search
  --whole-word             Match whole words only
```

### `map` - Intent-to-Implementation Mapping

Map business requirements and user stories to code implementations.

```bash
tree-sitter-cli map <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json, markdown [default: table]
  --requirements <FILE>    Requirements specification file
  --confidence <THRESHOLD> Minimum mapping confidence threshold
```

**Capabilities:**

- **Requirement Tracing**: Track requirements to implementation
- **Coverage Analysis**: Identify missing or incomplete implementations
- **Quality Assessment**: Evaluate implementation quality against requirements
- **Gap Analysis**: Find unimplemented requirements and orphaned code

### `explain` - AI Code Explanation

Generate comprehensive explanations of code functionality and architecture.

```bash
tree-sitter-cli explain <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: markdown, json [default: markdown]
  --detail-level <LEVEL>   Explanation detail: basic, detailed, comprehensive
  --include-examples       Include usage examples
```

### `insights` - Codebase Insights

Generate high-level insights and recommendations for the codebase.

```bash
tree-sitter-cli insights <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json, markdown [default: table]
  --focus <AREA>           Focus area: security, performance, quality, architecture
```

### `interactive` - Interactive Analysis Mode

Enter interactive mode for real-time code exploration and analysis.

```bash
tree-sitter-cli interactive <PATH>
```

**Interactive Features:**

- **Real-time Analysis**: Instant feedback as you explore code
- **Command History**: Navigate through previous commands
- **Context-Aware Suggestions**: Smart suggestions based on current context
- **Multi-format Output**: Switch between output formats dynamically

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

### Advanced Security Analysis

```rust
use rust_tree_sitter::{CodebaseAnalyzer, EnhancedSecurityScanner};
use std::path::PathBuf;

// Analyze codebase
let mut analyzer = CodebaseAnalyzer::new()?;
let analysis = analyzer.analyze_directory(&PathBuf::from("./src"))?;

// Run enhanced security scan
let security_scanner = EnhancedSecurityScanner::new();
let security_result = security_scanner.scan_analysis_result(&analysis)?;

println!("Security Score: {}/100", security_result.security_score);
println!("Found {} total findings", security_result.total_findings);

// Display vulnerabilities
for vuln in &security_result.vulnerability_findings {
    println!("🔒 {}: {} (confidence: {:.2})",
             vuln.severity, vuln.title, vuln.confidence);
}

// Display secrets
for secret in &security_result.secret_findings {
    println!("🔑 {}: {} (entropy: {:.2})",
             secret.secret_type, secret.location.file.display(), secret.entropy);
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
    status: RequirementStatus::Approved,
};

mapping_system.add_requirement(requirement);

// Generate mappings
let mappings = mapping_system.generate_mappings(&analysis)?;
println!("Generated {} mappings", mappings.len());

// Build traceability matrix
let traceability = mapping_system.build_traceability_matrix()?;
println!("Requirement coverage: {:.1}%",
         traceability.coverage_metrics.requirement_coverage * 100.0);
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
let perf_result = perf_analyzer.analyze_performance(&analysis)?;

println!("Performance Score: {}/100", perf_result.overall_score);
println!("Found {} hotspots", perf_result.hotspots.len());

for hotspot in &perf_result.hotspots {
    println!("⚡ {}: {} (impact: {})",
             hotspot.hotspot_type, hotspot.location.file.display(), hotspot.impact_score);
}
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

- **156 Total Tests Passing**: Comprehensive test suite covering all functionality
- **Core Parsing**: All parsing functionality working across 7 languages with full coverage
- **Symbol Extraction**: Working for all supported languages with comprehensive symbol detection
- **Enhanced Security Analysis**: Multi-layered security scanning with OWASP categorization, secrets detection, and dependency analysis
- **Performance Analysis**: Cyclomatic complexity calculation, hotspot detection, and optimization recommendations
- **Intent Mapping**: Requirements-to-implementation mapping with validation and traceability
- **AI-Assisted Features**: Semantic analysis, automated reasoning, and code explanation
- **CLI Commands**: All 11 commands working with comprehensive option support
- **Output Formats**: JSON, table, markdown, summary formats with detailed reporting
- **Error Handling**: Robust Result<T,E> patterns throughout with comprehensive error coverage
- **Constants Management**: Centralized configuration with validation and consistency checks

### Test Categories

- **Unit Tests**: 156 tests covering individual components and functions
- **Integration Tests**: End-to-end testing of CLI commands and workflows
- **Error Handling Tests**: Comprehensive error condition and edge case testing
- **Configuration Tests**: Validation of all configuration options and defaults
- **Security Tests**: Vulnerability detection accuracy and false positive prevention
- **Performance Tests**: Analysis accuracy and optimization recommendation validation

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.