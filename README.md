# Rust Tree-sitter Agent Code Utility

A Rust library for parsing and analyzing source code using tree-sitter. Provides abstractions for parsing, navigating, and querying syntax trees across multiple programming languages with analysis capabilities for security, performance, and code quality.

Built for developers who need code analysis tools and insights into code structure and quality.

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
- **Language Detection**: Automatic detection from file extensions
- **Symbol Extraction**: Functions, classes, structs, methods, types, interfaces, implementations
- **Advanced Language Features**: Language-specific construct detection

### Analysis Capabilities
- **Codebase Analysis**: Directory analysis with file metrics, symbol extraction, and statistics
- **Security Scanning**: Pattern-based vulnerability detection with OWASP categorization
- **Performance Analysis**: Cyclomatic complexity calculation and optimization recommendations
- **Dependency Analysis**: Package manager file parsing (package.json, requirements.txt, Cargo.toml, go.mod)
- **Code Quality**: Code smell detection and improvement recommendations

### CLI Interface
- **Multiple Commands**: analyze, security, refactor, dependencies, symbols
- **Output Formats**: JSON, table, markdown, summary
- **Progress Tracking**: Progress indicators for long-running operations
- **Filtering Options**: Severity levels, file types, symbol types

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
Scan for security vulnerabilities using pattern-based detection.

```bash
tree-sitter-cli security <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>         Output format: table, json, markdown [default: table]
  --min-severity <SEVERITY>     Minimum severity: critical, high, medium, low, info [default: medium]
  --save-report <FILE>          Save detailed report to file
```

**Example:**
```bash
tree-sitter-cli security ./src --min-severity high --format json
```

**Detects:**
- SQL injection vulnerabilities
- Command injection patterns
- Hardcoded secrets and API keys
- Cross-site scripting (XSS) patterns
- Insecure cryptographic practices
- Missing authorization checks
- Input validation issues

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

### `refactor` - Code Improvement Suggestions
Analyze code for refactoring opportunities and improvements.

```bash
tree-sitter-cli refactor <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json, markdown [default: table]
```

**Provides:**
- Code smell detection
- Design pattern recommendations
- Modernization suggestions
- Performance improvement hints

### `dependencies` - Dependency Analysis
Analyze project dependencies from package manager files.

```bash
tree-sitter-cli dependencies <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>    Output format: table, json [default: table]
```

**Supports:**
- package.json (Node.js)
- requirements.txt (Python)
- Cargo.toml (Rust)
- go.mod (Go)

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

// Create analyzer
let mut analyzer = CodebaseAnalyzer::new();

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
let mut analyzer = CodebaseAnalyzer::new();
let analysis = analyzer.analyze_directory(&PathBuf::from("./src"))?;

// Run security scan
let security_analyzer = AdvancedSecurityAnalyzer::new()?;
let security_result = security_analyzer.analyze(&analysis)?;

println!("Found {} vulnerabilities", security_result.total_vulnerabilities);
for vuln in &security_result.vulnerabilities {
    println!("🔒 {}: {} ({})", vuln.severity, vuln.title, vuln.location.file.display());
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
- **127 Total Tests Passing**: 109 unit tests + 18 integration test suites
- **Core Parsing**: All parsing functionality working across 7 languages
- **Symbol Extraction**: Working for all supported languages with comprehensive coverage
- **Security Analysis**: Pattern detection working with OWASP categorization
- **Performance Analysis**: Cyclomatic complexity and optimization recommendations
- **CLI Commands**: All commands (analyze, security, symbols, refactor, dependencies) working
- **Output Formats**: JSON, table, markdown formats all working

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.