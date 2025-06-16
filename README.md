# Rust Tree-sitter Agent Code Utility

A Rust library for parsing and analyzing source code using tree-sitter. Provides abstractions for parsing, navigating, and querying syntax trees across multiple programming languages with analysis capabilities for security, performance, and code quality.

Built for developers who need code analysis tools and basic insights into code structure and quality.

## Table of Contents

- [Features](#features)
- [What Actually Works](#what-actually-works)
- [Test Coverage](#test-coverage)
- [Quick Start](#quick-start)
- [Library Usage](#library-usage)
- [Supported Languages](#supported-languages)
- [Contributing](#contributing)
- [License](#license)

## Features

### Core Language Support
- **7 Programming Languages**: Rust, JavaScript, TypeScript, Python, C, C++, Go
- **Language Detection**: Automatic detection from file extensions
- **Symbol Extraction**: Functions, classes, structs, methods, types, interfaces
- **Advanced Language Features**: Comprehensive detection of language-specific constructs

### Analysis Capabilities
- **Codebase Analysis**: File analysis with symbol extraction and basic statistics
- **Security Scanning**: Pattern-based vulnerability detection for common issues
- **Performance Analysis**: Cyclomatic complexity calculation and basic optimization suggestions
- **Dependency Analysis**: Basic package manager file parsing
- **Code Quality**: Simple code smell detection and improvement recommendations

### Experimental Features
- **Code Evolution Tracking**: Basic Git history analysis (experimental)
- **Intent Mapping**: Requirements traceability system (experimental)
- **Semantic Graphs**: Basic code relationship modeling (experimental)
- **Reasoning Engine**: Simple logic-based analysis (experimental)

### CLI Interface

- **Multiple Commands**: analyze, security, refactor, dependencies
- **Output Formats**: Text, JSON, summary formats
- **Progress Tracking**: Basic progress indicators for operations

## What Actually Works

### Core Functionality

- **Tree-sitter Parsing**: Parse source code into syntax trees for 7 languages
- **Symbol Extraction**: Extract functions, classes, methods, and other symbols
- **Language Detection**: Detect programming language from file extensions
- **Query System**: Basic tree-sitter query execution

### Analysis Systems

- **Codebase Analysis**: Directory analysis with file and symbol metrics
- **Security Analysis**: Pattern-based vulnerability detection for common issues
- **Performance Analysis**: Cyclomatic complexity calculation and basic recommendations
- **Dependency Analysis**: Basic package manager file parsing
- **Code Quality**: Simple code smell detection

### CLI Commands

- `analyze`: Basic codebase analysis with file and symbol metrics
- `security`: Pattern-based security scanning for common vulnerabilities
- `refactor`: Basic code improvement suggestions
- `dependencies`: Package manager file parsing and dependency listing

## Test Coverage

### Current Test Status

- **Core Parsing**: All basic parsing functionality working
- **Symbol Extraction**: Working for all supported languages
- **Security Analysis**: Basic pattern detection working
- **Performance Analysis**: Cyclomatic complexity calculation working
- **Dependency Analysis**: Basic package file parsing working

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
rust_tree_sitter = "0.1.0"
```

### CLI Usage

```bash
# Build the CLI tool
cargo build --release --bin tree-sitter-cli

# Basic codebase analysis
./target/release/tree-sitter-cli analyze ./src --format summary

# Security scanning
./target/release/tree-sitter-cli security ./src

# AI-powered explanations
./target/release/tree-sitter-cli explain ./src

# Refactoring suggestions
./target/release/tree-sitter-cli refactor ./src
```

## Library Usage

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
use rust_tree_sitter::{detect_language_from_extension};

// Detect language from extension
if let Some(lang) = detect_language_from_extension("py") {
    println!("Detected language: {}", lang.name());
}
```

### Codebase Analysis

```rust
use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig};

// Create analyzer
let mut analyzer = CodebaseAnalyzer::new();

// Analyze directory
let result = analyzer.analyze_directory("./src")?;

// Access results
println!("Found {} files", result.total_files);
for file_info in &result.files {
    println!("📁 {} ({} symbols)", file_info.path.display(), file_info.symbols.len());
}
```

## Supported Languages

| Language   | Extensions           | Symbol Extraction | Status |
|------------|---------------------|-------------------|---------|
| Rust       | `.rs`               | ✅ Basic          | 🟢 Working |
| JavaScript | `.js`, `.mjs`, `.jsx` | ✅ Basic          | 🟢 Working |
| TypeScript | `.ts`, `.tsx`       | ✅ Basic          | 🟢 Working |
| Go         | `.go`               | ✅ Basic          | 🟢 Working |
| Python     | `.py`, `.pyi`       | ✅ Basic          | 🟢 Working |
| C          | `.c`, `.h`          | ✅ Basic          | 🟢 Working |
| C++        | `.cpp`, `.hpp`, etc | ✅ Basic          | 🟢 Working |

### Language Feature Detection

Basic language feature detection is working for:

- JavaScript: Private field detection (`#privateField` syntax)
- TypeScript: Namespace traversal and decorator extraction
- Rust: Trait, impl block, associated type, and method detection
- Go: Interface method extraction and embedded types detection
- Python: Async function detection using proper AST traversal
- C: Function pointer typedef and bitfield_clause detection

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.