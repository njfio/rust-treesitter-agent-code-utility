# Rust Tree-sitter Agent Code Utility

A Rust library for parsing and analyzing source code using tree-sitter. Provides high-level abstractions for parsing, navigating, and querying syntax trees across multiple programming languages.

Built for developers and AI code agents who need to understand code structure and extract symbols from codebases.

## Table of Contents

- [Features](#features)
- [What Actually Works](#what-actually-works)
- [Limitations](#limitations)
- [Quick Start](#quick-start)
- [Library Usage](#library-usage)
- [Supported Languages](#supported-languages)
- [Contributing](#contributing)
- [License](#license)

## Features

### Language Support
- **7 Programming Languages**: Rust, JavaScript, TypeScript, Python, C, C++, Go
- **Language Detection**: Automatic detection from file extensions
- **Symbol Extraction**: Functions, classes, structs, methods, types
- **Missing Language Features Detection**: Identifies advanced language constructs

### Analysis Capabilities
- **Basic Codebase Analysis**: File counting, symbol extraction, language statistics ✅
- **Security Scanning**: Pattern-based vulnerability detection ⚠️ *High false positive rate*
- **Code Explanations**: AI-powered code analysis ⚠️ *Basic implementation, experimental*
- **Refactoring Suggestions**: Basic code improvement recommendations ⚠️ *Generic suggestions only*
- **Dependency Analysis**: Basic dependency scanning ⚠️ *Very limited, often returns 0 dependencies*

### CLI Interface
- **Multiple Commands**: analyze, explain, security, refactor, dependencies
- **Output Formats**: Text, JSON, summary formats
- **Progress Tracking**: Visual progress indicators for long operations

## What Actually Works

### Core Functionality
- **Tree-sitter Parsing**: Parse source code into syntax trees for 7 languages
- **Symbol Extraction**: Extract functions, classes, methods, and other symbols
- **Language Detection**: Detect programming language from file extensions
- **Missing Language Features**: Detect advanced language constructs (6/6 tests passing)

### CLI Commands
- `analyze`: Basic codebase analysis with file counts and symbol statistics
- `explain`: AI-powered code explanations and architectural insights
- `security`: Security vulnerability scanning (finds 250+ vulnerability types)
- `refactor`: Code improvement suggestions (58 refactoring opportunities detected)
- `dependencies`: Basic dependency analysis (limited functionality)

### Security Analysis
- **Pattern-based Detection**: Hardcoded secrets, SQL injection, weak crypto
- **OWASP Coverage**: Partial coverage of OWASP Top 10 vulnerabilities
- **Severity Scoring**: Critical, High, Medium severity levels
- **Output Formats**: Text reports with colored output

## Limitations

### What Doesn't Work Well
- **Dependency Analysis**: Very limited functionality, often returns 0 dependencies
- **AI Features**: Basic implementations, not production-ready
- **Database Integration**: Infrastructure exists but limited real-world usage
- **API Integrations**: Rate limiting and HTTP clients implemented but not fully utilized
- **Test Coverage**: Many features lack comprehensive testing

### Development Status
- **Core Parsing**: Stable and working
- **Security Scanning**: Basic pattern matching, many false positives
- **Advanced Features**: Experimental, under active development
- **Documentation**: Reflects aspirational features rather than current reality

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
| Rust       | `.rs`               | ✅ Complete       | 🟢 Full |
| JavaScript | `.js`, `.mjs`, `.jsx` | ✅ Complete       | 🟢 Full |
| TypeScript | `.ts`, `.tsx`       | ✅ Complete       | 🟢 Full |
| Go         | `.go`               | ✅ Complete       | 🟢 Full |
| Python     | `.py`, `.pyi`       | ✅ Complete       | 🟢 Full |
| C          | `.c`, `.h`          | ✅ Complete       | 🟢 Full |
| C++        | `.cpp`, `.hpp`, etc | ✅ Complete       | 🟢 Full |

### Missing Language Features Detection

All 6 missing language features tests are passing:
- JavaScript: Private field detection (`#privateField` syntax)
- TypeScript: Namespace traversal and decorator extraction
- Rust: Trait, impl block, associated type, and method detection
- Go: Interface method extraction and embedded types detection
- Python: Async function detection using proper AST traversal
- C: Function pointer typedef and bitfield_clause detection

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.








