# Rust Tree-sitter Library

A comprehensive Rust library for processing source code using tree-sitter with **AI-powered analysis capabilities**. This library provides high-level abstractions for parsing, navigating, and querying syntax trees across multiple programming languages, enhanced with intelligent code explanations, security scanning, and smart refactoring suggestions.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [🧠 AI-Powered Features](#-ai-powered-features)
  - [AI Code Explanations](#ai-code-explanations)
  - [Security Vulnerability Scanning](#security-vulnerability-scanning)
  - [Smart Refactoring Suggestions](#smart-refactoring-suggestions)
- [🚀 Smart CLI Interface](#-smart-cli-interface)
- [Supported Languages](#supported-languages)
- [Advanced Usage](#advanced-usage)
- [Examples](#examples)
- [Performance](#performance)
- [Contributing](#contributing)
- [License](#license)

## Features

- 🚀 **Multi-language support**: Rust, JavaScript, Python, C, C++
- ⚡ **Incremental parsing** for efficient updates
- 🔍 **Powerful query system** for pattern matching
- 🧭 **Intuitive tree navigation** utilities
- 🔒 **Thread-safe** parser management
- 💾 **Memory-efficient** tree handling
- 🎯 **Language-specific** utilities (starting with Rust)
- 🤖 **AI-friendly** codebase analysis for code agents
- 🚀 **Smart CLI interface** with interactive exploration and insights
- 🧠 **AI-powered explanations** with natural language code descriptions
- 🔍 **Security vulnerability scanning** with compliance assessment
- 🎯 **Smart refactoring suggestions** with automated improvements

## Quick Start

Add this to your `Cargo.toml`:

```toml
[dependencies]
rust_tree_sitter = "0.1.0"
```

### Basic Usage

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
    
    // Find all functions
    let functions = tree.find_nodes_by_kind("function_item");
    println!("Found {} function(s)", functions.len());
    
    Ok(())
}
```

### Language Detection

```rust
use rust_tree_sitter::{detect_language_from_path, detect_language_from_extension};

// Detect language from file path
if let Some(lang) = detect_language_from_path("src/main.rs") {
    println!("Detected language: {}", lang.name());
}

// Detect language from extension
if let Some(lang) = detect_language_from_extension("py") {
    println!("Detected language: {}", lang.name());
}
```

### Using Queries

```rust
use rust_tree_sitter::{Parser, Language, Query};

let mut parser = Parser::new(Language::Rust)?;
let source = r#"
    pub fn public_function() {}
    fn private_function() {}
"#;

let tree = parser.parse(source, None)?;

// Query for public functions
let query = Query::new(Language::Rust, r#"
    (function_item
        (visibility_modifier) @visibility
        name: (identifier) @name
    ) @function
"#)?;

let matches = query.matches(&tree)?;
for query_match in matches {
    if let Some(name_capture) = query_match.capture_by_name(&query, "name") {
        println!("Public function: {}", name_capture.text()?);
    }
}
```

### Incremental Parsing

```rust
use rust_tree_sitter::{Parser, Language, create_edit};
use tree_sitter::Point;

let mut parser = Parser::new(Language::Rust)?;
let mut source = "fn hello() {}".to_string();

// Initial parse
let mut tree = parser.parse(&source, None)?;

// Make an edit
let edit = create_edit(
    3, 8, 5,           // byte positions: start, old_end, new_end
    0, 3, 0, 8, 0, 5   // line/column positions
);

source.replace_range(3..8, "hi");  // Change "hello" to "hi"
tree.edit(&edit);

// Reparse incrementally
let new_tree = parser.parse(&source, Some(&tree))?;
```

### Codebase Analysis for AI Agents

```rust
use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig};

// Create analyzer with custom configuration
let config = AnalysisConfig {
    max_file_size: Some(500 * 1024), // 500KB max
    exclude_dirs: vec!["target".to_string(), "node_modules".to_string()],
    max_depth: Some(10),
    ..Default::default()
};

let mut analyzer = CodebaseAnalyzer::with_config(config);

// Analyze entire codebase
let result = analyzer.analyze_directory("./src")?;

// Access structured information
println!("Found {} files in {} languages", result.total_files, result.languages.len());
println!("Total symbols: {}", result.files.iter().map(|f| f.symbols.len()).sum::<usize>());

// Iterate through files and symbols
for file_info in &result.files {
    println!("📁 {} ({} symbols)", file_info.path.display(), file_info.symbols.len());
    for symbol in &file_info.symbols {
        println!("  - {} {} at line {}", symbol.kind, symbol.name, symbol.start_line);
    }
}
```

## 🧠 AI-Powered Features

### AI Code Explanations

Get natural language explanations of your codebase:

```bash
# Generate comprehensive AI explanations
./target/release/tree-sitter-cli explain ./src --detailed --learning

# Focus on specific files
./target/release/tree-sitter-cli explain ./src --file src/main.rs

# Get learning recommendations
./target/release/tree-sitter-cli explain ./src --learning --format markdown
```

**Example Output:**

```text
🧠 AI CODE EXPLANATIONS
Purpose: A comprehensive Rust library for processing source code using tree-sitter
Architecture: Modular architecture with clear separation of concerns
Complexity: Very High - Expert developers recommended
Technologies: Rust, Tree-sitter, CLI, Parsing and AST
```

### Security Vulnerability Scanning

Comprehensive security analysis with actionable insights:

```bash
# Full security scan with compliance check
./target/release/tree-sitter-cli security ./src --compliance

# Focus on high-severity issues
./target/release/tree-sitter-cli security ./src --min-severity high

# Generate security report
./target/release/tree-sitter-cli security ./src --format json --output security-report.json
```

**Example Output:**

```text
🔍 SECURITY SCAN RESULTS
Security Score: 85/100
Total Vulnerabilities: 3

🚨 VULNERABILITIES FOUND
1. Potential hardcoded secret detected (High severity)
   Location: config.rs:42
   Fix: Use environment variables for sensitive data

💡 RECOMMENDATIONS
- Implement automated security scanning in CI/CD pipeline
- Review unsafe code blocks for memory safety
```

### Smart Refactoring Suggestions

Intelligent code improvement recommendations:

```bash
# Get all refactoring suggestions
./target/release/tree-sitter-cli refactor ./src

# Focus on quick wins (easy improvements)
./target/release/tree-sitter-cli refactor ./src --quick-wins

# Show only high-priority improvements
./target/release/tree-sitter-cli refactor ./src --min-priority high
```

**Example Output:**

```text
🎯 REFACTORING ANALYSIS
Quality Score: 78/100
Total Opportunities: 8
Quick Wins: 3

📈 IMPACT SUMMARY
Maintainability: +65%
Readability: +70%
Technical Debt: -40%
Time Saved: 2.5 hours
```

## 🚀 Smart CLI Interface

The library includes a powerful command-line interface for intelligent codebase analysis:

```bash
# Build the CLI
cargo build --release --bin tree-sitter-cli

# Analyze a codebase
./target/release/tree-sitter-cli analyze ./src

# Generate AI-friendly insights
./target/release/tree-sitter-cli insights ./src

# Interactive exploration
./target/release/tree-sitter-cli interactive ./src

# Generate visual code maps
./target/release/tree-sitter-cli map ./src --map-type overview --show-sizes --show-symbols

# AI-powered code explanations
./target/release/tree-sitter-cli explain ./src --detailed --learning

# Security vulnerability scanning
./target/release/tree-sitter-cli security ./src --compliance

# Smart refactoring suggestions
./target/release/tree-sitter-cli refactor ./src --quick-wins

# Find symbols with wildcards
./target/release/tree-sitter-cli find ./src --name "test*" --public-only

# Advanced pattern matching
./target/release/tree-sitter-cli query ./src -p "(function_item) @func" -l rust
```

### CLI Features

- **🔍 Smart Analysis**: Comprehensive codebase analysis with detailed metrics
- **🧠 AI Insights**: Generate intelligent recommendations and architectural analysis
- **🎯 Pattern Matching**: Advanced tree-sitter query system for finding code patterns
- **📊 Statistics**: Detailed statistics about code complexity, size, and organization
- **🔎 Symbol Search**: Find functions, classes, and symbols with wildcard support
- **🎮 Interactive Mode**: Explore codebases interactively with real-time commands
- **🗺️ Visual Code Maps**: Generate beautiful project structure visualizations
- **🧠 AI Explanations**: Natural language code descriptions and insights
- **🔍 Security Scanning**: Vulnerability detection with compliance assessment
- **🎯 Smart Refactoring**: Automated improvement suggestions with impact analysis
- **📋 Multiple Formats**: Output in JSON, Markdown, Table, Text, ASCII, Unicode, and Mermaid

See [CLI_README.md](CLI_README.md) for complete CLI documentation.

## Supported Languages

| Language   | Version | Extensions           | Highlights | Queries |
|------------|---------|---------------------|------------|---------|
| Rust       | 0.21.0  | `.rs`               | ✅         | ✅      |
| JavaScript | 0.21.0  | `.js`, `.mjs`, `.jsx` | ✅         | ✅      |
| Python     | 0.21.0  | `.py`, `.pyi`       | ✅         | ❌      |
| C          | 0.21.0  | `.c`, `.h`          | ✅         | ❌      |
| C++        | 0.22.0  | `.cpp`, `.hpp`, etc | ✅         | ❌      |

## Advanced Usage

### Query Builder

```rust
use rust_tree_sitter::QueryBuilder;

let query = QueryBuilder::new(Language::Rust)
    .find_kind("function_item", "function")
    .find_kind("struct_item", "struct")
    .add_pattern("(impl_item) @impl")
    .build()?;

let matches = query.matches(&tree)?;
```

### Rust-Specific Utilities

```rust
use rust_tree_sitter::languages::rust::RustSyntax;

// Check node types
if RustSyntax::is_function(&node) {
    if let Some(name) = RustSyntax::function_name(&node, source) {
        println!("Function: {}", name);
    }
}

// Find all functions in a tree
let functions = RustSyntax::find_functions(&tree, source);
for (name, node) in functions {
    println!("Found function: {} at {}:{}", 
        name, 
        node.start_position().row + 1, 
        node.start_position().column
    );
}
```

### Error Handling

```rust
use rust_tree_sitter::{Parser, Language, Error};

let mut parser = Parser::new(Language::Rust)?;
let source = "fn main( { invalid syntax }";

match parser.parse(source, None) {
    Ok(tree) => {
        if tree.has_error() {
            let errors = tree.error_nodes();
            println!("Found {} parse errors", errors.len());
            for error in errors {
                println!("Error at {}:{}", 
                    error.start_position().row + 1,
                    error.start_position().column
                );
            }
        }
    }
    Err(e) => eprintln!("Parse failed: {}", e),
}
```

## Examples

Run the included examples:

```bash
# Basic usage example
cargo run --example basic_usage

# Incremental parsing example
cargo run --example incremental_parsing

# Codebase analysis example (for AI agents)
cargo run --example analyze_codebase -- ./src
```

## Testing

Run the test suite:

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_rust_specific_parsing
```

## Performance

The library is optimized for:

- **Incremental parsing**: Only re-parse changed portions of the code
- **Memory efficiency**: Shared text buffers and minimal allocations
- **Thread safety**: Safe concurrent usage with separate parser instances

Typical performance characteristics:

- Initial parse: ~2-3x slower than native language parsers
- Incremental updates: Near real-time performance
- Memory usage: Proportional to source code size with minimal overhead

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

```bash
git clone https://github.com/yourusername/rust_tree_sitter.git
cd rust_tree_sitter
cargo build
cargo test
```

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

## Acknowledgments

- [Tree-sitter](https://tree-sitter.github.io/) for the excellent parsing library
- The Rust tree-sitter bindings maintainers
- All language grammar contributors

## Changelog

### 0.1.0 (Initial Release)

#### Core Library Features

- Multi-language parsing support (Rust, JavaScript, Python, C, C++)
- Incremental parsing capabilities
- Query system with builder pattern
- Rust-specific syntax utilities
- Thread-safe parser management
- Memory-efficient tree handling

#### AI-Powered Intelligence

- 🧠 **AI Code Explanations**: Natural language descriptions of codebase purpose and architecture
- 🔍 **Security Vulnerability Scanning**: Comprehensive security analysis with OWASP compliance
- 🎯 **Smart Refactoring Suggestions**: Automated code improvement recommendations with impact analysis

#### Smart CLI Interface

- Interactive codebase exploration with real-time commands
- Visual code maps with multiple output formats (JSON, Markdown, Table, Text, ASCII, Unicode, Mermaid)
- Progress indicators with beautiful colored output
- Comprehensive analysis and insights generation

#### Documentation & Examples

- Comprehensive examples and documentation
- CLI usage guides and tutorials
- Performance benchmarks and optimization tips
