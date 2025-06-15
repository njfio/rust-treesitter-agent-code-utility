# Rust Tree-sitter Agent Code Utility

A production-ready Rust library for parsing and analyzing source code using tree-sitter. Designed for AI code agents, developer tools, and automated code analysis with comprehensive symbol extraction and advanced language feature detection.

## Features

- **6 Programming Languages**: Rust, JavaScript, TypeScript, Python, C, Go with full AST parsing
- **Advanced Symbol Extraction**: Functions, classes, structs, methods, interfaces, traits, impl blocks, macros, lifetimes, async functions, private fields, channels, goroutines, and more
- **Missing Language Features Detection**: Comprehensive detection of advanced language constructs like TypeScript decorators, Rust associated types, Go embedded types, Python async functions, C function pointers, and JavaScript private fields
- **Tree-sitter Integration**: Full tree-sitter parsing with incremental updates and error recovery
- **Codebase Analysis**: Directory traversal with parallel processing and intelligent file filtering
- **CLI Interface**: Comprehensive command-line tool with 12+ analysis commands
- **Thread-Safe Design**: Concurrent usage with proper memory management
- **Production Quality**: Comprehensive error handling, extensive test coverage, and performance optimization

## Quick Start

Add to your `Cargo.toml`:

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

### Codebase Analysis

```rust
use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig};

let config = AnalysisConfig {
    max_file_size: Some(500 * 1024), // 500KB max
    exclude_dirs: vec!["target".to_string(), "node_modules".to_string()],
    max_depth: Some(10),
    ..Default::default()
};

let mut analyzer = CodebaseAnalyzer::with_config(config);
let result = analyzer.analyze_directory("./src")?;

println!("Found {} files in {} languages", result.total_files, result.languages.len());
for file_info in &result.files {
    println!("📁 {} ({} symbols)", file_info.path.display(), file_info.symbols.len());
    for symbol in &file_info.symbols {
        println!("  - {} {} at line {}", symbol.kind, symbol.name, symbol.start_line);
    }
}
```

## Supported Languages & Features

### Language Support Matrix

| Language   | Extensions           | Basic Symbols | Advanced Features | Missing Features Detection |
|------------|---------------------|---------------|-------------------|---------------------------|
| **Rust**   | `.rs`               | ✅ Complete   | ✅ Complete       | ✅ Complete               |
| **JavaScript** | `.js`, `.mjs`, `.jsx` | ✅ Complete   | ✅ Complete       | ✅ Complete               |
| **TypeScript** | `.ts`, `.tsx`       | ✅ Complete   | ✅ Complete       | ✅ Complete               |
| **Go**     | `.go`               | ✅ Complete   | ✅ Complete       | ✅ Complete               |
| **Python** | `.py`, `.pyi`       | ✅ Complete   | ✅ Complete       | ✅ Complete               |
| **C**      | `.c`, `.h`          | ✅ Complete   | ✅ Complete       | ✅ Complete               |

### Detailed Language Features

#### **Rust**
- **Basic**: Functions, structs, enums, modules, constants, variables
- **Advanced**: Traits, impl blocks, lifetimes, macros, associated types, const generics, methods
- **Missing Features**: Comprehensive detection of all modern Rust constructs

#### **JavaScript**
- **Basic**: Functions, classes, variables, imports/exports
- **Advanced**: Arrow functions, async/await, destructuring, spread syntax, template literals
- **Missing Features**: Private fields (`#field`), generators, closures, modern ES features

#### **TypeScript**
- **Basic**: All JavaScript features plus interfaces, type aliases, enums
- **Advanced**: Generics, decorators, namespaces, mapped types, conditional types
- **Missing Features**: Advanced type system features, utility types, template literal types

#### **Go**
- **Basic**: Functions, structs, interfaces, packages, constants, variables
- **Advanced**: Methods with receivers, goroutines, channels, select statements, defer
- **Missing Features**: Embedded types, type assertions, interface methods

#### **Python**
- **Basic**: Functions, classes, variables, imports, modules
- **Advanced**: Decorators, async/await, comprehensions, context managers, lambda functions
- **Missing Features**: Async functions, generators, metaclasses, descriptors

#### **C**
- **Basic**: Functions, structs, enums, typedefs, macros, variables
- **Advanced**: Function pointers, unions, bit fields, static/inline functions, preprocessor macros
- **Missing Features**: Complex pointer types, advanced macro patterns

## CLI Interface

The library includes a comprehensive CLI tool with 12+ analysis commands:

```bash
# Install the CLI
cargo install --path .

# Basic codebase analysis
tree-sitter-cli analyze ./src --format table

# Query specific patterns
tree-sitter-cli query ./src --pattern "(function_item name: (identifier) @name)" --language rust

# Generate code maps
tree-sitter-cli map ./src --format unicode --show-symbols

# Security analysis
tree-sitter-cli security ./src --format table --min-severity medium

# Performance analysis
tree-sitter-cli performance ./src --category complexity --top 20

# Test coverage analysis
tree-sitter-cli coverage ./src --format table --detailed

# Smart refactoring suggestions
tree-sitter-cli refactor ./src --category complexity --quick-wins

# AI-powered insights
tree-sitter-cli insights ./src --focus architecture --format markdown

# Interactive exploration
tree-sitter-cli interactive ./src
```

### Available Commands

| Command | Description | Key Features |
|---------|-------------|--------------|
| `analyze` | Comprehensive codebase analysis | Symbol extraction, file statistics, language detection |
| `query` | Tree-sitter pattern matching | Custom queries, context display, multiple output formats |
| `stats` | Codebase statistics | File counts, language distribution, complexity metrics |
| `find` | Symbol search | Name/type filtering, wildcard support, visibility filtering |
| `map` | Visual code structure | ASCII/Unicode trees, dependency graphs, symbol counts |
| `security` | Security vulnerability scanning | OWASP patterns, secret detection, compliance checking |
| `performance` | Performance hotspot detection | Complexity analysis, memory patterns, optimization suggestions |
| `coverage` | Test coverage analysis | Function coverage, line coverage, uncovered code detection |
| `refactor` | Smart refactoring suggestions | Code quality improvements, architectural recommendations |
| `insights` | AI-powered code analysis | Architecture insights, quality assessment, learning recommendations |
| `dependencies` | Dependency analysis | Vulnerability scanning, license compliance, outdated packages |
| `explain` | Code explanations | AI-powered explanations, learning paths, detailed analysis |

## API Documentation

### Basic Usage

```rust
use rust_tree_sitter::{Parser, Language};

// Create a parser for any supported language
let mut parser = Parser::new(Language::Rust)?;

// Parse source code
let source = "fn main() { println!(\"Hello, world!\"); }";
let tree = parser.parse(source, None)?;

// Navigate the syntax tree
let root = tree.root_node();
println!("Root node: {}", root.kind());

// Find specific node types
let functions = tree.find_nodes_by_kind("function_item");
println!("Found {} function(s)", functions.len());
```

### Advanced Symbol Extraction

```rust
use rust_tree_sitter::languages::rust::RustSyntax;

// Extract all functions with metadata
let functions = RustSyntax::find_functions(&tree, source);
for (name, start, end) in functions {
    println!("Function '{}' at {}:{}", name, start.row, start.column);
}

// Extract traits and implementations
let traits = RustSyntax::find_traits(&tree, source);
let impl_blocks = RustSyntax::find_impl_blocks(&tree, source);

// Extract lifetimes and associated types
let lifetimes = RustSyntax::find_lifetimes(&tree, source);
let associated_types = RustSyntax::find_associated_types(&tree, source);
```

### Missing Language Features Detection

```rust
use rust_tree_sitter::languages::{
    javascript::JavaScriptSyntax,
    typescript::TypeScriptSyntax,
    python::PythonSyntax,
};

// Detect JavaScript private fields
let private_fields = JavaScriptSyntax::find_private_fields(&tree, source);

// Detect TypeScript decorators and namespaces
let decorators = TypeScriptSyntax::find_decorators(&tree, source);
let namespaces = TypeScriptSyntax::find_namespaces(&tree, source);

// Detect Python async functions
let async_functions = PythonSyntax::find_async_functions(&tree, source);
```

## Testing

```bash
# Run all tests (200+ tests)
cargo test

# Run missing language features tests
cargo test --test missing_language_features_tests

# Run with output
cargo test -- --nocapture

# Run specific language tests
cargo test test_rust_missing_features
cargo test test_javascript_missing_features
cargo test test_typescript_missing_features
```

## Installation

Add to your `Cargo.toml`:

```toml
[dependencies]
rust_tree_sitter = "0.1.0"
```

Or install the CLI:

```bash
cargo install --git https://github.com/njfio/rust-treesitter-agent-code-utility.git
```

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
