# Rust Tree-sitter Agent Code Utility

A Rust library for parsing and analyzing source code using tree-sitter. Provides symbol extraction, codebase analysis, and comprehensive error handling across multiple programming languages.

## Features

- **6 Programming Languages**: Rust, JavaScript, TypeScript, Python, C, Go
- **Language Detection**: Automatic detection from file extensions
- **Symbol Extraction**: Functions, classes, structs, methods, types, interfaces, traits, impl blocks, macros, lifetimes, generators, async functions, closures, destructuring, private fields, channels, goroutines, etc.
- **Tree-sitter Parsing**: Full tree-sitter integration with incremental parsing
- **Comprehensive Error Handling**: Detailed error reporting with recovery strategies and performance metrics
- **Thread-Safe Design**: Concurrent usage with separate parser instances
- **Codebase Analysis**: Directory traversal and file processing with graceful error recovery

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

## Supported Languages

| Language   | Extensions           | Symbol Extraction | Status |
|------------|---------------------|-------------------|---------|
| Rust       | `.rs`               | ✅ Complete       | Full |
| JavaScript | `.js`, `.mjs`, `.jsx` | ✅ Complete       | Full |
| TypeScript | `.ts`, `.tsx`       | ✅ Complete       | Full |
| Go         | `.go`               | ✅ Complete       | Full |
| Python     | `.py`, `.pyi`       | ✅ Complete       | Partial |
| C          | `.c`, `.h`          | ✅ Complete       | Partial |

## Testing

```bash
# Run all tests
cargo test

# Run with output
cargo test -- --nocapture

# Run specific test
cargo test test_rust_specific_parsing
```

## License

This project is licensed under either of

- Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.
