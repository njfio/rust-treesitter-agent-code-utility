# Rust Tree-Sitter Agent Code Utility

A comprehensive, production-ready library and CLI tool for intelligent codebase analysis using tree-sitter. Designed specifically for AI code agents and developers who need deep, semantic understanding of source code across multiple programming languages.

## 🚀 Features

### Core Analysis Capabilities
- **Multi-language Support**: Rust, JavaScript, TypeScript, Python, C, C++, Go
- **Semantic Code Parsing**: Deep AST analysis with tree-sitter
- **Symbol Extraction**: Functions, classes, structs, interfaces, and more
- **Dependency Analysis**: Package manager detection and dependency mapping
- **Performance Analysis**: Hotspot detection and complexity analysis
- **Security Scanning**: Vulnerability detection and OWASP compliance
- **Test Coverage Analysis**: Coverage estimation and quality assessment
- **Smart Refactoring**: Code smell detection and improvement suggestions

### Advanced AI Features
- **AI-Powered Code Explanations**: Deep semantic understanding and learning recommendations
- **Enhanced Security Analysis**: Advanced vulnerability detection with compliance checking
- **Smart Refactoring Engine**: Automated code improvements with confidence scoring
- **Technical Debt Analysis**: Comprehensive debt tracking and remediation suggestions
- **Code Quality Metrics**: Maintainability, complexity, and architecture analysis

### CLI Interface
- **Interactive Mode**: Explore codebases interactively
- **Multiple Output Formats**: JSON, Markdown, HTML, ASCII tables
- **Visual Code Maps**: Project structure visualization
- **Batch Processing**: Analyze entire directories efficiently
- **Extensible Queries**: Custom tree-sitter query support

## 📦 Installation

### From Crates.io
```bash
cargo install rust-tree-sitter
```

### From Source
```bash
git clone https://github.com/njfio/rust-treesitter-agent-code-utility.git
cd rust-treesitter-agent-code-utility
cargo build --release
```

### As a Library
Add to your `Cargo.toml`:
```toml
[dependencies]
rust-tree-sitter = "0.1.0"
```

## 🔧 Quick Start

### CLI Usage

#### Basic Analysis
```bash
# Analyze a codebase
tree-sitter-cli analyze /path/to/project --format json

# Get statistics
tree-sitter-cli stats /path/to/project

# Find symbols
tree-sitter-cli find /path/to/project --name "main" --symbol-type function
```

#### Advanced Features
```bash
# Security scanning
tree-sitter-cli security /path/to/project --format markdown --output security-report.md

# Performance analysis
tree-sitter-cli performance /path/to/project --category complexity --top 20

# Dependency analysis
tree-sitter-cli dependencies /path/to/project --vulnerabilities --licenses --graph

# Smart refactoring suggestions
tree-sitter-cli refactor /path/to/project --category complexity --quick-wins

# Test coverage analysis
tree-sitter-cli coverage /path/to/project --detailed --format html --output coverage.html

# AI-powered explanations
tree-sitter-cli explain /path/to/project --file src/main.rs --detailed --learning

# Visual code map
tree-sitter-cli map /path/to/project --format mermaid --show-symbols --show-sizes
```

### Library Usage

#### Basic Parsing
```rust
use rust_tree_sitter::{Parser, Language};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = "fn main() { println!(\"Hello, world!\"); }";
    let tree = parser.parse(source, None)?;
    
    println!("Root node: {}", tree.root_node().kind());
    Ok(())
}
```

#### Advanced Analysis
```rust
use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig};
use rust_tree_sitter::advanced_ai_analysis::AdvancedAIAnalyzer;
use rust_tree_sitter::dependency_analysis::DependencyAnalyzer;
use rust_tree_sitter::performance_analysis::PerformanceAnalyzer;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic codebase analysis
    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory("/path/to/project")?;
    
    println!("Found {} files in {} languages", 
             result.total_files, result.languages.len());
    
    // AI-powered analysis
    let ai_analyzer = AdvancedAIAnalyzer::new();
    let ai_result = ai_analyzer.analyze(&result)?;
    
    println!("Code quality score: {:.1}/10", ai_result.overall_quality_score);
    println!("Architecture insights: {}", ai_result.architecture_analysis.summary);
    
    // Dependency analysis
    let dep_analyzer = DependencyAnalyzer::new();
    let dep_result = dep_analyzer.analyze(&result)?;
    
    println!("Found {} dependencies across {} package managers", 
             dep_result.total_dependencies, dep_result.package_managers.len());
    
    // Performance analysis
    let perf_analyzer = PerformanceAnalyzer::new();
    let perf_result = perf_analyzer.analyze(&result)?;
    
    println!("Detected {} performance hotspots", perf_result.hotspots.len());
    
    Ok(())
}
```

#### Custom Queries
```rust
use rust_tree_sitter::{Query, QueryBuilder, Language};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Build a custom query
    let query = QueryBuilder::new(Language::Rust)
        .find_kind("function_item", "function")
        .find_kind("struct_item", "struct")
        .add_pattern("(impl_item) @impl")
        .build()?;
    
    let mut parser = Parser::new(Language::Rust)?;
    let source = r#"
        struct Point { x: i32, y: i32 }
        impl Point {
            fn new() -> Self { Point { x: 0, y: 0 } }
        }
        fn main() {}
    "#;
    
    let tree = parser.parse(source, None)?;
    let matches = query.matches(&tree)?;
    
    println!("Found {} matches", matches.len());
    
    Ok(())
}
```

## 📚 Documentation

### Core Concepts

#### Languages
The library supports multiple programming languages through tree-sitter grammars:
- **Rust**: Full support for modern Rust syntax
- **JavaScript/TypeScript**: ES6+ and TypeScript features
- **Python**: Python 3.x syntax and features
- **C/C++**: Modern C and C++ standards
- **Go**: Go modules and modern syntax

#### Analysis Pipeline
1. **Parsing**: Source code is parsed into ASTs using tree-sitter
2. **Symbol Extraction**: Functions, classes, and other symbols are identified
3. **Semantic Analysis**: Relationships and dependencies are analyzed
4. **Quality Assessment**: Code quality metrics are calculated
5. **AI Enhancement**: Advanced insights are generated using AI models

#### Query System
The library provides a powerful query system for extracting specific patterns:
- **Predefined Queries**: Common patterns for each language
- **Custom Queries**: Build your own tree-sitter queries
- **Query Builder**: Fluent API for constructing queries
- **Pattern Matching**: Advanced pattern matching capabilities

### API Reference

#### Core Types
- `Parser`: Main parsing interface
- `Language`: Supported programming languages
- `SyntaxTree`: Parsed AST representation
- `Query`: Tree-sitter query interface
- `CodebaseAnalyzer`: High-level analysis interface

#### Analysis Modules
- `advanced_ai_analysis`: AI-powered code analysis
- `dependency_analysis`: Dependency and package analysis
- `performance_analysis`: Performance hotspot detection
- `security_analysis`: Security vulnerability scanning
- `test_coverage`: Test coverage analysis
- `smart_refactoring`: Refactoring suggestions

### Examples

See the `examples/` directory for comprehensive examples:
- `basic_parsing.rs`: Basic parsing and tree navigation
- `symbol_extraction.rs`: Extracting symbols from code
- `custom_queries.rs`: Building custom queries
- `codebase_analysis.rs`: Full codebase analysis
- `ai_insights.rs`: AI-powered code insights
- `security_scanning.rs`: Security vulnerability detection
- `performance_analysis.rs`: Performance hotspot analysis

## 🧪 Testing

The library includes comprehensive test coverage:

```bash
# Run all tests
cargo test

# Run specific test suites
cargo test --test integration_tests
cargo test --test dependency_analysis_tests
cargo test --test performance_analysis_tests
cargo test --test smart_refactoring_tests

# Run with coverage
cargo test --all-features
```

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
git clone https://github.com/njfio/rust-treesitter-agent-code-utility.git
cd rust-treesitter-agent-code-utility
cargo build
cargo test
```

### Code Style
- Follow Rust standard formatting (`cargo fmt`)
- Ensure all tests pass (`cargo test`)
- Add documentation for public APIs
- Include examples for new features

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- [Tree-sitter](https://tree-sitter.github.io/) for the parsing infrastructure
- The Rust community for excellent tooling and libraries
- Contributors and users who help improve this project

## 📞 Support

- 📖 [Documentation](https://docs.rs/rust-tree-sitter)
- 🐛 [Issue Tracker](https://github.com/njfio/rust-treesitter-agent-code-utility/issues)
- 💬 [Discussions](https://github.com/njfio/rust-treesitter-agent-code-utility/discussions)
