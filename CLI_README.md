# 🚀 Tree-sitter CLI - Smart Codebase Analysis

A powerful command-line interface for intelligent codebase analysis using tree-sitter. Perfect for developers, code reviewers, and AI agents who need deep insights into code structure and quality.

## 🌟 Features

- **🔍 Multi-language Analysis**: Support for Rust, JavaScript, Python, C, C++
- **📊 Smart Insights**: AI-friendly analysis with actionable recommendations
- **🎯 Pattern Matching**: Advanced query system for finding code patterns
- **📈 Statistics & Metrics**: Comprehensive codebase statistics
- **🔎 Symbol Search**: Find functions, classes, and other symbols with wildcards
- **🎮 Interactive Mode**: Explore codebases interactively
- **🗺️ Visual Code Maps**: Generate beautiful project structure visualizations
- **📋 Multiple Output Formats**: JSON, Markdown, Table, Text, ASCII, Unicode, and Mermaid

## 🚀 Quick Start

### Installation

```bash
# Build from source
git clone https://github.com/yourusername/rust_tree_sitter.git
cd rust_tree_sitter
cargo build --release --bin tree-sitter-cli

# The binary will be at ./target/release/tree-sitter-cli
```

### Basic Usage

```bash
# Analyze a codebase
tree-sitter-cli analyze ./src

# Get smart insights
tree-sitter-cli insights ./src

# Show statistics
tree-sitter-cli stats ./src

# Find symbols
tree-sitter-cli find ./src --name "main*" --public-only

# Generate visual code maps
tree-sitter-cli map ./src --map-type overview --show-sizes --show-symbols

# Interactive exploration
tree-sitter-cli interactive ./src
```

## 📚 Commands

### `analyze` - Comprehensive Codebase Analysis

Analyze a codebase and extract detailed information about files, symbols, and structure.

```bash
tree-sitter-cli analyze <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>        Output format: table, json, summary [default: table]
  --max-size <SIZE>           Maximum file size in KB [default: 1024]
  --max-depth <DEPTH>         Maximum directory depth [default: 20]
  --include-hidden            Include hidden files and directories
  --exclude-dirs <DIRS>       Exclude directories (comma-separated)
  --include-exts <EXTS>       Include only specific extensions (comma-separated)
  -o, --output <FILE>         Save results to file
  --detailed                  Show detailed symbol information
```

**Examples:**
```bash
# Basic analysis with summary
tree-sitter-cli analyze ./src --format summary

# Detailed analysis with JSON output
tree-sitter-cli analyze ./src --detailed --format json -o analysis.json

# Analyze only Rust files
tree-sitter-cli analyze ./src --include-exts rs

# Limit directory depth
tree-sitter-cli analyze ./src --max-depth 2 --format summary
```

### `insights` - AI-Friendly Intelligence Report

Generate smart insights and recommendations for AI agents and developers.

```bash
tree-sitter-cli insights <PATH> [OPTIONS]

Options:
  --focus <AREA>              Focus area: all, architecture, quality, complexity [default: all]
  -f, --format <FORMAT>       Output format: markdown, json, text [default: markdown]
```

**Examples:**
```bash
# Generate comprehensive insights
tree-sitter-cli insights ./src

# Focus on architecture analysis
tree-sitter-cli insights ./src --focus architecture

# JSON output for AI processing
tree-sitter-cli insights ./src --format json
```

### `query` - Advanced Pattern Matching

Search for specific code patterns using tree-sitter queries.

```bash
tree-sitter-cli query <PATH> [OPTIONS]

Options:
  -p, --pattern <PATTERN>     Tree-sitter query pattern
  -l, --language <LANG>       Language: rust, javascript, python, c, cpp
  -c, --context <LINES>       Context lines around matches [default: 3]
  -f, --format <FORMAT>       Output format: table, json [default: table]
```

**Examples:**
```bash
# Find all public functions in Rust
tree-sitter-cli query ./src -p "(function_item (visibility_modifier) name: (identifier) @name)" -l rust

# Find all class definitions in JavaScript
tree-sitter-cli query ./src -p "(class_declaration name: (identifier) @name)" -l javascript
```

### `stats` - Codebase Statistics

Show comprehensive statistics about your codebase.

```bash
tree-sitter-cli stats <PATH> [OPTIONS]

Options:
  --top <N>                   Show top N files by various metrics [default: 10]
```

**Examples:**
```bash
# Show top 5 largest files
tree-sitter-cli stats ./src --top 5

# Full statistics
tree-sitter-cli stats ./src
```

### `find` - Symbol Search

Find specific symbols (functions, classes, structs, etc.) with advanced filtering.

```bash
tree-sitter-cli find <PATH> [OPTIONS]

Options:
  -n, --name <PATTERN>        Symbol name pattern (supports wildcards)
  -t, --symbol-type <TYPE>    Symbol type: function, class, struct, enum
  -l, --language <LANG>       Language filter
  --public-only               Show only public symbols
```

**Examples:**
```bash
# Find all functions starting with "test"
tree-sitter-cli find ./src --name "test*" --symbol-type function

# Find all public structs
tree-sitter-cli find ./src --symbol-type struct --public-only

# Find symbols in Rust files only
tree-sitter-cli find ./src --language rust
```

### `interactive` - Interactive Exploration

Explore codebases interactively with a command-line interface.

```bash
tree-sitter-cli interactive <PATH>

Available commands in interactive mode:
  help, h                     Show help
  stats                       Show codebase statistics
  languages, langs            Show language breakdown
  find <pattern>              Find symbols by name
  files <language>            Show files for language
  quit, exit, q               Exit interactive mode
```

### `map` - Visual Code Maps

Generate beautiful visual representations of your project structure.

```bash
tree-sitter-cli map <PATH> [OPTIONS]

Options:
  -m, --map-type <TYPE>       Map type: tree, symbols, dependencies, overview [default: overview]
  -f, --format <FORMAT>       Output format: ascii, unicode, json, mermaid [default: unicode]
  --max-depth <DEPTH>         Maximum depth to show [default: 5]
  --show-sizes                Show file sizes
  --show-symbols              Show symbol counts
  --languages <LANGUAGES>     Include only specific languages
  --collapse-empty            Collapse empty directories
```

**Examples:**
```bash
# Overview map with sizes and symbols
tree-sitter-cli map ./src --map-type overview --show-sizes --show-symbols

# Example output
src
├─ lib.rs (1.2 KB)
├─ parser.rs (3.4 KB)
└─ languages/
   └─ mod.rs (0.8 KB)

# Clean tree structure
tree-sitter-cli map ./src --map-type tree --max-depth 3

# Symbol distribution map
tree-sitter-cli map ./src --map-type symbols

# Mermaid diagram for documentation
tree-sitter-cli map ./src --format mermaid > project-structure.md

# JSON output for processing
tree-sitter-cli map ./src --format json > structure.json

# ASCII format for simple terminals
tree-sitter-cli map ./src --format ascii --collapse-empty

# Filter by language
tree-sitter-cli map ./src --languages rust,javascript
```

#### Map Types

- **`overview`**: Complete project overview with summary and tree structure
- **`tree`**: Clean directory tree with file information
- **`symbols`**: Detailed symbol breakdown by type and file
- **`dependencies`**: Module and file relationships

#### Output Formats

- **`unicode`**: Beautiful Unicode tree with icons (default)
- **`ascii`**: Simple ASCII tree for compatibility
- **`json`**: Structured data for programmatic use
- **`mermaid`**: Mermaid diagrams for documentation

### `security` - Vulnerability Scanning

Perform full security analysis with CVE lookup and secrets detection.

```bash
tree-sitter-cli security <PATH> [OPTIONS]

Options:
  -f, --format <FORMAT>      Output format: table, json, markdown [default: table]
  --min-severity <LEVEL>     Minimum severity to report [default: low]
  --compliance               Include OWASP compliance report
  -o, --output <FILE>        Save detailed report
  --summary-only             Show summary only
```

**Example:**

```bash
tree-sitter-cli security ./src --summary-only
```

```text
🔍 SECURITY REPORT
Vulnerabilities: 0
Secrets Detected: 0
Compliance: 5/5 rules passed
```

### `languages` - Supported Languages

Show all supported languages and their capabilities.

```bash
tree-sitter-cli languages
```

## 📊 Output Formats

### Table Format (Default)
Clean, readable tables perfect for terminal viewing.

### JSON Format
Structured data perfect for programmatic processing and AI agents.

### Markdown Format
Documentation-ready format with rich formatting.

### Summary Format
Concise overview with key metrics highlighted.

## 🎯 Use Cases

### For Developers
- **Code Review**: Quickly understand codebase structure and complexity
- **Refactoring**: Identify complexity hotspots and large files
- **Documentation**: Generate architecture overviews
- **Quality Assessment**: Check naming conventions and organization

### For AI Agents
- **Codebase Understanding**: Get structured information about code organization
- **Context Building**: Extract relevant symbols and their relationships
- **Quality Analysis**: Assess code quality and get improvement suggestions
- **Pattern Recognition**: Find specific code patterns across the codebase

### For Teams
- **Onboarding**: Help new team members understand codebase structure
- **Architecture Reviews**: Analyze separation of concerns and module organization
- **Technical Debt**: Identify areas needing refactoring
- **Standards Compliance**: Check naming conventions and code organization

## 🔧 Advanced Usage

### Combining Commands
```bash
# Generate insights and save detailed analysis
tree-sitter-cli insights ./src --format json > insights.json
tree-sitter-cli analyze ./src --detailed --format json > analysis.json

# Find complexity hotspots
tree-sitter-cli stats ./src --top 3
tree-sitter-cli find ./src --symbol-type function | head -20
```

### Integration with Other Tools
```bash
# Use with jq for JSON processing
tree-sitter-cli analyze ./src --format json | jq '.files[] | select(.symbols | length > 10)'

# Generate reports
tree-sitter-cli insights ./src --format markdown > ARCHITECTURE.md
```

### CI/CD Integration
```bash
# Check code quality in CI
tree-sitter-cli insights ./src --format json | jq '.quality.parse_success_rate < 95' && exit 1

# Generate documentation
tree-sitter-cli insights ./src --format markdown > docs/CODEBASE_ANALYSIS.md
```

## 🎨 Customization

### Configuration Files
The CLI respects standard configuration patterns and can be extended with custom analysis rules.

### Custom Queries
Write your own tree-sitter queries for specific pattern matching needs.

### Output Formatting
All output formats support customization and can be easily parsed by other tools.

## 🤝 Contributing

We welcome contributions! The CLI is built on top of the robust rust-tree-sitter library and can be extended with new analysis capabilities.

## 📄 License

This project is licensed under either of Apache License, Version 2.0 or MIT license at your option.

---

**Built with ❤️ using tree-sitter and Rust**
