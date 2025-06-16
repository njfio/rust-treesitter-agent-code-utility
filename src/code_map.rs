//! Code map utilities for building call graphs and module dependency graphs
//!
//! This module walks `CodebaseAnalyzer` results and constructs simplified
//! graphs that can be exported in GraphViz DOT or Mermaid formats.

use crate::{AnalysisResult, FileInfo, Symbol};
use std::collections::{HashSet};
use std::fs;
use std::path::PathBuf;

/// Representation of a call graph.
#[derive(Debug, Clone)]
pub struct CallGraph {
    pub nodes: HashSet<String>,
    pub edges: HashSet<(String, String)>,
}

impl CallGraph {
    /// Convert the call graph to GraphViz DOT format.
    pub fn to_dot(&self) -> String {
        let mut dot = String::from("digraph CallGraph {\n");
        for (from, to) in &self.edges {
            dot.push_str(&format!("    \"{}\" -> \"{}\";\n", from, to));
        }
        dot.push_str("}\n");
        dot
    }

    /// Convert the call graph to Mermaid format.
    pub fn to_mermaid(&self) -> String {
        let mut m = String::from("graph TD\n");
        for (from, to) in &self.edges {
            m.push_str(&format!("    {} --> {}\n", sanitize_mermaid(from), sanitize_mermaid(to)));
        }
        m
    }
}

/// Representation of a module dependency graph.
#[derive(Debug, Clone)]
pub struct ModuleGraph {
    pub nodes: HashSet<String>,
    pub edges: HashSet<(String, String)>,
}

impl ModuleGraph {
    /// Convert the module graph to GraphViz DOT format.
    pub fn to_dot(&self) -> String {
        let mut dot = String::from("digraph ModuleGraph {\n");
        for (from, to) in &self.edges {
            dot.push_str(&format!("    \"{}\" -> \"{}\";\n", from, to));
        }
        dot.push_str("}\n");
        dot
    }

    /// Convert the module graph to Mermaid format.
    pub fn to_mermaid(&self) -> String {
        let mut m = String::from("graph TD\n");
        for (from, to) in &self.edges {
            m.push_str(&format!("    {} --> {}\n", sanitize_mermaid(from), sanitize_mermaid(to)));
        }
        m
    }
}

/// Build a call graph from analysis results.
pub fn build_call_graph(result: &AnalysisResult) -> CallGraph {
    let root = &result.root_path;
    let mut nodes = HashSet::new();
    let mut edges = HashSet::new();

    // Collect all function symbols
    let mut functions: Vec<(&FileInfo, &Symbol)> = Vec::new();
    for file in &result.files {
        for sym in &file.symbols {
            if sym.kind == "function" || sym.kind == "method" {
                nodes.insert(format!("{}::{}", file.path.display(), sym.name));
                functions.push((file, sym));
            }
        }
    }

    // Build call relationships using AST analysis
    for (file, sym) in &functions {
        if let Ok(call_targets) = extract_function_calls_ast(root, file, sym) {
            let from = format!("{}::{}", file.path.display(), sym.name);
            for target in call_targets {
                // Try to match target with known functions
                for (other_file, other_sym) in &functions {
                    if other_sym.name == target {
                        let target_name = format!("{}::{}", other_file.path.display(), other_sym.name);
                        edges.insert((from.clone(), target_name));
                    }
                }
            }
        }
    }

    CallGraph { nodes, edges }
}

/// Build a module dependency graph from analysis results using AST analysis.
pub fn build_module_graph(result: &AnalysisResult) -> ModuleGraph {
    let root = &result.root_path;
    let mut nodes = HashSet::new();
    let mut edges = HashSet::new();

    for file in &result.files {
        let module_name = file.path.display().to_string();
        nodes.insert(module_name.clone());

        if let Ok(content) = fs::read_to_string(root.join(&file.path)) {
            // Use improved AST-based dependency extraction
            for dep in extract_dependencies(&content) {
                // Try to resolve dependency to actual files in the project
                let resolved_dep = resolve_dependency_to_file(result, &dep, &file.path);
                edges.insert((module_name.clone(), resolved_dep));
            }
        }
    }

    ModuleGraph { nodes, edges }
}

/// Resolve a dependency name to an actual file in the project
fn resolve_dependency_to_file(result: &AnalysisResult, dep_name: &str, current_file: &PathBuf) -> String {
    // Try to find a file that matches the dependency name
    for file in &result.files {
        let file_stem = file.path.file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("");

        // Check if file name matches dependency
        if file_stem == dep_name {
            return file.path.display().to_string();
        }

        // Check if any directory component matches
        for component in file.path.components() {
            if let Some(comp_str) = component.as_os_str().to_str() {
                if comp_str == dep_name {
                    return file.path.display().to_string();
                }
            }
        }
    }

    // If no file found, return the dependency name as-is
    dep_name.to_string()
}

fn read_symbol_content(root: &PathBuf, file: &FileInfo, sym: &Symbol) -> std::io::Result<String> {
    let path = root.join(&file.path);
    let content = fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().collect();
    let start = sym.start_line.saturating_sub(1);
    let end = sym.end_line.min(lines.len());
    Ok(lines[start..end].join("\n"))
}

/// Extract function calls using AST analysis instead of string matching
fn extract_function_calls_ast(root: &PathBuf, file: &FileInfo, sym: &Symbol) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    use crate::parser::Parser;
    use crate::languages::Language;

    let path = root.join(&file.path);
    let content = fs::read_to_string(path)?;

    // Get language from string
    let language: Language = file.language.parse()?;
    let parser = Parser::new(language)?;

    // Parse the file
    let syntax_tree = parser.parse(&content, None)?;
    let root_node = syntax_tree.root_node();

    // Extract the symbol's content range
    let lines: Vec<&str> = content.lines().collect();
    let start_byte = lines.iter()
        .take(sym.start_line.saturating_sub(1))
        .map(|line| line.len() + 1) // +1 for newline
        .sum::<usize>();
    let end_byte = lines.iter()
        .take(sym.end_line.min(lines.len()))
        .map(|line| line.len() + 1)
        .sum::<usize>();

    // Find the node that contains this symbol
    let symbol_node = find_node_at_range(&root_node.inner(), start_byte, end_byte);

    let mut function_calls = Vec::new();
    if let Some(node) = symbol_node {
        extract_calls_from_node(&node, &content, &mut function_calls);
    }

    Ok(function_calls)
}

/// Find AST node that contains the given byte range
fn find_node_at_range<'a>(node: &tree_sitter::Node<'a>, start_byte: usize, end_byte: usize) -> Option<tree_sitter::Node<'a>> {
    if node.start_byte() <= start_byte && node.end_byte() >= end_byte {
        // Check children first for more specific match
        for child in node.children(&mut node.walk()) {
            if let Some(found) = find_node_at_range(&child, start_byte, end_byte) {
                return Some(found);
            }
        }
        // Return this node if no child contains the range
        Some(*node)
    } else {
        None
    }
}

/// Extract function calls from an AST node
fn extract_calls_from_node(node: &tree_sitter::Node, content: &str, calls: &mut Vec<String>) {
    match node.kind() {
        "call_expression" | "function_call" => {
            // Extract function name from call expression
            if let Some(function_node) = node.child_by_field_name("function") {
                let function_text = &content[function_node.start_byte()..function_node.end_byte()];
                // Handle qualified names (e.g., obj.method, module::function)
                let name = function_text.split(&['.', ':'][..]).last().unwrap_or(function_text);
                calls.push(name.to_string());
            } else if let Some(first_child) = node.child(0) {
                // Fallback: use first child as function name
                let function_text = &content[first_child.start_byte()..first_child.end_byte()];
                let name = function_text.split(&['.', ':'][..]).last().unwrap_or(function_text);
                calls.push(name.to_string());
            }
        }
        "method_invocation" => {
            // Handle method calls (Java, C#, etc.)
            if let Some(method_node) = node.child_by_field_name("name") {
                let method_text = &content[method_node.start_byte()..method_node.end_byte()];
                calls.push(method_text.to_string());
            }
        }
        "member_expression" => {
            // Handle member access that might be function calls
            if let Some(property_node) = node.child_by_field_name("property") {
                let property_text = &content[property_node.start_byte()..property_node.end_byte()];
                calls.push(property_text.to_string());
            }
        }
        _ => {}
    }

    // Recursively process children
    for child in node.children(&mut node.walk()) {
        extract_calls_from_node(&child, content, calls);
    }
}

fn extract_dependencies(content: &str) -> Vec<String> {
    // Try AST-based extraction first, fall back to string-based for unsupported languages
    if let Ok(deps) = extract_dependencies_ast(content) {
        if !deps.is_empty() {
            return deps;
        }
    }

    // Fallback to string-based extraction for unsupported languages or when AST fails
    extract_dependencies_string_based(content)
}

/// Extract dependencies using AST analysis
fn extract_dependencies_ast(content: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    use crate::parser::Parser;
    use crate::languages::Language;

    // Detect language from content patterns
    let language_str = detect_language_from_content(content);
    let language: Language = language_str.parse()?;
    let parser = Parser::new(language)?;

    // Parse the content
    let syntax_tree = parser.parse(content, None)?;
    let root_node = syntax_tree.root_node();

    let mut dependencies = Vec::new();
    extract_imports_from_node(&root_node.inner(), content, &mut dependencies);

    Ok(dependencies)
}

/// Extract imports/dependencies from AST node
fn extract_imports_from_node(node: &tree_sitter::Node, content: &str, deps: &mut Vec<String>) {
    match node.kind() {
        // Rust
        "use_declaration" => {
            if let Some(path_node) = node.child_by_field_name("argument") {
                let path_text = &content[path_node.start_byte()..path_node.end_byte()];
                let dep = path_text.split("::").last().unwrap_or(path_text);
                deps.push(dep.to_string());
            }
        }
        "mod_item" => {
            if let Some(name_node) = node.child_by_field_name("name") {
                let name_text = &content[name_node.start_byte()..name_node.end_byte()];
                deps.push(name_text.to_string());
            }
        }
        // Python
        "import_from_statement" => {
            for child in node.children(&mut node.walk()) {
                if child.kind() == "dotted_name" || child.kind() == "identifier" {
                    let import_text = &content[child.start_byte()..child.end_byte()];
                    let dep = import_text.split('.').last().unwrap_or(import_text);
                    deps.push(dep.to_string());
                }
            }
        }
        // JavaScript/TypeScript
        "import_statement" => {
            // Check if it's a Python import first
            if node.parent().map_or(false, |p| p.kind() == "module") {
                // Python import
                for child in node.children(&mut node.walk()) {
                    if child.kind() == "dotted_name" || child.kind() == "identifier" {
                        let import_text = &content[child.start_byte()..child.end_byte()];
                        let dep = import_text.split('.').last().unwrap_or(import_text);
                        deps.push(dep.to_string());
                    }
                }
            } else {
                // JavaScript/TypeScript import
                if let Some(source_node) = node.child_by_field_name("source") {
                    let source_text = &content[source_node.start_byte()..source_node.end_byte()];
                    let dep = source_text.trim_matches(&['"', '\''][..]);
                    deps.push(dep.to_string());
                }
            }
        }
        "call_expression" => {
            // Handle require() calls
            if let Some(function_node) = node.child_by_field_name("function") {
                let function_text = &content[function_node.start_byte()..function_node.end_byte()];
                if function_text == "require" {
                    if let Some(args_node) = node.child_by_field_name("arguments") {
                        for child in args_node.children(&mut args_node.walk()) {
                            if child.kind() == "string" {
                                let dep_text = &content[child.start_byte()..child.end_byte()];
                                let dep = dep_text.trim_matches(&['"', '\''][..]);
                                deps.push(dep.to_string());
                            }
                        }
                    }
                }
            }
        }
        // C/C++
        "preproc_include" => {
            if let Some(path_node) = node.child_by_field_name("path") {
                let path_text = &content[path_node.start_byte()..path_node.end_byte()];
                let dep = path_text.trim_matches(&['<', '>', '"'][..]);
                deps.push(dep.to_string());
            }
        }
        _ => {}
    }

    // Recursively process children
    for child in node.children(&mut node.walk()) {
        extract_imports_from_node(&child, content, deps);
    }
}

/// Detect language from content patterns (simple heuristic)
fn detect_language_from_content(content: &str) -> String {
    if content.contains("use ") && content.contains("::") {
        "rust".to_string()
    } else if content.contains("import ") && (content.contains("from '") || content.contains("from \"")) {
        "javascript".to_string()
    } else if content.contains("import ") && content.contains("from ") {
        "python".to_string()
    } else if content.contains("#include") {
        "c".to_string()
    } else {
        "text".to_string() // fallback
    }
}

/// Fallback string-based dependency extraction
fn extract_dependencies_string_based(content: &str) -> Vec<String> {
    let mut deps = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("use ") || trimmed.starts_with("pub use ") {
            // Skip "use" or "pub use" and get the rest
            let use_part = if trimmed.starts_with("pub use ") {
                &trimmed[8..] // Skip "pub use "
            } else {
                &trimmed[4..] // Skip "use "
            };

            let use_part = use_part.trim_end_matches(';').trim();

            // Handle different use patterns
            if use_part.contains('{') {
                // Handle use serde::{Serialize, Deserialize};
                if let Some(module_part) = use_part.split("::").next() {
                    deps.push(module_part.to_string());
                }
            } else {
                // Handle simple use statements like use std::collections::HashMap;
                let dep = use_part.split("::").last().unwrap_or(use_part);
                deps.push(dep.to_string());
            }
        } else if trimmed.starts_with("mod ") {
            if let Some(rest) = trimmed.split_whitespace().nth(1) {
                deps.push(rest.trim_end_matches(';').to_string());
            }
        } else if trimmed.starts_with("import ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if let Some(part) = parts.last() {
                let dep = part.trim_matches(&['"', '\'', ';'][..]);
                deps.push(dep.to_string());
            }
        } else if trimmed.starts_with("from ") {
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                deps.push(parts[1].trim_matches(&['"', '\''][..]).to_string());
            }
        } else if trimmed.contains("require(") {
            if let Some(start) = trimmed.find("require(") {
                let rest = &trimmed[start + 8..];
                if let Some(end) = rest.find(')') {
                    let dep = rest[..end].trim_matches(&['"', '\'', ' '][..]);
                    deps.push(dep.to_string());
                }
            }
        } else if trimmed.starts_with("#include") {
            let dep = trimmed.trim_start_matches("#include").trim();
            let dep = dep.trim_matches(&['<', '>', '"'][..]);
            deps.push(dep.to_string());
        }
    }
    deps
}

fn sanitize_mermaid(text: &str) -> String {
    text.replace(':', "_").replace('.', "_").replace('/', "_")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{FileInfo, AnalysisResult};
    use std::path::PathBuf;

    #[test]
    fn test_extract_dependencies_rust() {
        let rust_code = r#"
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
mod utils;
pub use crate::analyzer::CodebaseAnalyzer;
"#;
        let deps = extract_dependencies_string_based(rust_code);
        assert!(deps.contains(&"HashMap".to_string()));
        assert!(deps.contains(&"utils".to_string()));
        assert!(deps.contains(&"CodebaseAnalyzer".to_string()));
    }

    #[test]
    fn test_extract_dependencies_python() {
        let python_code = r#"
import os
from collections import defaultdict
from mymodule import MyClass
"#;
        let deps = extract_dependencies_string_based(python_code);
        assert!(deps.contains(&"os".to_string()));
        assert!(deps.contains(&"collections".to_string()));
        assert!(deps.contains(&"mymodule".to_string()));
    }

    #[test]
    fn test_extract_dependencies_javascript() {
        let js_code = r#"
const fs = require('fs');
const path = require('path');
import React from 'react';
"#;
        let deps = extract_dependencies_string_based(js_code);
        assert!(deps.contains(&"fs".to_string()));
        assert!(deps.contains(&"path".to_string()));
        assert!(deps.contains(&"react".to_string()));
    }

    #[test]
    fn test_detect_language_from_content() {
        assert_eq!(detect_language_from_content("use std::collections::HashMap;"), "rust");
        assert_eq!(detect_language_from_content("import os\nfrom collections import defaultdict"), "python");
        assert_eq!(detect_language_from_content("import React from 'react';"), "javascript");
        assert_eq!(detect_language_from_content("#include <stdio.h>"), "c");
    }

    #[test]
    fn test_resolve_dependency_to_file() {
        let mut files = Vec::new();
        files.push(FileInfo {
            path: PathBuf::from("src/utils.rs"),
            language: "rust".to_string(),
            size: 100,
            lines: 10,
            parsed_successfully: true,
            parse_errors: Vec::new(),
            symbols: Vec::new(),
            security_vulnerabilities: Vec::new(),
        });
        files.push(FileInfo {
            path: PathBuf::from("src/analyzer.rs"),
            language: "rust".to_string(),
            size: 200,
            lines: 20,
            parsed_successfully: true,
            parse_errors: Vec::new(),
            symbols: Vec::new(),
            security_vulnerabilities: Vec::new(),
        });

        let result = AnalysisResult {
            root_path: PathBuf::from("."),
            total_files: 2,
            parsed_files: 2,
            error_files: 0,
            total_lines: 30,
            languages: std::collections::HashMap::new(),
            files,
            config: crate::AnalysisConfig::default(),
        };

        let resolved = resolve_dependency_to_file(&result, "utils", &PathBuf::from("src/main.rs"));
        assert_eq!(resolved, "src/utils.rs");

        let resolved = resolve_dependency_to_file(&result, "analyzer", &PathBuf::from("src/main.rs"));
        assert_eq!(resolved, "src/analyzer.rs");

        let resolved = resolve_dependency_to_file(&result, "nonexistent", &PathBuf::from("src/main.rs"));
        assert_eq!(resolved, "nonexistent");
    }
}

