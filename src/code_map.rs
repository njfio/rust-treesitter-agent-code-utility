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

    // Build simple call relationships by text search
    for (file, sym) in &functions {
        if let Ok(content) = read_symbol_content(root, file, sym) {
            for (other_file, other_sym) in &functions {
                if sym.name == other_sym.name && file.path == other_file.path {
                    continue;
                }
                let target_name = format!("{}::{}", other_file.path.display(), other_sym.name);
                if content.contains(&format!("{}(", other_sym.name)) {
                    let from = format!("{}::{}", file.path.display(), sym.name);
                    edges.insert((from, target_name));
                }
            }
        }
    }

    CallGraph { nodes, edges }
}

/// Build a module dependency graph from analysis results.
pub fn build_module_graph(result: &AnalysisResult) -> ModuleGraph {
    let root = &result.root_path;
    let mut nodes = HashSet::new();
    let mut edges = HashSet::new();

    for file in &result.files {
        let module_name = file.path.display().to_string();
        nodes.insert(module_name.clone());
        if let Ok(content) = fs::read_to_string(root.join(&file.path)) {
            for dep in extract_dependencies(&content) {
                edges.insert((module_name.clone(), dep));
            }
        }
    }

    ModuleGraph { nodes, edges }
}

fn read_symbol_content(root: &PathBuf, file: &FileInfo, sym: &Symbol) -> std::io::Result<String> {
    let path = root.join(&file.path);
    let content = fs::read_to_string(path)?;
    let lines: Vec<&str> = content.lines().collect();
    let start = sym.start_line.saturating_sub(1);
    let end = sym.end_line.min(lines.len());
    Ok(lines[start..end].join("\n"))
}

fn extract_dependencies(content: &str) -> Vec<String> {
    let mut deps = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("use ") || trimmed.starts_with("pub use ") {
            if let Some(rest) = trimmed.split_whitespace().nth(1) {
                let dep = rest.trim_end_matches(';').split("::").last().unwrap_or(rest);
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

