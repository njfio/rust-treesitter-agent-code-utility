//! Code analysis functionality for processing entire codebases
//! 
//! This module provides high-level functionality for AI code agents to analyze
//! entire folders and codebases, extracting structured information about the code.

use crate::error::{Error, Result};
use crate::languages::Language;
use crate::parser::Parser;

use crate::tree::SyntaxTree;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Depth level for analysis
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum AnalysisDepth {
    /// Only collect basic file metadata without parsing
    Basic,
    /// Parse files but skip symbol extraction
    Deep,
    /// Full parsing with symbol extraction
    Full,
}

impl Default for AnalysisDepth {
    fn default() -> Self {
        AnalysisDepth::Full
    }
}

impl std::str::FromStr for AnalysisDepth {
    type Err = ();
    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "basic" => Ok(AnalysisDepth::Basic),
            "deep" => Ok(AnalysisDepth::Deep),
            "full" | _ => Ok(AnalysisDepth::Full),
        }
    }
}

/// Configuration for codebase analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AnalysisConfig {
    /// Maximum file size to process (in bytes)
    pub max_file_size: Option<usize>,
    /// File extensions to include (if None, uses default for detected languages)
    pub include_extensions: Option<Vec<String>>,
    /// File extensions to exclude
    pub exclude_extensions: Vec<String>,
    /// Directories to exclude
    pub exclude_dirs: Vec<String>,
    /// Whether to follow symbolic links
    pub follow_symlinks: bool,
    /// Maximum depth to traverse
    pub max_depth: Option<usize>,
    /// Whether to include hidden files/directories
    pub include_hidden: bool,
    /// How much analysis to perform
    pub depth: AnalysisDepth,
}

impl Default for AnalysisConfig {
    fn default() -> Self {
        Self {
            max_file_size: Some(1024 * 1024), // 1MB default
            include_extensions: None,
            exclude_extensions: vec![
                "exe".to_string(), "bin".to_string(), "so".to_string(), "dll".to_string(),
                "png".to_string(), "jpg".to_string(), "jpeg".to_string(), "gif".to_string(),
                "pdf".to_string(), "zip".to_string(), "tar".to_string(), "gz".to_string(),
            ],
            exclude_dirs: vec![
                ".git".to_string(), "node_modules".to_string(), "target".to_string(),
                ".vscode".to_string(), ".idea".to_string(), "build".to_string(),
                "dist".to_string(), "__pycache__".to_string(), ".pytest_cache".to_string(),
            ],
            follow_symlinks: false,
            max_depth: Some(20),
            include_hidden: false,
            depth: AnalysisDepth::Full,
        }
    }
}

/// Information about a parsed file
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct FileInfo {
    /// File path relative to the analysis root
    pub path: PathBuf,
    /// Detected language
    pub language: String,
    /// File size in bytes
    pub size: usize,
    /// Number of lines
    pub lines: usize,
    /// Parse success status
    pub parsed_successfully: bool,
    /// Parse errors if any
    pub parse_errors: Vec<String>,
    /// Extracted symbols (functions, classes, etc.)
    pub symbols: Vec<Symbol>,
}

/// A code symbol (function, class, struct, etc.)
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Symbol {
    /// Symbol name
    pub name: String,
    /// Symbol type (function, class, struct, etc.)
    pub kind: String,
    /// Start line (1-based)
    pub start_line: usize,
    /// End line (1-based)
    pub end_line: usize,
    /// Start column (0-based)
    pub start_column: usize,
    /// End column (0-based)
    pub end_column: usize,
    /// Symbol visibility (public, private, etc.)
    pub visibility: String,
    /// Symbol documentation if available
    pub documentation: Option<String>,
}

/// Results of codebase analysis
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct AnalysisResult {
    /// Root directory that was analyzed
    pub root_path: PathBuf,
    /// Total number of files processed
    pub total_files: usize,
    /// Number of files successfully parsed
    pub parsed_files: usize,
    /// Number of files with parse errors
    pub error_files: usize,
    /// Total lines of code
    pub total_lines: usize,
    /// Languages detected and their file counts
    pub languages: HashMap<String, usize>,
    /// Information about each processed file
    pub files: Vec<FileInfo>,
    /// Analysis configuration used
    pub config: AnalysisConfig,
}

/// Main analyzer for processing codebases
pub struct CodebaseAnalyzer {
    config: AnalysisConfig,
    parsers: HashMap<Language, Parser>,
}

impl CodebaseAnalyzer {
    /// Create a new analyzer with default configuration
    pub fn new() -> Self {
        Self::with_config(AnalysisConfig::default())
    }

    /// Create a new analyzer with custom configuration
    pub fn with_config(config: AnalysisConfig) -> Self {
        Self {
            config,
            parsers: HashMap::new(),
        }
    }

    /// Get or create a parser for the given language
    fn get_parser(&mut self, language: Language) -> Result<&Parser> {
        if !self.parsers.contains_key(&language) {
            let parser = Parser::new(language)?;
            self.parsers.insert(language, parser);
        }
        Ok(self.parsers.get(&language).unwrap())
    }

    /// Analyze a directory and return structured results
    pub fn analyze_directory<P: AsRef<Path>>(&mut self, path: P) -> Result<AnalysisResult> {
        let root_path = path.as_ref().to_path_buf();
        
        if !root_path.exists() {
            return Err(Error::invalid_input(format!("Path does not exist: {}", root_path.display())));
        }

        if !root_path.is_dir() {
            return Err(Error::invalid_input(format!("Path is not a directory: {}", root_path.display())));
        }

        let mut result = AnalysisResult {
            root_path: root_path.clone(),
            total_files: 0,
            parsed_files: 0,
            error_files: 0,
            total_lines: 0,
            languages: HashMap::new(),
            files: Vec::new(),
            config: self.config.clone(),
        };

        self.analyze_directory_recursive(&root_path, &root_path, &mut result, 0)?;

        Ok(result)
    }

    /// Recursively analyze a directory
    fn analyze_directory_recursive(
        &mut self,
        current_path: &Path,
        root_path: &Path,
        result: &mut AnalysisResult,
        depth: usize,
    ) -> Result<()> {
        // Check depth limit
        if let Some(max_depth) = self.config.max_depth {
            if depth > max_depth {
                return Ok(());
            }
        }

        let entries = fs::read_dir(current_path)
            .map_err(|e| Error::internal(format!("Failed to read directory {}: {}", current_path.display(), e)))?;

        for entry in entries {
            let entry = entry.map_err(|e| Error::internal(format!("Failed to read directory entry: {}", e)))?;
            let path = entry.path();

            // Skip hidden files/directories if not included
            if !self.config.include_hidden {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with('.') {
                        continue;
                    }
                }
            }

            if path.is_dir() {
                // Check if directory should be excluded
                if let Some(dir_name) = path.file_name().and_then(|n| n.to_str()) {
                    if self.config.exclude_dirs.contains(&dir_name.to_string()) {
                        continue;
                    }
                }

                // Recursively analyze subdirectory
                self.analyze_directory_recursive(&path, root_path, result, depth + 1)?;
            } else if path.is_file() {
                // Analyze file
                if let Err(e) = self.analyze_file(&path, root_path, result) {
                    eprintln!("Warning: Failed to analyze file {}: {}", path.display(), e);
                }
            }
        }

        Ok(())
    }

    /// Analyze a single file
    fn analyze_file(&mut self, file_path: &Path, root_path: &Path, result: &mut AnalysisResult) -> Result<()> {
        // Get file extension
        let extension = file_path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("")
            .to_lowercase();

        // Check if extension should be excluded
        if self.config.exclude_extensions.contains(&extension) {
            return Ok(());
        }

        // Check if extension should be included (if filter is specified)
        if let Some(ref include_exts) = self.config.include_extensions {
            if !include_exts.contains(&extension) {
                return Ok(());
            }
        }

        // Detect language
        let language = match crate::detect_language_from_extension(&extension) {
            Some(lang) => lang,
            None => return Ok(()), // Skip files with unknown languages
        };

        // Check file size
        let metadata = fs::metadata(file_path)?;
        let file_size = metadata.len() as usize;
        
        if let Some(max_size) = self.config.max_file_size {
            if file_size > max_size {
                return Ok(()); // Skip large files
            }
        }

        // Read file content
        let content = fs::read_to_string(file_path)?;
        let line_count = content.lines().count();

        // Get relative path
        let relative_path = file_path.strip_prefix(root_path)
            .unwrap_or(file_path)
            .to_path_buf();

        result.total_files += 1;
        result.total_lines += line_count;

        // Update language statistics
        let lang_name = language.name().to_string();
        *result.languages.entry(lang_name.clone()).or_insert(0) += 1;

        // Skip parsing if depth is Basic
        if matches!(self.config.depth, AnalysisDepth::Basic) {
            let file_info = FileInfo {
                path: relative_path,
                language: lang_name,
                size: file_size,
                lines: line_count,
                parsed_successfully: false,
                parse_errors: Vec::new(),
                symbols: Vec::new(),
            };
            result.files.push(file_info);
            return Ok(());
        }

        // Parse the file
        let parser = self.get_parser(language)?;
        let mut file_info = FileInfo {
            path: relative_path,
            language: lang_name,
            size: file_size,
            lines: line_count,
            parsed_successfully: false,
            parse_errors: Vec::new(),
            symbols: Vec::new(),
        };

        match parser.parse(&content, None) {
            Ok(tree) => {
                file_info.parsed_successfully = true;
                result.parsed_files += 1;

                // Check for parse errors in the tree
                if tree.has_error() {
                    let error_nodes = tree.error_nodes();
                    for error_node in error_nodes {
                        let pos = error_node.start_position();
                        file_info.parse_errors.push(format!(
                            "Parse error at line {}, column {}: {}",
                            pos.row + 1,
                            pos.column,
                            error_node.kind()
                        ));
                    }
                }

                // Extract symbols only for Full depth
                if matches!(self.config.depth, AnalysisDepth::Full) {
                    file_info.symbols = self.extract_symbols(&tree, &content, language)?;
                }
            }
            Err(e) => {
                file_info.parse_errors.push(e.to_string());
                result.error_files += 1;
            }
        }

        result.files.push(file_info);
        Ok(())
    }

    /// Extract symbols from a syntax tree
    fn extract_symbols(&self, tree: &SyntaxTree, content: &str, language: Language) -> Result<Vec<Symbol>> {
        let mut symbols = Vec::new();

        match language {
            Language::Rust => {
                self.extract_rust_symbols(tree, content, &mut symbols)?;
            }
            Language::JavaScript | Language::TypeScript => {
                self.extract_javascript_symbols(tree, content, &mut symbols)?;
            }
            Language::Python => {
                self.extract_python_symbols(tree, content, &mut symbols)?;
            }
            Language::C | Language::Cpp => {
                self.extract_c_symbols(tree, content, &mut symbols)?;
            }
            Language::Go => {
                self.extract_go_symbols(tree, content, &mut symbols)?;
            }
        }

        Ok(symbols)
    }

    /// Extract Rust symbols
    fn extract_rust_symbols(&self, tree: &SyntaxTree, content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        // Extract functions
        let functions = tree.find_nodes_by_kind("function_item");
        for func in functions {
            if let Some(name_node) = func.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let visibility = if func.children().iter().any(|child| child.kind() == "visibility_modifier") {
                        "public"
                    } else {
                        "private"
                    };

                    let docs = self.extract_rust_doc_comments(content, func.start_position().row);

                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "function".to_string(),
                        start_line: func.start_position().row + 1,
                        end_line: func.end_position().row + 1,
                        start_column: func.start_position().column,
                        end_column: func.end_position().column,
                        visibility: visibility.to_string(),
                        documentation: docs,
                    });
                }
            }
        }

        // Extract structs
        let structs = tree.find_nodes_by_kind("struct_item");
        for struct_node in structs {
            if let Some(name_node) = struct_node.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let visibility = if struct_node.children().iter().any(|child| child.kind() == "visibility_modifier") {
                        "public"
                    } else {
                        "private"
                    };
                    
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "struct".to_string(),
                        start_line: struct_node.start_position().row + 1,
                        end_line: struct_node.end_position().row + 1,
                        start_column: struct_node.start_position().column,
                        end_column: struct_node.end_position().column,
                        visibility: visibility.to_string(),
                        documentation: None,
                    });
                }
            }
        }

        // Extract enums
        let enums = tree.find_nodes_by_kind("enum_item");
        for enum_node in enums {
            if let Some(name_node) = enum_node.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let visibility = if enum_node.children().iter().any(|child| child.kind() == "visibility_modifier") {
                        "public"
                    } else {
                        "private"
                    };
                    
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "enum".to_string(),
                        start_line: enum_node.start_position().row + 1,
                        end_line: enum_node.end_position().row + 1,
                        start_column: enum_node.start_position().column,
                        end_column: enum_node.end_position().column,
                        visibility: visibility.to_string(),
                        documentation: None,
                    });
                }
            }
        }

        Ok(())
    }

    /// Extract JavaScript symbols
    fn extract_javascript_symbols(&self, tree: &SyntaxTree, _content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        // Extract function declarations
        let functions = tree.find_nodes_by_kind("function_declaration");
        for func in functions {
            if let Some(name_node) = func.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "function".to_string(),
                        start_line: func.start_position().row + 1,
                        end_line: func.end_position().row + 1,
                        start_column: func.start_position().column,
                        end_column: func.end_position().column,
                        visibility: "public".to_string(),
                        documentation: None,
                    });
                }
            }
        }

        // Extract class declarations
        let classes = tree.find_nodes_by_kind("class_declaration");
        for class in classes {
            if let Some(name_node) = class.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "class".to_string(),
                        start_line: class.start_position().row + 1,
                        end_line: class.end_position().row + 1,
                        start_column: class.start_position().column,
                        end_column: class.end_position().column,
                        visibility: "public".to_string(),
                        documentation: None,
                    });
                }
            }
        }

        Ok(())
    }

    /// Extract Python symbols
    fn extract_python_symbols(&self, tree: &SyntaxTree, _content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        // Extract function definitions
        let functions = tree.find_nodes_by_kind("function_definition");
        for func in functions {
            if let Some(name_node) = func.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let visibility = if name.starts_with('_') { "private" } else { "public" };
                    
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "function".to_string(),
                        start_line: func.start_position().row + 1,
                        end_line: func.end_position().row + 1,
                        start_column: func.start_position().column,
                        end_column: func.end_position().column,
                        visibility: visibility.to_string(),
                        documentation: None,
                    });
                }
            }
        }

        // Extract class definitions
        let classes = tree.find_nodes_by_kind("class_definition");
        for class in classes {
            if let Some(name_node) = class.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let visibility = if name.starts_with('_') { "private" } else { "public" };
                    
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "class".to_string(),
                        start_line: class.start_position().row + 1,
                        end_line: class.end_position().row + 1,
                        start_column: class.start_position().column,
                        end_column: class.end_position().column,
                        visibility: visibility.to_string(),
                        documentation: None,
                    });
                }
            }
        }

        Ok(())
    }

    /// Extract C/C++ symbols
    fn extract_c_symbols(&self, tree: &SyntaxTree, _content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        // Extract function definitions
        let functions = tree.find_nodes_by_kind("function_definition");
        for func in functions {
            if let Some(declarator) = func.child_by_field_name("declarator") {
                if let Some(func_declarator) = declarator.children().iter()
                    .find(|child| child.kind() == "function_declarator") {
                    if let Some(name_node) = func_declarator.child_by_field_name("declarator") {
                        if let Ok(name) = name_node.text() {
                            symbols.push(Symbol {
                                name: name.to_string(),
                                kind: "function".to_string(),
                                start_line: func.start_position().row + 1,
                                end_line: func.end_position().row + 1,
                                start_column: func.start_position().column,
                                end_column: func.end_position().column,
                                visibility: "public".to_string(),
                                documentation: None,
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Extract Go symbols
    fn extract_go_symbols(&self, tree: &SyntaxTree, _content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        // Extract function declarations
        let functions = tree.find_nodes_by_kind("function_declaration");
        for func in functions {
            if let Some(name_node) = func.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let visibility = if name.chars().next().unwrap_or('a').is_uppercase() {
                        "public"
                    } else {
                        "private"
                    };
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "function".to_string(),
                        start_line: func.start_position().row + 1,
                        start_column: func.start_position().column,
                        end_line: func.end_position().row + 1,
                        end_column: func.end_position().column,
                        visibility: visibility.to_string(),
                        documentation: None,
                    });
                }
            }
        }

        // Extract method declarations
        let methods = tree.find_nodes_by_kind("method_declaration");
        for method in methods {
            if let Some(name_node) = method.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let visibility = if name.chars().next().unwrap_or('a').is_uppercase() {
                        "public"
                    } else {
                        "private"
                    };
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "method".to_string(),
                        start_line: method.start_position().row + 1,
                        start_column: method.start_position().column,
                        end_line: method.end_position().row + 1,
                        end_column: method.end_position().column,
                        visibility: visibility.to_string(),
                        documentation: None,
                    });
                }
            }
        }

        // Extract type declarations (structs, interfaces)
        let types = tree.find_nodes_by_kind("type_declaration");
        for type_decl in types {
            // Look for type_spec children
            for child in type_decl.children() {
                if child.kind() == "type_spec" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        if let Ok(name) = name_node.text() {
                            let kind = if let Some(type_node) = child.child_by_field_name("type") {
                                match type_node.kind() {
                                    "struct_type" => "struct",
                                    "interface_type" => "interface",
                                    _ => "type",
                                }
                            } else {
                                "type"
                            };
                            let visibility = if name.chars().next().unwrap_or('a').is_uppercase() {
                                "public"
                            } else {
                                "private"
                            };
                            symbols.push(Symbol {
                                name: name.to_string(),
                                kind: kind.to_string(),
                                start_line: type_decl.start_position().row + 1,
                                start_column: type_decl.start_position().column,
                                end_line: type_decl.end_position().row + 1,
                                end_column: type_decl.end_position().column,
                                visibility: visibility.to_string(),
                                documentation: None,
                            });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Extract doc comments preceding a Rust item start line
    fn extract_rust_doc_comments(&self, content: &str, start_row: usize) -> Option<String> {
        let lines: Vec<&str> = content.lines().collect();
        if start_row == 0 {
            return None;
        }

        let mut docs = Vec::new();
        let mut line_idx = start_row as isize - 1;
        while line_idx >= 0 {
            let line = lines[line_idx as usize].trim();
            if line.starts_with("///") {
                docs.push(line.trim_start_matches("///").trim());
            } else if line.is_empty() {
                line_idx -= 1;
                continue;
            } else {
                break;
            }
            line_idx -= 1;
        }

        if docs.is_empty() {
            None
        } else {
            docs.reverse();
            Some(docs.join("\n"))
        }
    }
}

impl Default for CodebaseAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_analyzer_creation() {
        let analyzer = CodebaseAnalyzer::new();
        assert_eq!(analyzer.config.max_file_size, Some(1024 * 1024));
    }

    #[test]
    fn test_analyze_directory() {
        // Create a temporary directory with some test files
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();

        // Create a Rust file
        let rust_file = temp_path.join("main.rs");
        fs::write(&rust_file, r#"
            /// Main entry point
            pub fn main() {
                println!("Hello, world!");
            }
            
            struct Point {
                x: i32,
                y: i32,
            }
        "#).unwrap();

        // Create a JavaScript file
        let js_file = temp_path.join("app.js");
        fs::write(&js_file, r#"
            function greet(name) {
                console.log("Hello, " + name);
            }
            
            class Calculator {
                add(a, b) {
                    return a + b;
                }
            }
        "#).unwrap();

        // Analyze the directory
        let mut analyzer = CodebaseAnalyzer::new();
        let result = analyzer.analyze_directory(temp_path).unwrap();

        assert_eq!(result.total_files, 2);
        assert_eq!(result.parsed_files, 2);
        assert_eq!(result.error_files, 0);
        assert!(result.languages.contains_key("Rust"));
        assert!(result.languages.contains_key("JavaScript"));

        // Check that symbols were extracted
        let rust_file_info = result.files.iter().find(|f| f.path.extension().unwrap() == "rs").unwrap();
        assert!(rust_file_info.symbols.len() > 0);
        let main_symbol = rust_file_info.symbols.iter().find(|s| s.name == "main").unwrap();
        assert_eq!(main_symbol.visibility, "public");
        assert_eq!(main_symbol.documentation.as_deref(), Some("Main entry point"));

        let js_file_info = result.files.iter().find(|f| f.path.extension().unwrap() == "js").unwrap();
        assert!(js_file_info.symbols.len() > 0);
        assert!(js_file_info.symbols.iter().any(|s| s.name == "greet"));
    }
}
