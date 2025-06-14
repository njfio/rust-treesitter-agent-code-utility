//! Code analysis functionality for processing entire codebases
//! 
//! This module provides high-level functionality for AI code agents to analyze
//! entire folders and codebases, extracting structured information about the code.

use crate::enhanced_error_handling::SafeFileOperations;
use crate::error::{Error, Result};
use crate::languages::Language;
use crate::parser::Parser;

use crate::tree::SyntaxTree;
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// Simple wrapper for directory entries to unify handling
struct DirEntryWrapper {
    path: PathBuf,
}

impl DirEntryWrapper {
    fn path(&self) -> PathBuf {
        self.path.clone()
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
    /// Whether to use enhanced error handling with recovery
    pub use_enhanced_error_handling: bool,
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
            use_enhanced_error_handling: true,
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
    /// Import statements found in the file
    pub imports: Vec<String>,
    /// Export statements found in the file
    pub exports: Vec<String>,
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
    /// Symbol documentation if available
    pub documentation: Option<String>,
    /// Whether the symbol is public/exported
    pub is_public: bool,
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
    /// Extracted symbols from all files
    pub symbols: Vec<Symbol>,
    /// Dependencies found in the codebase
    pub dependencies: Vec<String>,
}

impl Default for AnalysisResult {
    fn default() -> Self {
        Self {
            root_path: PathBuf::new(),
            total_files: 0,
            parsed_files: 0,
            error_files: 0,
            total_lines: 0,
            languages: HashMap::new(),
            files: Vec::new(),
            config: AnalysisConfig::default(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
        }
    }
}

/// Main analyzer for processing codebases
pub struct CodebaseAnalyzer {
    config: AnalysisConfig,
    parsers: HashMap<Language, Parser>,
    safe_file_ops: SafeFileOperations,
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
            safe_file_ops: SafeFileOperations::new(),
        }
    }

    /// Extract JSDoc comment for a function node
    fn extract_jsdoc_comment(start_pos: tree_sitter::Point, content: &str) -> Option<String> {
        // Look for comment nodes before the function
        let lines: Vec<&str> = content.lines().collect();
        let mut comment_lines = Vec::new();

        // Check lines before the function for JSDoc comments
        for line_idx in (0..start_pos.row).rev() {
            if let Some(line) = lines.get(line_idx) {
                let trimmed = line.trim();
                if trimmed.starts_with("/**") || trimmed.starts_with("*") || trimmed.ends_with("*/") {
                    comment_lines.insert(0, trimmed.to_string());
                    if trimmed.starts_with("/**") {
                        break;
                    }
                } else if !trimmed.is_empty() {
                    break;
                }
            }
        }

        if !comment_lines.is_empty() {
            Some(comment_lines.join("\n"))
        } else {
            None
        }
    }

    /// Extract TSDoc comment for a TypeScript function node
    fn extract_tsdoc_comment(start_pos: tree_sitter::Point, content: &str) -> Option<String> {
        // TSDoc uses the same format as JSDoc
        Self::extract_jsdoc_comment(start_pos, content)
    }

    /// Extract Go doc comment for a function node
    fn extract_go_doc_comment(start_pos: tree_sitter::Point, content: &str) -> Option<String> {
        // Go doc comments are single-line comments immediately before the declaration
        let lines: Vec<&str> = content.lines().collect();
        let mut comment_lines = Vec::new();

        // Check lines before the function for Go doc comments
        for line_idx in (0..start_pos.row).rev() {
            if let Some(line) = lines.get(line_idx) {
                let trimmed = line.trim();
                if trimmed.starts_with("//") {
                    comment_lines.insert(0, trimmed.trim_start_matches("//").trim().to_string());
                } else if !trimmed.is_empty() {
                    break;
                }
            }
        }

        if !comment_lines.is_empty() {
            Some(comment_lines.join("\n"))
        } else {
            None
        }
    }

    /// Get or create a parser for the given language
    fn get_parser(&mut self, language: Language) -> Result<&Parser> {
        if !self.parsers.contains_key(&language) {
            let parser = Parser::new(language)?;
            self.parsers.insert(language, parser);
        }
        self.parsers.get(&language)
            .ok_or_else(|| Error::internal(format!("Parser for language {:?} not found after creation", language)))
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
            symbols: Vec::new(),
            dependencies: Vec::new(),
        };

        self.analyze_directory_recursive(&root_path, &root_path, &mut result, 0)?;

        Ok(result)
    }

    /// Analyze a single file and return analysis result
    pub fn analyze_file<P: AsRef<Path>>(&mut self, file_path: P) -> Result<AnalysisResult> {
        let file_path = file_path.as_ref();
        let mut result = AnalysisResult {
            root_path: file_path.parent().unwrap_or(file_path).to_path_buf(),
            total_files: 0,
            parsed_files: 0,
            error_files: 0,
            total_lines: 0,
            languages: HashMap::new(),
            files: Vec::new(),
            config: self.config.clone(),
            symbols: Vec::new(),
            dependencies: Vec::new(),
        };

        self.analyze_single_file(file_path, file_path.parent().unwrap_or(file_path), &mut result)?;
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

        let entries = if self.config.use_enhanced_error_handling {
            // Use safe file operations with error recovery
            let paths = self.safe_file_ops.list_directory(current_path)?;
            paths.into_iter().map(|path| DirEntryWrapper { path }).collect::<Vec<_>>()
        } else {
            // Use standard file operations
            let entries = fs::read_dir(current_path)
                .map_err(|e| Error::internal(format!("Failed to read directory {}: {}", current_path.display(), e)))?;
            let mut result = Vec::new();
            for entry in entries {
                let entry = entry.map_err(|e| Error::internal(format!("Failed to read directory entry: {}", e)))?;
                result.push(DirEntryWrapper { path: entry.path() });
            }
            result
        };

        for entry in entries {
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
                if let Err(e) = self.analyze_single_file(&path, root_path, result) {
                    eprintln!("Warning: Failed to analyze file {}: {}", path.display(), e);
                }
            }
        }

        Ok(())
    }

    /// Analyze a single file
    fn analyze_single_file(&mut self, file_path: &Path, root_path: &Path, result: &mut AnalysisResult) -> Result<()> {
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

        // Check file size and read content with enhanced error handling
        let (file_size, content) = if self.config.use_enhanced_error_handling {
            // Use safe file operations with error recovery
            let metadata = self.safe_file_ops.get_metadata(file_path)?;
            let file_size = metadata.len() as usize;

            if let Some(max_size) = self.config.max_file_size {
                if file_size > max_size {
                    return Ok(()); // Skip large files
                }
            }

            let content = self.safe_file_ops.read_file(file_path)?;
            (file_size, content)
        } else {
            // Use standard file operations
            let metadata = fs::metadata(file_path)?;
            let file_size = metadata.len() as usize;

            if let Some(max_size) = self.config.max_file_size {
                if file_size > max_size {
                    return Ok(()); // Skip large files
                }
            }

            let content = fs::read_to_string(file_path)?;
            (file_size, content)
        };
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
            imports: Vec::new(),
            exports: Vec::new(),
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

                // Extract symbols
                file_info.symbols = self.extract_symbols(&tree, &content, language)?;
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
            Language::JavaScript => {
                self.extract_javascript_symbols(tree, content, &mut symbols)?;
            }
            Language::TypeScript => {
                self.extract_typescript_symbols(tree, content, &mut symbols)?;
            }
            Language::Python => {
                self.extract_python_symbols(tree, content, &mut symbols)?;
            }
            Language::C => {
                self.extract_c_symbols(tree, content, &mut symbols)?;
            }
            Language::Cpp => {
                self.extract_cpp_symbols(tree, content, &mut symbols)?;
            }
            Language::Go => {
                self.extract_go_symbols(tree, content, &mut symbols)?;
            }
        }

        Ok(symbols)
    }

    /// Extract Rust symbols
    fn extract_rust_symbols(&self, tree: &SyntaxTree, content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        use crate::languages::rust::RustSyntax;

        // Extract functions
        let functions = RustSyntax::find_functions(tree, content);
        for (name, start_pos, end_pos) in functions {
            let is_public = RustSyntax::is_public_function(&name, content);
            let documentation = RustSyntax::extract_doc_comment(&name, content);

            symbols.push(Symbol {
                name,
                kind: "function".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation,
                is_public,
            });
        }

        // Extract structs
        let structs = RustSyntax::find_structs(tree, content);
        for (name, start_pos, end_pos) in structs {
            let is_public = RustSyntax::is_public_struct(&name, content);
            let documentation = RustSyntax::extract_doc_comment(&name, content);

            symbols.push(Symbol {
                name,
                kind: "struct".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation,
                is_public,
            });
        }

        // Extract structs
        let structs = tree.find_nodes_by_kind("struct_item");
        for struct_node in structs {
            if let Some(name_node) = struct_node.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let is_public = struct_node.children().iter().any(|child| child.kind() == "visibility_modifier");
                    
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "struct".to_string(),
                        start_line: struct_node.start_position().row + 1,
                        end_line: struct_node.end_position().row + 1,
                        start_column: struct_node.start_position().column,
                        end_column: struct_node.end_position().column,
                        documentation: None,
                        is_public,
                    });
                }
            }
        }

        // Extract enums
        let enums = tree.find_nodes_by_kind("enum_item");
        for enum_node in enums {
            if let Some(name_node) = enum_node.child_by_field_name("name") {
                if let Ok(name) = name_node.text() {
                    let is_public = enum_node.children().iter().any(|child| child.kind() == "visibility_modifier");
                    
                    symbols.push(Symbol {
                        name: name.to_string(),
                        kind: "enum".to_string(),
                        start_line: enum_node.start_position().row + 1,
                        end_line: enum_node.end_position().row + 1,
                        start_column: enum_node.start_position().column,
                        end_column: enum_node.end_position().column,
                        documentation: None,
                        is_public,
                    });
                }
            }
        }

        Ok(())
    }

    /// Extract JavaScript symbols
    fn extract_javascript_symbols(&self, tree: &SyntaxTree, content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        use crate::languages::javascript::JavaScriptSyntax;

        // Extract functions
        let functions = JavaScriptSyntax::find_functions(tree, content);
        for (name, start_pos, end_pos) in functions {
            symbols.push(Symbol {
                name,
                kind: "function".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: Self::extract_jsdoc_comment(start_pos, content),
                is_public: true, // JavaScript functions are generally public
            });
        }

        // Extract classes
        let classes = JavaScriptSyntax::find_classes(tree, content);
        for (name, start_pos, end_pos) in classes {
            symbols.push(Symbol {
                name,
                kind: "class".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true,
            });
        }

        Ok(())
    }

    /// Extract TypeScript symbols
    fn extract_typescript_symbols(&self, tree: &SyntaxTree, content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        use crate::languages::typescript::TypeScriptSyntax;

        // Extract functions
        let functions = TypeScriptSyntax::find_functions(tree, content);
        for (name, start_pos, end_pos) in functions {
            symbols.push(Symbol {
                name,
                kind: "function".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: Self::extract_tsdoc_comment(start_pos, content),
                is_public: true, // TypeScript functions are generally public
            });
        }

        // Extract classes
        let classes = TypeScriptSyntax::find_classes(tree, content);
        for (name, start_pos, end_pos) in classes {
            symbols.push(Symbol {
                name,
                kind: "class".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true,
            });
        }

        // Extract interfaces
        let interfaces = TypeScriptSyntax::find_interfaces(tree, content);
        for (name, start_pos, end_pos) in interfaces {
            symbols.push(Symbol {
                name,
                kind: "interface".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true,
            });
        }

        // Extract type aliases
        let type_aliases = TypeScriptSyntax::find_type_aliases(tree, content);
        for (name, start_pos, end_pos) in type_aliases {
            symbols.push(Symbol {
                name,
                kind: "type".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true,
            });
        }

        // Extract enums
        let enums = TypeScriptSyntax::find_enums(tree, content);
        for (name, start_pos, end_pos) in enums {
            symbols.push(Symbol {
                name,
                kind: "enum".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true,
            });
        }

        Ok(())
    }

    /// Extract Python symbols
    fn extract_python_symbols(&self, tree: &SyntaxTree, content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        use crate::languages::python::PythonSyntax;

        // Extract functions
        let functions = PythonSyntax::find_functions(tree, content);
        for (name, start_pos, end_pos) in functions {
            let is_public = !name.starts_with('_');
            let documentation = PythonSyntax::extract_docstring(&name, content);

            symbols.push(Symbol {
                name,
                kind: "function".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation,
                is_public,
            });
        }

        // Extract classes
        let classes = PythonSyntax::find_classes(tree, content);
        for (name, start_pos, end_pos) in classes {
            let is_public = !name.starts_with('_');
            let documentation = PythonSyntax::extract_docstring(&name, content);

            symbols.push(Symbol {
                name,
                kind: "class".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation,
                is_public,
            });
        }

        // Extract methods within classes
        let methods = PythonSyntax::find_methods(tree, content);
        for (class_name, method_name, location) in methods {
            let is_public = !method_name.starts_with('_');
            let full_name = format!("{}::{}", class_name, method_name);

            symbols.push(Symbol {
                name: full_name.clone(),
                kind: "method".to_string(),
                start_line: location.row + 1,
                end_line: location.row + 1,
                start_column: location.column,
                end_column: location.column,
                documentation: PythonSyntax::extract_docstring(&full_name, content),
                is_public,
            });
        }

        // Extract global variables
        let globals = PythonSyntax::find_global_variables(tree, content);
        for (name, location) in globals {
            let is_public = !name.starts_with('_');

            symbols.push(Symbol {
                name,
                kind: "variable".to_string(),
                start_line: location.row + 1,
                end_line: location.row + 1,
                start_column: location.column,
                end_column: location.column,
                documentation: None,
                is_public,
            });
        }

        Ok(())
    }

    /// Extract C/C++ symbols
    fn extract_c_symbols(&self, tree: &SyntaxTree, content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        use crate::languages::c::CSyntax;
        use crate::languages::cpp::CppSyntax;

        // Extract functions
        let functions = CSyntax::find_functions(tree, content);
        for (name, start_pos, end_pos) in functions {
            symbols.push(Symbol {
                name,
                kind: "function".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true, // C functions are generally public
            });
        }

        // Extract structs
        let structs = CSyntax::find_structs(tree, content);
        for (name, start_pos, end_pos) in structs {
            symbols.push(Symbol {
                name,
                kind: "struct".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true,
            });
        }

        // Extract typedefs
        let typedefs = CSyntax::find_typedefs(tree, content);
        for (name, start_pos, end_pos) in typedefs {
            symbols.push(Symbol {
                name,
                kind: "typedef".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true,
            });
        }

        // For C++, also extract classes and namespaces
        let classes = CppSyntax::find_classes(tree, content);
        for (name, start_pos, end_pos) in classes {
            // Find the class node to check access modifiers
            let class_nodes = tree.find_nodes_by_kind("class_specifier");
            let is_public = class_nodes.iter()
                .find(|node| node.start_position() == start_pos)
                .map(|node| CppSyntax::is_public_member(node))
                .unwrap_or(true);

            symbols.push(Symbol {
                name,
                kind: "class".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public,
            });
        }

        let namespaces = CppSyntax::find_namespaces(tree, content);
        for (name, start_pos, end_pos) in namespaces {
            symbols.push(Symbol {
                name,
                kind: "namespace".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true,
            });
        }

        Ok(())
    }

    /// Extract C++ symbols (separate from C for better C++ specific features)
    fn extract_cpp_symbols(&self, tree: &SyntaxTree, content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        use crate::languages::c::CSyntax;
        use crate::languages::cpp::CppSyntax;

        // Extract functions (both C and C++ style)
        let functions = CSyntax::find_functions(tree, content);
        for (name, start_pos, end_pos) in functions {
            symbols.push(Symbol {
                name,
                kind: "function".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true, // C++ functions are generally public unless in private class section
            });
        }

        // Extract C++ classes
        let classes = CppSyntax::find_classes(tree, content);
        for (name, start_pos, end_pos) in classes {
            // Find the class node to check access modifiers
            let class_nodes = tree.find_nodes_by_kind("class_specifier");
            let is_public = class_nodes.iter()
                .find(|node| node.start_position() == start_pos)
                .map(|node| CppSyntax::is_public_member(node))
                .unwrap_or(true);

            symbols.push(Symbol {
                name,
                kind: "class".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public,
            });
        }

        // Extract namespaces
        let namespaces = CppSyntax::find_namespaces(tree, content);
        for (name, start_pos, end_pos) in namespaces {
            symbols.push(Symbol {
                name,
                kind: "namespace".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true,
            });
        }

        // Extract structs
        let structs = CSyntax::find_structs(tree, content);
        for (name, start_pos, end_pos) in structs {
            symbols.push(Symbol {
                name,
                kind: "struct".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true,
            });
        }

        // Extract typedefs (C-style typedefs also work in C++)
        let typedefs = CSyntax::find_typedefs(tree, content);
        for (name, start_pos, end_pos) in typedefs {
            symbols.push(Symbol {
                name,
                kind: "typedef".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public: true,
            });
        }

        Ok(())
    }

    /// Extract Go symbols
    fn extract_go_symbols(&self, tree: &SyntaxTree, content: &str, symbols: &mut Vec<Symbol>) -> Result<()> {
        use crate::languages::go::GoSyntax;

        // Extract functions
        let functions = GoSyntax::find_functions(tree, content);
        for (name, start_pos, end_pos) in functions {
            let is_public = GoSyntax::is_exported(&name);
            symbols.push(Symbol {
                name,
                kind: "function".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: Self::extract_go_doc_comment(start_pos, content),
                is_public,
            });
        }

        // Extract methods
        let methods = GoSyntax::find_methods(tree, content);
        for (name, receiver_type, start_pos, end_pos) in methods {
            let is_public = GoSyntax::is_exported(&name);
            symbols.push(Symbol {
                name: format!("{}::{}", receiver_type, name),
                kind: "method".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public,
            });
        }

        // Extract types (structs, interfaces)
        let types = GoSyntax::find_types(tree, content);
        for (name, start_pos, end_pos) in types {
            let is_public = GoSyntax::is_exported(&name);
            symbols.push(Symbol {
                name,
                kind: "type".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public,
            });
        }

        // Extract constants
        let constants = GoSyntax::find_constants(tree, content);
        for (name, start_pos, end_pos) in constants {
            let is_public = GoSyntax::is_exported(&name);
            symbols.push(Symbol {
                name,
                kind: "constant".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public,
            });
        }

        // Extract variables
        let variables = GoSyntax::find_variables(tree, content);
        for (name, start_pos, end_pos) in variables {
            let is_public = GoSyntax::is_exported(&name);
            symbols.push(Symbol {
                name,
                kind: "variable".to_string(),
                start_line: start_pos.row + 1,
                end_line: end_pos.row + 1,
                start_column: start_pos.column,
                end_column: end_pos.column,
                documentation: None,
                is_public,
            });
        }

        Ok(())
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
    fn test_analyze_directory() -> Result<()> {
        // Create a temporary directory with some test files
        let temp_dir = TempDir::new()
            .map_err(|e| Error::internal(format!("Failed to create temp directory: {}", e)))?;
        let temp_path = temp_dir.path();

        // Create a Rust file
        let rust_file = temp_path.join("main.rs");
        fs::write(&rust_file, r#"
            pub fn main() {
                println!("Hello, world!");
            }

            struct Point {
                x: i32,
                y: i32,
            }
        "#).map_err(|e| Error::file_system(format!("Failed to write Rust test file: {}", e)))?;

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
        "#).map_err(|e| Error::file_system(format!("Failed to write JavaScript test file: {}", e)))?;

        // Analyze the directory
        let mut analyzer = CodebaseAnalyzer::new();
        let result = analyzer.analyze_directory(temp_path)?;

        assert_eq!(result.total_files, 2);
        assert_eq!(result.parsed_files, 2);
        assert_eq!(result.error_files, 0);
        assert!(result.languages.contains_key("Rust"));
        assert!(result.languages.contains_key("JavaScript"));

        // Check that symbols were extracted
        let rust_file_info = result.files.iter()
            .find(|f| f.path.extension().map_or(false, |ext| ext == "rs"))
            .ok_or_else(|| Error::internal("No Rust file found in test results"))?;
        assert!(rust_file_info.symbols.len() > 0);
        assert!(rust_file_info.symbols.iter().any(|s| s.name == "main"));

        let js_file_info = result.files.iter()
            .find(|f| f.path.extension().map_or(false, |ext| ext == "js"))
            .ok_or_else(|| Error::internal("No JavaScript file found in test results"))?;
        assert!(js_file_info.symbols.len() > 0);
        assert!(js_file_info.symbols.iter().any(|s| s.name == "greet"));

        Ok(())
    }

    #[test]
    fn test_jsdoc_extraction() {
        let content = r#"
/**
 * This is a JSDoc comment
 * @param name The name parameter
 * @returns A greeting string
 */
function greet(name) {
    return "Hello, " + name;
}
        "#;

        let start_pos = tree_sitter::Point { row: 6, column: 0 };
        let doc = CodebaseAnalyzer::extract_jsdoc_comment(start_pos, content);

        assert!(doc.is_some());
        let doc_text = doc.unwrap();
        assert!(doc_text.contains("This is a JSDoc comment"));
        assert!(doc_text.contains("@param name"));
        assert!(doc_text.contains("@returns"));
    }

    #[test]
    fn test_go_doc_extraction() {
        let content = r#"
// Package main provides the entry point
package main

// greet returns a greeting message for the given name.
// It formats the name with a standard greeting.
func greet(name string) string {
    return "Hello, " + name
}
        "#;

        let start_pos = tree_sitter::Point { row: 6, column: 0 };
        let doc = CodebaseAnalyzer::extract_go_doc_comment(start_pos, content);

        assert!(doc.is_some());
        let doc_text = doc.unwrap();
        assert!(doc_text.contains("greet returns a greeting message"));
        assert!(doc_text.contains("It formats the name"));
    }

    #[test]
    fn test_no_documentation() {
        let content = r#"
function greet(name) {
    return "Hello, " + name;
}
        "#;

        let start_pos = tree_sitter::Point { row: 1, column: 0 };
        let doc = CodebaseAnalyzer::extract_jsdoc_comment(start_pos, content);

        assert!(doc.is_none());
    }
}
