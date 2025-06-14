//! Query system for pattern matching in syntax trees

use crate::error::{Error, Result};
use crate::languages::Language;
use crate::tree::{Node, SyntaxTree};
use tree_sitter::{Point, Range};

/// A wrapper around tree-sitter's Query with additional functionality
pub struct Query {
    inner: tree_sitter::Query,
    language: Language,
}

impl Query {
    /// Create a new query for the specified language
    pub fn new(language: Language, pattern: &str) -> Result<Self> {
        let ts_language = language.tree_sitter_language()?;
        let query = tree_sitter::Query::new(&ts_language, pattern)?;
        
        Ok(Self {
            inner: query,
            language,
        })
    }

    /// Get the language this query is for
    pub fn language(&self) -> Language {
        self.language
    }

    /// Get the number of patterns in this query
    pub fn pattern_count(&self) -> usize {
        self.inner.pattern_count()
    }

    /// Get capture names
    pub fn capture_names(&self) -> Vec<&str> {
        self.inner.capture_names().iter().copied().collect()
    }

    /// Execute the query on a syntax tree
    pub fn matches<'a>(&'a self, tree: &'a SyntaxTree) -> Result<Vec<QueryMatch<'a>>> {
        let mut cursor = tree_sitter::QueryCursor::new();
        let root = tree.root_node();

        let mut matches = Vec::new();

        // Collect all matches first to avoid lifetime issues
        let ts_matches: Vec<_> = cursor
            .matches(&self.inner, root.inner(), tree.source().as_bytes())
            .collect();

        // Convert to our QueryMatch type
        for ts_match in ts_matches {
            let mut captures = Vec::new();
            for capture in ts_match.captures {
                let node = Node::new(capture.node, tree.source());
                let query_capture = QueryCapture {
                    node,
                    index: capture.index,
                    name: self.inner.capture_names().get(capture.index as usize).map(|s| s.to_string()),
                };
                captures.push(query_capture);
            }

            let query_match = QueryMatch {
                pattern_index: ts_match.pattern_index,
                captures,
            };
            matches.push(query_match);
        }

        Ok(matches)
    }

    /// Execute the query and get captures
    pub fn captures<'a>(&'a self, tree: &'a SyntaxTree) -> Result<Vec<QueryCapture<'a>>> {
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut captures = Vec::new();

        // Get the source text from the tree
        let source = tree.source();

        // Execute the query and collect all captures
        for (query_match, _) in cursor.captures(&self.inner, tree.root_node().inner(), source.as_bytes()) {
            for capture in query_match.captures {
                let query_capture = QueryCapture::new(&capture, source, &self.inner);
                captures.push(query_capture);
            }
        }

        Ok(captures)
    }

    /// Execute the query on a specific node
    pub fn matches_in_node<'a>(&'a self, node: Node<'a>, source: &'a str) -> Result<Vec<QueryMatch<'a>>> {
        let mut cursor = tree_sitter::QueryCursor::new();
        let mut matches = Vec::new();

        // Execute the query on the specific node
        for query_match in cursor.matches(&self.inner, node.inner(), source.as_bytes()) {
            let mut captures = Vec::new();

            // Collect all captures for this match
            for capture in query_match.captures {
                let query_capture = QueryCapture::new(&capture, source, &self.inner);
                captures.push(query_capture);
            }

            let match_result = QueryMatch::new(query_match.pattern_index, captures);
            matches.push(match_result);
        }

        Ok(matches)
    }

    /// Create a query for syntax highlighting
    pub fn highlights(language: Language) -> Result<Self> {
        let highlights_query = language.highlights_query()
            .ok_or_else(|| Error::not_supported(format!("Highlights query not available for {}", language.name())))?;
        
        Self::new(language, highlights_query)
    }

    /// Create a query for finding function definitions
    pub fn functions(language: Language) -> Result<Self> {
        let pattern = match language {
            Language::Rust => "(function_item name: (identifier) @name) @function",
            Language::JavaScript => "(function_declaration name: (identifier) @name) @function",
            Language::TypeScript => "(function_declaration name: (identifier) @name) @function",
            Language::Python => "(function_definition name: (identifier) @name) @function",
            Language::C => "(function_definition declarator: (function_declarator declarator: (identifier) @name)) @function",
            Language::Cpp => "(function_definition declarator: (function_declarator declarator: (identifier) @name)) @function",
            Language::Go => "(function_declaration name: (identifier) @name) @function",
        };

        Self::new(language, pattern)
    }

    /// Create a query for finding class/struct definitions
    pub fn classes(language: Language) -> Result<Self> {
        let pattern = match language {
            Language::Rust => "(struct_item name: (type_identifier) @name) @struct",
            Language::JavaScript => "(class_declaration name: (identifier) @name) @class",
            Language::TypeScript => "(class_declaration name: (type_identifier) @name) @class",
            Language::Python => "(class_definition name: (identifier) @name) @class",
            Language::C => "(struct_specifier name: (type_identifier) @name) @struct",
            Language::Cpp => "[(class_specifier name: (type_identifier) @name) (struct_specifier name: (type_identifier) @name)] @class",
            Language::Go => "(type_declaration (type_spec name: (type_identifier) @name)) @struct",
        };

        Self::new(language, pattern)
    }
}

/// A query match result
pub struct QueryMatch<'a> {
    pattern_index: usize,
    captures: Vec<QueryCapture<'a>>,
}

impl<'a> QueryMatch<'a> {
    /// Create a new query match
    pub(crate) fn new(pattern_index: usize, captures: Vec<QueryCapture<'a>>) -> Self {
        Self {
            pattern_index,
            captures,
        }
    }

    /// Get the pattern index
    pub fn pattern_index(&self) -> usize {
        self.pattern_index
    }

    /// Get all captures in this match
    pub fn captures(&self) -> Vec<QueryCapture<'a>> {
        self.captures.clone()
    }

    /// Get a capture by name
    pub fn capture_by_name(&self, query: &Query, name: &str) -> Option<QueryCapture<'a>> {
        let capture_names = query.capture_names();
        let capture_index = capture_names.iter().position(|&n| n == name)?;

        self.captures.iter()
            .find(|capture| capture.index as usize == capture_index)
            .cloned()
    }
}

/// A query capture result
#[derive(Clone)]
pub struct QueryCapture<'a> {
    node: Node<'a>,
    index: u32,
    name: Option<String>,
}

impl<'a> QueryCapture<'a> {
    /// Create a new query capture
    pub(crate) fn new(
        capture: &tree_sitter::QueryCapture<'a>,
        source: &'a str,
        query: &tree_sitter::Query,
    ) -> Self {
        let name = query.capture_names()
            .get(capture.index as usize)
            .map(|s| s.to_string());

        Self {
            node: Node::new(capture.node, source),
            index: capture.index,
            name,
        }
    }

    /// Create from a tree-sitter capture
    pub(crate) fn from_capture(capture: &tree_sitter::QueryCapture<'a>, source: &'a str) -> Self {
        Self {
            node: Node::new(capture.node, source),
            index: capture.index,
            name: None,
        }
    }

    /// Get the captured node
    pub fn node(&self) -> Node<'a> {
        self.node
    }

    /// Get the capture index
    pub fn index(&self) -> u32 {
        self.index
    }

    /// Get the capture name (if available)
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    /// Get the text of the captured node
    pub fn text(&self) -> Result<&'a str> {
        self.node.text()
    }

    /// Get the byte range of the captured node
    pub fn byte_range(&self) -> Range {
        self.node.byte_range()
    }

    /// Get the start position of the captured node
    pub fn start_position(&self) -> Point {
        self.node.start_position()
    }

    /// Get the end position of the captured node
    pub fn end_position(&self) -> Point {
        self.node.end_position()
    }
}

/// Query builder for common patterns
pub struct QueryBuilder {
    language: Language,
    patterns: Vec<String>,
}

impl QueryBuilder {
    /// Create a new query builder
    pub fn new(language: Language) -> Self {
        Self {
            language,
            patterns: Vec::new(),
        }
    }

    /// Add a pattern to find nodes by kind
    pub fn find_kind(mut self, kind: &str, capture_name: &str) -> Self {
        self.patterns.push(format!("({}) @{}", kind, capture_name));
        self
    }

    /// Add a pattern to find nodes with specific field
    pub fn find_with_field(mut self, kind: &str, field: &str, field_kind: &str, capture_name: &str) -> Self {
        self.patterns.push(format!("({} {}: ({})) @{}", kind, field, field_kind, capture_name));
        self
    }

    /// Add a custom pattern
    pub fn add_pattern(mut self, pattern: &str) -> Self {
        self.patterns.push(pattern.to_string());
        self
    }

    /// Build the query
    pub fn build(self) -> Result<Query> {
        if self.patterns.is_empty() {
            return Err(Error::query("No patterns added to query builder"));
        }
        
        let combined_pattern = self.patterns.join("\n");
        Query::new(self.language, &combined_pattern)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Parser, Language};

    #[test]
    fn test_query_creation() {
        let query = Query::new(Language::Rust, "(function_item) @function");
        assert!(query.is_ok());
        
        let query = query.unwrap();
        assert_eq!(query.language(), Language::Rust);
        assert_eq!(query.pattern_count(), 1);
    }

    #[test]
    fn test_query_execution() {
        let mut parser = Parser::new(Language::Rust).unwrap();
        let source = "fn main() {} fn test() {}";
        let tree = parser.parse(source, None).unwrap();

        let query = Query::new(Language::Rust, "(function_item) @function").unwrap();
        let matches = query.matches(&tree).unwrap();
        
        assert_eq!(matches.len(), 2);
    }

    #[test]
    fn test_query_builder() {
        let query = QueryBuilder::new(Language::Rust)
            .find_kind("function_item", "function")
            .find_kind("struct_item", "struct")
            .build();

        match query {
            Ok(_) => {},
            Err(e) => {
                println!("Query error: {:?}", e);
                panic!("Query failed: {}", e);
            }
        }
    }

    #[test]
    fn test_predefined_queries() {
        let functions_query = Query::functions(Language::Rust);
        assert!(functions_query.is_ok());

        let classes_query = Query::classes(Language::Rust);
        assert!(classes_query.is_ok());
    }

    #[test]
    fn test_query_captures() {
        let mut parser = Parser::new(Language::Rust).unwrap();
        let source = "fn main() { let x = 42; } fn test() { let y = 24; }";
        let tree = parser.parse(source, None).unwrap();

        let query = Query::new(Language::Rust, "(function_item name: (identifier) @name) @function").unwrap();
        let captures = query.captures(&tree).unwrap();

        // Should have captures for function names and function items
        // Note: tree-sitter may return duplicate captures from multiple matches
        assert!(captures.len() >= 4);

        // Check that we can get text from captures
        let capture_texts: Vec<String> = captures.iter()
            .map(|c| c.text().unwrap().to_string())
            .collect();

        assert!(capture_texts.contains(&"main".to_string()));
        assert!(capture_texts.contains(&"test".to_string()));

        // Check that we have both function names and function bodies
        let name_captures: Vec<_> = captures.iter()
            .filter(|c| c.name() == Some("name"))
            .collect();
        let function_captures: Vec<_> = captures.iter()
            .filter(|c| c.name() == Some("function"))
            .collect();

        assert!(name_captures.len() >= 2);
        assert!(function_captures.len() >= 2);
    }

    #[test]
    fn test_matches_in_node() {
        let mut parser = Parser::new(Language::Rust).unwrap();
        let source = "fn main() { let x = 42; let y = 24; }";
        let tree = parser.parse(source, None).unwrap();

        // Get the function body
        let function_node = tree.find_nodes_by_kind("function_item")[0];
        let body_node = function_node.child_by_field_name("body").unwrap();

        let query = Query::new(Language::Rust, "(let_declaration pattern: (identifier) @var)").unwrap();
        let matches = query.matches_in_node(body_node, source).unwrap();

        // Should find 2 let declarations
        assert_eq!(matches.len(), 2);

        // Check that each match has captures
        for query_match in matches {
            assert!(!query_match.captures().is_empty());
        }
    }

    #[test]
    fn test_capture_names() {
        let mut parser = Parser::new(Language::Rust).unwrap();
        let source = "fn main() {}";
        let tree = parser.parse(source, None).unwrap();

        let query = Query::new(Language::Rust, "(function_item name: (identifier) @func_name) @function").unwrap();
        let captures = query.captures(&tree).unwrap();

        // Find captures by name
        let name_captures: Vec<_> = captures.iter()
            .filter(|c| c.name() == Some("func_name"))
            .collect();

        assert!(name_captures.len() >= 1);
        assert_eq!(name_captures[0].text().unwrap(), "main");

        // Verify we also have function captures
        let function_captures: Vec<_> = captures.iter()
            .filter(|c| c.name() == Some("function"))
            .collect();

        assert!(function_captures.len() >= 1);
    }
}
