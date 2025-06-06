//! Rust language specific functionality

use crate::error::Result;
use crate::query::Query;
use crate::tree::SyntaxTree;
use tree_sitter::Node;

/// Rust-specific syntax tree utilities
pub struct RustSyntax;

impl RustSyntax {
    /// Check if a node is a function definition
    pub fn is_function(node: &Node) -> bool {
        node.kind() == "function_item"
    }

    /// Check if a node is a struct definition
    pub fn is_struct(node: &Node) -> bool {
        node.kind() == "struct_item"
    }

    /// Check if a node is an enum definition
    pub fn is_enum(node: &Node) -> bool {
        node.kind() == "enum_item"
    }

    /// Check if a node is an impl block
    pub fn is_impl(node: &Node) -> bool {
        node.kind() == "impl_item"
    }

    /// Check if a node is a trait definition
    pub fn is_trait(node: &Node) -> bool {
        node.kind() == "trait_item"
    }

    /// Check if a node is a module definition
    pub fn is_module(node: &Node) -> bool {
        node.kind() == "mod_item"
    }

    /// Check if a node is a use statement
    pub fn is_use_statement(node: &Node) -> bool {
        node.kind() == "use_declaration"
    }

    /// Extract function name from a function node
    pub fn function_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_function(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.utf8_text(source.as_bytes()).ok())
            .map(|s| s.to_string())
    }

    /// Extract struct name from a struct node
    pub fn struct_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_struct(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.utf8_text(source.as_bytes()).ok())
            .map(|s| s.to_string())
    }

    /// Extract enum name from an enum node
    pub fn enum_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_enum(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.utf8_text(source.as_bytes()).ok())
            .map(|s| s.to_string())
    }

    /// Extract trait name from a trait node
    pub fn trait_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_trait(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.utf8_text(source.as_bytes()).ok())
            .map(|s| s.to_string())
    }

    /// Extract module name from a module node
    pub fn module_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_module(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.utf8_text(source.as_bytes()).ok())
            .map(|s| s.to_string())
    }

    /// Get all function definitions in a syntax tree
    pub fn find_functions(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point)> {
        let mut functions = Vec::new();
        let function_nodes = tree.find_nodes_by_kind("function_item");

        for func_node in function_nodes {
            let ts_node = func_node.inner();
            if let Some(name) = Self::function_name(&ts_node, source) {
                functions.push((name, func_node.start_position()));
            }
        }

        functions
    }

    /// Get all struct definitions in a syntax tree
    pub fn find_structs(tree: &SyntaxTree, source: &str) -> Vec<(String, tree_sitter::Point)> {
        let mut structs = Vec::new();
        let struct_nodes = tree.find_nodes_by_kind("struct_item");

        for struct_node in struct_nodes {
            let ts_node = struct_node.inner();
            if let Some(name) = Self::struct_name(&ts_node, source) {
                structs.push((name, struct_node.start_position()));
            }
        }

        structs
    }

    /// Create a query to find all public functions
    pub fn public_functions_query() -> Result<Query> {
        let query_str = r#"
            (function_item
                (visibility_modifier) @visibility
                name: (identifier) @name
            ) @function
        "#;
        Query::new(crate::Language::Rust, query_str)
    }

    /// Create a query to find all struct definitions
    pub fn structs_query() -> Result<Query> {
        let query_str = r#"
            (struct_item
                name: (type_identifier) @name
            ) @struct
        "#;
        Query::new(crate::Language::Rust, query_str)
    }

    /// Create a query to find all impl blocks
    pub fn impl_blocks_query() -> Result<Query> {
        let query_str = r#"
            (impl_item
                type: (type_identifier) @type
            ) @impl
        "#;
        Query::new(crate::Language::Rust, query_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parser;

    #[test]
    fn test_rust_syntax_detection() {
        let source = r#"
            fn main() {
                println!("Hello, world!");
            }
            
            struct Point {
                x: i32,
                y: i32,
            }
            
            enum Color {
                Red,
                Green,
                Blue,
            }
        "#;

        let mut parser = Parser::new(crate::Language::Rust).unwrap();
        let tree = parser.parse(source, None).unwrap();
        let root = tree.root_node();

        let mut found_function = false;
        let mut found_struct = false;
        let mut found_enum = false;

        let mut cursor = root.walk();
        if cursor.goto_first_child() {
            loop {
                let node = cursor.node();
                let ts_node = node.inner();
                if RustSyntax::is_function(&ts_node) {
                    found_function = true;
                    assert_eq!(RustSyntax::function_name(&ts_node, source), Some("main".to_string()));
                }
                if RustSyntax::is_struct(&ts_node) {
                    found_struct = true;
                    assert_eq!(RustSyntax::struct_name(&ts_node, source), Some("Point".to_string()));
                }
                if RustSyntax::is_enum(&ts_node) {
                    found_enum = true;
                    assert_eq!(RustSyntax::enum_name(&ts_node, source), Some("Color".to_string()));
                }

                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        assert!(found_function);
        assert!(found_struct);
        assert!(found_enum);
    }
}
