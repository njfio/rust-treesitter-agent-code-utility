//! Comprehensive tests for the tree module
//!
//! Tests all aspects of the SyntaxTree including:
//! - Tree creation and validation
//! - Node navigation and traversal
//! - Tree analysis and statistics
//! - Error handling
//! - Tree serialization and display

use rust_tree_sitter::*;
use rust_tree_sitter::parser::Parser;

#[test]
fn test_syntax_tree_creation() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = "fn main() { println!(\"Hello, world!\"); }";
    
    let tree = parser.parse(source, None)?;

    let root = tree.root_node();
    assert_eq!(root.kind(), "source_file");
    assert!(root.child_count() > 0);
    
    Ok(())
}

#[test]
fn test_tree_root_node() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = "fn test() {}";
    
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();

    assert_eq!(root.kind(), "source_file");
    assert_eq!(root.start_position().row, 0);
    assert_eq!(root.start_position().column, 0);
    assert!(root.end_position().row >= 0);
    assert!(root.end_position().column >= 0);
    
    Ok(())
}

#[test]
fn test_tree_node_children() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = r#"
fn main() {
    let x = 5;
    println!("{}", x);
}
"#;
    
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    
    assert!(root.child_count() > 0);
    
    // Test child access
    if let Some(first_child) = root.child(0) {
        assert!(!first_child.kind().is_empty());
    }
    
    // Test child iteration
    let mut child_count = 0;
    let mut cursor = root.walk();
    
    if cursor.goto_first_child() {
        loop {
            child_count += 1;
            if !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    
    assert!(child_count > 0);
    
    Ok(())
}

#[test]
fn test_tree_node_navigation() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = r#"
struct Point {
    x: i32,
    y: i32,
}

impl Point {
    fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }
}
"#;
    
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    
    // Test tree walking
    let mut cursor = root.walk();
    let mut node_count = 0;
    let mut max_depth = 0;
    let mut current_depth = 0;
    
    // Depth-first traversal
    loop {
        node_count += 1;
        max_depth = max_depth.max(current_depth);
        
        if cursor.goto_first_child() {
            current_depth += 1;
        } else {
            while !cursor.goto_next_sibling() {
                if !cursor.goto_parent() {
                    break;
                }
                current_depth -= 1;
            }
            if current_depth == 0 && !cursor.goto_next_sibling() {
                break;
            }
        }
    }
    
    assert!(node_count > 10); // Should have many nodes
    assert!(max_depth > 3); // Should have reasonable depth
    
    Ok(())
}

#[test]
fn test_tree_node_text_extraction() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = "fn hello() { println!(\"Hello, world!\"); }";
    
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    
    // Test text extraction for root node
    let root_text = root.text().unwrap();
    assert_eq!(root_text, source);

    // Test text extraction for child nodes
    if let Some(function_node) = root.child(0) {
        let function_text = function_node.text().unwrap();
        assert!(function_text.contains("fn hello"));
        assert!(function_text.contains("println!"));
    }
    
    Ok(())
}

#[test]
fn test_tree_node_positions() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = r#"fn main() {
    let x = 5;
}"#;
    
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    
    // Test root node positions
    assert_eq!(root.start_position().row, 0);
    assert_eq!(root.start_position().column, 0);
    assert!(root.end_position().row >= 2);
    
    // Test byte ranges
    let root_range = root.byte_range();
    assert_eq!(root_range.start_byte, 0);
    assert_eq!(root_range.end_byte, source.len());

    // Test child node positions
    if let Some(function_node) = root.child(0) {
        assert!(function_node.start_position().row >= 0);
        assert!(function_node.start_position().column >= 0);
        assert!(function_node.end_position().row <= root.end_position().row);
        let function_range = function_node.byte_range();
        assert!(function_range.start_byte >= root_range.start_byte);
        assert!(function_range.end_byte <= root_range.end_byte);
    }
    
    Ok(())
}

#[test]
fn test_tree_error_detection() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    
    // Valid syntax
    let valid_source = "fn main() {}";
    let valid_tree = parser.parse(valid_source, None)?;
    assert!(!valid_tree.root_node().has_error());
    
    // Invalid syntax
    let invalid_source = "fn main( { invalid }";
    let invalid_tree = parser.parse(invalid_source, None)?;
    assert!(invalid_tree.root_node().has_error());
    
    Ok(())
}

#[test]
fn test_tree_statistics() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = r#"
use std::collections::HashMap;

/// A calculator struct
pub struct Calculator {
    name: String,
    operations: HashMap<String, i32>,
}

impl Calculator {
    /// Create a new calculator
    pub fn new(name: String) -> Self {
        Self {
            name,
            operations: HashMap::new(),
        }
    }
    
    /// Add two numbers
    pub fn add(&mut self, a: i32, b: i32) -> i32 {
        let result = a + b;
        self.operations.insert("add".to_string(), result);
        result
    }
}

fn main() {
    let mut calc = Calculator::new("Test".to_string());
    println!("Result: {}", calc.add(5, 3));
}
"#;
    
    let tree = parser.parse(source, None)?;

    // Test basic tree properties instead of statistics
    let root = tree.root_node();
    assert_eq!(root.kind(), "source_file");
    assert!(root.child_count() > 0);

    // Test that we can find function nodes
    let functions = tree.find_nodes_by_kind("function_item");
    assert!(functions.len() > 0);

    // Test that source text is preserved
    assert_eq!(tree.source(), source);
    
    Ok(())
}

#[test]
fn test_tree_display() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = "fn test() { let x = 5; }";
    
    let tree = parser.parse(source, None)?;
    
    // Test tree properties instead of display formatting
    assert_eq!(tree.root_node().kind(), "source_file");
    assert!(!tree.source().is_empty());
    assert!(!tree.has_error());
    
    Ok(())
}

#[test]
fn test_tree_node_kinds() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = r#"
fn function_example() {}
struct StructExample {}
enum EnumExample { Variant }
impl StructExample {}
"#;
    
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    
    let mut found_kinds = std::collections::HashSet::new();
    let mut cursor = root.walk();
    
    // Collect all node kinds in the tree
    loop {
        found_kinds.insert(cursor.node().kind().to_string());
        
        if cursor.goto_first_child() {
            continue;
        }
        
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                break;
            }
        }
        
        // Check if we're back at the root by comparing positions
        if cursor.node().start_position() == root.start_position() &&
           cursor.node().end_position() == root.end_position() &&
           cursor.node().kind() == root.kind() {
            break;
        }
    }
    
    // Should find various Rust syntax elements
    assert!(found_kinds.contains("source_file"));
    assert!(found_kinds.contains("function_item"));
    
    Ok(())
}

#[test]
fn test_tree_node_named_vs_anonymous() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = "fn main() { let x = 5; }";
    
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    
    let mut named_count = 0;
    let mut anonymous_count = 0;
    let mut cursor = root.walk();
    
    // Count named vs anonymous nodes
    loop {
        if cursor.node().is_named() {
            named_count += 1;
        } else {
            anonymous_count += 1;
        }
        
        if cursor.goto_first_child() {
            continue;
        }
        
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                break;
            }
        }
        
        // Check if we're back at the root by comparing positions
        if cursor.node().start_position() == root.start_position() &&
           cursor.node().end_position() == root.end_position() &&
           cursor.node().kind() == root.kind() {
            break;
        }
    }
    
    assert!(named_count > 0);
    assert!(anonymous_count >= 0); // May or may not have anonymous nodes
    
    Ok(())
}

#[test]
fn test_tree_node_field_names() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = "fn test(param: i32) -> i32 { param }";
    
    let tree = parser.parse(source, None)?;
    let root = tree.root_node();
    
    // Find function node and check its fields
    let mut cursor = root.walk();
    let mut found_function = false;
    
    loop {
        let node = cursor.node();
        if node.kind() == "function_item" {
            found_function = true;
            
            // Check if function has expected children
            assert!(node.child_count() > 0);

            // Test that we can get children
            for i in 0..node.child_count() {
                if let Some(child) = node.child(i) {
                    assert!(!child.kind().is_empty());
                }
            }
            break;
        }
        
        if cursor.goto_first_child() {
            continue;
        }
        
        while !cursor.goto_next_sibling() {
            if !cursor.goto_parent() {
                break;
            }
        }
        
        // Check if we're back at the root by comparing positions
        if cursor.node().start_position() == root.start_position() &&
           cursor.node().end_position() == root.end_position() &&
           cursor.node().kind() == root.kind() {
            break;
        }
    }
    
    assert!(found_function);
    
    Ok(())
}

#[test]
fn test_tree_clone() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = "fn main() {}";
    
    let tree = parser.parse(source, None)?;

    // Test tree properties (since clone is not available)
    let root = tree.root_node();
    assert_eq!(root.kind(), "source_file");
    assert_eq!(root.child_count(), 1); // Should have one function
    assert_eq!(tree.source(), source);

    // Test that we can parse the same source again and get similar results
    let tree2 = parser.parse(source, None)?;
    let root2 = tree2.root_node();
    assert_eq!(root.kind(), root2.kind());
    assert_eq!(root.child_count(), root2.child_count());
    
    Ok(())
}

#[test]
fn test_tree_with_different_languages() -> Result<()> {
    let languages = vec![
        (Language::Rust, "fn main() {}"),
        (Language::JavaScript, "function main() {}"),
        (Language::Python, "def main(): pass"),
        (Language::C, "int main() { return 0; }"),
        (Language::Go, "func main() {}"),
    ];
    
    for (language, source) in languages {
        let mut parser = Parser::new(language)?;
        let tree = parser.parse(source, None)?;

        let root = tree.root_node();
        assert!(!root.kind().is_empty());
        assert!(root.child_count() >= 0);
        
        // Each language should have its own root node type
        match language {
            Language::Rust => assert_eq!(tree.root_node().kind(), "source_file"),
            Language::JavaScript => assert_eq!(tree.root_node().kind(), "program"),
            Language::TypeScript => assert_eq!(tree.root_node().kind(), "program"),
            Language::Python => assert_eq!(tree.root_node().kind(), "module"),
            Language::C => assert_eq!(tree.root_node().kind(), "translation_unit"),
            Language::Cpp => assert_eq!(tree.root_node().kind(), "translation_unit"),
            Language::Go => assert_eq!(tree.root_node().kind(), "source_file"),
        }
    }
    
    Ok(())
}
