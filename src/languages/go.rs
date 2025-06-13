//! Go language support for tree-sitter
//!
//! This module provides Go-specific utilities for parsing and analyzing
//! Go source code using tree-sitter.

use crate::error::{Error, Result};
use crate::query::Query;
use crate::tree::{Node, SyntaxTree};
use tree_sitter::Point;

/// Go-specific syntax utilities
pub struct GoSyntax;

impl GoSyntax {
    /// Check if a node represents a function declaration
    pub fn is_function_declaration(node: &Node) -> bool {
        node.kind() == "function_declaration"
    }

    /// Check if a node represents a method declaration
    pub fn is_method_declaration(node: &Node) -> bool {
        node.kind() == "method_declaration"
    }

    /// Check if a node represents a type declaration
    pub fn is_type_declaration(node: &Node) -> bool {
        node.kind() == "type_declaration"
    }

    /// Check if a node represents a struct type
    pub fn is_struct_type(node: &Node) -> bool {
        node.kind() == "struct_type"
    }

    /// Check if a node represents an interface type
    pub fn is_interface_type(node: &Node) -> bool {
        node.kind() == "interface_type"
    }

    /// Check if a node represents a package clause
    pub fn is_package_clause(node: &Node) -> bool {
        node.kind() == "package_clause"
    }

    /// Check if a node represents an import declaration
    pub fn is_import_declaration(node: &Node) -> bool {
        node.kind() == "import_declaration"
    }

    /// Check if a node represents a const declaration
    pub fn is_const_declaration(node: &Node) -> bool {
        node.kind() == "const_declaration"
    }

    /// Check if a node represents a var declaration
    pub fn is_var_declaration(node: &Node) -> bool {
        node.kind() == "var_declaration"
    }

    /// Extract function name from a function declaration
    pub fn function_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_function_declaration(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Extract method name from a method declaration
    pub fn method_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_method_declaration(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Extract receiver type from a method declaration
    pub fn method_receiver_type(node: &Node, source: &str) -> Option<String> {
        if !Self::is_method_declaration(node) {
            return None;
        }

        if let Some(receiver_node) = node.child_by_field_name("receiver") {
            // Look for the type in the receiver
            for child in receiver_node.children() {
                if child.kind() == "parameter_list" {
                    for param in child.children() {
                        if param.kind() == "parameter_declaration" {
                            if let Some(type_node) = param.child_by_field_name("type") {
                                // Handle pointer receivers
                                if type_node.kind() == "pointer_type" {
                                    if let Some(elem_node) = type_node.child_by_field_name("element") {
                                        return elem_node.text().ok().map(|s| s.to_string());
                                    }
                                } else {
                                    return type_node.text().ok().map(|s| s.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        None
    }

    /// Extract type name from a type declaration
    pub fn type_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_type_declaration(node) {
            return None;
        }

        // Look for type_spec
        for child in node.children() {
            if child.kind() == "type_spec" {
                if let Some(name_node) = child.child_by_field_name("name") {
                    return name_node.text().ok().map(|s| s.to_string());
                }
            }
        }

        None
    }

    /// Extract package name from a package clause
    pub fn package_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_package_clause(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Get function parameters
    pub fn function_parameters(node: &Node, source: &str) -> Vec<String> {
        if !Self::is_function_declaration(node) && !Self::is_method_declaration(node) {
            return Vec::new();
        }

        let mut parameters = Vec::new();

        if let Some(params_node) = node.child_by_field_name("parameters") {
            for child in params_node.children() {
                if child.kind() == "parameter_declaration" {
                    // Get parameter names
                    for param_part in child.children() {
                        if param_part.kind() == "identifier" {
                            if let Ok(param_name) = param_part.text() {
                                parameters.push(param_name.to_string());
                            }
                        }
                    }
                }
            }
        }

        parameters
    }

    /// Get function return types
    pub fn function_return_types(node: &Node, source: &str) -> Vec<String> {
        if !Self::is_function_declaration(node) && !Self::is_method_declaration(node) {
            return Vec::new();
        }

        let mut return_types = Vec::new();

        if let Some(result_node) = node.child_by_field_name("result") {
            for child in result_node.children() {
                match child.kind() {
                    "type_identifier" | "qualified_type" => {
                        if let Ok(type_name) = child.text() {
                            return_types.push(type_name.to_string());
                        }
                    }
                    "parameter_list" => {
                        // Multiple return values
                        for param in child.children() {
                            if param.kind() == "parameter_declaration" {
                                if let Some(type_node) = param.child_by_field_name("type") {
                                    if let Ok(type_name) = type_node.text() {
                                        return_types.push(type_name.to_string());
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        return_types
    }

    /// Get struct fields
    pub fn struct_fields(node: &Node, source: &str) -> Vec<(String, String)> {
        if !Self::is_struct_type(node) {
            return Vec::new();
        }

        let mut fields = Vec::new();

        if let Some(field_list) = node.child_by_field_name("fields") {
            for child in field_list.children() {
                if child.kind() == "field_declaration" {
                    let mut field_names = Vec::new();
                    let mut field_type = String::new();

                    for field_part in child.children() {
                        match field_part.kind() {
                            "field_identifier" => {
                                if let Ok(name) = field_part.text() {
                                    field_names.push(name.to_string());
                                }
                            }
                            "type_identifier" | "qualified_type" | "pointer_type" | "slice_type" | "array_type" => {
                                if let Ok(type_text) = field_part.text() {
                                    field_type = type_text.to_string();
                                }
                            }
                            _ => {}
                        }
                    }

                    // Add all field names with their type
                    for name in field_names {
                        fields.push((name, field_type.clone()));
                    }
                }
            }
        }

        fields
    }

    /// Get interface methods
    pub fn interface_methods(node: &Node, source: &str) -> Vec<String> {
        if !Self::is_interface_type(node) {
            return Vec::new();
        }

        let mut methods = Vec::new();

        if let Some(method_list) = node.child_by_field_name("methods") {
            for child in method_list.children() {
                if child.kind() == "method_spec" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        if let Ok(method_name) = name_node.text() {
                            methods.push(method_name.to_string());
                        }
                    }
                }
            }
        }

        methods
    }

    /// Check if a function/method is exported (starts with uppercase)
    pub fn is_exported(name: &str) -> bool {
        name.chars().next().map_or(false, |c| c.is_uppercase())
    }

    /// Check if a function is a main function
    pub fn is_main_function(node: &Node, source: &str) -> bool {
        if let Some(name) = Self::function_name(node, source) {
            return name == "main";
        }
        false
    }

    /// Check if a function is an init function
    pub fn is_init_function(node: &Node, source: &str) -> bool {
        if let Some(name) = Self::function_name(node, source) {
            return name == "init";
        }
        false
    }

    /// Get all import paths
    pub fn get_import_paths(tree: &SyntaxTree, source: &str) -> Vec<String> {
        let mut imports = Vec::new();
        let import_nodes = tree.find_nodes_by_kind("import_declaration");

        for import_node in import_nodes {
            for child in import_node.children() {
                if child.kind() == "import_spec" {
                    if let Some(path_node) = child.child_by_field_name("path") {
                        if let Ok(path) = path_node.text() {
                            // Remove quotes from import path
                            let cleaned_path = path.trim_matches('"');
                            imports.push(cleaned_path.to_string());
                        }
                    }
                } else if child.kind() == "import_spec_list" {
                    for spec in child.children() {
                        if spec.kind() == "import_spec" {
                            if let Some(path_node) = spec.child_by_field_name("path") {
                                if let Ok(path) = path_node.text() {
                                    let cleaned_path = path.trim_matches('"');
                                    imports.push(cleaned_path.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        imports
    }

    /// Get all function declarations in a syntax tree
    pub fn find_functions(tree: &SyntaxTree, source: &str) -> Vec<(String, Point)> {
        let mut functions = Vec::new();
        let function_nodes = tree.find_nodes_by_kind("function_declaration");

        for func_node in function_nodes {
            if let Some(name) = Self::function_name(&func_node, source) {
                functions.push((name, func_node.start_position()));
            }
        }

        functions
    }

    /// Get all method declarations in a syntax tree
    pub fn find_methods(tree: &SyntaxTree, source: &str) -> Vec<(String, String, Point)> {
        let mut methods = Vec::new();
        let method_nodes = tree.find_nodes_by_kind("method_declaration");

        for method_node in method_nodes {
            if let Some(name) = Self::method_name(&method_node, source) {
                let receiver_type = Self::method_receiver_type(&method_node, source)
                    .unwrap_or_else(|| "unknown".to_string());
                methods.push((name, receiver_type, method_node.start_position()));
            }
        }

        methods
    }

    /// Get all type declarations in a syntax tree
    pub fn find_types(tree: &SyntaxTree, source: &str) -> Vec<(String, Point)> {
        let mut types = Vec::new();
        let type_nodes = tree.find_nodes_by_kind("type_declaration");

        for type_node in type_nodes {
            if let Some(name) = Self::type_name(&type_node, source) {
                types.push((name, type_node.start_position()));
            }
        }

        types
    }

    /// Get all struct types in a syntax tree
    pub fn find_structs(tree: &SyntaxTree, source: &str) -> Vec<(String, Point)> {
        let mut structs = Vec::new();
        let type_nodes = tree.find_nodes_by_kind("type_declaration");

        for type_node in type_nodes {
            // Check if this type declaration contains a struct
            for child in type_node.children() {
                if child.kind() == "type_spec" {
                    if let Some(type_def) = child.child_by_field_name("type") {
                        if Self::is_struct_type(&type_def) {
                            if let Some(name) = Self::type_name(&type_node, source) {
                                structs.push((name, type_node.start_position()));
                            }
                        }
                    }
                }
            }
        }

        structs
    }

    /// Get all interface types in a syntax tree
    pub fn find_interfaces(tree: &SyntaxTree, source: &str) -> Vec<(String, Point)> {
        let mut interfaces = Vec::new();
        let type_nodes = tree.find_nodes_by_kind("type_declaration");

        for type_node in type_nodes {
            // Check if this type declaration contains an interface
            for child in type_node.children() {
                if child.kind() == "type_spec" {
                    if let Some(type_def) = child.child_by_field_name("type") {
                        if Self::is_interface_type(&type_def) {
                            if let Some(name) = Self::type_name(&type_node, source) {
                                interfaces.push((name, type_node.start_position()));
                            }
                        }
                    }
                }
            }
        }

        interfaces
    }

    /// Create a query to find all function declarations
    pub fn functions_query() -> Result<Query> {
        let query_str = r#"
            (function_declaration
                name: (identifier) @name
            ) @function
        "#;
        Query::new(crate::Language::Go, query_str)
    }

    /// Create a query to find all method declarations
    pub fn methods_query() -> Result<Query> {
        let query_str = r#"
            (method_declaration
                name: (field_identifier) @name
            ) @method
        "#;
        Query::new(crate::Language::Go, query_str)
    }

    /// Create a query to find all type declarations
    pub fn types_query() -> Result<Query> {
        let query_str = r#"
            (type_declaration
                (type_spec
                    name: (type_identifier) @name
                )
            ) @type
        "#;
        Query::new(crate::Language::Go, query_str)
    }

    /// Create a query to find all struct types
    pub fn structs_query() -> Result<Query> {
        let query_str = r#"
            (type_declaration
                (type_spec
                    name: (type_identifier) @name
                    type: (struct_type)
                )
            ) @struct
        "#;
        Query::new(crate::Language::Go, query_str)
    }

    /// Create a query to find all interface types
    pub fn interfaces_query() -> Result<Query> {
        let query_str = r#"
            (type_declaration
                (type_spec
                    name: (type_identifier) @name
                    type: (interface_type)
                )
            ) @interface
        "#;
        Query::new(crate::Language::Go, query_str)
    }

    /// Detect Go-specific features
    pub fn detect_go_features(tree: &SyntaxTree) -> Vec<String> {
        let mut features = Vec::new();

        // Check for goroutines
        if !tree.find_nodes_by_kind("go_statement").is_empty() {
            features.push("Goroutines".to_string());
        }

        // Check for channels
        if !tree.find_nodes_by_kind("channel_type").is_empty() {
            features.push("Channels".to_string());
        }

        // Check for select statements
        if !tree.find_nodes_by_kind("select_statement").is_empty() {
            features.push("Select Statements".to_string());
        }

        // Check for defer statements
        if !tree.find_nodes_by_kind("defer_statement").is_empty() {
            features.push("Defer Statements".to_string());
        }

        // Check for interfaces
        if !tree.find_nodes_by_kind("interface_type").is_empty() {
            features.push("Interfaces".to_string());
        }

        // Check for structs
        if !tree.find_nodes_by_kind("struct_type").is_empty() {
            features.push("Structs".to_string());
        }

        // Check for methods (functions with receivers)
        if !tree.find_nodes_by_kind("method_declaration").is_empty() {
            features.push("Methods".to_string());
        }

        // Check for type assertions
        if !tree.find_nodes_by_kind("type_assertion_expression").is_empty() {
            features.push("Type Assertions".to_string());
        }

        // Check for type switches
        if !tree.find_nodes_by_kind("type_switch_statement").is_empty() {
            features.push("Type Switches".to_string());
        }

        // Check for range loops
        if !tree.find_nodes_by_kind("range_clause").is_empty() {
            features.push("Range Loops".to_string());
        }

        // Check for variadic functions
        let function_nodes = tree.find_nodes_by_kind("function_declaration");
        for func_node in function_nodes {
            if let Some(params_node) = func_node.child_by_field_name("parameters") {
                for child in params_node.children() {
                    if child.kind() == "variadic_parameter_declaration" {
                        features.push("Variadic Functions".to_string());
                        break;
                    }
                }
            }
        }

        features
    }

    /// Analyze Go code complexity
    pub fn analyze_complexity(tree: &SyntaxTree) -> u32 {
        let mut complexity = 1; // Base complexity

        // Count decision points
        complexity += tree.find_nodes_by_kind("if_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("for_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("switch_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("type_switch_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("select_statement").len() as u32;

        // Add Go-specific complexity
        complexity += tree.find_nodes_by_kind("go_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("defer_statement").len() as u32;

        complexity
    }

    /// Get package-level analysis
    pub fn analyze_package(tree: &SyntaxTree, source: &str) -> PackageAnalysis {
        let package_nodes = tree.find_nodes_by_kind("package_clause");
        let package_name = if let Some(pkg_node) = package_nodes.first() {
            Self::package_name(pkg_node, source).unwrap_or_else(|| "unknown".to_string())
        } else {
            "unknown".to_string()
        };

        let imports = Self::get_import_paths(tree, source);
        let functions = Self::find_functions(tree, source);
        let methods = Self::find_methods(tree, source);
        let types = Self::find_types(tree, source);

        let exported_functions = functions.iter()
            .filter(|(name, _)| Self::is_exported(name))
            .count();

        let exported_types = types.iter()
            .filter(|(name, _)| Self::is_exported(name))
            .count();

        PackageAnalysis {
            package_name,
            imports,
            total_functions: functions.len(),
            exported_functions,
            total_methods: methods.len(),
            total_types: types.len(),
            exported_types,
        }
    }
}

/// Package-level analysis result
#[derive(Debug, Clone)]
pub struct PackageAnalysis {
    pub package_name: String,
    pub imports: Vec<String>,
    pub total_functions: usize,
    pub exported_functions: usize,
    pub total_methods: usize,
    pub total_types: usize,
    pub exported_types: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parser;

    #[test]
    fn test_go_function_detection() {
        let source = r#"
package main

import "fmt"

func main() {
    fmt.Println("Hello, World!")
}

func add(a, b int) int {
    return a + b
}

func init() {
    // initialization code
}
        "#;

        let mut parser = Parser::new(crate::Language::Go).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let functions = GoSyntax::find_functions(&tree, source);
        assert_eq!(functions.len(), 3);

        let function_names: Vec<&str> = functions.iter().map(|(name, _)| name.as_str()).collect();
        assert!(function_names.contains(&"main"));
        assert!(function_names.contains(&"add"));
        assert!(function_names.contains(&"init"));
    }

    #[test]
    fn test_go_method_detection() {
        let source = r#"
package main

type Rectangle struct {
    width, height float64
}

func (r Rectangle) Area() float64 {
    return r.width * r.height
}

func (r *Rectangle) Scale(factor float64) {
    r.width *= factor
    r.height *= factor
}
        "#;

        let mut parser = Parser::new(crate::Language::Go).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let methods = GoSyntax::find_methods(&tree, source);
        assert_eq!(methods.len(), 2);

        let method_info: Vec<(&str, &str)> = methods.iter()
            .map(|(name, receiver, _)| (name.as_str(), receiver.as_str()))
            .collect();

        assert!(method_info.contains(&("Area", "Rectangle")));
        assert!(method_info.contains(&("Scale", "Rectangle")));
    }

    #[test]
    fn test_go_struct_detection() {
        let source = r#"
package main

type Person struct {
    Name string
    Age  int
}

type Address struct {
    Street string
    City   string
    State  string
}
        "#;

        let mut parser = Parser::new(crate::Language::Go).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let structs = GoSyntax::find_structs(&tree, source);
        assert_eq!(structs.len(), 2);

        let struct_names: Vec<&str> = structs.iter().map(|(name, _)| name.as_str()).collect();
        assert!(struct_names.contains(&"Person"));
        assert!(struct_names.contains(&"Address"));
    }

    #[test]
    fn test_go_interface_detection() {
        let source = r#"
package main

type Writer interface {
    Write([]byte) (int, error)
}

type Reader interface {
    Read([]byte) (int, error)
}

type ReadWriter interface {
    Reader
    Writer
}
        "#;

        let mut parser = Parser::new(crate::Language::Go).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let interfaces = GoSyntax::find_interfaces(&tree, source);
        assert_eq!(interfaces.len(), 3);

        let interface_names: Vec<&str> = interfaces.iter().map(|(name, _)| name.as_str()).collect();
        assert!(interface_names.contains(&"Writer"));
        assert!(interface_names.contains(&"Reader"));
        assert!(interface_names.contains(&"ReadWriter"));
    }

    #[test]
    fn test_go_package_analysis() {
        let source = r#"
package mypackage

import (
    "fmt"
    "net/http"
)

func PublicFunction() {
    fmt.Println("Public")
}

func privateFunction() {
    fmt.Println("Private")
}

type PublicStruct struct {
    Field string
}

type privateStruct struct {
    field string
}
        "#;

        let mut parser = Parser::new(crate::Language::Go).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let analysis = GoSyntax::analyze_package(&tree, source);
        assert_eq!(analysis.package_name, "mypackage");
        assert_eq!(analysis.imports.len(), 2);
        assert!(analysis.imports.contains(&"fmt".to_string()));
        assert!(analysis.imports.contains(&"net/http".to_string()));
        assert_eq!(analysis.total_functions, 2);
        assert_eq!(analysis.exported_functions, 1); // Only PublicFunction
        assert_eq!(analysis.total_types, 2);
        assert_eq!(analysis.exported_types, 1); // Only PublicStruct
    }

    #[test]
    fn test_go_features_detection() {
        let source = r#"
package main

import "fmt"

func main() {
    ch := make(chan int)

    go func() {
        ch <- 42
    }()

    defer fmt.Println("Deferred")

    select {
    case value := <-ch:
        fmt.Println(value)
    default:
        fmt.Println("No value")
    }

    for i, v := range []int{1, 2, 3} {
        fmt.Printf("%d: %d\n", i, v)
    }

    var x interface{} = "hello"
    if str, ok := x.(string); ok {
        fmt.Println(str)
    }
}
        "#;

        let mut parser = Parser::new(crate::Language::Go).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let features = GoSyntax::detect_go_features(&tree);
        assert!(features.contains(&"Goroutines".to_string()));
        assert!(features.contains(&"Channels".to_string()));
        assert!(features.contains(&"Select Statements".to_string()));
        assert!(features.contains(&"Defer Statements".to_string()));
        assert!(features.contains(&"Range Loops".to_string()));
        assert!(features.contains(&"Type Assertions".to_string()));
    }

    #[test]
    fn test_function_parameters_and_returns() {
        let source = r#"
package main

func add(a, b int) int {
    return a + b
}

func divide(a, b float64) (float64, error) {
    if b == 0 {
        return 0, fmt.Errorf("division by zero")
    }
    return a / b, nil
}

func variadic(args ...string) {
    for _, arg := range args {
        fmt.Println(arg)
    }
}
        "#;

        let mut parser = Parser::new(crate::Language::Go).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let function_nodes = tree.find_nodes_by_kind("function_declaration");
        assert_eq!(function_nodes.len(), 3);

        // Test parameters
        let params1 = GoSyntax::function_parameters(&function_nodes[0], source);
        assert_eq!(params1.len(), 2);
        assert!(params1.contains(&"a".to_string()));
        assert!(params1.contains(&"b".to_string()));

        // Test return types
        let returns1 = GoSyntax::function_return_types(&function_nodes[0], source);
        assert_eq!(returns1.len(), 1);
        assert!(returns1.contains(&"int".to_string()));

        let returns2 = GoSyntax::function_return_types(&function_nodes[1], source);
        assert_eq!(returns2.len(), 2);
        assert!(returns2.contains(&"float64".to_string()));
        assert!(returns2.contains(&"error".to_string()));
    }

    #[test]
    fn test_struct_fields() {
        let source = r#"
package main

type Person struct {
    Name    string
    Age     int
    Email   string
    Address *Address
}
        "#;

        let mut parser = Parser::new(crate::Language::Go).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let struct_nodes = tree.find_nodes_by_kind("struct_type");
        assert!(!struct_nodes.is_empty());

        let fields = GoSyntax::struct_fields(&struct_nodes[0], source);
        assert_eq!(fields.len(), 4);

        let field_names: Vec<&str> = fields.iter().map(|(name, _)| name.as_str()).collect();
        assert!(field_names.contains(&"Name"));
        assert!(field_names.contains(&"Age"));
        assert!(field_names.contains(&"Email"));
        assert!(field_names.contains(&"Address"));
    }

    #[test]
    fn test_exported_vs_private() {
        assert!(GoSyntax::is_exported("PublicFunction"));
        assert!(GoSyntax::is_exported("PublicStruct"));
        assert!(!GoSyntax::is_exported("privateFunction"));
        assert!(!GoSyntax::is_exported("privateStruct"));
        assert!(!GoSyntax::is_exported(""));
    }

    #[test]
    fn test_special_functions() {
        let source = r#"
package main

func main() {
    fmt.Println("Main function")
}

func init() {
    fmt.Println("Init function")
}

func regularFunction() {
    fmt.Println("Regular function")
}
        "#;

        let mut parser = Parser::new(crate::Language::Go).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let function_nodes = tree.find_nodes_by_kind("function_declaration");
        assert_eq!(function_nodes.len(), 3);

        assert!(GoSyntax::is_main_function(&function_nodes[0], source));
        assert!(GoSyntax::is_init_function(&function_nodes[1], source));
        assert!(!GoSyntax::is_main_function(&function_nodes[2], source));
        assert!(!GoSyntax::is_init_function(&function_nodes[2], source));
    }
}
