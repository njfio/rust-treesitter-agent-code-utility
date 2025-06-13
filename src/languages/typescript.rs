//! TypeScript language support for tree-sitter
//!
//! This module provides TypeScript-specific utilities for parsing and analyzing
//! TypeScript source code using tree-sitter.

use crate::error::{Error, Result};
use crate::query::Query;
use crate::tree::{Node, SyntaxTree};
use tree_sitter::Point;

/// TypeScript-specific syntax utilities
pub struct TypeScriptSyntax;

impl TypeScriptSyntax {
    /// Check if a node represents a function declaration
    pub fn is_function_declaration(node: &Node) -> bool {
        node.kind() == "function_declaration"
    }

    /// Check if a node represents a function expression
    pub fn is_function_expression(node: &Node) -> bool {
        node.kind() == "function_expression"
    }

    /// Check if a node represents an arrow function
    pub fn is_arrow_function(node: &Node) -> bool {
        node.kind() == "arrow_function"
    }

    /// Check if a node represents any kind of function
    pub fn is_function(node: &Node) -> bool {
        Self::is_function_declaration(node) 
            || Self::is_function_expression(node) 
            || Self::is_arrow_function(node)
    }

    /// Check if a node represents a class declaration
    pub fn is_class_declaration(node: &Node) -> bool {
        node.kind() == "class_declaration"
    }

    /// Check if a node represents an interface declaration
    pub fn is_interface_declaration(node: &Node) -> bool {
        node.kind() == "interface_declaration"
    }

    /// Check if a node represents a type alias declaration
    pub fn is_type_alias_declaration(node: &Node) -> bool {
        node.kind() == "type_alias_declaration"
    }

    /// Check if a node represents an enum declaration
    pub fn is_enum_declaration(node: &Node) -> bool {
        node.kind() == "enum_declaration"
    }

    /// Check if a node represents a namespace declaration
    pub fn is_namespace_declaration(node: &Node) -> bool {
        node.kind() == "namespace_declaration" || node.kind() == "module_declaration"
    }

    /// Check if a node represents a method signature
    pub fn is_method_signature(node: &Node) -> bool {
        node.kind() == "method_signature"
    }

    /// Check if a node represents a property signature
    pub fn is_property_signature(node: &Node) -> bool {
        node.kind() == "property_signature"
    }

    /// Check if a node represents a method definition
    pub fn is_method_definition(node: &Node) -> bool {
        node.kind() == "method_definition"
    }

    /// Check if a node represents a decorator
    pub fn is_decorator(node: &Node) -> bool {
        node.kind() == "decorator"
    }

    /// Check if a node represents a generic type
    pub fn is_generic_type(node: &Node) -> bool {
        node.kind() == "generic_type"
    }

    /// Extract function name from a function node
    pub fn function_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_function(node) {
            return None;
        }

        // Try to get name from identifier field
        if let Some(name_node) = node.child_by_field_name("name") {
            return name_node.text().ok().map(|s| s.to_string());
        }

        // For arrow functions assigned to variables, get the variable name
        if Self::is_arrow_function(node) {
            if let Some(parent) = node.parent() {
                if parent.kind() == "variable_declarator" {
                    if let Some(id_node) = parent.child_by_field_name("name") {
                        return id_node.text().ok().map(|s| s.to_string());
                    }
                }
            }
        }

        None
    }

    /// Extract class name from a class node
    pub fn class_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_class_declaration(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Extract interface name from an interface node
    pub fn interface_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_interface_declaration(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Extract type alias name from a type alias node
    pub fn type_alias_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_type_alias_declaration(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Extract enum name from an enum node
    pub fn enum_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_enum_declaration(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Extract namespace name from a namespace node
    pub fn namespace_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_namespace_declaration(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Extract method name from a method definition node
    pub fn method_name(node: &Node, source: &str) -> Option<String> {
        if !Self::is_method_definition(node) && !Self::is_method_signature(node) {
            return None;
        }

        node.child_by_field_name("name")
            .and_then(|name_node| name_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Check if a function has type annotations
    pub fn has_type_annotations(node: &Node) -> bool {
        if !Self::is_function(node) {
            return false;
        }

        for child in node.children() {
            if child.kind() == "type_annotation" {
                return true;
            }
        }
        false
    }

    /// Get function return type annotation
    pub fn function_return_type(node: &Node, source: &str) -> Option<String> {
        if !Self::is_function(node) {
            return None;
        }

        node.child_by_field_name("return_type")
            .and_then(|type_node| type_node.text().ok())
            .map(|s| s.to_string())
    }

    /// Get function parameters with types
    pub fn function_parameters_with_types(node: &Node, source: &str) -> Vec<(String, Option<String>)> {
        if !Self::is_function(node) {
            return Vec::new();
        }

        let mut parameters = Vec::new();

        if let Some(params_node) = node.child_by_field_name("parameters") {
            for child in params_node.children() {
                if child.kind() == "required_parameter" || child.kind() == "optional_parameter" {
                    let name = child.child_by_field_name("pattern")
                        .and_then(|n| n.text().ok())
                        .map(|s| s.to_string());

                    let type_annotation = child.child_by_field_name("type")
                        .and_then(|n| n.text().ok())
                        .map(|s| s.to_string());

                    if let Some(param_name) = name {
                        parameters.push((param_name, type_annotation));
                    }
                }
            }
        }

        parameters
    }

    /// Get generic type parameters
    pub fn generic_type_parameters(node: &Node, source: &str) -> Vec<String> {
        let mut type_params = Vec::new();
        
        if let Some(type_params_node) = node.child_by_field_name("type_parameters") {
            for child in type_params_node.children() {
                if child.kind() == "type_parameter" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        if let Ok(name) = name_node.text() {
                            type_params.push(name.to_string());
                        }
                    }
                }
            }
        }

        type_params
    }

    /// Check if a class member is public
    pub fn is_public_member(node: &Node) -> bool {
        for child in node.children() {
            if child.kind() == "accessibility_modifier" {
                if let Ok(text) = child.text() {
                    return text == "public";
                }
            }
        }
        true // Default to public if no modifier
    }

    /// Check if a class member is private
    pub fn is_private_member(node: &Node) -> bool {
        for child in node.children() {
            if child.kind() == "accessibility_modifier" {
                if let Ok(text) = child.text() {
                    return text == "private";
                }
            }
        }
        false
    }

    /// Check if a class member is protected
    pub fn is_protected_member(node: &Node) -> bool {
        for child in node.children() {
            if child.kind() == "accessibility_modifier" {
                if let Ok(text) = child.text() {
                    return text == "protected";
                }
            }
        }
        false
    }

    /// Check if a member is static
    pub fn is_static_member(node: &Node) -> bool {
        for child in node.children() {
            if child.kind() == "static" {
                return true;
            }
        }
        false
    }

    /// Check if a member is readonly
    pub fn is_readonly_member(node: &Node) -> bool {
        for child in node.children() {
            if child.kind() == "readonly" {
                return true;
            }
        }
        false
    }

    /// Get decorators applied to a node
    pub fn get_decorators(node: &Node, source: &str) -> Vec<String> {
        let mut decorators = Vec::new();

        for child in node.children() {
            if Self::is_decorator(&child) {
                if let Ok(decorator_text) = child.text() {
                    decorators.push(decorator_text.to_string());
                }
            }
        }

        decorators
    }

    /// Get all function definitions in a syntax tree
    pub fn find_functions(tree: &SyntaxTree, source: &str) -> Vec<(String, Point)> {
        let mut functions = Vec::new();

        // Find function declarations
        let function_nodes = tree.find_nodes_by_kind("function_declaration");
        for func_node in function_nodes {
            if let Some(name) = Self::function_name(&func_node, source) {
                functions.push((name, func_node.start_position()));
            }
        }

        // Find function expressions
        let expr_nodes = tree.find_nodes_by_kind("function_expression");
        for func_node in expr_nodes {
            if let Some(name) = Self::function_name(&func_node, source) {
                functions.push((name, func_node.start_position()));
            }
        }

        // Find arrow functions
        let arrow_nodes = tree.find_nodes_by_kind("arrow_function");
        for func_node in arrow_nodes {
            if let Some(name) = Self::function_name(&func_node, source) {
                functions.push((name, func_node.start_position()));
            }
        }

        functions
    }

    /// Get all class definitions in a syntax tree
    pub fn find_classes(tree: &SyntaxTree, source: &str) -> Vec<(String, Point)> {
        let mut classes = Vec::new();
        let class_nodes = tree.find_nodes_by_kind("class_declaration");

        for class_node in class_nodes {
            if let Some(name) = Self::class_name(&class_node, source) {
                classes.push((name, class_node.start_position()));
            }
        }

        classes
    }

    /// Get all interface definitions in a syntax tree
    pub fn find_interfaces(tree: &SyntaxTree, source: &str) -> Vec<(String, Point)> {
        let mut interfaces = Vec::new();
        let interface_nodes = tree.find_nodes_by_kind("interface_declaration");

        for interface_node in interface_nodes {
            if let Some(name) = Self::interface_name(&interface_node, source) {
                interfaces.push((name, interface_node.start_position()));
            }
        }

        interfaces
    }

    /// Get all type alias definitions in a syntax tree
    pub fn find_type_aliases(tree: &SyntaxTree, source: &str) -> Vec<(String, Point)> {
        let mut type_aliases = Vec::new();
        let type_nodes = tree.find_nodes_by_kind("type_alias_declaration");

        for type_node in type_nodes {
            if let Some(name) = Self::type_alias_name(&type_node, source) {
                type_aliases.push((name, type_node.start_position()));
            }
        }

        type_aliases
    }

    /// Get all enum definitions in a syntax tree
    pub fn find_enums(tree: &SyntaxTree, source: &str) -> Vec<(String, Point)> {
        let mut enums = Vec::new();
        let enum_nodes = tree.find_nodes_by_kind("enum_declaration");

        for enum_node in enum_nodes {
            if let Some(name) = Self::enum_name(&enum_node, source) {
                enums.push((name, enum_node.start_position()));
            }
        }

        enums
    }

    /// Get all namespace definitions in a syntax tree
    pub fn find_namespaces(tree: &SyntaxTree, source: &str) -> Vec<(String, Point)> {
        let mut namespaces = Vec::new();

        let namespace_nodes = tree.find_nodes_by_kind("namespace_declaration");
        for ns_node in namespace_nodes {
            if let Some(name) = Self::namespace_name(&ns_node, source) {
                namespaces.push((name, ns_node.start_position()));
            }
        }

        let module_nodes = tree.find_nodes_by_kind("module_declaration");
        for mod_node in module_nodes {
            if let Some(name) = Self::namespace_name(&mod_node, source) {
                namespaces.push((name, mod_node.start_position()));
            }
        }

        namespaces
    }

    /// Create a query to find all function declarations
    pub fn functions_query() -> Result<Query> {
        let query_str = r#"
            (function_declaration
                name: (identifier) @name
            ) @function

            (function_expression
                name: (identifier) @name
            ) @function

            (arrow_function) @function
        "#;
        Query::new(crate::Language::TypeScript, query_str)
    }

    /// Create a query to find all class definitions
    pub fn classes_query() -> Result<Query> {
        let query_str = r#"
            (class_declaration
                name: (type_identifier) @name
            ) @class
        "#;
        Query::new(crate::Language::TypeScript, query_str)
    }

    /// Create a query to find all interface definitions
    pub fn interfaces_query() -> Result<Query> {
        let query_str = r#"
            (interface_declaration
                name: (type_identifier) @name
            ) @interface
        "#;
        Query::new(crate::Language::TypeScript, query_str)
    }

    /// Create a query to find all type alias definitions
    pub fn type_aliases_query() -> Result<Query> {
        let query_str = r#"
            (type_alias_declaration
                name: (type_identifier) @name
            ) @type_alias
        "#;
        Query::new(crate::Language::TypeScript, query_str)
    }

    /// Create a query to find all enum definitions
    pub fn enums_query() -> Result<Query> {
        let query_str = r#"
            (enum_declaration
                name: (identifier) @name
            ) @enum
        "#;
        Query::new(crate::Language::TypeScript, query_str)
    }

    /// Create a query to find all namespace definitions
    pub fn namespaces_query() -> Result<Query> {
        let query_str = r#"
            (namespace_declaration
                name: (identifier) @name
            ) @namespace

            (module_declaration
                name: (identifier) @name
            ) @namespace
        "#;
        Query::new(crate::Language::TypeScript, query_str)
    }

    /// Create a query to find all method definitions
    pub fn methods_query() -> Result<Query> {
        let query_str = r#"
            (method_definition
                name: (property_identifier) @name
            ) @method

            (method_signature
                name: (property_identifier) @name
            ) @method
        "#;
        Query::new(crate::Language::TypeScript, query_str)
    }

    /// Detect TypeScript-specific features
    pub fn detect_typescript_features(tree: &SyntaxTree) -> Vec<String> {
        let mut features = Vec::new();

        // Check for interfaces
        if !tree.find_nodes_by_kind("interface_declaration").is_empty() {
            features.push("Interfaces".to_string());
        }

        // Check for type aliases
        if !tree.find_nodes_by_kind("type_alias_declaration").is_empty() {
            features.push("Type Aliases".to_string());
        }

        // Check for enums
        if !tree.find_nodes_by_kind("enum_declaration").is_empty() {
            features.push("Enums".to_string());
        }

        // Check for generics
        if !tree.find_nodes_by_kind("type_parameters").is_empty() {
            features.push("Generics".to_string());
        }

        // Check for decorators
        if !tree.find_nodes_by_kind("decorator").is_empty() {
            features.push("Decorators".to_string());
        }

        // Check for namespaces
        if !tree.find_nodes_by_kind("namespace_declaration").is_empty()
            || !tree.find_nodes_by_kind("module_declaration").is_empty() {
            features.push("Namespaces/Modules".to_string());
        }

        // Check for type annotations
        if !tree.find_nodes_by_kind("type_annotation").is_empty() {
            features.push("Type Annotations".to_string());
        }

        // Check for access modifiers
        if !tree.find_nodes_by_kind("accessibility_modifier").is_empty() {
            features.push("Access Modifiers".to_string());
        }

        features
    }

    /// Analyze TypeScript code complexity
    pub fn analyze_complexity(tree: &SyntaxTree) -> u32 {
        let mut complexity = 1; // Base complexity

        // Count decision points (same as JavaScript)
        complexity += tree.find_nodes_by_kind("if_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("while_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("for_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("for_in_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("switch_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("try_statement").len() as u32;
        complexity += tree.find_nodes_by_kind("catch_clause").len() as u32;
        complexity += tree.find_nodes_by_kind("conditional_expression").len() as u32;

        // Add TypeScript-specific complexity
        complexity += tree.find_nodes_by_kind("type_assertion").len() as u32;
        complexity += tree.find_nodes_by_kind("as_expression").len() as u32;

        complexity
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parser;

    #[test]
    fn test_typescript_function_detection() {
        let source = r#"
            function regularFunction(): string {
                return "hello";
            }

            const arrowFunction = (): number => {
                return 42;
            };

            async function asyncFunction(): Promise<void> {
                await something();
            }
        "#;

        let mut parser = Parser::new(crate::Language::TypeScript).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let functions = TypeScriptSyntax::find_functions(&tree, source);
        assert_eq!(functions.len(), 3);

        let function_names: Vec<&str> = functions.iter().map(|(name, _)| name.as_str()).collect();
        assert!(function_names.contains(&"regularFunction"));
        assert!(function_names.contains(&"arrowFunction"));
        assert!(function_names.contains(&"asyncFunction"));
    }

    #[test]
    fn test_typescript_class_detection() {
        let source = r#"
            class MyClass {
                private value: number;

                constructor(value: number) {
                    this.value = value;
                }

                public getValue(): number {
                    return this.value;
                }
            }
        "#;

        let mut parser = Parser::new(crate::Language::TypeScript).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let classes = TypeScriptSyntax::find_classes(&tree, source);
        assert_eq!(classes.len(), 1);
        assert_eq!(classes[0].0, "MyClass");
    }

    #[test]
    fn test_typescript_interface_detection() {
        let source = r#"
            interface User {
                id: number;
                name: string;
                email?: string;
            }

            interface Admin extends User {
                permissions: string[];
            }
        "#;

        let mut parser = Parser::new(crate::Language::TypeScript).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let interfaces = TypeScriptSyntax::find_interfaces(&tree, source);
        assert_eq!(interfaces.len(), 2);

        let interface_names: Vec<&str> = interfaces.iter().map(|(name, _)| name.as_str()).collect();
        assert!(interface_names.contains(&"User"));
        assert!(interface_names.contains(&"Admin"));
    }

    #[test]
    fn test_typescript_type_alias_detection() {
        let source = r#"
            type StringOrNumber = string | number;
            type UserCallback = (user: User) => void;
        "#;

        let mut parser = Parser::new(crate::Language::TypeScript).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let type_aliases = TypeScriptSyntax::find_type_aliases(&tree, source);
        assert_eq!(type_aliases.len(), 2);

        let type_names: Vec<&str> = type_aliases.iter().map(|(name, _)| name.as_str()).collect();
        assert!(type_names.contains(&"StringOrNumber"));
        assert!(type_names.contains(&"UserCallback"));
    }

    #[test]
    fn test_typescript_enum_detection() {
        let source = r#"
            enum Color {
                Red,
                Green,
                Blue
            }

            enum Status {
                Active = "active",
                Inactive = "inactive"
            }
        "#;

        let mut parser = Parser::new(crate::Language::TypeScript).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let enums = TypeScriptSyntax::find_enums(&tree, source);
        assert_eq!(enums.len(), 2);

        let enum_names: Vec<&str> = enums.iter().map(|(name, _)| name.as_str()).collect();
        assert!(enum_names.contains(&"Color"));
        assert!(enum_names.contains(&"Status"));
    }

    #[test]
    fn test_typescript_features_detection() {
        let source = r#"
            interface Config {
                apiUrl: string;
            }

            type Handler<T> = (data: T) => void;

            enum LogLevel {
                Info,
                Warning,
                Error
            }

            @Component
            class MyComponent {
                private config: Config;

                constructor(config: Config) {
                    this.config = config;
                }
            }
        "#;

        let mut parser = Parser::new(crate::Language::TypeScript).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let features = TypeScriptSyntax::detect_typescript_features(&tree);
        assert!(features.contains(&"Interfaces".to_string()));
        assert!(features.contains(&"Type Aliases".to_string()));
        assert!(features.contains(&"Enums".to_string()));
        assert!(features.contains(&"Generics".to_string()));
        assert!(features.contains(&"Decorators".to_string()));
        assert!(features.contains(&"Type Annotations".to_string()));
        assert!(features.contains(&"Access Modifiers".to_string()));
    }

    #[test]
    fn test_function_parameters_with_types() {
        let source = r#"
            function processUser(id: number, name: string, email?: string): User {
                return { id, name, email };
            }
        "#;

        let mut parser = Parser::new(crate::Language::TypeScript).unwrap();
        let tree = parser.parse(source, None).unwrap();

        let function_nodes = tree.find_nodes_by_kind("function_declaration");
        assert!(!function_nodes.is_empty());

        let params = TypeScriptSyntax::function_parameters_with_types(&function_nodes[0], source);
        assert_eq!(params.len(), 3);

        assert_eq!(params[0].0, "id");
        assert_eq!(params[0].1, Some("number".to_string()));

        assert_eq!(params[1].0, "name");
        assert_eq!(params[1].1, Some("string".to_string()));

        assert_eq!(params[2].0, "email");
        assert_eq!(params[2].1, Some("string".to_string()));
    }
}
