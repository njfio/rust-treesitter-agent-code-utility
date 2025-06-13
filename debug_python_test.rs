use rust_tree_sitter::{Parser, Language};
use rust_tree_sitter::languages::python::PythonSyntax;

fn main() {
    let source = r#"
"""Module docstring"""

def public_function(param: int) -> str:
    """This is a documented function"""
    return f"Value: {param}"

def _private_function():
    """Private function with documentation"""
    print("Private")

class PublicClass:
    """A documented class"""
    
    def __init__(self, value: int):
        """Constructor"""
        self.value = value
        self._private_attr = 0
    
    def public_method(self) -> int:
        """Public method"""
        return self.value
    
    def _private_method(self):
        """Private method"""
        return self._private_attr

class _PrivateClass:
    """Private class"""
    pass

# Global variables
PUBLIC_CONSTANT = 42
_private_variable = "secret"
    "#;

    let mut parser = Parser::new(Language::Python).expect("Failed to create Python parser");
    let tree = parser.parse(source, None).expect("Failed to parse Python source");

    // Test function extraction
    let functions = PythonSyntax::find_functions(&tree, source);
    println!("Found {} functions:", functions.len());
    for (name, pos) in &functions {
        println!("  - {} at line {}", name, pos.row + 1);
    }

    // Test class extraction
    let classes = PythonSyntax::find_classes(&tree, source);
    println!("\nFound {} classes:", classes.len());
    for (name, pos) in &classes {
        println!("  - {} at line {}", name, pos.row + 1);
    }

    // Test method extraction
    let methods = PythonSyntax::find_methods(&tree, source);
    println!("\nFound {} methods:", methods.len());
    for (class_name, method_name, pos) in &methods {
        println!("  - {}.{} at line {}", class_name, method_name, pos.row + 1);
    }

    // Test global variable extraction
    let globals = PythonSyntax::find_global_variables(&tree, source);
    println!("\nFound {} global variables:", globals.len());
    for (name, pos) in &globals {
        println!("  - {} at line {}", name, pos.row + 1);
    }
}
