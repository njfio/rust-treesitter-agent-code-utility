//! Comprehensive tests for the parser module
//!
//! Tests all aspects of the Parser including:
//! - Parser creation for all supported languages
//! - Source code parsing
//! - Error handling
//! - Tree generation and validation
//! - Language detection

use rust_tree_sitter::*;
use rust_tree_sitter::parser::Parser;

#[test]
fn test_parser_creation_rust() {
    let parser = Parser::new(Language::Rust);
    assert!(parser.is_ok());
}

#[test]
fn test_parser_creation_javascript() {
    let parser = Parser::new(Language::JavaScript);
    assert!(parser.is_ok());
}

#[test]
fn test_parser_creation_typescript() {
    let parser = Parser::new(Language::TypeScript);
    assert!(parser.is_ok());
}

#[test]
fn test_parser_creation_python() {
    let parser = Parser::new(Language::Python);
    assert!(parser.is_ok());
}

#[test]
fn test_parser_creation_c() {
    let parser = Parser::new(Language::C);
    assert!(parser.is_ok());
}

#[test]
fn test_parser_creation_cpp() {
    let parser = Parser::new(Language::Cpp);
    assert!(parser.is_ok());
}

#[test]
fn test_parser_creation_go() {
    let parser = Parser::new(Language::Go);
    assert!(parser.is_ok());
}

#[test]
fn test_parse_simple_rust_code() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = "fn main() { println!(\"Hello, world!\"); }";
    
    let tree = parser.parse(source, None)?;

    let root = tree.root_node();
    assert_eq!(root.kind(), "source_file");
    assert!(root.child_count() > 0);
    
    Ok(())
}

#[test]
fn test_parse_complex_rust_code() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = r#"
use std::collections::HashMap;

/// A documented struct
pub struct Calculator {
    pub name: String,
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
    let mut calc = Calculator::new("MyCalc".to_string());
    let result = calc.add(5, 3);
    println!("Result: {}", result);
}
"#;
    
    let tree = parser.parse(source, None)?;

    let root = tree.root_node();
    assert_eq!(root.kind(), "source_file");

    // Should have multiple top-level items
    assert!(root.child_count() >= 3); // use, struct, impl, fn
    
    Ok(())
}

#[test]
fn test_parse_javascript_code() -> Result<()> {
    let mut parser = Parser::new(Language::JavaScript)?;
    let source = r#"
function greet(name) {
    console.log(`Hello, ${name}!`);
}

class Person {
    constructor(name, age) {
        this.name = name;
        this.age = age;
    }
    
    introduce() {
        greet(this.name);
        console.log(`I am ${this.age} years old.`);
    }
}

const person = new Person("Alice", 30);
person.introduce();
"#;
    
    let tree = parser.parse(source, None)?;

    let root = tree.root_node();
    assert_eq!(root.kind(), "program");
    assert!(root.child_count() > 0);
    
    Ok(())
}

#[test]
fn test_parse_typescript_code() -> Result<()> {
    let mut parser = Parser::new(Language::TypeScript)?;
    let source = r#"
interface Calculator {
    add(a: number, b: number): number;
    subtract(a: number, b: number): number;
}

class BasicCalculator implements Calculator {
    add(a: number, b: number): number {
        return a + b;
    }
    
    subtract(a: number, b: number): number {
        return a - b;
    }
}

function createCalculator(): Calculator {
    return new BasicCalculator();
}

const calc: Calculator = createCalculator();
console.log(calc.add(5, 3));
"#;
    
    let tree = parser.parse(source, None)?;

    let root = tree.root_node();
    assert_eq!(root.kind(), "program");
    assert!(root.child_count() > 0);
    
    Ok(())
}

#[test]
fn test_parse_python_code() -> Result<()> {
    let mut parser = Parser::new(Language::Python)?;
    let source = r#"
def greet(name: str) -> None:
    """Greet a person by name."""
    print(f"Hello, {name}!")

class Calculator:
    """A simple calculator class."""
    
    def __init__(self, name: str):
        self.name = name
        self.history = []
    
    def add(self, a: int, b: int) -> int:
        """Add two numbers."""
        result = a + b
        self.history.append(f"{a} + {b} = {result}")
        return result
    
    def get_history(self) -> list:
        """Get calculation history."""
        return self.history.copy()

if __name__ == "__main__":
    calc = Calculator("MyCalc")
    result = calc.add(5, 3)
    greet("World")
    print(f"Result: {result}")
"#;
    
    let tree = parser.parse(source, None)?;

    let root = tree.root_node();
    assert_eq!(root.kind(), "module");
    assert!(root.child_count() > 0);
    
    Ok(())
}

#[test]
fn test_parse_c_code() -> Result<()> {
    let mut parser = Parser::new(Language::C)?;
    let source = r#"
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    int x;
    int y;
} Point;

int add(int a, int b) {
    return a + b;
}

void print_point(Point* p) {
    printf("Point: (%d, %d)\n", p->x, p->y);
}

int main() {
    Point p = {10, 20};
    int result = add(5, 3);
    
    print_point(&p);
    printf("Addition result: %d\n", result);
    
    return 0;
}
"#;
    
    let tree = parser.parse(source, None)?;

    let root = tree.root_node();
    assert_eq!(root.kind(), "translation_unit");
    assert!(root.child_count() > 0);
    
    Ok(())
}

#[test]
fn test_parse_cpp_code() -> Result<()> {
    let mut parser = Parser::new(Language::Cpp)?;
    let source = r#"
#include <iostream>
#include <string>
#include <vector>

class Calculator {
private:
    std::string name;
    std::vector<int> history;

public:
    Calculator(const std::string& name) : name(name) {}
    
    int add(int a, int b) {
        int result = a + b;
        history.push_back(result);
        return result;
    }
    
    void printHistory() const {
        std::cout << "History for " << name << ":" << std::endl;
        for (int result : history) {
            std::cout << result << " ";
        }
        std::cout << std::endl;
    }
};

int main() {
    Calculator calc("MyCalculator");
    int result = calc.add(5, 3);
    
    std::cout << "Result: " << result << std::endl;
    calc.printHistory();
    
    return 0;
}
"#;
    
    let tree = parser.parse(source, None)?;

    let root = tree.root_node();
    assert_eq!(root.kind(), "translation_unit");
    assert!(root.child_count() > 0);
    
    Ok(())
}

#[test]
fn test_parse_go_code() -> Result<()> {
    let mut parser = Parser::new(Language::Go)?;
    let source = r#"
package main

import (
    "fmt"
    "strings"
)

type Calculator struct {
    Name    string
    History []int
}

func NewCalculator(name string) *Calculator {
    return &Calculator{
        Name:    name,
        History: make([]int, 0),
    }
}

func (c *Calculator) Add(a, b int) int {
    result := a + b
    c.History = append(c.History, result)
    return result
}

func (c *Calculator) PrintHistory() {
    fmt.Printf("History for %s: %v\n", c.Name, c.History)
}

func greet(name string) {
    fmt.Printf("Hello, %s!\n", strings.Title(name))
}

func main() {
    calc := NewCalculator("MyCalculator")
    result := calc.Add(5, 3)
    
    greet("world")
    fmt.Printf("Result: %d\n", result)
    calc.PrintHistory()
}
"#;
    
    let tree = parser.parse(source, None)?;

    let root = tree.root_node();
    assert_eq!(root.kind(), "source_file");
    assert!(root.child_count() > 0);
    
    Ok(())
}

#[test]
fn test_parse_invalid_syntax() {
    let mut parser = Parser::new(Language::Rust).unwrap();
    let source = "fn main( { invalid syntax }";
    
    let tree = parser.parse(source, None);
    
    // Should still create a tree, but it will have error nodes
    assert!(tree.is_ok());
    let tree = tree.unwrap();
    let root = tree.root_node();

    // The tree should indicate there are syntax errors
    assert!(root.has_error());
}

#[test]
fn test_parse_empty_source() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = "";
    
    let tree = parser.parse(source, None)?;

    let root = tree.root_node();
    assert_eq!(root.kind(), "source_file");
    // Empty source should have minimal child count
    assert!(root.child_count() == 0);
    
    Ok(())
}

#[test]
fn test_parse_whitespace_only() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = "   \n\n\t  \n  ";
    
    let tree = parser.parse(source, None)?;

    let root = tree.root_node();
    assert_eq!(root.kind(), "source_file");
    
    Ok(())
}

#[test]
fn test_parse_with_comments() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source = r#"
// This is a line comment
/* This is a block comment */

/// Documentation comment
fn main() {
    // Another comment
    println!("Hello"); /* inline comment */
}
"#;
    
    let tree = parser.parse(source, None)?;

    let root = tree.root_node();
    assert_eq!(root.kind(), "source_file");
    assert!(root.child_count() > 0);
    
    Ok(())
}

#[test]
fn test_parse_incremental() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    let source1 = "fn main() {}";
    
    let tree1 = parser.parse(source1, None)?;
    let root1 = tree1.root_node();
    assert_eq!(root1.kind(), "source_file");

    // Parse with previous tree for incremental parsing
    let source2 = "fn main() { println!(\"Hello\"); }";
    let tree2 = parser.parse(source2, Some(&tree1))?;

    let root2 = tree2.root_node();
    assert_eq!(root2.kind(), "source_file");
    
    Ok(())
}

#[test]
fn test_parser_reuse() -> Result<()> {
    let mut parser = Parser::new(Language::Rust)?;
    
    // Parse multiple sources with the same parser
    let sources = vec![
        "fn test1() {}",
        "fn test2() { let x = 5; }",
        "struct Test { field: i32 }",
    ];
    
    for source in sources {
        let tree = parser.parse(source, None)?;
        let root = tree.root_node();
        assert_eq!(root.kind(), "source_file");
    }
    
    Ok(())
}
