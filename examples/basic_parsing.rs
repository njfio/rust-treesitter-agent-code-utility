//! Basic parsing example demonstrating core tree-sitter functionality
//!
//! This example shows how to:
//! - Parse source code into an AST
//! - Navigate the syntax tree
//! - Extract basic information from nodes
//! - Handle different programming languages

use rust_tree_sitter::{Parser, Language, detect_language_from_extension};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("🌳 Basic Tree-Sitter Parsing Example\n");
    
    // Example 1: Parse Rust code
    parse_rust_example()?;
    
    // Example 2: Parse JavaScript code
    parse_javascript_example()?;
    
    // Example 3: Parse Python code
    parse_python_example()?;
    
    // Example 4: Auto-detect language and parse
    auto_detect_and_parse_example()?;
    
    Ok(())
}

fn parse_rust_example() -> Result<(), Box<dyn Error>> {
    println!("📦 Parsing Rust Code:");
    println!("====================");
    
    let rust_code = r#"
use std::collections::HashMap;

/// A simple user struct
#[derive(Debug, Clone)]
pub struct User {
    pub id: u32,
    pub name: String,
    pub email: String,
}

impl User {
    /// Create a new user
    pub fn new(id: u32, name: String, email: String) -> Self {
        Self { id, name, email }
    }
    
    /// Check if the user has a valid email
    pub fn has_valid_email(&self) -> bool {
        self.email.contains('@') && self.email.contains('.')
    }
}

fn main() {
    let mut users = HashMap::new();
    let user = User::new(1, "Alice".to_string(), "alice@example.com".to_string());
    users.insert(user.id, user);
    
    println!("Created {} users", users.len());
}
    "#;
    
    let mut parser = Parser::new(Language::Rust)?;
    let tree = parser.parse(rust_code, None)?;
    let root_node = tree.root_node();
    
    println!("Root node kind: {}", root_node.kind());
    println!("Number of children: {}", root_node.child_count());
    println!("Source code range: {}..{}", root_node.inner().start_byte(), root_node.inner().end_byte());
    
    // Walk through top-level items
    println!("\nTop-level items:");
    for i in 0..root_node.child_count() {
        if let Some(child) = root_node.child(i) {
            if child.kind() != "line_comment" && !child.kind().is_empty() {
                let start_pos = child.start_position();
                println!("  - {} at line {}, column {}", 
                         child.kind(), start_pos.row + 1, start_pos.column + 1);
            }
        }
    }
    
    // Find all function definitions
    println!("\nFunction definitions:");
    find_functions_recursive(&root_node.inner(), rust_code);
    
    println!();
    Ok(())
}

fn parse_javascript_example() -> Result<(), Box<dyn Error>> {
    println!("🟨 Parsing JavaScript Code:");
    println!("===========================");
    
    let js_code = r#"
/**
 * User management class
 */
class UserManager {
    constructor() {
        this.users = new Map();
        this.nextId = 1;
    }
    
    /**
     * Add a new user
     * @param {string} name - User's name
     * @param {string} email - User's email
     * @returns {Object} The created user
     */
    addUser(name, email) {
        const user = {
            id: this.nextId++,
            name: name,
            email: email,
            createdAt: new Date()
        };
        
        this.users.set(user.id, user);
        return user;
    }
    
    /**
     * Get user by ID
     */
    getUser(id) {
        return this.users.get(id);
    }
    
    /**
     * Get all users
     */
    getAllUsers() {
        return Array.from(this.users.values());
    }
}

// Usage example
const manager = new UserManager();
const alice = manager.addUser("Alice", "alice@example.com");
const bob = manager.addUser("Bob", "bob@example.com");

console.log(`Created ${manager.getAllUsers().length} users`);
    "#;
    
    let mut parser = Parser::new(Language::JavaScript)?;
    let tree = parser.parse(js_code, None)?;
    let root_node = tree.root_node();
    
    println!("Root node kind: {}", root_node.kind());
    println!("Number of children: {}", root_node.child_count());
    
    // Find all method definitions
    println!("\nMethod definitions:");
    find_methods_recursive(&root_node.inner(), js_code);
    
    println!();
    Ok(())
}

fn parse_python_example() -> Result<(), Box<dyn Error>> {
    println!("🐍 Parsing Python Code:");
    println!("=======================");
    
    let python_code = r#"
"""
User management module
"""

from typing import Dict, List, Optional
from datetime import datetime

class User:
    """Represents a user in the system"""
    
    def __init__(self, user_id: int, name: str, email: str):
        self.id = user_id
        self.name = name
        self.email = email
        self.created_at = datetime.now()
    
    def is_valid_email(self) -> bool:
        """Check if the user has a valid email format"""
        return '@' in self.email and '.' in self.email
    
    def __str__(self) -> str:
        return f"User(id={self.id}, name='{self.name}', email='{self.email}')"

class UserManager:
    """Manages a collection of users"""
    
    def __init__(self):
        self.users: Dict[int, User] = {}
        self.next_id = 1
    
    def add_user(self, name: str, email: str) -> User:
        """Add a new user to the system"""
        user = User(self.next_id, name, email)
        self.users[user.id] = user
        self.next_id += 1
        return user
    
    def get_user(self, user_id: int) -> Optional[User]:
        """Get a user by ID"""
        return self.users.get(user_id)
    
    def get_all_users(self) -> List[User]:
        """Get all users"""
        return list(self.users.values())

# Usage example
if __name__ == "__main__":
    manager = UserManager()
    alice = manager.add_user("Alice", "alice@example.com")
    bob = manager.add_user("Bob", "bob@example.com")
    
    print(f"Created {len(manager.get_all_users())} users")
    "#;
    
    let mut parser = Parser::new(Language::Python)?;
    let tree = parser.parse(python_code, None)?;
    let root_node = tree.root_node();
    
    println!("Root node kind: {}", root_node.kind());
    println!("Number of children: {}", root_node.child_count());
    
    // Find all function definitions
    println!("\nFunction definitions:");
    find_python_functions_recursive(&root_node.inner(), python_code);
    
    println!();
    Ok(())
}

fn auto_detect_and_parse_example() -> Result<(), Box<dyn Error>> {
    println!("🔍 Auto-detecting Language and Parsing:");
    println!("=======================================");
    
    let examples = vec![
        ("example.rs", "fn main() { println!(\"Hello from Rust!\"); }"),
        ("example.js", "function main() { console.log('Hello from JavaScript!'); }"),
        ("example.py", "def main():\n    print('Hello from Python!')"),
        ("example.c", "#include <stdio.h>\nint main() { printf(\"Hello from C!\\n\"); return 0; }"),
    ];
    
    for (filename, code) in examples {
        if let Some(language) = detect_language_from_extension(filename) {
            println!("\nFile: {} -> Language: {:?}", filename, language);
            
            let mut parser = Parser::new(language)?;
            let tree = parser.parse(code, None)?;
            let root_node = tree.root_node();
            
            println!("  Root node: {}", root_node.kind());
            println!("  Children: {}", root_node.child_count());
            
            // Find the main function/method
            if let Some(main_node) = find_main_function(&root_node.inner(), code) {
                let start_pos = main_node.start_position();
                println!("  Main function found at line {}, column {}", 
                         start_pos.row + 1, start_pos.column + 1);
            }
        } else {
            println!("Could not detect language for {}", filename);
        }
    }
    
    Ok(())
}

// Helper functions for traversing the syntax tree

fn find_functions_recursive(node: &tree_sitter::Node, source: &str) {
    if node.kind() == "function_item" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = &source[name_node.start_byte()..name_node.end_byte()];
            let start_pos = node.start_position();
            println!("  - {} at line {}", name, start_pos.row + 1);
        }
    }
    
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_functions_recursive(&child, source);
        }
    }
}

fn find_methods_recursive(node: &tree_sitter::Node, source: &str) {
    if node.kind() == "method_definition" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = &source[name_node.start_byte()..name_node.end_byte()];
            let start_pos = node.start_position();
            println!("  - {} at line {}", name, start_pos.row + 1);
        }
    }
    
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_methods_recursive(&child, source);
        }
    }
}

fn find_python_functions_recursive(node: &tree_sitter::Node, source: &str) {
    if node.kind() == "function_definition" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = &source[name_node.start_byte()..name_node.end_byte()];
            let start_pos = node.start_position();
            println!("  - {} at line {}", name, start_pos.row + 1);
        }
    }
    
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            find_python_functions_recursive(&child, source);
        }
    }
}

fn find_main_function<'a>(node: &tree_sitter::Node<'a>, source: &str) -> Option<tree_sitter::Node<'a>> {
    // Check if this node is a main function
    if node.kind() == "function_item" || node.kind() == "function_declaration" || node.kind() == "function_definition" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = &source[name_node.start_byte()..name_node.end_byte()];
            if name == "main" {
                return Some(*node);
            }
        }
    }
    
    // Recursively search children
    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            if let Some(main_node) = find_main_function(&child, source) {
                return Some(main_node);
            }
        }
    }
    
    None
}
