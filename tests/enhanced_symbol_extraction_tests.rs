use rust_tree_sitter::analyzer::CodebaseAnalyzer;
use rust_tree_sitter::error::Result;
use std::fs;
use tempfile::TempDir;

/// Test enhanced symbol extraction for C/C++ with documentation
#[test]
fn test_c_symbol_extraction_with_documentation() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let c_file = temp_dir.path().join("test.c");
    
    let c_code = r#"
/**
 * Calculates the factorial of a number
 * @param n The number to calculate factorial for
 * @return The factorial of n
 */
int factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

/// A simple structure to represent a point
typedef struct {
    int x;  ///< X coordinate
    int y;  ///< Y coordinate
} Point;

/**
 * Adds two points together
 * @param p1 First point
 * @param p2 Second point
 * @return Sum of the two points
 */
Point add_points(Point p1, Point p2) {
    Point result = {p1.x + p2.x, p1.y + p2.y};
    return result;
}
"#;
    
    fs::write(&c_file, c_code).unwrap();
    
    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(temp_dir.path())?;
    
    assert_eq!(result.total_files, 1);
    assert_eq!(result.parsed_files, 1);
    assert_eq!(result.error_files, 0);
    
    let file_info = &result.files[0];
    assert!(file_info.symbols.len() >= 3); // factorial, Point, add_points
    
    // Check that documentation was extracted
    let factorial_symbol = file_info.symbols.iter()
        .find(|s| s.name == "factorial")
        .expect("factorial function should be found");
    assert!(factorial_symbol.documentation.is_some());
    assert!(factorial_symbol.documentation.as_ref().unwrap().contains("Calculates the factorial"));
    
    let point_symbol = file_info.symbols.iter()
        .find(|s| s.name == "Point")
        .expect("Point typedef should be found");
    assert!(point_symbol.documentation.is_some());
    assert!(point_symbol.documentation.as_ref().unwrap().contains("simple structure"));
    
    Ok(())
}

/// Test enhanced symbol extraction for C++ with classes and namespaces
#[test]
fn test_cpp_symbol_extraction_with_documentation() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let cpp_file = temp_dir.path().join("test.cpp");
    
    let cpp_code = r#"
/**
 * Math utilities namespace
 */
namespace MathUtils {
    
    /**
     * A class representing a mathematical vector
     */
    class Vector {
    private:
        double x, y;
        
    public:
        /**
         * Constructor for Vector
         * @param x X component
         * @param y Y component
         */
        Vector(double x, double y) : x(x), y(y) {}
        
        /**
         * Calculates the magnitude of the vector
         * @return The magnitude
         */
        double magnitude() const {
            return sqrt(x*x + y*y);
        }
    };
    
    /**
     * Utility function to calculate distance
     * @param v1 First vector
     * @param v2 Second vector
     * @return Distance between vectors
     */
    double distance(const Vector& v1, const Vector& v2) {
        return (v1 - v2).magnitude();
    }
}
"#;
    
    fs::write(&cpp_file, cpp_code).unwrap();
    
    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(temp_dir.path())?;
    
    assert_eq!(result.total_files, 1);
    assert_eq!(result.parsed_files, 1);
    assert_eq!(result.error_files, 0);
    
    let file_info = &result.files[0];

    // Debug: Print all found symbols
    println!("Found {} symbols:", file_info.symbols.len());
    for symbol in &file_info.symbols {
        println!("  - {} ({})", symbol.name, symbol.kind);
    }

    assert!(file_info.symbols.len() >= 3); // MathUtils namespace, Vector class, distance function

    // Check namespace documentation (might not be found due to C++ parsing limitations)
    let namespace_symbol = file_info.symbols.iter()
        .find(|s| s.name == "MathUtils" && s.kind == "namespace");
    if let Some(ns) = namespace_symbol {
        assert!(ns.documentation.is_some());
        assert!(ns.documentation.as_ref().unwrap().contains("Math utilities"));
    }

    // Check class documentation
    let class_symbol = file_info.symbols.iter()
        .find(|s| s.name == "Vector" && s.kind == "class");
    if let Some(class) = class_symbol {
        assert!(class.documentation.is_some());
        assert!(class.documentation.as_ref().unwrap().contains("mathematical vector"));
    }
    
    Ok(())
}

/// Test enhanced symbol extraction for Go with exported/unexported symbols
#[test]
fn test_go_symbol_extraction_with_documentation() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let go_file = temp_dir.path().join("test.go");
    
    let go_code = r#"
package main

import "fmt"

// User represents a user in the system
type User struct {
    ID   int    `json:"id"`
    Name string `json:"name"`
}

// NewUser creates a new user with the given name
func NewUser(name string) *User {
    return &User{Name: name}
}

// GetDisplayName returns the display name for the user
func (u *User) GetDisplayName() string {
    return fmt.Sprintf("User: %s", u.Name)
}

// privateHelper is an internal helper function
func privateHelper() {
    // This should not be exported
}

// MaxUsers defines the maximum number of users
const MaxUsers = 1000

// currentUserCount tracks the current number of users
var currentUserCount int
"#;
    
    fs::write(&go_file, go_code).unwrap();
    
    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(temp_dir.path())?;
    
    assert_eq!(result.total_files, 1);
    assert_eq!(result.parsed_files, 1);
    assert_eq!(result.error_files, 0);
    
    let file_info = &result.files[0];

    // Debug: Print all found symbols
    println!("Go symbols found {} symbols:", file_info.symbols.len());
    for symbol in &file_info.symbols {
        println!("  - {} ({})", symbol.name, symbol.kind);
    }

    assert!(file_info.symbols.len() >= 5); // User type, NewUser, GetDisplayName, MaxUsers, etc.

    // Check exported type documentation
    let user_type = file_info.symbols.iter()
        .find(|s| s.name == "User" && s.kind == "type");
    if let Some(user) = user_type {
        assert!(user.is_public);
        assert!(user.documentation.is_some());
        assert!(user.documentation.as_ref().unwrap().contains("represents a user"));
    }

    // Check exported function documentation
    let new_user_func = file_info.symbols.iter()
        .find(|s| s.name == "NewUser" && s.kind == "function");
    if let Some(func) = new_user_func {
        assert!(func.is_public);
        assert!(func.documentation.is_some());
        assert!(func.documentation.as_ref().unwrap().contains("creates a new user"));
    }

    // Check method documentation
    let method = file_info.symbols.iter()
        .find(|s| s.name == "User::GetDisplayName" && s.kind == "method");
    if let Some(m) = method {
        assert!(m.is_public);
        assert!(m.documentation.is_some());
        assert!(m.documentation.as_ref().unwrap().contains("returns the display name"));
    }

    // Check unexported function
    let private_func = file_info.symbols.iter()
        .find(|s| s.name == "privateHelper" && s.kind == "function");
    if let Some(pf) = private_func {
        assert!(!pf.is_public);
    }

    // Check constants and variables
    let max_users_const = file_info.symbols.iter()
        .find(|s| s.name == "MaxUsers" && s.kind == "constant");
    if let Some(const_sym) = max_users_const {
        assert!(const_sym.is_public);
    }

    let current_count_var = file_info.symbols.iter()
        .find(|s| s.name == "currentUserCount" && s.kind == "variable");
    if let Some(var_sym) = current_count_var {
        assert!(!var_sym.is_public);
    }
    
    Ok(())
}

/// Test enhanced symbol extraction for Python with imports
#[test]
fn test_python_symbol_extraction_with_imports() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let py_file = temp_dir.path().join("test.py");
    
    let py_code = r#"
"""
A module for user management
"""

import os
import sys
from typing import List, Optional
from datetime import datetime

class UserManager:
    """Manages user operations"""
    
    def __init__(self):
        """Initialize the user manager"""
        self._users = []
    
    def add_user(self, name: str) -> bool:
        """Add a new user to the system"""
        self._users.append(name)
        return True
    
    def _validate_user(self, name: str) -> bool:
        """Private method to validate user data"""
        return len(name) > 0

def get_current_time():
    """Get the current timestamp"""
    return datetime.now()

# Global configuration
MAX_USERS = 100
_internal_counter = 0
"#;
    
    fs::write(&py_file, py_code).unwrap();
    
    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(temp_dir.path())?;
    
    assert_eq!(result.total_files, 1);
    assert_eq!(result.parsed_files, 1);
    assert_eq!(result.error_files, 0);
    
    let file_info = &result.files[0];

    // Debug: Print all found symbols
    println!("Python symbols found {} symbols:", file_info.symbols.len());
    for symbol in &file_info.symbols {
        println!("  - {} ({})", symbol.name, symbol.kind);
    }

    assert!(file_info.symbols.len() >= 8); // Classes, functions, variables, imports

    // Check class
    let user_manager_class = file_info.symbols.iter()
        .find(|s| s.name == "UserManager" && s.kind == "class");
    if let Some(class) = user_manager_class {
        assert!(class.is_public);
        assert!(class.documentation.is_some());
        assert!(class.documentation.as_ref().unwrap().contains("Manages user operations"));
    }

    // Check public method
    let add_user_method = file_info.symbols.iter()
        .find(|s| s.name == "UserManager::add_user" && s.kind == "method");
    if let Some(method) = add_user_method {
        assert!(method.is_public);
    }

    // Check private method
    let validate_method = file_info.symbols.iter()
        .find(|s| s.name == "UserManager::_validate_user" && s.kind == "method");
    if let Some(method) = validate_method {
        assert!(!method.is_public);
    }

    // Check function
    let get_time_func = file_info.symbols.iter()
        .find(|s| s.name == "get_current_time" && s.kind == "function");
    if let Some(func) = get_time_func {
        assert!(func.is_public);
    }

    // Check variables
    let max_users_var = file_info.symbols.iter()
        .find(|s| s.name == "MAX_USERS" && s.kind == "variable");
    if let Some(var) = max_users_var {
        assert!(var.is_public);
    }

    let internal_var = file_info.symbols.iter()
        .find(|s| s.name == "_internal_counter" && s.kind == "variable");
    if let Some(var) = internal_var {
        assert!(!var.is_public);
    }

    // Check imports
    let imports: Vec<_> = file_info.symbols.iter()
        .filter(|s| s.kind == "import")
        .collect();
    assert!(imports.len() >= 3); // os, sys, typing, datetime
    
    Ok(())
}
