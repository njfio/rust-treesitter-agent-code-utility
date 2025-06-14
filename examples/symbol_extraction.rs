//! Symbol extraction example demonstrating advanced code analysis
//!
//! This example shows how to:
//! - Extract functions, classes, structs, and other symbols
//! - Analyze symbol relationships and dependencies
//! - Generate symbol maps and documentation
//! - Handle complex code structures

use rust_tree_sitter::{Parser, Language, Node};
use std::collections::HashMap;
use std::error::Error;

#[derive(Debug, Clone)]
pub struct Symbol {
    pub name: String,
    pub kind: String,
    pub line: usize,
    pub column: usize,
    pub visibility: Option<String>,
    pub parameters: Vec<String>,
    pub return_type: Option<String>,
    pub documentation: Option<String>,
}

#[derive(Debug)]
pub struct SymbolMap {
    pub symbols: Vec<Symbol>,
    pub symbol_index: HashMap<String, usize>,
}

impl SymbolMap {
    pub fn new() -> Self {
        Self {
            symbols: Vec::new(),
            symbol_index: HashMap::new(),
        }
    }

    pub fn add_symbol(&mut self, symbol: Symbol) {
        let index = self.symbols.len();
        self.symbol_index.insert(symbol.name.clone(), index);
        self.symbols.push(symbol);
    }

    pub fn find_symbol(&self, name: &str) -> Option<&Symbol> {
        self.symbol_index.get(name).map(|&index| &self.symbols[index])
    }

    pub fn symbols_by_kind(&self, kind: &str) -> Vec<&Symbol> {
        self.symbols.iter().filter(|s| s.kind == kind).collect()
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("🔍 Symbol Extraction Example\n");

    // Example 1: Extract symbols from Rust code
    extract_rust_symbols()?;

    // Example 2: Extract symbols from JavaScript code
    extract_javascript_symbols()?;

    // Example 3: Extract symbols from Python code
    extract_python_symbols()?;

    // Example 4: Generate symbol documentation
    generate_symbol_documentation()?;

    Ok(())
}

fn extract_rust_symbols() -> Result<(), Box<dyn Error>> {
    println!("📦 Extracting Rust Symbols:");
    println!("===========================");

    let rust_code = r#"
//! A comprehensive example module demonstrating various Rust constructs

use std::collections::HashMap;
use std::fmt::{Display, Formatter, Result as FmtResult};

/// Configuration for the application
#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub port: u16,
    pub debug: bool,
}

impl Config {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self {
            database_url: "localhost:5432".to_string(),
            port: 8080,
            debug: false,
        }
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Result<Self, String> {
        // Implementation would read from env vars
        Ok(Self::new())
    }
}

impl Display for Config {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "Config {{ url: {}, port: {} }}", self.database_url, self.port)
    }
}

/// User management trait
pub trait UserManager {
    type User;
    type Error;

    /// Add a new user
    fn add_user(&mut self, user: Self::User) -> Result<(), Self::Error>;

    /// Get user by ID
    fn get_user(&self, id: u32) -> Option<&Self::User>;
}

/// Simple user struct
#[derive(Debug, Clone, PartialEq)]
pub struct User {
    pub id: u32,
    pub name: String,
    pub email: String,
}

/// In-memory user store
pub struct InMemoryUserStore {
    users: HashMap<u32, User>,
    next_id: u32,
}

impl InMemoryUserStore {
    /// Create a new empty user store
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
            next_id: 1,
        }
    }

    /// Get the number of users
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Check if the store is empty
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
}

impl UserManager for InMemoryUserStore {
    type User = User;
    type Error = String;

    fn add_user(&mut self, mut user: Self::User) -> Result<(), Self::Error> {
        if user.name.is_empty() {
            return Err("User name cannot be empty".to_string());
        }

        user.id = self.next_id;
        self.next_id += 1;
        self.users.insert(user.id, user);
        Ok(())
    }

    fn get_user(&self, id: u32) -> Option<&Self::User> {
        self.users.get(&id)
    }
}

/// Application error types
#[derive(Debug)]
pub enum AppError {
    DatabaseError(String),
    ValidationError(String),
    NotFound,
}

impl Display for AppError {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        match self {
            AppError::DatabaseError(msg) => write!(f, "Database error: {}", msg),
            AppError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            AppError::NotFound => write!(f, "Resource not found"),
        }
    }
}

/// Main application function
pub fn main() -> Result<(), AppError> {
    let config = Config::new();
    let mut store = InMemoryUserStore::new();

    let user = User {
        id: 0, // Will be set by add_user
        name: "Alice".to_string(),
        email: "alice@example.com".to_string(),
    };

    store.add_user(user).map_err(AppError::ValidationError)?;

    println!("Application started with config: {}", config);
    println!("User store has {} users", store.len());

    Ok(())
}

/// Helper function to validate email addresses
fn validate_email(email: &str) -> bool {
    email.contains('@') && email.contains('.')
}

/// Constant for maximum username length
const MAX_USERNAME_LENGTH: usize = 50;

/// Static configuration instance
static DEFAULT_CONFIG: Config = Config {
    database_url: String::new(),
    port: 8080,
    debug: false,
};
    "#;

    let mut symbol_map = SymbolMap::new();
    let mut parser = Parser::new(Language::Rust)?;
    let tree = parser.parse(rust_code, None)?;

    // Extract different types of symbols
    extract_rust_structs(&tree.root_node(), rust_code, &mut symbol_map);
    extract_rust_functions(&tree.root_node(), rust_code, &mut symbol_map);
    extract_rust_traits(&tree.root_node(), rust_code, &mut symbol_map);
    extract_rust_enums(&tree.root_node(), rust_code, &mut symbol_map);
    extract_rust_constants(&tree.root_node(), rust_code, &mut symbol_map);

    // Display results
    println!("Found {} symbols:", symbol_map.symbols.len());

    for kind in &["struct", "function", "trait", "enum", "const", "static"] {
        let symbols = symbol_map.symbols_by_kind(kind);
        if !symbols.is_empty() {
            println!("\n{}s ({}):", kind.to_uppercase(), symbols.len());
            for symbol in symbols {
                println!("  - {} at line {}", symbol.name, symbol.line);
                if let Some(ref doc) = symbol.documentation {
                    println!("    Doc: {}", doc.trim());
                }
            }
        }
    }

    println!();
    Ok(())
}

fn extract_javascript_symbols() -> Result<(), Box<dyn Error>> {
    println!("🟨 Extracting JavaScript Symbols:");
    println!("=================================");

    let js_code = r#"
/**
 * Advanced user management system
 * @module UserManagement
 */

/**
 * Base class for all entities
 */
class Entity {
    /**
     * Create a new entity
     * @param {number} id - Entity ID
     */
    constructor(id) {
        this.id = id;
        this.createdAt = new Date();
    }

    /**
     * Get entity ID
     * @returns {number} The entity ID
     */
    getId() {
        return this.id;
    }

    /**
     * Get creation timestamp
     * @returns {Date} Creation date
     */
    getCreatedAt() {
        return this.createdAt;
    }
}

/**
 * User class extending Entity
 */
class User extends Entity {
    /**
     * Create a new user
     * @param {number} id - User ID
     * @param {string} name - User name
     * @param {string} email - User email
     */
    constructor(id, name, email) {
        super(id);
        this.name = name;
        this.email = email;
        this.isActive = true;
    }

    /**
     * Validate user email
     * @returns {boolean} True if email is valid
     */
    isValidEmail() {
        return this.email.includes('@') && this.email.includes('.');
    }

    /**
     * Deactivate the user
     */
    deactivate() {
        this.isActive = false;
    }

    /**
     * Get user display name
     * @returns {string} Display name
     */
    getDisplayName() {
        return `${this.name} (${this.email})`;
    }
}

/**
 * User repository for data access
 */
class UserRepository {
    /**
     * Create a new repository
     */
    constructor() {
        this.users = new Map();
        this.nextId = 1;
    }

    /**
     * Add a new user
     * @param {string} name - User name
     * @param {string} email - User email
     * @returns {User} The created user
     */
    createUser(name, email) {
        const user = new User(this.nextId++, name, email);
        this.users.set(user.id, user);
        return user;
    }

    /**
     * Find user by ID
     * @param {number} id - User ID
     * @returns {User|undefined} The user or undefined
     */
    findById(id) {
        return this.users.get(id);
    }

    /**
     * Find users by email
     * @param {string} email - Email to search for
     * @returns {User[]} Array of matching users
     */
    findByEmail(email) {
        return Array.from(this.users.values()).filter(user => user.email === email);
    }

    /**
     * Get all users
     * @returns {User[]} All users
     */
    getAllUsers() {
        return Array.from(this.users.values());
    }

    /**
     * Delete user by ID
     * @param {number} id - User ID to delete
     * @returns {boolean} True if user was deleted
     */
    deleteUser(id) {
        return this.users.delete(id);
    }
}

/**
 * Utility functions for user management
 */
const UserUtils = {
    /**
     * Validate email format
     * @param {string} email - Email to validate
     * @returns {boolean} True if valid
     */
    validateEmail(email) {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        return emailRegex.test(email);
    },

    /**
     * Generate random user ID
     * @returns {number} Random ID
     */
    generateId() {
        return Math.floor(Math.random() * 1000000);
    },

    /**
     * Format user for display
     * @param {User} user - User to format
     * @returns {string} Formatted string
     */
    formatUser(user) {
        return `${user.name} <${user.email}> (ID: ${user.id})`;
    }
};

/**
 * Main application function
 */
function main() {
    const repository = new UserRepository();

    // Create some test users
    const alice = repository.createUser("Alice Johnson", "alice@example.com");
    const bob = repository.createUser("Bob Smith", "bob@example.com");

    console.log("Created users:");
    repository.getAllUsers().forEach(user => {
        console.log(`  - ${UserUtils.formatUser(user)}`);
    });

    // Validate emails
    console.log("\nEmail validation:");
    repository.getAllUsers().forEach(user => {
        const isValid = UserUtils.validateEmail(user.email);
        console.log(`  - ${user.name}: ${isValid ? 'Valid' : 'Invalid'}`);
    });
}

// Constants
const MAX_USERS = 1000;
const DEFAULT_TIMEOUT = 5000;

// Run the application
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { User, UserRepository, UserUtils };
} else {
    main();
}
    "#;

    let mut symbol_map = SymbolMap::new();
    let mut parser = Parser::new(Language::JavaScript)?;
    let tree = parser.parse(js_code, None)?;

    // Extract JavaScript symbols
    extract_js_classes(&tree.root_node(), js_code, &mut symbol_map);
    extract_js_functions(&tree.root_node(), js_code, &mut symbol_map);
    extract_js_methods(&tree.root_node(), js_code, &mut symbol_map);
    extract_js_variables(&tree.root_node(), js_code, &mut symbol_map);

    // Display results
    println!("Found {} symbols:", symbol_map.symbols.len());

    for kind in &["class", "function", "method", "variable"] {
        let symbols = symbol_map.symbols_by_kind(kind);
        if !symbols.is_empty() {
            println!("\n{}s ({}):", kind.to_uppercase(), symbols.len());
            for symbol in symbols {
                println!("  - {} at line {}", symbol.name, symbol.line);
                if !symbol.parameters.is_empty() {
                    println!("    Parameters: {}", symbol.parameters.join(", "));
                }
            }
        }
    }

    println!();
    Ok(())
}

fn extract_python_symbols() -> Result<(), Box<dyn Error>> {
    println!("🐍 Extracting Python Symbols:");
    println!("=============================");

    let python_code = r#"
"""
Advanced user management system in Python
"""

from typing import Dict, List, Optional, Protocol
from datetime import datetime
from abc import ABC, abstractmethod

class UserManagerProtocol(Protocol):
    """Protocol defining user manager interface"""

    def add_user(self, user: 'User') -> None:
        """Add a user to the system"""
        ...

    def get_user(self, user_id: int) -> Optional['User']:
        """Get a user by ID"""
        ...

class Entity(ABC):
    """Base class for all entities"""

    def __init__(self, entity_id: int):
        self.id = entity_id
        self.created_at = datetime.now()

    @abstractmethod
    def validate(self) -> bool:
        """Validate the entity"""
        pass

    def get_age(self) -> float:
        """Get entity age in seconds"""
        return (datetime.now() - self.created_at).total_seconds()

class User(Entity):
    """User entity with validation"""

    def __init__(self, user_id: int, name: str, email: str):
        super().__init__(user_id)
        self.name = name
        self.email = email
        self.is_active = True

    def validate(self) -> bool:
        """Validate user data"""
        return bool(self.name and '@' in self.email)

    def deactivate(self) -> None:
        """Deactivate the user"""
        self.is_active = False

    def __str__(self) -> str:
        return f"User(id={self.id}, name='{self.name}', email='{self.email}')"

    def __repr__(self) -> str:
        return self.__str__()

class UserRepository:
    """Repository for managing users"""

    def __init__(self):
        self._users: Dict[int, User] = {}
        self._next_id = 1

    def add_user(self, name: str, email: str) -> User:
        """Add a new user"""
        user = User(self._next_id, name, email)
        if not user.validate():
            raise ValueError("Invalid user data")

        self._users[user.id] = user
        self._next_id += 1
        return user

    def get_user(self, user_id: int) -> Optional[User]:
        """Get user by ID"""
        return self._users.get(user_id)

    def find_by_email(self, email: str) -> List[User]:
        """Find users by email"""
        return [user for user in self._users.values() if user.email == email]

    def get_all_users(self) -> List[User]:
        """Get all users"""
        return list(self._users.values())

    def delete_user(self, user_id: int) -> bool:
        """Delete user by ID"""
        return self._users.pop(user_id, None) is not None

    @property
    def count(self) -> int:
        """Get user count"""
        return len(self._users)

def validate_email(email: str) -> bool:
    """Validate email format"""
    import re
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))

def create_test_users(repository: UserRepository) -> List[User]:
    """Create test users"""
    users = []
    test_data = [
        ("Alice Johnson", "alice@example.com"),
        ("Bob Smith", "bob@example.com"),
        ("Charlie Brown", "charlie@example.com"),
    ]

    for name, email in test_data:
        try:
            user = repository.add_user(name, email)
            users.append(user)
        except ValueError as e:
            print(f"Failed to create user {name}: {e}")

    return users

def main():
    """Main application function"""
    repository = UserRepository()

    # Create test users
    users = create_test_users(repository)

    print(f"Created {len(users)} users:")
    for user in users:
        print(f"  - {user}")
        print(f"    Valid: {user.validate()}")
        print(f"    Age: {user.get_age():.2f} seconds")

    # Test email validation
    print("\nEmail validation:")
    for user in users:
        is_valid = validate_email(user.email)
        print(f"  - {user.name}: {is_valid}")

# Constants
MAX_USERS = 1000
DEFAULT_TIMEOUT = 30

if __name__ == "__main__":
    main()
    "#;

    let mut symbol_map = SymbolMap::new();
    let mut parser = Parser::new(Language::Python)?;
    let tree = parser.parse(python_code, None)?;

    // Extract Python symbols
    extract_python_classes(&tree.root_node(), python_code, &mut symbol_map);
    extract_python_functions(&tree.root_node(), python_code, &mut symbol_map);
    extract_python_methods(&tree.root_node(), python_code, &mut symbol_map);

    // Display results
    println!("Found {} symbols:", symbol_map.symbols.len());

    for kind in &["class", "function", "method"] {
        let symbols = symbol_map.symbols_by_kind(kind);
        if !symbols.is_empty() {
            println!("\n{}s ({}):", kind.to_uppercase(), symbols.len());
            for symbol in symbols {
                println!("  - {} at line {}", symbol.name, symbol.line);
                if !symbol.parameters.is_empty() {
                    println!("    Parameters: {}", symbol.parameters.join(", "));
                }
            }
        }
    }

    println!();
    Ok(())
}

fn generate_symbol_documentation() -> Result<(), Box<dyn Error>> {
    println!("📚 Generating Symbol Documentation:");
    println!("==================================");

    // This would typically generate comprehensive documentation
    // For this example, we'll show how to extract and format documentation

    let rust_code = r#"
/// A comprehensive user management system
///
/// This module provides functionality for managing users in a system,
/// including creation, validation, and storage operations.
pub mod user_management {
    use std::collections::HashMap;

    /// Represents a user in the system
    ///
    /// # Examples
    ///
    /// ```
    /// let user = User::new(1, "Alice".to_string(), "alice@example.com".to_string());
    /// assert!(user.is_valid());
    /// ```
    #[derive(Debug, Clone, PartialEq)]
    pub struct User {
        /// Unique identifier for the user
        pub id: u32,
        /// User's display name
        pub name: String,
        /// User's email address
        pub email: String,
    }

    impl User {
        /// Creates a new user with the given parameters
        ///
        /// # Arguments
        ///
        /// * `id` - Unique identifier for the user
        /// * `name` - User's display name
        /// * `email` - User's email address
        ///
        /// # Returns
        ///
        /// A new `User` instance
        pub fn new(id: u32, name: String, email: String) -> Self {
            Self { id, name, email }
        }

        /// Validates the user's data
        ///
        /// Checks that the name is not empty and the email contains '@'
        ///
        /// # Returns
        ///
        /// `true` if the user data is valid, `false` otherwise
        pub fn is_valid(&self) -> bool {
            !self.name.is_empty() && self.email.contains('@')
        }
    }
}
    "#;

    let mut parser = Parser::new(Language::Rust)?;
    let tree = parser.parse(rust_code, None)?;

    println!("Documentation extracted from Rust code:");
    extract_documentation_comments(&tree.root_node(), rust_code);

    println!();
    Ok(())
}

// Helper functions for extracting symbols from different languages

fn extract_rust_structs(node: &Node, source: &str, symbol_map: &mut SymbolMap) {
    if node.kind() == "struct_item" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = name_node.text().unwrap_or("unknown");
            let start_pos = node.start_position();

            let symbol = Symbol {
                name: name.to_string(),
                kind: "struct".to_string(),
                line: start_pos.row + 1,
                column: start_pos.column + 1,
                visibility: None, // Simplified for now
                parameters: Vec::new(),
                return_type: None,
                documentation: None, // Simplified for now
            };

            symbol_map.add_symbol(symbol);
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_rust_structs(&child, source, symbol_map);
        }
    }
}

fn extract_rust_functions(node: &Node, source: &str, symbol_map: &mut SymbolMap) {
    if node.kind() == "function_item" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = name_node.text().unwrap_or("unknown");
            let start_pos = node.start_position();

            let symbol = Symbol {
                name: name.to_string(),
                kind: "function".to_string(),
                line: start_pos.row + 1,
                column: start_pos.column + 1,
                visibility: None,
                parameters: Vec::new(),
                return_type: None,
                documentation: None,
            };

            symbol_map.add_symbol(symbol);
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_rust_functions(&child, source, symbol_map);
        }
    }
}

fn extract_rust_traits(node: &Node, source: &str, symbol_map: &mut SymbolMap) {
    if node.kind() == "trait_item" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = name_node.text().unwrap_or("unknown");
            let start_pos = node.start_position();

            let symbol = Symbol {
                name: name.to_string(),
                kind: "trait".to_string(),
                line: start_pos.row + 1,
                column: start_pos.column + 1,
                visibility: None,
                parameters: Vec::new(),
                return_type: None,
                documentation: None,
            };

            symbol_map.add_symbol(symbol);
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_rust_traits(&child, source, symbol_map);
        }
    }
}

fn extract_rust_enums(node: &Node, source: &str, symbol_map: &mut SymbolMap) {
    if node.kind() == "enum_item" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = name_node.text().unwrap_or("unknown");
            let start_pos = node.start_position();

            let symbol = Symbol {
                name: name.to_string(),
                kind: "enum".to_string(),
                line: start_pos.row + 1,
                column: start_pos.column + 1,
                visibility: None,
                parameters: Vec::new(),
                return_type: None,
                documentation: None,
            };

            symbol_map.add_symbol(symbol);
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_rust_enums(&child, source, symbol_map);
        }
    }
}

fn extract_rust_constants(node: &Node, source: &str, symbol_map: &mut SymbolMap) {
    if node.kind() == "const_item" || node.kind() == "static_item" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = name_node.text().unwrap_or("unknown");
            let start_pos = node.start_position();
            let kind = if node.kind() == "const_item" { "const" } else { "static" };

            let symbol = Symbol {
                name: name.to_string(),
                kind: kind.to_string(),
                line: start_pos.row + 1,
                column: start_pos.column + 1,
                visibility: None,
                parameters: Vec::new(),
                return_type: None,
                documentation: None,
            };

            symbol_map.add_symbol(symbol);
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_rust_constants(&child, source, symbol_map);
        }
    }
}

fn extract_js_classes(node: &Node, source: &str, symbol_map: &mut SymbolMap) {
    if node.kind() == "class_declaration" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = name_node.text().unwrap_or("unknown");
            let start_pos = node.start_position();

            let symbol = Symbol {
                name: name.to_string(),
                kind: "class".to_string(),
                line: start_pos.row + 1,
                column: start_pos.column + 1,
                visibility: None,
                parameters: Vec::new(),
                return_type: None,
                documentation: None,
            };

            symbol_map.add_symbol(symbol);
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_js_classes(&child, source, symbol_map);
        }
    }
}

fn extract_js_functions(node: &Node, source: &str, symbol_map: &mut SymbolMap) {
    if node.kind() == "function_declaration" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = name_node.text().unwrap_or("unknown");
            let start_pos = node.start_position();

            let symbol = Symbol {
                name: name.to_string(),
                kind: "function".to_string(),
                line: start_pos.row + 1,
                column: start_pos.column + 1,
                visibility: None,
                parameters: Vec::new(),
                return_type: None,
                documentation: None,
            };

            symbol_map.add_symbol(symbol);
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_js_functions(&child, source, symbol_map);
        }
    }
}

fn extract_js_methods(node: &Node, source: &str, symbol_map: &mut SymbolMap) {
    if node.kind() == "method_definition" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = name_node.text().unwrap_or("unknown");
            let start_pos = node.start_position();

            let symbol = Symbol {
                name: name.to_string(),
                kind: "method".to_string(),
                line: start_pos.row + 1,
                column: start_pos.column + 1,
                visibility: None,
                parameters: Vec::new(),
                return_type: None,
                documentation: None,
            };

            symbol_map.add_symbol(symbol);
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_js_methods(&child, source, symbol_map);
        }
    }
}

fn extract_js_variables(node: &Node, source: &str, symbol_map: &mut SymbolMap) {
    if node.kind() == "variable_declaration" {
        for i in 0..node.child_count() {
            if let Some(child) = node.child(i) {
                if child.kind() == "variable_declarator" {
                    if let Some(name_node) = child.child_by_field_name("name") {
                        let name = name_node.text().unwrap_or("unknown");
                        let start_pos = child.start_position();

                        let symbol = Symbol {
                            name: name.to_string(),
                            kind: "variable".to_string(),
                            line: start_pos.row + 1,
                            column: start_pos.column + 1,
                            visibility: None,
                            parameters: Vec::new(),
                            return_type: None,
                            documentation: None,
                        };

                        symbol_map.add_symbol(symbol);
                    }
                }
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_js_variables(&child, source, symbol_map);
        }
    }
}

fn extract_python_classes(node: &Node, source: &str, symbol_map: &mut SymbolMap) {
    if node.kind() == "class_definition" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = name_node.text().unwrap_or("unknown");
            let start_pos = node.start_position();

            let symbol = Symbol {
                name: name.to_string(),
                kind: "class".to_string(),
                line: start_pos.row + 1,
                column: start_pos.column + 1,
                visibility: None,
                parameters: Vec::new(),
                return_type: None,
                documentation: None,
            };

            symbol_map.add_symbol(symbol);
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_python_classes(&child, source, symbol_map);
        }
    }
}

fn extract_python_functions(node: &Node, source: &str, symbol_map: &mut SymbolMap) {
    if node.kind() == "function_definition" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = name_node.text().unwrap_or("unknown");
            let start_pos = node.start_position();

            let symbol = Symbol {
                name: name.to_string(),
                kind: "function".to_string(),
                line: start_pos.row + 1,
                column: start_pos.column + 1,
                visibility: None,
                parameters: Vec::new(),
                return_type: None,
                documentation: None,
            };

            symbol_map.add_symbol(symbol);
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_python_functions(&child, source, symbol_map);
        }
    }
}

fn extract_python_methods(node: &Node, source: &str, symbol_map: &mut SymbolMap) {
    if node.kind() == "method_definition" {
        if let Some(name_node) = node.child_by_field_name("name") {
            let name = name_node.text().unwrap_or("unknown");
            let start_pos = node.start_position();

            let symbol = Symbol {
                name: name.to_string(),
                kind: "method".to_string(),
                line: start_pos.row + 1,
                column: start_pos.column + 1,
                visibility: None,
                parameters: Vec::new(),
                return_type: None,
                documentation: None,
            };

            symbol_map.add_symbol(symbol);
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_python_methods(&child, source, symbol_map);
        }
    }
}

fn extract_documentation_comments(node: &Node, source: &str) {
    if node.kind() == "line_comment" {
        if let Ok(comment) = node.text() {
            if comment.starts_with("///") {
                let start_pos = node.start_position();
                println!("  Line {}: {}", start_pos.row + 1, comment.trim());
            }
        }
    }

    for i in 0..node.child_count() {
        if let Some(child) = node.child(i) {
            extract_documentation_comments(&child, source);
        }
    }
}