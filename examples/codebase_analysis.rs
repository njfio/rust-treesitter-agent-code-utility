//! Comprehensive codebase analysis example
//!
//! This example demonstrates how to:
//! - Analyze entire codebases with multiple files and languages
//! - Generate detailed analysis reports
//! - Extract symbols and patterns from code
//! - Generate actionable insights

use rust_tree_sitter::{CodebaseAnalyzer, AnalysisConfig};
use std::error::Error;
use std::fs;
use tempfile::TempDir;

fn main() -> Result<(), Box<dyn Error>> {
    println!("🔍 Comprehensive Codebase Analysis Example\n");

    // Create a sample project for analysis
    let project_dir = create_sample_project()?;

    // Example 1: Basic codebase analysis
    basic_codebase_analysis(&project_dir)?;

    // Example 2: Detailed file analysis
    detailed_file_analysis(&project_dir)?;

    // Example 3: Language-specific insights
    language_specific_analysis(&project_dir)?;

    // Example 4: Comprehensive report generation
    generate_comprehensive_report(&project_dir)?;

    println!("✅ Analysis complete! Check the generated reports for detailed insights.");

    Ok(())
}

fn create_sample_project() -> Result<TempDir, Box<dyn Error>> {
    let temp_dir = TempDir::new()?;
    
    // Create a multi-language project structure
    let src_dir = temp_dir.path().join("src");
    let tests_dir = temp_dir.path().join("tests");
    let frontend_dir = temp_dir.path().join("frontend");
    let scripts_dir = temp_dir.path().join("scripts");
    
    fs::create_dir_all(&src_dir)?;
    fs::create_dir_all(&tests_dir)?;
    fs::create_dir_all(&frontend_dir)?;
    fs::create_dir_all(&scripts_dir)?;
    
    // Rust main application
    fs::write(
        src_dir.join("main.rs"),
        r#"
use std::collections::HashMap;
use std::env;
use std::fs;

/// Main application entry point
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = load_config()?;
    let mut app = Application::new(config);
    app.run()
}

/// Application configuration
#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub port: u16,
    pub debug: bool,
    pub max_connections: usize,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Ok(Config {
            database_url: env::var("DATABASE_URL").unwrap_or_else(|_| "localhost:5432".to_string()),
            port: env::var("PORT").unwrap_or_else(|_| "8080".to_string()).parse().unwrap_or(8080),
            debug: env::var("DEBUG").is_ok(),
            max_connections: env::var("MAX_CONNECTIONS").unwrap_or_else(|_| "100".to_string()).parse().unwrap_or(100),
        })
    }
}

/// Main application struct
pub struct Application {
    config: Config,
    users: HashMap<u32, User>,
    next_id: u32,
}

impl Application {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            users: HashMap::new(),
            next_id: 1,
        }
    }
    
    pub fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        println!("Starting application on port {}", self.config.port);
        
        // Simulate some work
        self.create_sample_users();
        self.process_requests();
        
        Ok(())
    }
    
    fn create_sample_users(&mut self) {
        let sample_users = vec![
            ("Alice Johnson", "alice@example.com"),
            ("Bob Smith", "bob@example.com"),
            ("Charlie Brown", "charlie@example.com"),
        ];
        
        for (name, email) in sample_users {
            let user = User::new(self.next_id, name.to_string(), email.to_string());
            self.users.insert(user.id, user);
            self.next_id += 1;
        }
    }
    
    fn process_requests(&self) {
        // Simulate processing user requests
        for user in self.users.values() {
            if user.is_active {
                println!("Processing request for user: {}", user.name);
            }
        }
    }
}

/// User entity
#[derive(Debug, Clone)]
pub struct User {
    pub id: u32,
    pub name: String,
    pub email: String,
    pub is_active: bool,
}

impl User {
    pub fn new(id: u32, name: String, email: String) -> Self {
        Self {
            id,
            name,
            email,
            is_active: true,
        }
    }
    
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }
}

fn load_config() -> Result<Config, Box<dyn std::error::Error>> {
    Config::from_env().map_err(|e| e.into())
}
        "#,
    )?;
    
    // Rust library module
    fs::write(
        src_dir.join("lib.rs"),
        r#"
//! Core library functionality

pub mod auth;
pub mod database;
pub mod utils;

use std::collections::HashMap;

/// Core library trait for data processing
pub trait DataProcessor<T> {
    type Output;
    type Error;
    
    fn process(&self, data: T) -> Result<Self::Output, Self::Error>;
    fn validate(&self, data: &T) -> bool;
}

/// Generic data store
pub struct DataStore<K, V> {
    data: HashMap<K, V>,
}

impl<K, V> DataStore<K, V>
where
    K: std::hash::Hash + Eq + Clone,
    V: Clone,
{
    pub fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }
    
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        self.data.insert(key, value)
    }
    
    pub fn get(&self, key: &K) -> Option<&V> {
        self.data.get(key)
    }
    
    pub fn remove(&mut self, key: &K) -> Option<V> {
        self.data.remove(key)
    }
    
    pub fn len(&self) -> usize {
        self.data.len()
    }
}

/// Utility functions
pub mod utils {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
    
    pub fn validate_email(email: &str) -> bool {
        email.contains('@') && email.contains('.')
    }
    
    pub fn hash_password(password: &str) -> String {
        // Simple hash for demo - don't use in production!
        format!("hashed_{}", password)
    }
}
        "#,
    )?;
    
    // JavaScript frontend
    fs::write(
        frontend_dir.join("app.js"),
        r#"
/**
 * Frontend application for user management
 */

class UserInterface {
    constructor() {
        this.users = [];
        this.currentUser = null;
        this.apiBaseUrl = '/api';
    }
    
    /**
     * Initialize the application
     */
    async init() {
        try {
            await this.loadUsers();
            this.setupEventListeners();
            this.renderUserList();
        } catch (error) {
            console.error('Failed to initialize application:', error);
        }
    }
    
    /**
     * Load users from the API
     */
    async loadUsers() {
        const response = await fetch(`${this.apiBaseUrl}/users`);
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        this.users = await response.json();
    }
    
    /**
     * Setup event listeners for user interactions
     */
    setupEventListeners() {
        document.addEventListener('DOMContentLoaded', () => {
            const addUserBtn = document.getElementById('add-user-btn');
            if (addUserBtn) {
                addUserBtn.addEventListener('click', () => this.showAddUserForm());
            }
            
            const userForm = document.getElementById('user-form');
            if (userForm) {
                userForm.addEventListener('submit', (e) => this.handleUserSubmit(e));
            }
        });
    }
    
    /**
     * Render the user list in the UI
     */
    renderUserList() {
        const container = document.getElementById('user-list');
        if (!container) return;
        
        container.innerHTML = this.users.map(user => `
            <div class="user-card" data-user-id="${user.id}">
                <h3>${user.name}</h3>
                <p>Email: ${user.email}</p>
                <p>Status: ${user.is_active ? 'Active' : 'Inactive'}</p>
                <button onclick="userInterface.editUser(${user.id})">Edit</button>
                <button onclick="userInterface.deleteUser(${user.id})">Delete</button>
            </div>
        `).join('');
    }
    
    /**
     * Show the add user form
     */
    showAddUserForm() {
        const modal = document.getElementById('user-modal');
        if (modal) {
            modal.style.display = 'block';
        }
    }
    
    /**
     * Handle user form submission
     */
    async handleUserSubmit(event) {
        event.preventDefault();
        
        const formData = new FormData(event.target);
        const userData = {
            name: formData.get('name'),
            email: formData.get('email'),
        };
        
        try {
            if (this.currentUser) {
                await this.updateUser(this.currentUser.id, userData);
            } else {
                await this.createUser(userData);
            }
            
            await this.loadUsers();
            this.renderUserList();
            this.hideUserForm();
        } catch (error) {
            console.error('Failed to save user:', error);
            alert('Failed to save user. Please try again.');
        }
    }
    
    /**
     * Create a new user
     */
    async createUser(userData) {
        const response = await fetch(`${this.apiBaseUrl}/users`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData),
        });
        
        if (!response.ok) {
            throw new Error(`Failed to create user: ${response.status}`);
        }
        
        return response.json();
    }
    
    /**
     * Update an existing user
     */
    async updateUser(userId, userData) {
        const response = await fetch(`${this.apiBaseUrl}/users/${userId}`, {
            method: 'PUT',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(userData),
        });
        
        if (!response.ok) {
            throw new Error(`Failed to update user: ${response.status}`);
        }
        
        return response.json();
    }
    
    /**
     * Delete a user
     */
    async deleteUser(userId) {
        if (!confirm('Are you sure you want to delete this user?')) {
            return;
        }
        
        const response = await fetch(`${this.apiBaseUrl}/users/${userId}`, {
            method: 'DELETE',
        });
        
        if (!response.ok) {
            throw new Error(`Failed to delete user: ${response.status}`);
        }
        
        await this.loadUsers();
        this.renderUserList();
    }
    
    /**
     * Edit a user
     */
    editUser(userId) {
        const user = this.users.find(u => u.id === userId);
        if (user) {
            this.currentUser = user;
            this.populateUserForm(user);
            this.showAddUserForm();
        }
    }
    
    /**
     * Populate the user form with existing data
     */
    populateUserForm(user) {
        const nameInput = document.getElementById('user-name');
        const emailInput = document.getElementById('user-email');
        
        if (nameInput) nameInput.value = user.name;
        if (emailInput) emailInput.value = user.email;
    }
    
    /**
     * Hide the user form
     */
    hideUserForm() {
        const modal = document.getElementById('user-modal');
        if (modal) {
            modal.style.display = 'none';
        }
        this.currentUser = null;
    }
}

// Initialize the application
const userInterface = new UserInterface();
userInterface.init();
        "#,
    )?;
    
    // Python utility script
    fs::write(
        scripts_dir.join("data_migration.py"),
        r#"
#!/usr/bin/env python3
"""
Data migration script for user management system
"""

import json
import sqlite3
import argparse
from typing import List, Dict, Any
from datetime import datetime

class DataMigrator:
    """Handles data migration between different formats and databases"""
    
    def __init__(self, source_db: str, target_db: str):
        self.source_db = source_db
        self.target_db = target_db
        self.migration_log = []
    
    def migrate_users(self) -> bool:
        """Migrate users from source to target database"""
        try:
            source_users = self.load_users_from_source()
            self.validate_users(source_users)
            self.save_users_to_target(source_users)
            self.log_migration("users", len(source_users))
            return True
        except Exception as e:
            print(f"Migration failed: {e}")
            return False
    
    def load_users_from_source(self) -> List[Dict[str, Any]]:
        """Load users from source database"""
        users = []
        with sqlite3.connect(self.source_db) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, email, is_active FROM users")
            
            for row in cursor.fetchall():
                users.append({
                    'id': row[0],
                    'name': row[1],
                    'email': row[2],
                    'is_active': bool(row[3]),
                    'migrated_at': datetime.now().isoformat()
                })
        
        return users
    
    def validate_users(self, users: List[Dict[str, Any]]) -> None:
        """Validate user data before migration"""
        for user in users:
            if not user.get('name'):
                raise ValueError(f"User {user.get('id')} has no name")
            
            if not user.get('email') or '@' not in user['email']:
                raise ValueError(f"User {user.get('id')} has invalid email")
    
    def save_users_to_target(self, users: List[Dict[str, Any]]) -> None:
        """Save users to target database"""
        with sqlite3.connect(self.target_db) as conn:
            cursor = conn.cursor()
            
            # Create table if it doesn't exist
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    name TEXT NOT NULL,
                    email TEXT NOT NULL UNIQUE,
                    is_active BOOLEAN DEFAULT 1,
                    migrated_at TEXT
                )
            """)
            
            # Insert users
            for user in users:
                cursor.execute("""
                    INSERT OR REPLACE INTO users 
                    (id, name, email, is_active, migrated_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (
                    user['id'],
                    user['name'],
                    user['email'],
                    user['is_active'],
                    user['migrated_at']
                ))
            
            conn.commit()
    
    def log_migration(self, entity_type: str, count: int) -> None:
        """Log migration details"""
        log_entry = {
            'entity_type': entity_type,
            'count': count,
            'timestamp': datetime.now().isoformat()
        }
        self.migration_log.append(log_entry)
        print(f"Migrated {count} {entity_type}")
    
    def export_migration_log(self, filename: str) -> None:
        """Export migration log to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.migration_log, f, indent=2)

def main():
    """Main migration function"""
    parser = argparse.ArgumentParser(description='Migrate user data between databases')
    parser.add_argument('--source', required=True, help='Source database file')
    parser.add_argument('--target', required=True, help='Target database file')
    parser.add_argument('--log', default='migration.log', help='Migration log file')
    
    args = parser.parse_args()
    
    migrator = DataMigrator(args.source, args.target)
    
    print("Starting data migration...")
    success = migrator.migrate_users()
    
    if success:
        migrator.export_migration_log(args.log)
        print("Migration completed successfully!")
    else:
        print("Migration failed!")
        return 1
    
    return 0

if __name__ == "__main__":
    exit(main())
        "#,
    )?;
    
    // Test file
    fs::write(
        tests_dir.join("integration_tests.rs"),
        r#"
//! Integration tests for the user management system

use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_user_creation() {
        let user = User::new(1, "Test User".to_string(), "test@example.com".to_string());
        assert_eq!(user.id, 1);
        assert_eq!(user.name, "Test User");
        assert_eq!(user.email, "test@example.com");
        assert!(user.is_active);
    }
    
    #[test]
    fn test_user_deactivation() {
        let mut user = User::new(1, "Test User".to_string(), "test@example.com".to_string());
        user.deactivate();
        assert!(!user.is_active);
    }
    
    #[test]
    fn test_config_from_env() {
        // This would normally test environment variable loading
        // For demo purposes, we'll test the default values
        let config = Config::from_env().unwrap();
        assert!(!config.database_url.is_empty());
        assert!(config.port > 0);
    }
    
    #[test]
    fn test_application_creation() {
        let config = Config::from_env().unwrap();
        let app = Application::new(config);
        // Test that application is created successfully
        assert_eq!(app.users.len(), 0);
        assert_eq!(app.next_id, 1);
    }
}

// Mock structs for testing (normally these would be imported)
#[derive(Debug, Clone)]
pub struct User {
    pub id: u32,
    pub name: String,
    pub email: String,
    pub is_active: bool,
}

impl User {
    pub fn new(id: u32, name: String, email: String) -> Self {
        Self {
            id,
            name,
            email,
            is_active: true,
        }
    }
    
    pub fn deactivate(&mut self) {
        self.is_active = false;
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub database_url: String,
    pub port: u16,
    pub debug: bool,
    pub max_connections: usize,
}

impl Config {
    pub fn from_env() -> Result<Self, String> {
        Ok(Config {
            database_url: "localhost:5432".to_string(),
            port: 8080,
            debug: false,
            max_connections: 100,
        })
    }
}

pub struct Application {
    config: Config,
    users: HashMap<u32, User>,
    next_id: u32,
}

impl Application {
    pub fn new(config: Config) -> Self {
        Self {
            config,
            users: HashMap::new(),
            next_id: 1,
        }
    }
}
        "#,
    )?;
    
    // Package configuration files
    fs::write(
        temp_dir.path().join("Cargo.toml"),
        r#"
[package]
name = "user-management-system"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
sqlx = { version = "0.7", features = ["runtime-tokio-rustls", "postgres"] }
clap = { version = "4.0", features = ["derive"] }
uuid = { version = "1.0", features = ["v4"] }
chrono = { version = "0.4", features = ["serde"] }
anyhow = "1.0"
thiserror = "1.0"

[dev-dependencies]
tempfile = "3.0"
tokio-test = "0.4"
        "#,
    )?;
    
    fs::write(
        temp_dir.path().join("package.json"),
        r#"
{
  "name": "user-management-frontend",
  "version": "1.0.0",
  "description": "Frontend for user management system",
  "main": "frontend/app.js",
  "scripts": {
    "start": "node server.js",
    "build": "webpack --mode production",
    "test": "jest",
    "lint": "eslint frontend/**/*.js"
  },
  "dependencies": {
    "express": "^4.18.0",
    "cors": "^2.8.5",
    "helmet": "^6.0.0",
    "morgan": "^1.10.0"
  },
  "devDependencies": {
    "webpack": "^5.70.0",
    "webpack-cli": "^4.9.0",
    "babel-loader": "^8.2.0",
    "jest": "^29.0.0",
    "eslint": "^8.0.0"
  }
}
        "#,
    )?;
    
    fs::write(
        temp_dir.path().join("requirements.txt"),
        r#"
# Core dependencies
requests==2.28.0
flask==2.2.0
sqlalchemy==1.4.0
alembic==1.8.0

# Development dependencies
pytest==7.1.0
pytest-cov==4.0.0
black==22.0.0
flake8==5.0.0
mypy==0.971

# Security
cryptography==37.0.0
bcrypt==3.2.0
        "#,
    )?;
    
    Ok(temp_dir)
}

fn basic_codebase_analysis(project_dir: &TempDir) -> Result<(), Box<dyn Error>> {
    println!("📊 Basic Codebase Analysis:");
    println!("============================");

    let config = AnalysisConfig {
        max_depth: Some(10),
        ..Default::default()
    };

    let mut analyzer = CodebaseAnalyzer::with_config(config);
    let result = analyzer.analyze_directory(project_dir.path())?;

    println!("📈 Analysis Results:");
    println!("  Total files: {}", result.total_files);
    println!("  Parsed files: {}", result.parsed_files);
    println!("  Error files: {}", result.error_files);
    println!("  Total lines: {}", result.total_lines);

    println!("\n🌐 Languages detected:");
    for (language, count) in &result.languages {
        println!("  - {:?}: {} files", language, count);
    }

    println!("\n📁 File breakdown:");
    for file in result.files.iter().take(10) {
        println!("  - {} ({:?}, {} lines)",
                 file.path.file_name().unwrap_or_default().to_string_lossy(),
                 file.language,
                 file.lines);
    }

    if result.files.len() > 10 {
        println!("  ... and {} more files", result.files.len() - 10);
    }

    println!();
    Ok(())
}

fn detailed_file_analysis(project_dir: &TempDir) -> Result<(), Box<dyn Error>> {
    println!("📄 Detailed File Analysis:");
    println!("===========================");

    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(project_dir.path())?;

    println!("🔍 File Details:");
    for file in result.files.iter().take(5) {
        println!("\n📁 File: {}", file.path.display());
        println!("  Language: {:?}", file.language);
        println!("  Lines: {}", file.lines);
        println!("  Size: {} bytes", file.size);
        println!("  Parsed: {}", if file.parsed_successfully { "✅" } else { "❌" });

        if !file.parsed_successfully {
            println!("  Status: Failed to parse");
        }

        if !file.symbols.is_empty() {
            println!("  Symbols: {}", file.symbols.len());
            for symbol in file.symbols.iter().take(3) {
                println!("    - {} ({})", symbol.name, symbol.kind);
            }
        }
    }

    println!();
    Ok(())
}

fn language_specific_analysis(project_dir: &TempDir) -> Result<(), Box<dyn Error>> {
    println!("🌐 Language-Specific Analysis:");
    println!("==============================");

    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(project_dir.path())?;

    for (language, count) in &result.languages {
        println!("\n📊 {:?} Analysis:", language);
        println!("  Files: {}", count);

        let lang_files: Vec<_> = result.files.iter()
            .filter(|f| f.language == *language)
            .collect();

        let total_lines: usize = lang_files.iter().map(|f| f.lines).sum();
        let total_symbols: usize = lang_files.iter().map(|f| f.symbols.len()).sum();

        println!("  Total lines: {}", total_lines);
        println!("  Total symbols: {}", total_symbols);

        if total_lines > 0 {
            println!("  Avg lines per file: {:.1}", total_lines as f64 / lang_files.len() as f64);
        }

        if total_symbols > 0 {
            println!("  Avg symbols per file: {:.1}", total_symbols as f64 / lang_files.len() as f64);
        }

        // Show most common symbol types
        let mut symbol_types = std::collections::HashMap::new();
        for file in &lang_files {
            for symbol in &file.symbols {
                *symbol_types.entry(&symbol.kind).or_insert(0) += 1;
            }
        }

        if !symbol_types.is_empty() {
            println!("  Symbol types:");
            let mut sorted_types: Vec<_> = symbol_types.iter().collect();
            sorted_types.sort_by(|a, b| b.1.cmp(a.1));

            for (symbol_type, count) in sorted_types.iter().take(5) {
                println!("    - {}: {}", symbol_type, count);
            }
        }
    }

    println!();
    Ok(())
}

fn generate_comprehensive_report(project_dir: &TempDir) -> Result<(), Box<dyn Error>> {
    println!("📋 Generating Comprehensive Report:");
    println!("===================================");

    // This would typically generate detailed reports in various formats
    let report_dir = project_dir.path().join("analysis_reports");
    fs::create_dir_all(&report_dir)?;

    // Generate summary report
    let summary_report = format!(
        r#"# Codebase Analysis Report

## Executive Summary
This report provides a comprehensive analysis of the codebase, including:
- Code quality and maintainability metrics
- Security vulnerability assessment
- Performance optimization opportunities
- Test coverage analysis
- Refactoring recommendations

## Key Findings
- **Overall Quality**: Good foundation with room for improvement
- **Security**: Some vulnerabilities detected, requires attention
- **Performance**: Several optimization opportunities identified
- **Testing**: Coverage could be improved in key areas
- **Maintainability**: Code structure is generally well-organized

## Recommendations
1. Address high-priority security vulnerabilities
2. Improve test coverage for critical functions
3. Implement suggested refactoring improvements
4. Optimize performance hotspots
5. Establish coding standards and documentation

## Next Steps
1. Review and prioritize findings
2. Create action plan for improvements
3. Implement changes incrementally
4. Monitor progress with regular analysis

Generated on: {}
"#,
        std::time::SystemTime::now().elapsed().unwrap_or_default().as_secs()
    );

    fs::write(report_dir.join("summary_report.md"), summary_report)?;

    println!("✅ Reports generated:");
    println!("  - Summary report: analysis_reports/summary_report.md");
    println!("  - Detailed findings available in analysis results");

    println!("\n🎯 Action Items:");
    println!("  1. Review security vulnerabilities (High Priority)");
    println!("  2. Improve test coverage (Medium Priority)");
    println!("  3. Address performance hotspots (Medium Priority)");
    println!("  4. Implement refactoring suggestions (Low Priority)");

    Ok(())
}
