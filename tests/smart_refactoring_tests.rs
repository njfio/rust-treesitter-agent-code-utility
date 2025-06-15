//! Comprehensive tests for smart refactoring functionality
//!
//! Tests automated code improvements, refactoring suggestions, code smell detection,
//! and intelligent code transformations across multiple languages.

use rust_tree_sitter::*;
use rust_tree_sitter::smart_refactoring::{
    SmartRefactoringEngine, RefactoringConfig, RefactoringResult, RefactoringSuggestion,
    CodeSmell, RefactoringType, ImprovementCategory
};
use std::path::PathBuf;
use std::fs;
use tempfile::TempDir;

#[test]
fn test_refactoring_engine_creation() {
    let engine = SmartRefactoringEngine::new();
    // Test that the engine was created successfully
    // Note: We can't access internal config fields directly, so just test creation
    assert!(engine.config.code_smell_fixes);
    assert!(engine.config.pattern_recommendations);
}

#[test]
fn test_refactoring_engine_with_custom_config() {
    let config = RefactoringConfig {
        detect_code_smells: true,
        suggest_improvements: false,
        auto_apply_safe_refactorings: false,
        preserve_behavior: true,
        min_confidence_threshold: 0.8,
        max_suggestions_per_file: 10,
    };
    
    let engine = SmartRefactoringEngine::with_test_config(config);
    // Test that the engine was created successfully
    // Note: The internal config structure is different from the test config
    assert!(engine.config.code_smell_fixes);
    assert!(!engine.config.pattern_recommendations);
    assert_eq!(engine.config.min_confidence, 0.8);
    assert_eq!(engine.config.max_suggestions_per_category, 10);
}

#[test]
fn test_rust_code_smell_detection() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let rust_file = temp_dir.path().join("smelly_code.rs");
    
    let rust_content = r#"
// Long function with too many parameters
pub fn process_user_data(
    name: String,
    email: String,
    age: u32,
    address: String,
    phone: String,
    country: String,
    city: String,
    postal_code: String,
    emergency_contact: String,
    preferences: Vec<String>,
) -> Result<User, String> {
    // Very long function body
    if name.is_empty() {
        return Err("Name is empty".to_string());
    }
    if email.is_empty() {
        return Err("Email is empty".to_string());
    }
    if age > 150 {
        return Err("Invalid age".to_string());
    }
    if address.is_empty() {
        return Err("Address is empty".to_string());
    }
    if phone.is_empty() {
        return Err("Phone is empty".to_string());
    }
    if country.is_empty() {
        return Err("Country is empty".to_string());
    }
    if city.is_empty() {
        return Err("City is empty".to_string());
    }
    if postal_code.is_empty() {
        return Err("Postal code is empty".to_string());
    }
    if emergency_contact.is_empty() {
        return Err("Emergency contact is empty".to_string());
    }
    
    Ok(User {
        name,
        email,
        age,
        address,
        phone,
        country,
        city,
        postal_code,
        emergency_contact,
        preferences,
    })
}

// Duplicated code
pub fn validate_email_format(email: &str) -> bool {
    email.contains('@') && email.contains('.')
}

pub fn check_email_validity(email: &str) -> bool {
    email.contains('@') && email.contains('.')
}

// Large class with too many responsibilities
pub struct UserManager {
    users: Vec<User>,
    database_connection: String,
    cache: HashMap<String, User>,
    logger: Logger,
    email_service: EmailService,
    notification_service: NotificationService,
    analytics_service: AnalyticsService,
}

impl UserManager {
    // Method with too many nested conditions
    pub fn process_login(&self, username: &str, password: &str) -> Result<User, String> {
        if !username.is_empty() {
            if !password.is_empty() {
                if let Some(user) = self.find_user(username) {
                    if self.verify_password(&user, password) {
                        if user.is_active {
                            if !user.is_locked {
                                if user.email_verified {
                                    return Ok(user);
                                } else {
                                    return Err("Email not verified".to_string());
                                }
                            } else {
                                return Err("Account locked".to_string());
                            }
                        } else {
                            return Err("Account inactive".to_string());
                        }
                    } else {
                        return Err("Invalid password".to_string());
                    }
                } else {
                    return Err("User not found".to_string());
                }
            } else {
                return Err("Password is empty".to_string());
            }
        } else {
            return Err("Username is empty".to_string());
        }
    }
}

pub struct User {
    pub name: String,
    pub email: String,
    pub age: u32,
    pub address: String,
    pub phone: String,
    pub country: String,
    pub city: String,
    pub postal_code: String,
    pub emergency_contact: String,
    pub preferences: Vec<String>,
    pub is_active: bool,
    pub is_locked: bool,
    pub email_verified: bool,
}
    "#;
    
    fs::write(&rust_file, rust_content)?;
    
    let engine = SmartRefactoringEngine::new();
    let result = engine.analyze_file(&rust_file)?;
    
    // Should detect multiple code smells
    assert!(!result.code_smells.is_empty());
    
    // Should detect long parameter list
    let long_param_smell = result.code_smells.iter()
        .find(|smell| matches!(smell.smell_type, CodeSmell::LongParameterList));
    assert!(long_param_smell.is_some());
    
    // Should detect duplicated code
    let duplicate_smell = result.code_smells.iter()
        .find(|smell| matches!(smell.smell_type, CodeSmell::DuplicatedCode));
    assert!(duplicate_smell.is_some());
    
    // Should detect complex method
    let complex_method_smell = result.code_smells.iter()
        .find(|smell| matches!(smell.smell_type, CodeSmell::ComplexMethod));
    assert!(complex_method_smell.is_some());
    
    Ok(())
}

#[test]
fn test_javascript_refactoring_suggestions() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let js_file = temp_dir.path().join("legacy_code.js");
    
    let js_content = r#"
// Function that can be simplified
function calculateTotal(items) {
    var total = 0;
    for (var i = 0; i < items.length; i++) {
        total = total + items[i].price;
    }
    return total;
}

// Callback hell
function processUserData(userId, callback) {
    getUserById(userId, function(user) {
        if (user) {
            getPermissions(user.id, function(permissions) {
                if (permissions) {
                    getPreferences(user.id, function(preferences) {
                        if (preferences) {
                            callback(null, {
                                user: user,
                                permissions: permissions,
                                preferences: preferences
                            });
                        } else {
                            callback(new Error('Failed to get preferences'));
                        }
                    });
                } else {
                    callback(new Error('Failed to get permissions'));
                }
            });
        } else {
            callback(new Error('User not found'));
        }
    });
}

// Inefficient array operations
function filterAndTransform(data) {
    var filtered = [];
    for (var i = 0; i < data.length; i++) {
        if (data[i].active) {
            filtered.push(data[i]);
        }
    }
    
    var transformed = [];
    for (var j = 0; j < filtered.length; j++) {
        transformed.push({
            id: filtered[j].id,
            name: filtered[j].name.toUpperCase(),
            status: 'ACTIVE'
        });
    }
    
    return transformed;
}

// Magic numbers
function calculateDiscount(price, customerType) {
    if (customerType === 'premium') {
        return price * 0.15;
    } else if (customerType === 'gold') {
        return price * 0.10;
    } else if (customerType === 'silver') {
        return price * 0.05;
    } else {
        return 0;
    }
}
    "#;
    
    fs::write(&js_file, js_content)?;
    
    let engine = SmartRefactoringEngine::new();
    let result = engine.analyze_file(&js_file)?;
    
    // Should suggest refactoring improvements
    assert!(!result.suggestions.is_empty());
    
    // Should suggest modern JavaScript features
    let modern_js_suggestion = result.suggestions.iter()
        .find(|s| matches!(s.improvement_category, ImprovementCategory::ModernSyntax));
    assert!(modern_js_suggestion.is_some());
    
    // Should suggest performance improvements
    let performance_suggestion = result.suggestions.iter()
        .find(|s| matches!(s.improvement_category, ImprovementCategory::Performance));
    assert!(performance_suggestion.is_some());
    
    Ok(())
}

#[test]
fn test_python_refactoring_suggestions() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let py_file = temp_dir.path().join("legacy_python.py");
    
    let py_content = r#"
# Inefficient list comprehension
def process_numbers(numbers):
    result = []
    for num in numbers:
        if num > 0:
            result.append(num * 2)
    return result

# Long function with multiple responsibilities
def handle_user_registration(username, email, password, first_name, last_name, age, country):
    # Validation
    if not username:
        raise ValueError("Username is required")
    if not email:
        raise ValueError("Email is required")
    if not password:
        raise ValueError("Password is required")
    if len(password) < 8:
        raise ValueError("Password too short")
    if '@' not in email:
        raise ValueError("Invalid email")
    
    # Password hashing
    import hashlib
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    # Database operations
    user_data = {
        'username': username,
        'email': email,
        'password': hashed_password,
        'first_name': first_name,
        'last_name': last_name,
        'age': age,
        'country': country,
        'created_at': datetime.now(),
        'is_active': True
    }
    
    # Save to database
    database.save_user(user_data)
    
    # Send welcome email
    email_service.send_welcome_email(email, first_name)
    
    # Log registration
    logger.info(f"User {username} registered successfully")
    
    # Update analytics
    analytics.track_user_registration(username, country)
    
    return user_data

# Nested loops that can be optimized
def find_common_elements(list1, list2):
    common = []
    for item1 in list1:
        for item2 in list2:
            if item1 == item2 and item1 not in common:
                common.append(item1)
    return common

# Class with too many instance variables
class UserProfile:
    def __init__(self, user_id, username, email, first_name, last_name, 
                 age, country, city, postal_code, phone, address, 
                 emergency_contact, preferences, settings, permissions,
                 created_at, updated_at, last_login, login_count):
        self.user_id = user_id
        self.username = username
        self.email = email
        self.first_name = first_name
        self.last_name = last_name
        self.age = age
        self.country = country
        self.city = city
        self.postal_code = postal_code
        self.phone = phone
        self.address = address
        self.emergency_contact = emergency_contact
        self.preferences = preferences
        self.settings = settings
        self.permissions = permissions
        self.created_at = created_at
        self.updated_at = updated_at
        self.last_login = last_login
        self.login_count = login_count
    "#;
    
    fs::write(&py_file, py_content)?;
    
    let engine = SmartRefactoringEngine::new();
    let result = engine.analyze_file(&py_file)?;
    
    // Should detect code smells and suggest improvements
    assert!(!result.code_smells.is_empty());
    assert!(!result.suggestions.is_empty());
    
    // Should suggest Pythonic improvements
    let pythonic_suggestion = result.suggestions.iter()
        .find(|s| s.description.contains("list comprehension") || s.description.contains("pythonic"));
    assert!(pythonic_suggestion.is_some());
    
    Ok(())
}

#[test]
fn test_extract_method_refactoring() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let rust_file = temp_dir.path().join("long_method.rs");
    
    let rust_content = r#"
pub fn process_order(order: &Order) -> Result<ProcessedOrder, String> {
    // Validation section - can be extracted
    if order.items.is_empty() {
        return Err("Order has no items".to_string());
    }
    if order.customer_id.is_empty() {
        return Err("Customer ID is missing".to_string());
    }
    if order.shipping_address.is_empty() {
        return Err("Shipping address is missing".to_string());
    }
    
    // Calculation section - can be extracted
    let mut total = 0.0;
    let mut tax = 0.0;
    for item in &order.items {
        total += item.price * item.quantity as f64;
        tax += item.price * item.quantity as f64 * 0.08;
    }
    
    // Shipping calculation - can be extracted
    let shipping_cost = if total > 100.0 {
        0.0
    } else if total > 50.0 {
        5.0
    } else {
        10.0
    };
    
    // Final processing
    Ok(ProcessedOrder {
        order_id: order.id.clone(),
        subtotal: total,
        tax,
        shipping: shipping_cost,
        total: total + tax + shipping_cost,
    })
}
    "#;
    
    fs::write(&rust_file, rust_content)?;
    
    let engine = SmartRefactoringEngine::new();
    let result = engine.analyze_file(&rust_file)?;
    
    // Should suggest extract method refactoring
    let extract_method_suggestion = result.suggestions.iter()
        .find(|s| matches!(s.refactoring_type, RefactoringType::ExtractMethod));
    assert!(extract_method_suggestion.is_some());
    
    Ok(())
}

#[test]
fn test_rename_refactoring_suggestions() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let rust_file = temp_dir.path().join("poor_names.rs");
    
    let rust_content = r#"
pub fn calc(x: i32, y: i32) -> i32 {
    x + y
}

pub fn proc(data: &str) -> String {
    data.to_uppercase()
}

pub struct Mgr {
    pub items: Vec<String>,
}

impl Mgr {
    pub fn do_stuff(&self, thing: &str) -> bool {
        self.items.contains(&thing.to_string())
    }
}

pub fn handle(input: &[u8]) -> Vec<u8> {
    input.iter().map(|b| b.wrapping_add(1)).collect()
}
    "#;
    
    fs::write(&rust_file, rust_content)?;
    
    let engine = SmartRefactoringEngine::new();
    let result = engine.analyze_file(&rust_file)?;
    
    // Should suggest rename refactorings for poor names
    let rename_suggestions: Vec<_> = result.suggestions.iter()
        .filter(|s| matches!(s.refactoring_type, RefactoringType::Rename))
        .collect();
    assert!(!rename_suggestions.is_empty());
    
    Ok(())
}

#[test]
fn test_refactoring_confidence_scoring() -> Result<()> {
    let temp_dir = TempDir::new()?;
    let rust_file = temp_dir.path().join("simple_refactor.rs");
    
    let rust_content = r#"
pub fn add_numbers(a: i32, b: i32) -> i32 {
    return a + b;  // Unnecessary return statement
}

pub fn is_even(n: i32) -> bool {
    if n % 2 == 0 {
        return true;
    } else {
        return false;
    }
}
    "#;
    
    fs::write(&rust_file, rust_content)?;
    
    let engine = SmartRefactoringEngine::new();
    let result = engine.analyze_file(&rust_file)?;
    
    // Should have suggestions with confidence scores
    assert!(!result.suggestions.is_empty());
    
    for suggestion in &result.suggestions {
        assert!(suggestion.confidence >= 0.0);
        assert!(suggestion.confidence <= 1.0);
        assert!(!suggestion.description.is_empty());
        assert!(!suggestion.suggested_code.is_empty());
    }
    
    Ok(())
}

#[test]
fn test_directory_refactoring_analysis() -> Result<()> {
    let temp_dir = TempDir::new()?;
    
    // Create multiple files with different refactoring opportunities
    let file1 = temp_dir.path().join("file1.rs");
    fs::write(&file1, "pub fn calc(x: i32) -> i32 { return x * 2; }")?;
    
    let file2 = temp_dir.path().join("file2.rs");
    fs::write(&file2, r#"
pub fn long_function(a: i32, b: i32, c: i32, d: i32, e: i32) -> i32 {
    if a > 0 {
        if b > 0 {
            if c > 0 {
                if d > 0 {
                    if e > 0 {
                        return a + b + c + d + e;
                    }
                }
            }
        }
    }
    0
}
    "#)?;
    
    let engine = SmartRefactoringEngine::new();
    let result = engine.analyze_directory(temp_dir.path())?;
    
    // Should analyze multiple files
    assert!(!result.file_results.is_empty());
    assert!(result.overall_score >= 0.0);
    assert!(result.overall_score <= 100.0);
    
    // Should aggregate suggestions from all files
    let total_suggestions: usize = result.file_results.iter()
        .map(|fr| fr.suggestions.len())
        .sum();
    assert!(total_suggestions > 0);
    
    Ok(())
}
