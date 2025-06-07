// Phase 2 Demo File - Showcasing Advanced Intelligence Features
// This file contains various code patterns to demonstrate the new capabilities

use std::collections::HashMap;

// Example with potential security vulnerabilities
pub struct UserService {
    // Hardcoded API key (security issue)
    api_key: String,
    users: HashMap<String, User>,
}

pub struct User {
    pub id: String,
    pub name: String,
    pub email: String,
    password: String, // Should be hashed
}

impl UserService {
    pub fn new() -> Self {
        Self {
            // This is a security vulnerability - hardcoded secret
            api_key: "sk_live_1234567890abcdef".to_string(),
            users: HashMap::new(),
        }
    }
    
    // Long method that could be refactored (code smell)
    pub fn authenticate_user(&self, username: &str, password: &str) -> Result<User, String> {
        // Input validation missing (security issue)
        let user = self.users.get(username);
        
        match user {
            Some(u) => {
                // Weak password comparison (security issue)
                if u.password == password {
                    // TODO: Add proper logging
                    println!("User authenticated: {}", username);
                    Ok(u.clone())
                } else {
                    Err("Invalid credentials".to_string())
                }
            }
            None => {
                // Information disclosure (security issue)
                Err(format!("User {} not found", username))
            }
        }
    }
    
    // Performance issue - inefficient string concatenation
    pub fn generate_user_report(&self) -> String {
        let mut report = String::new();
        for (id, user) in &self.users {
            // String concatenation in loop (performance issue)
            report = report + &format!("User {}: {} ({})\n", id, user.name, user.email);
        }
        report
    }
    
    // Duplicate code pattern (code smell)
    pub fn create_admin_user(&self, name: String, email: String) -> User {
        User {
            id: format!("admin_{}", name),
            name: name.clone(),
            email: email.clone(),
            password: "admin123".to_string(), // Hardcoded password (security issue)
        }
    }
    
    // More duplicate code (code smell)
    pub fn create_regular_user(&self, name: String, email: String) -> User {
        User {
            id: format!("user_{}", name),
            name: name.clone(),
            email: email.clone(),
            password: "user123".to_string(), // Hardcoded password (security issue)
        }
    }
    
    // Potential SQL injection vulnerability
    pub fn find_user_by_query(&self, query: &str) -> Vec<User> {
        // This would be vulnerable if it was actual SQL
        let sql = format!("SELECT * FROM users WHERE name = '{}'", query);
        println!("Executing query: {}", sql);
        
        // Simplified implementation
        self.users.values().cloned().collect()
    }
    
    // Weak cryptographic function usage
    pub fn hash_password(&self, password: &str) -> String {
        // MD5 is cryptographically weak (security issue)
        format!("md5({})", password)
    }
}

// Factory pattern opportunity
pub struct UserFactory;

impl UserFactory {
    pub fn create_user(user_type: &str, name: String, email: String) -> User {
        match user_type {
            "admin" => User {
                id: format!("admin_{}", name),
                name,
                email,
                password: "admin123".to_string(),
            },
            "regular" => User {
                id: format!("user_{}", name),
                name,
                email,
                password: "user123".to_string(),
            },
            _ => panic!("Unknown user type"), // Poor error handling
        }
    }
}

// Observer pattern opportunity
pub trait UserEventListener {
    fn on_user_created(&self, user: &User);
    fn on_user_deleted(&self, user_id: &str);
}

pub struct UserEventManager {
    listeners: Vec<Box<dyn UserEventListener>>,
}

impl UserEventManager {
    pub fn new() -> Self {
        Self {
            listeners: Vec::new(),
        }
    }
    
    pub fn add_listener(&mut self, listener: Box<dyn UserEventListener>) {
        self.listeners.push(listener);
    }
    
    pub fn notify_user_created(&self, user: &User) {
        for listener in &self.listeners {
            listener.on_user_created(user);
        }
    }
}

// Modernization opportunity - old-style error handling
pub fn process_user_data(data: &str) -> String {
    let parsed = data.parse::<i32>().unwrap(); // Should use expect() or proper error handling
    format!("Processed: {}", parsed)
}

// Performance optimization opportunity - vector without capacity
pub fn collect_user_ids(users: &[User]) -> Vec<String> {
    let mut ids = Vec::new(); // Should use with_capacity
    for user in users {
        ids.push(user.id.clone());
    }
    ids
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_user_creation() {
        let service = UserService::new();
        assert_eq!(service.users.len(), 0);
    }
    
    // TODO: Add more comprehensive tests
    // FIXME: Test coverage is insufficient
}
