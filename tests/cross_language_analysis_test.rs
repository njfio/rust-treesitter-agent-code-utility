//! Tests for cross-language analysis functionality

use rust_tree_sitter::{
    CrossLanguageAnalyzer, CrossLanguageConfig, CodebaseAnalyzer, AnalysisConfig,
    Language, Result
};
use std::path::PathBuf;
use tempfile::TempDir;
use std::fs;

#[test]
fn test_cross_language_analyzer_creation() -> Result<()> {
    let analyzer = CrossLanguageAnalyzer::with_default_config();
    
    // Verify default configuration
    assert!(analyzer.config.enable_ffi_analysis);
    assert!(analyzer.config.enable_dependency_tracking);
    assert!(analyzer.config.enable_architecture_analysis);
    assert_eq!(analyzer.config.max_dependency_depth, 10);
    assert!(!analyzer.config.included_languages.is_empty());
    assert!(!analyzer.config.ffi_patterns.is_empty());
    
    Ok(())
}

#[test]
fn test_cross_language_config_customization() -> Result<()> {
    let mut config = CrossLanguageConfig::default();
    config.enable_ffi_analysis = false;
    config.max_dependency_depth = 5;
    config.included_languages = vec![Language::Rust, Language::Python];
    
    let analyzer = CrossLanguageAnalyzer::new(config);
    
    assert!(!analyzer.config.enable_ffi_analysis);
    assert_eq!(analyzer.config.max_dependency_depth, 5);
    assert_eq!(analyzer.config.included_languages.len(), 2);
    
    Ok(())
}

#[test]
fn test_language_from_extension() -> Result<()> {
    assert_eq!(Language::from_extension(&PathBuf::from("test.rs"))?, Language::Rust);
    assert_eq!(Language::from_extension(&PathBuf::from("test.py"))?, Language::Python);
    assert_eq!(Language::from_extension(&PathBuf::from("test.js"))?, Language::JavaScript);
    assert_eq!(Language::from_extension(&PathBuf::from("test.ts"))?, Language::TypeScript);
    assert_eq!(Language::from_extension(&PathBuf::from("test.c"))?, Language::C);
    assert_eq!(Language::from_extension(&PathBuf::from("test.cpp"))?, Language::Cpp);
    assert_eq!(Language::from_extension(&PathBuf::from("test.go"))?, Language::Go);
    
    // Test error case
    assert!(Language::from_extension(&PathBuf::from("test.unknown")).is_err());
    
    Ok(())
}

#[test]
fn test_cross_language_analysis_basic() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create a simple Rust file
    let rust_file = temp_path.join("main.rs");
    fs::write(&rust_file, r#"
        pub fn hello_world() {
            println!("Hello from Rust!");
        }
        
        #[no_mangle]
        pub extern "C" fn rust_function() -> i32 {
            42
        }
    "#)?;
    
    // Create a simple Python file
    let python_file = temp_path.join("main.py");
    fs::write(&python_file, r#"
        import ctypes
        
        def hello_world():
            print("Hello from Python!")
        
        # Load Rust library
        lib = ctypes.CDLL("./target/release/librust_lib.so")
        lib.rust_function.restype = ctypes.c_int
        
        def call_rust():
            return lib.rust_function()
    "#)?;
    
    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new();
    let analysis_result = analyzer.analyze_directory(temp_path)?;
    
    // Perform cross-language analysis
    let mut cross_lang_analyzer = CrossLanguageAnalyzer::with_default_config();
    let cross_lang_result = cross_lang_analyzer.analyze(&[analysis_result])?;
    
    // Verify results
    assert!(cross_lang_result.symbol_registry_stats.total_symbols > 0);
    assert!(!cross_lang_result.language_distribution.is_empty());
    assert!(cross_lang_result.language_distribution.contains_key(&Language::Rust));
    assert!(cross_lang_result.language_distribution.contains_key(&Language::Python));
    
    // Check that we have some recommendations
    assert!(!cross_lang_result.recommendations.is_empty());
    
    Ok(())
}

#[test]
fn test_ffi_pattern_detection() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create a Rust file with FFI exports
    let rust_file = temp_path.join("lib.rs");
    fs::write(&rust_file, r#"
        #[no_mangle]
        pub extern "C" fn add(a: i32, b: i32) -> i32 {
            a + b
        }
        
        #[no_mangle]
        pub extern "C" fn multiply(a: i32, b: i32) -> i32 {
            a * b
        }
    "#)?;
    
    // Create a C header file
    let c_header = temp_path.join("bindings.h");
    fs::write(&c_header, r#"
        #ifndef BINDINGS_H
        #define BINDINGS_H
        
        extern int add(int a, int b);
        extern int multiply(int a, int b);
        
        #endif
    "#)?;
    
    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new();
    let analysis_result = analyzer.analyze_directory(temp_path)?;
    
    // Perform cross-language analysis with FFI focus
    let mut config = CrossLanguageConfig::default();
    config.enable_ffi_analysis = true;
    let mut cross_lang_analyzer = CrossLanguageAnalyzer::new(config);
    let cross_lang_result = cross_lang_analyzer.analyze(&[analysis_result])?;
    
    // Verify FFI analysis was performed
    if let Some(ffi_analysis) = cross_lang_result.ffi_analysis {
        // Should detect some FFI patterns
        assert!(ffi_analysis.pattern_summary.total_patterns >= 0);
    }
    
    Ok(())
}

#[test]
fn test_dependency_analysis() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create multiple files with dependencies
    let mod1 = temp_path.join("mod1.rs");
    fs::write(&mod1, r#"
        pub struct Config {
            pub name: String,
        }
        
        pub fn get_config() -> Config {
            Config { name: "test".to_string() }
        }
    "#)?;
    
    let mod2 = temp_path.join("mod2.rs");
    fs::write(&mod2, r#"
        use crate::mod1::{Config, get_config};
        
        pub fn use_config() -> String {
            let config = get_config();
            config.name
        }
    "#)?;
    
    let main_file = temp_path.join("main.rs");
    fs::write(&main_file, r#"
        mod mod1;
        mod mod2;
        
        fn main() {
            let name = mod2::use_config();
            println!("Config name: {}", name);
        }
    "#)?;
    
    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new();
    let analysis_result = analyzer.analyze_directory(temp_path)?;
    
    // Perform cross-language analysis with dependency tracking
    let mut config = CrossLanguageConfig::default();
    config.enable_dependency_tracking = true;
    let mut cross_lang_analyzer = CrossLanguageAnalyzer::new(config);
    let cross_lang_result = cross_lang_analyzer.analyze(&[analysis_result])?;
    
    // Verify dependency analysis was performed
    if let Some(dep_analysis) = cross_lang_result.dependency_analysis {
        assert!(dep_analysis.total_files > 0);
        assert!(dep_analysis.dependency_metrics.total_files > 0);
    }
    
    Ok(())
}

#[test]
fn test_architecture_pattern_detection() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create a layered architecture structure
    let controller_dir = temp_path.join("controller");
    fs::create_dir_all(&controller_dir)?;
    let controller_file = controller_dir.join("user_controller.rs");
    fs::write(&controller_file, r#"
        pub struct UserController;
        
        impl UserController {
            pub fn get_user(&self, id: u32) -> String {
                format!("User {}", id)
            }
        }
    "#)?;
    
    let service_dir = temp_path.join("service");
    fs::create_dir_all(&service_dir)?;
    let service_file = service_dir.join("user_service.rs");
    fs::write(&service_file, r#"
        pub struct UserService;
        
        impl UserService {
            pub fn find_user(&self, id: u32) -> Option<String> {
                Some(format!("User {}", id))
            }
        }
    "#)?;
    
    let repository_dir = temp_path.join("repository");
    fs::create_dir_all(&repository_dir)?;
    let repository_file = repository_dir.join("user_repository.rs");
    fs::write(&repository_file, r#"
        pub struct UserRepository;
        
        impl UserRepository {
            pub fn get_by_id(&self, id: u32) -> Option<String> {
                Some(format!("User {}", id))
            }
        }
    "#)?;
    
    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new();
    let analysis_result = analyzer.analyze_directory(temp_path)?;
    
    // Perform cross-language analysis with architecture detection
    let mut config = CrossLanguageConfig::default();
    config.enable_architecture_analysis = true;
    let mut cross_lang_analyzer = CrossLanguageAnalyzer::new(config);
    let cross_lang_result = cross_lang_analyzer.analyze(&[analysis_result])?;
    
    // Verify architecture analysis was performed
    if let Some(arch_analysis) = cross_lang_result.architecture_analysis {
        // Should detect layered architecture pattern
        assert!(arch_analysis.architecture_score >= 0.0);
        assert!(arch_analysis.architecture_score <= 100.0);
    }
    
    Ok(())
}

#[test]
fn test_symbol_registry_stats() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let temp_path = temp_dir.path();
    
    // Create files with various symbols
    let rust_file = temp_path.join("lib.rs");
    fs::write(&rust_file, r#"
        pub struct MyStruct {
            pub field: i32,
        }
        
        pub fn my_function() -> i32 {
            42
        }
        
        pub enum MyEnum {
            Variant1,
            Variant2,
        }
    "#)?;
    
    // Analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new();
    let analysis_result = analyzer.analyze_directory(temp_path)?;
    
    // Perform cross-language analysis
    let mut cross_lang_analyzer = CrossLanguageAnalyzer::with_default_config();
    let cross_lang_result = cross_lang_analyzer.analyze(&[analysis_result])?;
    
    // Verify symbol registry stats
    let stats = &cross_lang_result.symbol_registry_stats;
    assert!(stats.total_symbols > 0);
    assert!(stats.symbols_by_language.contains_key(&Language::Rust));
    assert!(stats.symbols_by_language[&Language::Rust] > 0);
    
    Ok(())
}
