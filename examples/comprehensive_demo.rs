//! Comprehensive demonstration of the rust-treesitter library improvements
//!
//! This example showcases:
//! 1. Complete module functionality (enhanced_security, infrastructure, intent_mapping)
//! 2. Enhanced error handling with detailed context
//! 3. Comprehensive documentation and usage examples

use rust_tree_sitter::{
    CodeAnalyzer, AnalysisConfig, AnalysisDepth,
    Error, Result,
    intent_mapping::{
        IntentMappingSystem, Requirement, Implementation, RequirementType, 
        ImplementationType, Priority, RequirementStatus, ImplementationStatus,
        MappingConfig, MappingType
    },
};

#[cfg(any(feature = "net", feature = "db"))]
use rust_tree_sitter::{
    enhanced_security::{EnhancedSecurityScanner, EnhancedSecurityConfig},
    infrastructure::ConfigurationManager,
};

use std::path::PathBuf;

fn main() -> Result<()> {
    println!("🚀 Comprehensive Rust Tree-sitter Library Demo");
    println!("===============================================");
    
    // Demonstrate enhanced error handling
    demonstrate_error_handling()?;
    
    // Demonstrate completed intent mapping system
    demonstrate_intent_mapping()?;
    
    // Demonstrate enhanced security (if features enabled)
    #[cfg(any(feature = "net", feature = "db"))]
    demonstrate_enhanced_security()?;
    
    // Demonstrate comprehensive code analysis
    demonstrate_code_analysis()?;
    
    println!("\n✅ All demonstrations completed successfully!");
    Ok(())
}

/// Demonstrate the enhanced error handling system
fn demonstrate_error_handling() -> Result<()> {
    println!("\n📋 1. Enhanced Error Handling Demonstration");
    println!("==========================================");
    
    // Demonstrate different error types with context
    let errors = vec![
        Error::config_error_with_context(
            "Invalid configuration value",
            Some(PathBuf::from("config.yaml")),
            Some("ai.max_tokens".to_string())
        ),
        Error::network_error_with_details(
            "Connection timeout",
            Some("https://api.openai.com".to_string()),
            Some(408)
        ),
        Error::auth_error_with_provider(
            "Invalid API key",
            "OpenAI"
        ),
        Error::rate_limit_error_with_retry(
            "API rate limit exceeded",
            60
        ),
        Error::timeout_error("AI analysis", 30000),
        Error::resource_exhausted_with_details(
            "memory",
            "Analysis requires too much memory",
            Some("2.5GB".to_string()),
            Some("2GB".to_string())
        ),
        Error::validation_error_with_context(
            "Invalid file extension",
            Some("file_type".to_string()),
            Some(".rs, .py, .js".to_string()),
            Some(".txt".to_string())
        ),
        Error::dependency_error_with_versions(
            "tree-sitter",
            "Version mismatch",
            Some(">=0.20.0".to_string()),
            Some("0.19.5".to_string())
        ),
        Error::security_error_with_details(
            "Potential SQL injection vulnerability",
            Some("SQL_INJECTION".to_string()),
            Some("HIGH".to_string()),
            Some(PathBuf::from("src/database.rs")),
            Some(42)
        ),
        Error::analysis_error_with_context(
            "parser",
            "Failed to parse syntax tree",
            Some(PathBuf::from("src/malformed.rs")),
            Some("Unexpected token at position 156".to_string())
        ),
    ];
    
    for (i, error) in errors.iter().enumerate() {
        println!("  {}. {}", i + 1, error);
    }
    
    println!("✅ Error handling demonstration complete");
    Ok(())
}

/// Demonstrate the completed intent mapping system
fn demonstrate_intent_mapping() -> Result<()> {
    println!("\n🎯 2. Intent Mapping System Demonstration");
    println!("========================================");
    
    let mut mapping_system = IntentMappingSystem::new();
    
    // Add sample requirements
    let requirements = vec![
        Requirement {
            id: "REQ-001".to_string(),
            description: "User authentication system".to_string(),
            requirement_type: RequirementType::Security,
            priority: Priority::Critical,
            status: RequirementStatus::Approved,
        },
        Requirement {
            id: "REQ-002".to_string(),
            description: "Data validation and sanitization".to_string(),
            requirement_type: RequirementType::Security,
            priority: Priority::High,
            status: RequirementStatus::Approved,
        },
        Requirement {
            id: "REQ-003".to_string(),
            description: "Performance monitoring dashboard".to_string(),
            requirement_type: RequirementType::Performance,
            priority: Priority::Medium,
            status: RequirementStatus::Draft,
        },
    ];
    
    for req in requirements {
        mapping_system.add_requirement(req)?;
    }
    
    // Add sample implementations
    let implementations = vec![
        Implementation {
            id: "IMPL-001".to_string(),
            description: "JWT authentication middleware".to_string(),
            implementation_type: ImplementationType::Function,
            file_path: "src/auth.rs".to_string(),
            line_range: Some((10, 50)),
            status: ImplementationStatus::Complete,
        },
        Implementation {
            id: "IMPL-002".to_string(),
            description: "Input validation functions".to_string(),
            implementation_type: ImplementationType::Module,
            file_path: "src/validation.rs".to_string(),
            line_range: Some((1, 200)),
            status: ImplementationStatus::Complete,
        },
        Implementation {
            id: "IMPL-003".to_string(),
            description: "Metrics collection service".to_string(),
            implementation_type: ImplementationType::Class,
            file_path: "src/metrics.rs".to_string(),
            line_range: Some((20, 150)),
            status: ImplementationStatus::InProgress,
        },
    ];
    
    for impl_item in implementations {
        mapping_system.add_implementation(impl_item)?;
    }
    
    // Create mappings
    mapping_system.create_mapping(
        "REQ-001".to_string(),
        "IMPL-001".to_string(),
        MappingType::Direct,
    )?;
    
    mapping_system.create_mapping(
        "REQ-002".to_string(),
        "IMPL-002".to_string(),
        MappingType::Direct,
    )?;
    
    mapping_system.create_mapping(
        "REQ-003".to_string(),
        "IMPL-003".to_string(),
        MappingType::Partial,
    )?;
    
    // Auto-discover additional mappings
    let config = MappingConfig::default();
    let discovered = mapping_system.discover_mappings(&config)?;
    println!("  📊 Auto-discovered {} additional mappings", discovered);
    
    // Analyze mappings
    let analysis = mapping_system.analyze_mappings(&config)?;
    println!("  📈 Analysis Results:");
    println!("     Total requirements: {}", analysis.total_requirements);
    println!("     Total implementations: {}", analysis.total_implementations);
    println!("     Total mappings: {}", analysis.total_mappings);
    println!("     Coverage: {:.1}%", analysis.coverage_percentage);
    println!("     Quality score: {:.2}", analysis.quality_score);
    
    if !analysis.unmapped_requirements.is_empty() {
        println!("     Unmapped requirements: {:?}", analysis.unmapped_requirements);
    }
    
    if !analysis.unmapped_implementations.is_empty() {
        println!("     Unmapped implementations: {:?}", analysis.unmapped_implementations);
    }
    
    // Validate a mapping
    mapping_system.validate_mapping("REQ-001", "IMPL-001")?;
    println!("  ✅ Validated mapping REQ-001 -> IMPL-001");
    
    println!("✅ Intent mapping demonstration complete");
    Ok(())
}

/// Demonstrate enhanced security features (when available)
#[cfg(any(feature = "net", feature = "db"))]
fn demonstrate_enhanced_security() -> Result<()> {
    println!("\n🛡️  3. Enhanced Security Demonstration");
    println!("=====================================");
    
    // Create enhanced security scanner
    let config = EnhancedSecurityConfig::default();
    let scanner = EnhancedSecurityScanner::new(config);
    
    // Sample code with security issues
    let sample_code = r#"
        fn unsafe_function() {
            let password = "admin123"; // Hardcoded password
            let query = format!("SELECT * FROM users WHERE id = {}", user_id); // SQL injection
            println!("Password: {}", password); // Sensitive data logging
            std::process::Command::new("sh").arg("-c").arg(&user_input); // Command injection
        }
    "#;
    
    // Scan for vulnerabilities
    match scanner.scan_code(sample_code, "sample.rs") {
        Ok(results) => {
            println!("  🔍 Enhanced security scan results:");
            for result in results.vulnerabilities {
                println!("     🚨 {}: {} (Line: {})", 
                         result.severity, result.description, result.line);
                println!("        Recommendation: {}", result.recommendation);
            }
            println!("     Overall security score: {:.1}/10", results.security_score);
        }
        Err(e) => {
            println!("  ⚠️  Enhanced security scan failed: {}", e);
            println!("     (This is expected if infrastructure dependencies are not available)");
        }
    }
    
    println!("✅ Enhanced security demonstration complete");
    Ok(())
}

/// Demonstrate comprehensive code analysis
fn demonstrate_code_analysis() -> Result<()> {
    println!("\n📊 4. Comprehensive Code Analysis Demonstration");
    println!("==============================================");
    
    // Create analyzer with comprehensive configuration
    let config = AnalysisConfig {
        depth: AnalysisDepth::Full,
        max_depth: 10,
        include_tests: true,
        parallel_processing: true,
        file_extensions: vec!["rs".to_string()],
        exclude_patterns: vec!["target/".to_string()],
        max_file_size: Some(1024 * 1024), // 1MB
        enable_caching: true,
        cache_ttl_seconds: 3600,
        ..Default::default()
    };
    
    let analyzer = CodeAnalyzer::new(config);
    
    // Analyze the current file (this example)
    match analyzer.analyze_file("examples/comprehensive_demo.rs") {
        Ok(result) => {
            println!("  📁 Analysis of examples/comprehensive_demo.rs:");
            println!("     Functions: {}", result.symbols.functions.len());
            println!("     Structs: {}", result.symbols.structs.len());
            println!("     Imports: {}", result.symbols.imports.len());
            println!("     Lines of code: {}", result.metrics.lines_of_code);
            println!("     Complexity score: {:.2}", result.metrics.complexity_score);
            
            if !result.security_issues.is_empty() {
                println!("     Security issues: {}", result.security_issues.len());
                for issue in result.security_issues.iter().take(3) {
                    println!("       - {}", issue.description);
                }
            } else {
                println!("     ✅ No security issues found");
            }
        }
        Err(e) => {
            println!("  ⚠️  Analysis failed: {}", e);
            println!("     This might be expected if the file doesn't exist yet");
        }
    }
    
    println!("✅ Code analysis demonstration complete");
    Ok(())
}
