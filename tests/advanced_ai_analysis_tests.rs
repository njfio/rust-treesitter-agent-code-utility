//! Comprehensive tests for Advanced AI Code Explanations
//!
//! Tests the deep semantic understanding, architecture pattern recognition,
//! and intelligent code analysis capabilities.

use rust_tree_sitter::*;
use rust_tree_sitter::advanced_ai_analysis::{PatternType, AbstractionType};
use std::path::PathBuf;

#[test]
fn test_advanced_ai_analyzer_creation() {
    let analyzer = AdvancedAIAnalyzer::new();
    assert!(analyzer.config.semantic_analysis);
    assert!(analyzer.config.pattern_recognition);
    assert!(analyzer.config.quality_assessment);
}

#[test]
fn test_advanced_ai_analyzer_with_custom_config() {
    let config = AdvancedAIConfig {
        semantic_analysis: true,
        pattern_recognition: false,
        quality_assessment: true,
        learning_recommendations: false,
        relationship_analysis: true,
        documentation_generation: false,
        min_confidence: 0.7,
    };
    
    let analyzer = AdvancedAIAnalyzer::with_config(config.clone());
    assert_eq!(analyzer.config.semantic_analysis, config.semantic_analysis);
    assert_eq!(analyzer.config.pattern_recognition, config.pattern_recognition);
    assert_eq!(analyzer.config.min_confidence, config.min_confidence);
}

#[test]
fn test_semantic_analysis_with_rust_code() -> Result<()> {
    let analyzer = AdvancedAIAnalyzer::new();
    
    // Create a mock analysis result with Rust code
    let analysis_result = create_mock_rust_analysis_result();
    
    let ai_result = analyzer.analyze(&analysis_result)?;
    
    // Verify semantic analysis results
    assert!(ai_result.intelligence_score > 0);
    assert!(!ai_result.semantic_analysis.concepts.is_empty());
    assert!(!ai_result.semantic_analysis.abstractions.is_empty());
    
    // Check for system programming domain insight
    let has_system_insight = ai_result.semantic_analysis.domain_insights
        .iter()
        .any(|insight| insight.domain == "System Programming");
    assert!(has_system_insight);
    
    Ok(())
}

#[test]
fn test_architecture_pattern_detection_mvc() -> Result<()> {
    let analyzer = AdvancedAIAnalyzer::new();
    
    // Create a mock analysis result with MVC structure
    let analysis_result = create_mock_mvc_analysis_result();
    
    let ai_result = analyzer.analyze(&analysis_result)?;
    
    // Verify MVC pattern detection
    let mvc_pattern = ai_result.architecture_patterns
        .iter()
        .find(|p| matches!(p.pattern_type, PatternType::MVC));
    
    assert!(mvc_pattern.is_some());
    let mvc = mvc_pattern.unwrap();
    assert_eq!(mvc.name, "Model-View-Controller (MVC)");
    assert!(mvc.confidence > 0.8);
    assert_eq!(mvc.components.len(), 3);
    
    Ok(())
}

#[test]
fn test_code_quality_assessment() -> Result<()> {
    let analyzer = AdvancedAIAnalyzer::new();
    let analysis_result = create_mock_complex_analysis_result();
    
    let ai_result = analyzer.analyze(&analysis_result)?;
    
    // Verify quality assessment
    let quality = &ai_result.quality_assessment;
    assert!(quality.overall_score > 0);
    assert!(quality.maintainability.maintainability_index > 0.0);
    assert!(quality.readability.readability_score > 0.0);
    assert!(quality.design_quality.solid_adherence > 0.0);
    
    Ok(())
}

#[test]
fn test_learning_path_generation() -> Result<()> {
    let analyzer = AdvancedAIAnalyzer::new();
    let analysis_result = create_mock_beginner_analysis_result();
    
    let ai_result = analyzer.analyze(&analysis_result)?;
    
    // Verify learning paths are generated
    assert!(!ai_result.learning_paths.is_empty());
    
    let learning_path = &ai_result.learning_paths[0];
    assert!(!learning_path.title.is_empty());
    assert!(!learning_path.steps.is_empty());
    assert!(learning_path.estimated_time > 0.0);
    
    Ok(())
}

#[test]
fn test_semantic_concept_identification() -> Result<()> {
    let analyzer = AdvancedAIAnalyzer::new();
    let analysis_result = create_mock_web_app_analysis_result();
    
    let ai_result = analyzer.analyze(&analysis_result)?;
    
    // Check for web application concepts
    let concepts = &ai_result.semantic_analysis.concepts;
    
    let has_user_management = concepts
        .iter()
        .any(|c| c.name == "User Management");
    assert!(has_user_management);
    
    let has_api_interface = concepts
        .iter()
        .any(|c| c.name == "API Interface");
    assert!(has_api_interface);
    
    Ok(())
}

#[test]
fn test_code_abstraction_analysis() -> Result<()> {
    let analyzer = AdvancedAIAnalyzer::new();
    let analysis_result = create_mock_oop_analysis_result();
    
    let ai_result = analyzer.analyze(&analysis_result)?;
    
    // Verify abstraction analysis
    let abstractions = &ai_result.semantic_analysis.abstractions;
    assert!(!abstractions.is_empty());
    
    let function_abstractions: Vec<_> = abstractions
        .iter()
        .filter(|a| matches!(a.abstraction_type, AbstractionType::Function))
        .collect();
    assert!(!function_abstractions.is_empty());
    
    let class_abstractions: Vec<_> = abstractions
        .iter()
        .filter(|a| matches!(a.abstraction_type, AbstractionType::Class))
        .collect();
    assert!(!class_abstractions.is_empty());
    
    Ok(())
}

#[test]
fn test_semantic_clustering() -> Result<()> {
    let analyzer = AdvancedAIAnalyzer::new();
    let analysis_result = create_mock_clustered_analysis_result();
    
    let ai_result = analyzer.analyze(&analysis_result)?;
    
    // Verify semantic clustering
    let clusters = &ai_result.semantic_analysis.clusters;
    assert!(!clusters.is_empty());
    
    let auth_cluster = clusters
        .iter()
        .find(|c| c.name == "Authentication & Security");
    assert!(auth_cluster.is_some());
    
    let data_cluster = clusters
        .iter()
        .find(|c| c.name == "Data Management");
    assert!(data_cluster.is_some());
    
    Ok(())
}

#[test]
fn test_ai_recommendations_generation() -> Result<()> {
    let analyzer = AdvancedAIAnalyzer::new();
    let analysis_result = create_mock_analysis_with_issues();
    
    let ai_result = analyzer.analyze(&analysis_result)?;
    
    // Verify AI recommendations are generated
    assert!(!ai_result.ai_recommendations.is_empty());

    let recommendation = &ai_result.ai_recommendations[0];
    assert!(!recommendation.category.is_empty());
    assert!(!recommendation.recommendation.is_empty());
    assert!(recommendation.confidence > 0.0);
    
    Ok(())
}

#[test]
fn test_technical_debt_analysis() -> Result<()> {
    let analyzer = AdvancedAIAnalyzer::new();
    let analysis_result = create_mock_debt_heavy_analysis_result();
    
    let ai_result = analyzer.analyze(&analysis_result)?;
    
    // Verify technical debt analysis
    let debt_analysis = &ai_result.quality_assessment.technical_debt;
    assert!(debt_analysis.total_debt > 0.0);
    assert!(!debt_analysis.high_priority_debt.is_empty());
    assert!(debt_analysis.estimated_effort > 0.0);
    
    Ok(())
}

#[test]
fn test_documentation_insights_generation() -> Result<()> {
    let analyzer = AdvancedAIAnalyzer::new();
    let analysis_result = create_mock_undocumented_analysis_result();
    
    let ai_result = analyzer.analyze(&analysis_result)?;
    
    // Verify documentation insights
    assert!(!ai_result.documentation_insights.is_empty());

    let insight = &ai_result.documentation_insights[0];
    assert!(!insight.target.is_empty());
    assert!(!insight.improvements.is_empty());
    
    Ok(())
}

// Helper functions to create mock analysis results
fn create_mock_rust_analysis_result() -> AnalysisResult {
    let mut languages = std::collections::HashMap::new();
    languages.insert("Rust".to_string(), 100);

    AnalysisResult {
        root_path: std::path::PathBuf::from("/mock/project"),
        total_files: 10,
        parsed_files: 10,
        error_files: 0,
        total_lines: 1000,
        languages,
        files: vec![
            create_mock_file_info("src/main.rs", vec![
                create_mock_symbol("main", "function"),
                create_mock_symbol("Config", "struct"),
            ]),
            create_mock_file_info("src/lib.rs", vec![
                create_mock_symbol("Parser", "struct"),
                create_mock_symbol("parse", "function"),
            ]),
        ],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}

fn create_mock_mvc_analysis_result() -> AnalysisResult {
    let mut languages = std::collections::HashMap::new();
    languages.insert("JavaScript".to_string(), 80);
    languages.insert("TypeScript".to_string(), 20);

    AnalysisResult {
        root_path: std::path::PathBuf::from("/mock/mvc-project"),
        total_files: 15,
        parsed_files: 15,
        error_files: 0,
        total_lines: 2000,
        languages,
        files: vec![
            create_mock_file_info("src/user_model.js", vec![
                create_mock_symbol("User", "class"),
            ]),
            create_mock_file_info("src/user_view.js", vec![
                create_mock_symbol("UserView", "class"),
            ]),
            create_mock_file_info("src/user_controller.js", vec![
                create_mock_symbol("UserController", "class"),
            ]),
        ],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}

fn create_mock_file_info(path: &str, symbols: Vec<Symbol>) -> FileInfo {
    FileInfo {
        path: PathBuf::from(path),
        language: "Rust".to_string(),
        size: 1000,
        lines: 100,
        parsed_successfully: true,
        parse_errors: vec![],
        symbols,
        imports: vec![],
        exports: vec![],
    }
}

fn create_mock_symbol(name: &str, kind: &str) -> Symbol {
    Symbol {
        name: name.to_string(),
        kind: kind.to_string(),
        start_line: 1,
        end_line: 10,
        start_column: 0,
        end_column: 10,
        documentation: None,
        is_public: true,
    }
}

fn create_mock_complex_analysis_result() -> AnalysisResult {
    let mut languages = std::collections::HashMap::new();
    languages.insert("Rust".to_string(), 60);
    languages.insert("JavaScript".to_string(), 40);

    AnalysisResult {
        root_path: std::path::PathBuf::from("/mock/complex-project"),
        total_files: 25,
        parsed_files: 25,
        error_files: 0,
        total_lines: 5000,
        languages,
        files: vec![
            create_mock_file_info("src/complex_module.rs", vec![
                create_mock_symbol("ComplexProcessor", "struct"),
                create_mock_symbol("process_data", "function"),
                create_mock_symbol("validate_input", "function"),
            ]),
        ],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}

fn create_mock_beginner_analysis_result() -> AnalysisResult {
    let mut languages = std::collections::HashMap::new();
    languages.insert("Python".to_string(), 100);

    AnalysisResult {
        root_path: std::path::PathBuf::from("/mock/beginner-project"),
        total_files: 5,
        parsed_files: 5,
        error_files: 0,
        total_lines: 200,
        languages,
        files: vec![
            create_mock_file_info("hello.py", vec![
                create_mock_symbol("main", "function"),
            ]),
        ],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}

fn create_mock_web_app_analysis_result() -> AnalysisResult {
    let mut languages = std::collections::HashMap::new();
    languages.insert("JavaScript".to_string(), 70);
    languages.insert("TypeScript".to_string(), 30);

    AnalysisResult {
        root_path: std::path::PathBuf::from("/mock/webapp-project"),
        total_files: 20,
        parsed_files: 20,
        error_files: 0,
        total_lines: 3000,
        languages,
        files: vec![
            create_mock_file_info("src/user_manager.js", vec![
                create_mock_symbol("UserManager", "class"),
                create_mock_symbol("createUser", "function"),
            ]),
            create_mock_file_info("src/api_handler.js", vec![
                create_mock_symbol("ApiHandler", "class"),
                create_mock_symbol("handleRequest", "function"),
            ]),
        ],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}

fn create_mock_oop_analysis_result() -> AnalysisResult {
    let mut languages = std::collections::HashMap::new();
    languages.insert("TypeScript".to_string(), 100);

    AnalysisResult {
        root_path: std::path::PathBuf::from("/mock/oop-project"),
        total_files: 12,
        parsed_files: 12,
        error_files: 0,
        total_lines: 1500,
        languages,
        files: vec![
            create_mock_file_info("src/service.ts", vec![
                create_mock_symbol("DataService", "class"),
                create_mock_symbol("processData", "function"),
                create_mock_symbol("validateData", "function"),
            ]),
            create_mock_file_info("src/manager.ts", vec![
                create_mock_symbol("ServiceManager", "class"),
                create_mock_symbol("initialize", "function"),
            ]),
        ],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}

fn create_mock_clustered_analysis_result() -> AnalysisResult {
    let mut languages = std::collections::HashMap::new();
    languages.insert("Rust".to_string(), 100);

    AnalysisResult {
        root_path: std::path::PathBuf::from("/mock/clustered-project"),
        total_files: 18,
        parsed_files: 18,
        error_files: 0,
        total_lines: 2500,
        languages,
        files: vec![
            create_mock_file_info("src/auth/login.rs", vec![
                create_mock_symbol("login", "function"),
            ]),
            create_mock_file_info("src/auth/security.rs", vec![
                create_mock_symbol("validate_token", "function"),
            ]),
            create_mock_file_info("src/data/repository.rs", vec![
                create_mock_symbol("Repository", "struct"),
            ]),
            create_mock_file_info("src/data/database.rs", vec![
                create_mock_symbol("Database", "struct"),
            ]),
        ],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}

fn create_mock_analysis_with_issues() -> AnalysisResult {
    let mut languages = std::collections::HashMap::new();
    languages.insert("Rust".to_string(), 100);

    AnalysisResult {
        root_path: std::path::PathBuf::from("/mock/issues-project"),
        total_files: 30,
        parsed_files: 30,
        error_files: 0,
        total_lines: 8000,
        languages,
        files: vec![
            create_mock_file_info("src/legacy_code.rs", vec![
                create_mock_symbol("legacy_function", "function"),
                create_mock_symbol("OldStruct", "struct"),
            ]),
        ],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}

fn create_mock_debt_heavy_analysis_result() -> AnalysisResult {
    let mut languages = std::collections::HashMap::new();
    languages.insert("JavaScript".to_string(), 100);

    AnalysisResult {
        root_path: std::path::PathBuf::from("/mock/debt-project"),
        total_files: 50,
        parsed_files: 50,
        error_files: 0,
        total_lines: 15000,
        languages,
        files: vec![
            create_mock_file_info("src/monolith.js", vec![
                create_mock_symbol("massiveFunction", "function"),
                create_mock_symbol("GodClass", "class"),
            ]),
        ],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}

fn create_mock_undocumented_analysis_result() -> AnalysisResult {
    let mut languages = std::collections::HashMap::new();
    languages.insert("Python".to_string(), 100);

    AnalysisResult {
        root_path: std::path::PathBuf::from("/mock/undocumented-project"),
        total_files: 15,
        parsed_files: 15,
        error_files: 0,
        total_lines: 2000,
        languages,
        files: vec![
            create_mock_file_info("src/undocumented.py", vec![
                create_mock_symbol("mystery_function", "function"),
                create_mock_symbol("UnknownClass", "class"),
            ]),
        ],
        config: AnalysisConfig::default(),
        symbols: vec![],
        dependencies: vec![],
    }
}
