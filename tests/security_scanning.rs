use rust_tree_sitter::{CodebaseAnalyzer, AdvancedSecurityAnalyzer};
use std::path::PathBuf;

#[test]
fn advanced_security_detects_vulnerabilities() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from("test_files");
    let mut analyzer = CodebaseAnalyzer::new();
    let mut analysis = analyzer.analyze_directory(&root)?;
    for file in &mut analysis.files {
        file.path = analysis.root_path.join(&file.path);
    }
    let scanner = AdvancedSecurityAnalyzer::new()?;
    let result = scanner.analyze(&analysis)?;
    assert!(result.total_vulnerabilities > 0);
    Ok(())
}
