use rust_tree_sitter::{CodebaseAnalyzer, EnhancedSecurityScanner, EnhancedSecurityConfig};
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // First, analyze the codebase
    let mut analyzer = CodebaseAnalyzer::new()?;
    let path = PathBuf::from("./src");
    let analysis_result = analyzer.analyze_directory(&path)?;
    
    println!("=== Codebase Analysis Complete ===");
    println!("Analyzed {} files", analysis_result.total_files);
    
    // Create security scanner with enhanced configuration
    let security_config = EnhancedSecurityConfig {
        enable_vulnerability_db: true,
        enable_secrets_detection: true,
        enable_owasp_scanning: true,
        enable_dependency_scanning: true,
        min_confidence: 0.7,
        max_findings_per_category: 50,
    };
    
    let security_scanner = EnhancedSecurityScanner::with_config(security_config);
    
    // Run comprehensive security scan
    println!("\n=== Running Security Analysis ===");
    let security_result = security_scanner.scan_analysis_result(&analysis_result)?;
    
    // Display overall security metrics
    println!("\n=== Security Assessment Results ===");
    println!("Overall Security Score: {}/100", security_result.security_score);
    println!("Total Findings: {}", security_result.total_findings);
    println!("High Severity: {}", security_result.high_severity_count);
    println!("Medium Severity: {}", security_result.medium_severity_count);
    println!("Low Severity: {}", security_result.low_severity_count);
    
    // Display vulnerability findings
    if !security_result.vulnerability_findings.is_empty() {
        println!("\n=== Vulnerability Findings ===");
        for (i, vuln) in security_result.vulnerability_findings.iter().enumerate() {
            println!("{}. {} ({})", i + 1, vuln.title, vuln.severity);
            println!("   File: {}", vuln.location.file.display());
            println!("   Line: {}", vuln.location.line);
            println!("   Confidence: {:.2}", vuln.confidence);
            if let Some(cwe) = &vuln.cwe_id {
                println!("   CWE: {}", cwe);
            }
            if let Some(owasp) = &vuln.owasp_category {
                println!("   OWASP: {}", owasp);
            }
            println!("   Description: {}", vuln.description);
            if let Some(remediation) = &vuln.remediation {
                println!("   Remediation: {}", remediation);
            }
            println!();
        }
    }
    
    // Display secret findings
    if !security_result.secret_findings.is_empty() {
        println!("\n=== Secret Findings ===");
        for (i, secret) in security_result.secret_findings.iter().enumerate() {
            println!("{}. {} Secret", i + 1, secret.secret_type);
            println!("   File: {}", secret.location.file.display());
            println!("   Line: {}", secret.location.line);
            println!("   Entropy: {:.2}", secret.entropy);
            println!("   Confidence: {:.2}", secret.confidence);
            println!("   Context: {}", secret.context);
            println!();
        }
    }
    
    // Display dependency findings
    if !security_result.dependency_findings.is_empty() {
        println!("\n=== Dependency Vulnerability Findings ===");
        for (i, dep) in security_result.dependency_findings.iter().enumerate() {
            println!("{}. {} v{}", i + 1, dep.package_name, dep.version);
            println!("   Vulnerability: {}", dep.vulnerability_id);
            println!("   Severity: {}", dep.severity);
            println!("   Description: {}", dep.description);
            if let Some(fixed_version) = &dep.fixed_version {
                println!("   Fixed in: {}", fixed_version);
            }
            println!();
        }
    }
    
    // Display compliance assessment
    println!("\n=== Compliance Assessment ===");
    let compliance = &security_result.compliance_assessment;
    println!("OWASP Compliance Score: {}/100", compliance.owasp_score);
    println!("CWE Coverage: {}/100", compliance.cwe_coverage);
    
    if !compliance.missing_controls.is_empty() {
        println!("\nMissing Security Controls:");
        for control in &compliance.missing_controls {
            println!("  - {}", control);
        }
    }
    
    if !compliance.recommendations.is_empty() {
        println!("\nSecurity Recommendations:");
        for (i, rec) in compliance.recommendations.iter().enumerate() {
            println!("{}. {} (Priority: {})", i + 1, rec.title, rec.priority);
            println!("   Description: {}", rec.description);
            if let Some(effort) = &rec.estimated_effort {
                println!("   Estimated Effort: {}", effort);
            }
            println!();
        }
    }
    
    // Generate security report
    if security_result.total_findings > 0 {
        println!("\n=== Security Report Summary ===");
        println!("⚠️  Security issues found!");
        println!("📊 Security Score: {}/100", security_result.security_score);
        
        if security_result.high_severity_count > 0 {
            println!("🔴 {} high severity issues require immediate attention", 
                     security_result.high_severity_count);
        }
        
        if security_result.medium_severity_count > 0 {
            println!("🟡 {} medium severity issues should be addressed", 
                     security_result.medium_severity_count);
        }
        
        println!("\nNext Steps:");
        println!("1. Review and fix high severity vulnerabilities");
        println!("2. Implement missing security controls");
        println!("3. Update vulnerable dependencies");
        println!("4. Remove or secure hardcoded secrets");
        println!("5. Re-run security scan to verify fixes");
    } else {
        println!("\n✅ No security issues found!");
        println!("🎉 Security Score: {}/100", security_result.security_score);
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;
    
    #[test]
    fn test_security_analysis_with_vulnerabilities() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        
        // Create a file with potential security issues
        let vulnerable_code = r#"
            use std::process::Command;
            
            fn execute_command(user_input: &str) {
                // Potential command injection vulnerability
                let output = Command::new("sh")
                    .arg("-c")
                    .arg(user_input)  // Direct user input to shell
                    .output()
                    .expect("Failed to execute command");
            }
            
            fn database_query(user_id: &str) -> String {
                // Potential SQL injection vulnerability
                format!("SELECT * FROM users WHERE id = '{}'", user_id)
            }
            
            const API_KEY: &str = "sk-1234567890abcdef"; // Hardcoded secret
        "#;
        
        fs::write(temp_dir.path().join("vulnerable.rs"), vulnerable_code)?;
        
        // Analyze the code
        let mut analyzer = CodebaseAnalyzer::new()?;
        let analysis_result = analyzer.analyze_directory(temp_dir.path())?;
        
        // Run security scan
        let security_scanner = EnhancedSecurityScanner::new();
        let security_result = security_scanner.scan_analysis_result(&analysis_result)?;
        
        // Should find security issues
        assert!(security_result.total_findings > 0);
        assert!(security_result.security_score < 100);
        
        // Should detect command injection
        let has_command_injection = security_result.vulnerability_findings
            .iter()
            .any(|v| v.title.to_lowercase().contains("command injection"));
        assert!(has_command_injection);
        
        // Should detect potential SQL injection
        let has_sql_injection = security_result.vulnerability_findings
            .iter()
            .any(|v| v.title.to_lowercase().contains("sql injection"));
        assert!(has_sql_injection);
        
        // Should detect hardcoded secret
        assert!(!security_result.secret_findings.is_empty());
        
        Ok(())
    }
    
    #[test]
    fn test_security_analysis_clean_code() -> Result<(), Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        
        // Create secure code
        let secure_code = r#"
            use std::process::Command;
            use std::env;
            
            fn execute_safe_command(command: &str, args: &[&str]) -> Result<String, std::io::Error> {
                let output = Command::new(command)
                    .args(args)
                    .output()?;
                
                Ok(String::from_utf8_lossy(&output.stdout).to_string())
            }
            
            fn get_api_key() -> Option<String> {
                env::var("API_KEY").ok()
            }
        "#;
        
        fs::write(temp_dir.path().join("secure.rs"), secure_code)?;
        
        // Analyze the code
        let mut analyzer = CodebaseAnalyzer::new()?;
        let analysis_result = analyzer.analyze_directory(temp_dir.path())?;
        
        // Run security scan
        let security_scanner = EnhancedSecurityScanner::new();
        let security_result = security_scanner.scan_analysis_result(&analysis_result)?;
        
        // Should have fewer or no security issues
        assert!(security_result.security_score > 80); // Should have a good security score
        
        Ok(())
    }
}
