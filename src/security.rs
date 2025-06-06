//! Security vulnerability detection and analysis
//! 
//! This module provides security scanning capabilities to detect
//! common vulnerabilities and security issues in code.

use crate::{FileInfo, Symbol, AnalysisResult};
use std::collections::HashMap;

#[cfg(feature = "serde")]
use serde::{Serialize, Deserialize};

/// Security scanner for detecting vulnerabilities
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityScanner {
    /// Configuration for security scanning
    pub config: SecurityConfig,
}

/// Configuration for security scanning
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityConfig {
    /// Enable SQL injection detection
    pub sql_injection_detection: bool,
    /// Enable XSS detection
    pub xss_detection: bool,
    /// Enable path traversal detection
    pub path_traversal_detection: bool,
    /// Enable unsafe code detection
    pub unsafe_code_detection: bool,
    /// Enable hardcoded secrets detection
    pub secrets_detection: bool,
    /// Enable buffer overflow detection
    pub buffer_overflow_detection: bool,
    /// Enable insecure random detection
    pub insecure_random_detection: bool,
    /// Minimum severity level to report
    pub min_severity: SecuritySeverity,
}

/// Security scan results
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityScanResult {
    /// Overall security score (0-100)
    pub security_score: u8,
    /// Total vulnerabilities found
    pub total_vulnerabilities: usize,
    /// Vulnerabilities by severity
    pub vulnerabilities_by_severity: HashMap<SecuritySeverity, usize>,
    /// Detailed vulnerability findings
    pub vulnerabilities: Vec<SecurityVulnerability>,
    /// Security recommendations
    pub recommendations: Vec<SecurityRecommendation>,
    /// Compliance status
    pub compliance: ComplianceStatus,
}

/// A detected security vulnerability
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityVulnerability {
    /// Vulnerability ID/type
    pub id: String,
    /// Human-readable title
    pub title: String,
    /// Detailed description
    pub description: String,
    /// Severity level
    pub severity: SecuritySeverity,
    /// Confidence level of detection
    pub confidence: ConfidenceLevel,
    /// Location where vulnerability was found
    pub location: VulnerabilityLocation,
    /// Code snippet showing the issue
    pub code_snippet: String,
    /// How to fix this vulnerability
    pub fix_suggestion: String,
    /// References for more information
    pub references: Vec<String>,
    /// CWE (Common Weakness Enumeration) ID if applicable
    pub cwe_id: Option<u32>,
}

/// Location of a vulnerability
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct VulnerabilityLocation {
    /// File path
    pub file: String,
    /// Line number
    pub line: usize,
    /// Column number
    pub column: usize,
    /// Function or symbol name if applicable
    pub symbol: Option<String>,
}

/// Security recommendation
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SecurityRecommendation {
    /// Recommendation category
    pub category: String,
    /// Recommendation text
    pub recommendation: String,
    /// Priority level
    pub priority: RecommendationPriority,
    /// Implementation difficulty
    pub difficulty: ImplementationDifficulty,
}

/// Compliance status for various standards
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct ComplianceStatus {
    /// OWASP Top 10 compliance
    pub owasp_top10: ComplianceLevel,
    /// CWE compliance
    pub cwe_compliance: ComplianceLevel,
    /// Language-specific security guidelines
    pub language_guidelines: ComplianceLevel,
    /// Overall compliance score
    pub overall_score: u8,
}

/// Security severity levels
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum SecuritySeverity {
    /// Critical security issue
    Critical,
    /// High severity issue
    High,
    /// Medium severity issue
    Medium,
    /// Low severity issue
    Low,
    /// Informational
    Info,
}

/// Confidence level in vulnerability detection
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ConfidenceLevel {
    /// Very confident this is a real vulnerability
    High,
    /// Moderately confident
    Medium,
    /// Low confidence, might be false positive
    Low,
}

/// Recommendation priority
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum RecommendationPriority {
    /// Must fix immediately
    Critical,
    /// Should fix soon
    High,
    /// Should fix when convenient
    Medium,
    /// Nice to have
    Low,
}

/// Implementation difficulty
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ImplementationDifficulty {
    /// Easy to implement
    Easy,
    /// Moderate effort required
    Medium,
    /// Significant effort required
    Hard,
    /// Very difficult to implement
    VeryHard,
}

/// Compliance level
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub enum ComplianceLevel {
    /// Fully compliant
    Compliant,
    /// Mostly compliant with minor issues
    MostlyCompliant,
    /// Partially compliant
    PartiallyCompliant,
    /// Not compliant
    NonCompliant,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            sql_injection_detection: true,
            xss_detection: true,
            path_traversal_detection: true,
            unsafe_code_detection: true,
            secrets_detection: true,
            buffer_overflow_detection: true,
            insecure_random_detection: true,
            min_severity: SecuritySeverity::Low,
        }
    }
}

impl SecurityScanner {
    /// Create a new security scanner with default configuration
    pub fn new() -> Self {
        Self {
            config: SecurityConfig::default(),
        }
    }
    
    /// Create a new security scanner with custom configuration
    pub fn with_config(config: SecurityConfig) -> Self {
        Self { config }
    }
    
    /// Scan a codebase for security vulnerabilities
    pub fn scan(&self, analysis_result: &AnalysisResult) -> SecurityScanResult {
        let mut vulnerabilities = Vec::new();
        
        // Scan each file for vulnerabilities
        for file in &analysis_result.files {
            vulnerabilities.extend(self.scan_file(file));
        }
        
        // Filter by minimum severity
        vulnerabilities.retain(|v| self.meets_severity_threshold(&v.severity));
        
        // Calculate statistics
        let total_vulnerabilities = vulnerabilities.len();
        let mut vulnerabilities_by_severity = HashMap::new();
        for vuln in &vulnerabilities {
            *vulnerabilities_by_severity.entry(vuln.severity.clone()).or_insert(0) += 1;
        }
        
        let security_score = self.calculate_security_score(&vulnerabilities, analysis_result);
        let recommendations = self.generate_recommendations(&vulnerabilities, analysis_result);
        let compliance = self.assess_compliance(&vulnerabilities, analysis_result);
        
        SecurityScanResult {
            security_score,
            total_vulnerabilities,
            vulnerabilities_by_severity,
            vulnerabilities,
            recommendations,
            compliance,
        }
    }
    
    /// Scan a single file for vulnerabilities
    fn scan_file(&self, file: &FileInfo) -> Vec<SecurityVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Read file content for analysis (in a real implementation)
        // For now, we'll analyze based on symbols and patterns
        
        for symbol in &file.symbols {
            vulnerabilities.extend(self.scan_symbol(symbol, file));
        }
        
        // Scan for file-level issues
        vulnerabilities.extend(self.scan_file_patterns(file));
        
        vulnerabilities
    }
    
    /// Scan a symbol for security issues
    fn scan_symbol(&self, symbol: &Symbol, file: &FileInfo) -> Vec<SecurityVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        // Check for unsafe patterns in symbol names
        if self.config.unsafe_code_detection {
            vulnerabilities.extend(self.check_unsafe_patterns(symbol, file));
        }
        
        if self.config.insecure_random_detection {
            vulnerabilities.extend(self.check_insecure_random(symbol, file));
        }
        
        if self.config.secrets_detection {
            vulnerabilities.extend(self.check_hardcoded_secrets(symbol, file));
        }
        
        vulnerabilities
    }
    
    /// Scan file for pattern-based vulnerabilities
    fn scan_file_patterns(&self, file: &FileInfo) -> Vec<SecurityVulnerability> {
        let mut vulnerabilities = Vec::new();
        
        let file_path = file.path.to_string_lossy().to_lowercase();
        
        // Check for sensitive file patterns
        if file_path.contains("password") || file_path.contains("secret") || file_path.contains("key") {
            vulnerabilities.push(SecurityVulnerability {
                id: "SENSITIVE_FILE".to_string(),
                title: "Potentially sensitive file detected".to_string(),
                description: "File name suggests it may contain sensitive information".to_string(),
                severity: SecuritySeverity::Medium,
                confidence: ConfidenceLevel::Medium,
                location: VulnerabilityLocation {
                    file: file.path.display().to_string(),
                    line: 1,
                    column: 1,
                    symbol: None,
                },
                code_snippet: format!("File: {}", file.path.display()),
                fix_suggestion: "Ensure sensitive data is properly encrypted and not committed to version control".to_string(),
                references: vec![
                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure".to_string(),
                ],
                cwe_id: Some(200), // CWE-200: Information Exposure
            });
        }
        
        vulnerabilities
    }

    // Helper methods for security analysis

    fn meets_severity_threshold(&self, severity: &SecuritySeverity) -> bool {
        use SecuritySeverity::*;
        match (&self.config.min_severity, severity) {
            (Critical, Critical) => true,
            (High, Critical | High) => true,
            (Medium, Critical | High | Medium) => true,
            (Low, Critical | High | Medium | Low) => true,
            (Info, _) => true,
            _ => false,
        }
    }

    fn calculate_security_score(&self, vulnerabilities: &[SecurityVulnerability], _result: &AnalysisResult) -> u8 {
        if vulnerabilities.is_empty() {
            return 100;
        }

        let mut score: u8 = 100;
        for vuln in vulnerabilities {
            let deduction = match vuln.severity {
                SecuritySeverity::Critical => 25,
                SecuritySeverity::High => 15,
                SecuritySeverity::Medium => 8,
                SecuritySeverity::Low => 3,
                SecuritySeverity::Info => 1,
            };
            score = score.saturating_sub(deduction);
        }

        score
    }

    fn generate_recommendations(&self, vulnerabilities: &[SecurityVulnerability], _result: &AnalysisResult) -> Vec<SecurityRecommendation> {
        let mut recommendations = Vec::new();

        if vulnerabilities.iter().any(|v| matches!(v.severity, SecuritySeverity::Critical)) {
            recommendations.push(SecurityRecommendation {
                category: "Critical Issues".to_string(),
                recommendation: "Address critical security vulnerabilities immediately".to_string(),
                priority: RecommendationPriority::Critical,
                difficulty: ImplementationDifficulty::Medium,
            });
        }

        if vulnerabilities.len() > 5 {
            recommendations.push(SecurityRecommendation {
                category: "Security Review".to_string(),
                recommendation: "Conduct comprehensive security review and implement security testing".to_string(),
                priority: RecommendationPriority::High,
                difficulty: ImplementationDifficulty::Hard,
            });
        }

        recommendations.push(SecurityRecommendation {
            category: "Best Practices".to_string(),
            recommendation: "Implement automated security scanning in CI/CD pipeline".to_string(),
            priority: RecommendationPriority::Medium,
            difficulty: ImplementationDifficulty::Medium,
        });

        recommendations
    }

    fn assess_compliance(&self, vulnerabilities: &[SecurityVulnerability], _result: &AnalysisResult) -> ComplianceStatus {
        let critical_count = vulnerabilities.iter().filter(|v| matches!(v.severity, SecuritySeverity::Critical)).count();
        let high_count = vulnerabilities.iter().filter(|v| matches!(v.severity, SecuritySeverity::High)).count();

        let owasp_compliance = if critical_count == 0 && high_count == 0 {
            ComplianceLevel::Compliant
        } else if critical_count == 0 && high_count < 3 {
            ComplianceLevel::MostlyCompliant
        } else if critical_count < 2 {
            ComplianceLevel::PartiallyCompliant
        } else {
            ComplianceLevel::NonCompliant
        };

        let overall_score = if vulnerabilities.is_empty() {
            100
        } else {
            (100 - (vulnerabilities.len() * 10).min(100)) as u8
        };

        ComplianceStatus {
            owasp_top10: owasp_compliance.clone(),
            cwe_compliance: owasp_compliance.clone(),
            language_guidelines: owasp_compliance,
            overall_score,
        }
    }

    fn check_unsafe_patterns(&self, symbol: &Symbol, file: &FileInfo) -> Vec<SecurityVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for unsafe Rust code
        if symbol.name.contains("unsafe") || symbol.kind.contains("unsafe") {
            vulnerabilities.push(SecurityVulnerability {
                id: "UNSAFE_CODE".to_string(),
                title: "Unsafe code block detected".to_string(),
                description: "Unsafe code bypasses Rust's safety guarantees and should be carefully reviewed".to_string(),
                severity: SecuritySeverity::Medium,
                confidence: ConfidenceLevel::High,
                location: VulnerabilityLocation {
                    file: file.path.display().to_string(),
                    line: symbol.start_line,
                    column: symbol.start_column,
                    symbol: Some(symbol.name.clone()),
                },
                code_snippet: format!("unsafe {}", symbol.name),
                fix_suggestion: "Review unsafe code for memory safety and consider safe alternatives".to_string(),
                references: vec![
                    "https://doc.rust-lang.org/book/ch19-01-unsafe-rust.html".to_string(),
                ],
                cwe_id: Some(119), // CWE-119: Buffer Overflow
            });
        }

        vulnerabilities
    }

    fn check_insecure_random(&self, symbol: &Symbol, file: &FileInfo) -> Vec<SecurityVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for weak random number generation
        if symbol.name.to_lowercase().contains("rand") && !symbol.name.contains("secure") {
            vulnerabilities.push(SecurityVulnerability {
                id: "WEAK_RANDOM".to_string(),
                title: "Potentially weak random number generation".to_string(),
                description: "Using non-cryptographically secure random number generation for security-sensitive operations".to_string(),
                severity: SecuritySeverity::Medium,
                confidence: ConfidenceLevel::Medium,
                location: VulnerabilityLocation {
                    file: file.path.display().to_string(),
                    line: symbol.start_line,
                    column: symbol.start_column,
                    symbol: Some(symbol.name.clone()),
                },
                code_snippet: symbol.name.clone(),
                fix_suggestion: "Use cryptographically secure random number generators for security-sensitive operations".to_string(),
                references: vec![
                    "https://owasp.org/www-community/vulnerabilities/Insecure_Randomness".to_string(),
                ],
                cwe_id: Some(338), // CWE-338: Use of Cryptographically Weak PRNG
            });
        }

        vulnerabilities
    }

    fn check_hardcoded_secrets(&self, symbol: &Symbol, file: &FileInfo) -> Vec<SecurityVulnerability> {
        let mut vulnerabilities = Vec::new();

        // Check for potential hardcoded secrets
        let suspicious_names = ["password", "secret", "key", "token", "api_key", "private"];
        if suspicious_names.iter().any(|&name| symbol.name.to_lowercase().contains(name)) {
            vulnerabilities.push(SecurityVulnerability {
                id: "HARDCODED_SECRET".to_string(),
                title: "Potential hardcoded secret detected".to_string(),
                description: "Symbol name suggests it may contain hardcoded sensitive information".to_string(),
                severity: SecuritySeverity::High,
                confidence: ConfidenceLevel::Medium,
                location: VulnerabilityLocation {
                    file: file.path.display().to_string(),
                    line: symbol.start_line,
                    column: symbol.start_column,
                    symbol: Some(symbol.name.clone()),
                },
                code_snippet: symbol.name.clone(),
                fix_suggestion: "Use environment variables or secure configuration management for sensitive data".to_string(),
                references: vec![
                    "https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure".to_string(),
                ],
                cwe_id: Some(798), // CWE-798: Use of Hard-coded Credentials
            });
        }

        vulnerabilities
    }
}

impl std::fmt::Display for SecuritySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecuritySeverity::Critical => write!(f, "Critical"),
            SecuritySeverity::High => write!(f, "High"),
            SecuritySeverity::Medium => write!(f, "Medium"),
            SecuritySeverity::Low => write!(f, "Low"),
            SecuritySeverity::Info => write!(f, "Info"),
        }
    }
}

impl std::fmt::Display for ConfidenceLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfidenceLevel::High => write!(f, "High"),
            ConfidenceLevel::Medium => write!(f, "Medium"),
            ConfidenceLevel::Low => write!(f, "Low"),
        }
    }
}

impl std::fmt::Display for RecommendationPriority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecommendationPriority::Critical => write!(f, "Critical"),
            RecommendationPriority::High => write!(f, "High"),
            RecommendationPriority::Medium => write!(f, "Medium"),
            RecommendationPriority::Low => write!(f, "Low"),
        }
    }
}
