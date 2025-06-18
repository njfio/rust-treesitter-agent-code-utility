//! Constants used throughout the rust-treesitter library
//!
//! This module contains all magic numbers and configuration constants
//! used across the codebase, providing clear documentation for their purpose.

/// Security analysis constants
pub mod security {
    /// Default minimum confidence threshold for security findings (0.0-1.0)
    pub const DEFAULT_MIN_CONFIDENCE: f64 = 0.7;
    
    /// Maximum security score (0-100)
    pub const MAX_SECURITY_SCORE: u8 = 100;
    
    /// Perfect security score when no issues found
    pub const PERFECT_SECURITY_SCORE: u8 = 100;
    
    /// Base security score before deductions
    pub const BASE_SECURITY_SCORE: u8 = 100;
    
    /// Divisor for coverage percentage calculation
    pub const COVERAGE_CALCULATION_DIVISOR: f64 = 10.0;
    
    /// High secrets compliance score threshold
    pub const HIGH_SECRETS_COMPLIANCE: u8 = 100;
    
    /// Medium secrets compliance score
    pub const MEDIUM_SECRETS_COMPLIANCE: u8 = 80;
    
    /// Effort estimation for different severity levels
    pub const HIGH_SEVERITY_EFFORT: f64 = 3.0;
    pub const MEDIUM_SEVERITY_EFFORT: f64 = 1.5;
    pub const LOW_SEVERITY_EFFORT: f64 = 0.5;
}

/// Intent mapping and traceability constants
pub mod intent_mapping {
    /// Default confidence threshold for automatic mapping (0.0-1.0)
    pub const DEFAULT_CONFIDENCE_THRESHOLD: f64 = 0.7;
    
    /// Maximum mapping distance threshold (0.0-1.0)
    pub const DEFAULT_MAX_MAPPING_DISTANCE: f64 = 0.8;
    
    /// Auto-validation threshold for high-confidence mappings (0.0-1.0)
    pub const DEFAULT_AUTO_VALIDATION_THRESHOLD: f64 = 0.9;
    
    /// Default values for initialization
    pub const DEFAULT_COVERAGE: f64 = 0.0;
    pub const DEFAULT_COMPLEXITY: f64 = 1.0;
    pub const DEFAULT_MAINTAINABILITY: f64 = 0.8;
    pub const DEFAULT_PERFORMANCE: f64 = 0.8;
    pub const DEFAULT_SECURITY: f64 = 0.8;
    
    /// Validation scoring weights
    pub const VALIDATION_CONFIDENCE_WEIGHT: f64 = 0.4;
    pub const VALIDATION_REQUIREMENT_WEIGHT: f64 = 0.2;
    pub const VALIDATION_IMPLEMENTATION_WEIGHT: f64 = 0.2;
    pub const VALIDATION_QUALITY_WEIGHT: f64 = 0.2;
    
    /// Validation thresholds
    pub const VALIDATION_VALID_THRESHOLD: f64 = 0.8;
    pub const VALIDATION_REVIEW_THRESHOLD: f64 = 0.5;
    pub const QUALITY_COVERAGE_THRESHOLD: f64 = 0.7;
    pub const COVERAGE_THRESHOLD: f64 = 0.8;
    
    /// Pattern matching weights
    pub const USER_STORY_API_WEIGHT: f64 = 0.3;
    pub const FUNCTIONAL_FUNCTION_WEIGHT: f64 = 0.4;
    pub const TECHNICAL_MODULE_WEIGHT: f64 = 0.3;
    pub const SECURITY_WEIGHT: f64 = 0.2;
    pub const KEYWORD_SIMILARITY_WEIGHT: f64 = 0.7;
}

/// Performance analysis constants
pub mod performance {
    /// Maximum performance score (0-100)
    pub const MAX_PERFORMANCE_SCORE: u8 = 100;
    
    /// Base performance score before deductions
    pub const BASE_PERFORMANCE_SCORE: f64 = 100.0;
    
    /// Function length threshold for high severity
    pub const FUNCTION_LENGTH_HIGH_THRESHOLD: usize = 100;
    
    /// Large codebase threshold (number of files)
    pub const LARGE_CODEBASE_THRESHOLD: usize = 100;
    
    /// Lines per complexity unit for size calculation
    pub const LINES_PER_COMPLEXITY_UNIT: f64 = 100.0;
    
    /// Maximum impact scores
    pub const MAX_CPU_IMPACT: f64 = 100.0;
    pub const MAX_OVERALL_IMPACT: f64 = 100.0;
    
    /// Impact calculation multipliers
    pub const COMPLEXITY_CPU_MULTIPLIER: f64 = 5.0;
    pub const COMPLEXITY_OVERALL_MULTIPLIER: f64 = 4.0;
}

/// Test coverage constants
pub mod test_coverage {
    /// Maximum test coverage score (0-100)
    pub const MAX_COVERAGE_SCORE: f64 = 100.0;
    
    /// Perfect coverage when no functions to test
    pub const PERFECT_COVERAGE_SCORE: f64 = 100.0;
    
    /// Percentage multiplier for coverage calculations
    pub const PERCENTAGE_MULTIPLIER: f64 = 100.0;
}

/// Refactoring constants
pub mod refactoring {
    /// Large file threshold (lines of code)
    pub const LARGE_FILE_THRESHOLD: usize = 500;
    
    /// Base refactoring score
    pub const BASE_REFACTORING_SCORE: u8 = 100;
}

/// File size and processing constants
pub mod file_processing {
    /// Default maximum file size (1MB in bytes)
    pub const DEFAULT_MAX_FILE_SIZE: usize = 1024 * 1024;
    
    /// Kilobyte size
    pub const KILOBYTE: usize = 1024;
    
    /// Megabyte size
    pub const MEGABYTE: usize = 1024 * 1024;
}

/// Scoring and percentage constants
pub mod scoring {
    /// Minimum score value
    pub const MIN_SCORE: f64 = 0.0;
    
    /// Maximum score value
    pub const MAX_SCORE: f64 = 100.0;
    
    /// Perfect score
    pub const PERFECT_SCORE: f64 = 100.0;
    
    /// Percentage conversion factor
    pub const PERCENTAGE_FACTOR: f64 = 100.0;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_constants() {
        assert!(security::DEFAULT_MIN_CONFIDENCE > 0.0);
        assert!(security::DEFAULT_MIN_CONFIDENCE <= 1.0);
        assert_eq!(security::MAX_SECURITY_SCORE, 100);
    }

    #[test]
    fn test_intent_mapping_constants() {
        assert!(intent_mapping::DEFAULT_CONFIDENCE_THRESHOLD > 0.0);
        assert!(intent_mapping::DEFAULT_CONFIDENCE_THRESHOLD <= 1.0);
        assert!(intent_mapping::DEFAULT_AUTO_VALIDATION_THRESHOLD > intent_mapping::DEFAULT_CONFIDENCE_THRESHOLD);
    }

    #[test]
    fn test_performance_constants() {
        assert_eq!(performance::MAX_PERFORMANCE_SCORE, 100);
        assert!(performance::FUNCTION_LENGTH_HIGH_THRESHOLD > 0);
    }

    #[test]
    fn test_file_processing_constants() {
        assert_eq!(file_processing::DEFAULT_MAX_FILE_SIZE, 1024 * 1024);
        assert_eq!(file_processing::MEGABYTE, 1024 * 1024);
    }
}
