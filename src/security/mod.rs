//! Real security analysis implementation
//! 
//! This module provides production-grade security analysis with real
//! vulnerability database integration, secrets detection, and OWASP compliance.

pub mod vulnerability_db;
pub mod secrets_detector;
pub mod owasp_detector;

pub use vulnerability_db::*;
pub use secrets_detector::*;
pub use owasp_detector::*;
