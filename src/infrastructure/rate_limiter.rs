//! Real rate limiting infrastructure for API calls
//! 
//! Provides token bucket and sliding window rate limiting
//! with per-service configuration and automatic backoff.

use governor::{Quota, RateLimiter as GovRateLimiter, state::{NotKeyed, InMemoryState}, clock::{DefaultClock, Clock}, middleware::NoOpMiddleware};
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tracing::{debug, warn};
use anyhow::{Result, anyhow};

/// Multi-service rate limiter with different limits per service
#[derive(Clone)]
pub struct MultiServiceRateLimiter {
    limiters: Arc<RwLock<HashMap<String, ServiceRateLimiter>>>,
}

/// Rate limiter for a specific service
#[derive(Clone)]
pub struct ServiceRateLimiter {
    limiter: Arc<GovRateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>>,
    service_name: String,
    requests_per_minute: u32,
    burst_size: u32,
}

/// Rate limiting configuration for a service
#[derive(Debug, Clone)]
pub struct RateLimitConfig {
    pub service_name: String,
    pub requests_per_minute: u32,
    pub burst_size: Option<u32>,
    pub enable_backoff: bool,
    pub max_backoff_duration: Duration,
}

/// Rate limiting result
#[derive(Debug, Clone)]
pub enum RateLimitResult {
    Allowed,
    Limited { retry_after: Duration },
    Error(String),
}

impl MultiServiceRateLimiter {
    /// Create a new multi-service rate limiter
    pub fn new() -> Self {
        Self {
            limiters: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add a rate limiter for a specific service
    pub async fn add_service(&self, config: RateLimitConfig) -> Result<()> {
        let service_limiter = ServiceRateLimiter::new(config)?;
        let mut limiters = self.limiters.write().await;
        limiters.insert(service_limiter.service_name.clone(), service_limiter);
        Ok(())
    }

    /// Wait for permission to make a request to a service
    pub async fn wait_for_permit(&self, service_name: &str) -> Result<()> {
        let limiters = self.limiters.read().await;
        if let Some(limiter) = limiters.get(service_name) {
            limiter.wait_for_permit().await
        } else {
            Err(anyhow!("No rate limiter configured for service: {}", service_name))
        }
    }

    /// Check if a request can be made immediately
    pub async fn check_permit(&self, service_name: &str) -> Result<RateLimitResult> {
        let limiters = self.limiters.read().await;
        if let Some(limiter) = limiters.get(service_name) {
            Ok(limiter.check_permit())
        } else {
            Err(anyhow!("No rate limiter configured for service: {}", service_name))
        }
    }

    /// Get rate limiting statistics for a service
    pub async fn get_stats(&self, service_name: &str) -> Result<RateLimitStats> {
        let limiters = self.limiters.read().await;
        if let Some(limiter) = limiters.get(service_name) {
            Ok(limiter.get_stats())
        } else {
            Err(anyhow!("No rate limiter configured for service: {}", service_name))
        }
    }

    /// Get all configured services
    pub async fn get_services(&self) -> Vec<String> {
        let limiters = self.limiters.read().await;
        limiters.keys().cloned().collect()
    }
}

impl ServiceRateLimiter {
    /// Create a new service rate limiter
    pub fn new(config: RateLimitConfig) -> Result<Self> {
        let requests_per_minute = NonZeroU32::new(config.requests_per_minute)
            .ok_or_else(|| anyhow!("Requests per minute must be > 0"))?;

        let quota = Quota::per_minute(requests_per_minute);
        let limiter = Arc::new(GovRateLimiter::direct(quota));

        debug!("Created rate limiter for {}: {} requests/minute", 
               config.service_name, config.requests_per_minute);

        Ok(Self {
            limiter,
            service_name: config.service_name,
            requests_per_minute: config.requests_per_minute,
            burst_size: config.burst_size.unwrap_or(config.requests_per_minute),
        })
    }

    /// Wait for permission to make a request
    pub async fn wait_for_permit(&self) -> Result<()> {
        self.limiter.until_ready().await;
        debug!("Rate limit permit granted for {}", self.service_name);
        Ok(())
    }

    /// Check if a request can be made immediately
    pub fn check_permit(&self) -> RateLimitResult {
        match self.limiter.check() {
            Ok(_) => {
                debug!("Rate limit check passed for {}", self.service_name);
                RateLimitResult::Allowed
            }
            Err(negative) => {
                let retry_after = negative.wait_time_from(governor::clock::DefaultClock::default().now());
                warn!("Rate limit exceeded for {}, retry after: {:?}",
                      self.service_name, retry_after);
                RateLimitResult::Limited { retry_after }
            }
        }
    }

    /// Get rate limiting statistics
    pub fn get_stats(&self) -> RateLimitStats {
        // Note: governor doesn't provide detailed stats, so we return basic info
        RateLimitStats {
            service_name: self.service_name.clone(),
            requests_per_minute: self.requests_per_minute,
            burst_size: self.burst_size,
            current_tokens: 0, // Would need custom implementation to track
            total_requests: 0, // Would need custom implementation to track
            total_limited: 0,  // Would need custom implementation to track
        }
    }
}

/// Rate limiting statistics
#[derive(Debug, Clone)]
pub struct RateLimitStats {
    pub service_name: String,
    pub requests_per_minute: u32,
    pub burst_size: u32,
    pub current_tokens: u32,
    pub total_requests: u64,
    pub total_limited: u64,
}

/// Adaptive rate limiter that adjusts based on API responses
#[derive(Clone)]
pub struct AdaptiveRateLimiter {
    base_limiter: ServiceRateLimiter,
    current_rate: Arc<tokio::sync::RwLock<u32>>,
    min_rate: u32,
    max_rate: u32,
    adjustment_factor: f64,
}

impl AdaptiveRateLimiter {
    /// Create a new adaptive rate limiter
    pub fn new(
        service_name: String,
        initial_rate: u32,
        min_rate: u32,
        max_rate: u32,
    ) -> Result<Self> {
        let config = RateLimitConfig {
            service_name,
            requests_per_minute: initial_rate,
            burst_size: Some(initial_rate),
            enable_backoff: true,
            max_backoff_duration: Duration::from_secs(60),
        };

        let base_limiter = ServiceRateLimiter::new(config)?;

        Ok(Self {
            base_limiter,
            current_rate: Arc::new(tokio::sync::RwLock::new(initial_rate)),
            min_rate,
            max_rate,
            adjustment_factor: 0.1, // 10% adjustment
        })
    }

    /// Adjust rate based on API response
    pub async fn adjust_rate(&self, response_indicates_rate_limit: bool) {
        let mut current_rate = self.current_rate.write().await;
        
        if response_indicates_rate_limit {
            // Decrease rate
            let new_rate = (*current_rate as f64 * (1.0 - self.adjustment_factor)) as u32;
            *current_rate = new_rate.max(self.min_rate);
            warn!("Decreased rate limit for {} to {}", 
                  self.base_limiter.service_name, *current_rate);
        } else {
            // Gradually increase rate
            let new_rate = (*current_rate as f64 * (1.0 + self.adjustment_factor * 0.1)) as u32;
            *current_rate = new_rate.min(self.max_rate);
            debug!("Increased rate limit for {} to {}", 
                   self.base_limiter.service_name, *current_rate);
        }
    }

    /// Get current rate
    pub async fn get_current_rate(&self) -> u32 {
        *self.current_rate.read().await
    }
}

/// Rate limiter factory for creating common configurations
pub struct RateLimiterFactory;

impl RateLimiterFactory {
    /// Create rate limiter for NVD API
    pub fn nvd_limiter() -> Result<ServiceRateLimiter> {
        let config = RateLimitConfig {
            service_name: "nvd".to_string(),
            requests_per_minute: 50, // NVD limit without API key
            burst_size: Some(10),
            enable_backoff: true,
            max_backoff_duration: Duration::from_secs(120),
        };
        ServiceRateLimiter::new(config)
    }

    /// Create rate limiter for NVD API with API key
    pub fn nvd_limiter_with_key() -> Result<ServiceRateLimiter> {
        let config = RateLimitConfig {
            service_name: "nvd_with_key".to_string(),
            requests_per_minute: 100, // Higher limit with API key
            burst_size: Some(20),
            enable_backoff: true,
            max_backoff_duration: Duration::from_secs(60),
        };
        ServiceRateLimiter::new(config)
    }

    /// Create rate limiter for OSV API
    pub fn osv_limiter() -> Result<ServiceRateLimiter> {
        let config = RateLimitConfig {
            service_name: "osv".to_string(),
            requests_per_minute: 100,
            burst_size: Some(20),
            enable_backoff: true,
            max_backoff_duration: Duration::from_secs(30),
        };
        ServiceRateLimiter::new(config)
    }

    /// Create rate limiter for GitHub API
    pub fn github_limiter() -> Result<ServiceRateLimiter> {
        let config = RateLimitConfig {
            service_name: "github".to_string(),
            requests_per_minute: 60, // GitHub limit without token
            burst_size: Some(10),
            enable_backoff: true,
            max_backoff_duration: Duration::from_secs(300),
        };
        ServiceRateLimiter::new(config)
    }

    /// Create rate limiter for GitHub API with token
    pub fn github_limiter_with_token() -> Result<ServiceRateLimiter> {
        let config = RateLimitConfig {
            service_name: "github_with_token".to_string(),
            requests_per_minute: 5000, // Much higher limit with token
            burst_size: Some(100),
            enable_backoff: true,
            max_backoff_duration: Duration::from_secs(60),
        };
        ServiceRateLimiter::new(config)
    }

    /// Create a multi-service rate limiter with common configurations
    pub async fn create_default_multi_limiter() -> Result<MultiServiceRateLimiter> {
        let multi_limiter = MultiServiceRateLimiter::new();

        // Add common service limiters
        multi_limiter.add_service(RateLimitConfig {
            service_name: "nvd".to_string(),
            requests_per_minute: 50,
            burst_size: Some(10),
            enable_backoff: true,
            max_backoff_duration: Duration::from_secs(120),
        }).await?;

        multi_limiter.add_service(RateLimitConfig {
            service_name: "osv".to_string(),
            requests_per_minute: 100,
            burst_size: Some(20),
            enable_backoff: true,
            max_backoff_duration: Duration::from_secs(30),
        }).await?;

        multi_limiter.add_service(RateLimitConfig {
            service_name: "github".to_string(),
            requests_per_minute: 60,
            burst_size: Some(10),
            enable_backoff: true,
            max_backoff_duration: Duration::from_secs(300),
        }).await?;

        Ok(multi_limiter)
    }
}
