//! Performance optimization utilities for large codebase analysis
//!
//! This module provides parallel processing, memory optimization, and caching
//! capabilities to handle large codebases efficiently.

use crate::error::{Error, Result};
use crate::analyzer::{AnalysisResult, CodebaseAnalyzer, AnalysisConfig};
use crate::enhanced_error_handling::SafeFileOperations;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use rayon::prelude::*;
use dashmap::DashMap;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Configuration for performance optimization
#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    /// Maximum number of worker threads for parallel processing
    pub max_threads: usize,
    /// Chunk size for batching files
    pub chunk_size: usize,
    /// Enable memory optimization features
    pub enable_memory_optimization: bool,
    /// Enable result caching
    pub enable_caching: bool,
    /// Maximum memory usage in bytes (0 = unlimited)
    pub max_memory_usage: usize,
    /// Enable incremental analysis
    pub enable_incremental: bool,
    /// Cache TTL in seconds
    pub cache_ttl: u64,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            max_threads: num_cpus::get(),
            chunk_size: 100,
            enable_memory_optimization: true,
            enable_caching: true,
            max_memory_usage: 1024 * 1024 * 1024, // 1GB
            enable_incremental: true,
            cache_ttl: 3600, // 1 hour
        }
    }
}

/// Memory usage statistics
#[derive(Debug, Clone)]
pub struct MemoryStats {
    pub total_allocated: usize,
    pub peak_usage: usize,
    pub current_usage: usize,
    pub cache_usage: usize,
    pub files_in_memory: usize,
}

/// Performance metrics for analysis operations
#[derive(Debug, Clone)]
pub struct PerformanceMetrics {
    pub total_files: usize,
    pub processed_files: usize,
    pub failed_files: usize,
    pub total_duration: Duration,
    pub average_file_time: Duration,
    pub memory_stats: MemoryStats,
    pub cache_hits: usize,
    pub cache_misses: usize,
}

/// Cache entry for analysis results
#[derive(Debug, Clone)]
struct CacheEntry {
    result: AnalysisResult,
    timestamp: Instant,
    file_hash: u64,
}

/// Optimized analyzer with parallel processing and caching
pub struct OptimizedAnalyzer {
    config: PerformanceConfig,
    analyzer: Arc<Mutex<CodebaseAnalyzer>>,
    cache: Arc<DashMap<PathBuf, CacheEntry>>,
    memory_tracker: Arc<AtomicUsize>,
    metrics: Arc<Mutex<PerformanceMetrics>>,
    safe_file_ops: SafeFileOperations,
}

impl OptimizedAnalyzer {
    /// Create a new optimized analyzer
    pub fn new(analysis_config: AnalysisConfig, perf_config: PerformanceConfig) -> Self {
        // Configure rayon thread pool
        rayon::ThreadPoolBuilder::new()
            .num_threads(perf_config.max_threads)
            .build_global()
            .unwrap_or_else(|_| {
                eprintln!("Warning: Failed to configure thread pool, using default");
            });

        let metrics = PerformanceMetrics {
            total_files: 0,
            processed_files: 0,
            failed_files: 0,
            total_duration: Duration::new(0, 0),
            average_file_time: Duration::new(0, 0),
            memory_stats: MemoryStats {
                total_allocated: 0,
                peak_usage: 0,
                current_usage: 0,
                cache_usage: 0,
                files_in_memory: 0,
            },
            cache_hits: 0,
            cache_misses: 0,
        };

        Self {
            config: perf_config,
            analyzer: Arc::new(Mutex::new(CodebaseAnalyzer::with_config(analysis_config))),
            cache: Arc::new(DashMap::new()),
            memory_tracker: Arc::new(AtomicUsize::new(0)),
            metrics: Arc::new(Mutex::new(metrics)),
            safe_file_ops: SafeFileOperations::new(),
        }
    }

    /// Analyze a directory with parallel processing and optimization
    pub fn analyze_directory_optimized<P: AsRef<Path>>(&mut self, path: P) -> Result<AnalysisResult> {
        let start_time = Instant::now();
        let path = path.as_ref();

        // Collect all files to process
        let files = self.collect_files_optimized(path)?;
        
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.total_files = files.len();
        }

        // Process files in parallel chunks
        let results = self.process_files_parallel(files)?;

        // Merge results
        let final_result = self.merge_analysis_results(results)?;

        // Update metrics
        let duration = start_time.elapsed();
        {
            let mut metrics = self.metrics.lock().unwrap();
            metrics.total_duration = duration;
            if metrics.processed_files > 0 {
                metrics.average_file_time = duration / metrics.processed_files as u32;
            }
            metrics.memory_stats.current_usage = self.memory_tracker.load(Ordering::Relaxed);
            metrics.memory_stats.cache_usage = self.calculate_cache_memory_usage();
        }

        Ok(final_result)
    }

    /// Collect files with memory-efficient directory traversal
    fn collect_files_optimized<P: AsRef<Path>>(&mut self, path: P) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        let mut stack = vec![path.as_ref().to_path_buf()];

        while let Some(current_path) = stack.pop() {
            // Check memory usage
            if self.config.max_memory_usage > 0 {
                let current_usage = self.memory_tracker.load(Ordering::Relaxed);
                if current_usage > self.config.max_memory_usage {
                    return Err(Error::internal("Memory usage limit exceeded during file collection".to_string()));
                }
            }

            let entries = self.safe_file_ops.list_directory(&current_path)?;
            
            for entry in entries {
                if entry.is_file() {
                    if self.is_supported_file(&entry) {
                        files.push(entry);
                        // Track memory usage (approximate)
                        self.memory_tracker.fetch_add(std::mem::size_of::<PathBuf>(), Ordering::Relaxed);
                    }
                } else if entry.is_dir() && !self.should_skip_directory(&entry) {
                    stack.push(entry);
                }
            }
        }

        Ok(files)
    }

    /// Process files in parallel chunks
    fn process_files_parallel(&mut self, files: Vec<PathBuf>) -> Result<Vec<AnalysisResult>> {
        let chunk_size = self.config.chunk_size;
        let chunks: Vec<_> = files.chunks(chunk_size).collect();

        let results: Result<Vec<_>> = chunks
            .into_par_iter()
            .map(|chunk| self.process_chunk(chunk.to_vec()))
            .collect();

        results
    }

    /// Process a chunk of files
    fn process_chunk(&self, files: Vec<PathBuf>) -> Result<AnalysisResult> {
        let mut chunk_results = Vec::new();

        for file_path in files {
            match self.process_single_file(&file_path) {
                Ok(result) => {
                    chunk_results.push(result);
                    let mut metrics = self.metrics.lock().unwrap();
                    metrics.processed_files += 1;
                }
                Err(e) => {
                    eprintln!("Warning: Failed to process file {}: {}", file_path.display(), e);
                    let mut metrics = self.metrics.lock().unwrap();
                    metrics.failed_files += 1;
                }
            }
        }

        // Merge chunk results
        self.merge_analysis_results(chunk_results)
    }

    /// Process a single file with caching
    fn process_single_file(&self, file_path: &Path) -> Result<AnalysisResult> {
        // Check cache first
        if self.config.enable_caching {
            if let Some(cached_result) = self.get_cached_result(file_path)? {
                let mut metrics = self.metrics.lock().unwrap();
                metrics.cache_hits += 1;
                return Ok(cached_result);
            }
        }

        // Process file
        let result = {
            let mut analyzer = self.analyzer.lock().unwrap();
            analyzer.analyze_file(file_path)?
        };

        // Cache result
        if self.config.enable_caching {
            self.cache_result(file_path, &result)?;
        }

        let mut metrics = self.metrics.lock().unwrap();
        metrics.cache_misses += 1;

        Ok(result)
    }

    /// Get cached result if valid
    fn get_cached_result(&self, file_path: &Path) -> Result<Option<AnalysisResult>> {
        if let Some(entry) = self.cache.get(file_path) {
            // Check if cache entry is still valid
            let age = entry.timestamp.elapsed();
            if age.as_secs() < self.config.cache_ttl {
                // Check if file has been modified
                let current_hash = self.calculate_file_hash(file_path)?;
                if current_hash == entry.file_hash {
                    return Ok(Some(entry.result.clone()));
                }
            }
            
            // Remove expired or invalid entry
            drop(entry);
            self.cache.remove(file_path);
        }

        Ok(None)
    }

    /// Cache analysis result
    fn cache_result(&self, file_path: &Path, result: &AnalysisResult) -> Result<()> {
        let file_hash = self.calculate_file_hash(file_path)?;
        let entry = CacheEntry {
            result: result.clone(),
            timestamp: Instant::now(),
            file_hash,
        };

        self.cache.insert(file_path.to_path_buf(), entry);

        // Update memory tracking
        let entry_size = std::mem::size_of::<CacheEntry>() + 
                        std::mem::size_of::<PathBuf>() +
                        file_path.as_os_str().len();
        self.memory_tracker.fetch_add(entry_size, Ordering::Relaxed);

        Ok(())
    }

    /// Calculate file hash for cache validation
    fn calculate_file_hash(&self, file_path: &Path) -> Result<u64> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let metadata = std::fs::metadata(file_path)
            .map_err(|e| Error::file_system(format!("Failed to get metadata for {}: {}", file_path.display(), e)))?;

        let mut hasher = DefaultHasher::new();
        metadata.len().hash(&mut hasher);
        if let Ok(modified) = metadata.modified() {
            if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                duration.as_secs().hash(&mut hasher);
            }
        }

        Ok(hasher.finish())
    }

    /// Merge multiple analysis results
    fn merge_analysis_results(&self, results: Vec<AnalysisResult>) -> Result<AnalysisResult> {
        if results.is_empty() {
            return Ok(AnalysisResult::default());
        }

        let mut merged = results[0].clone();

        for result in results.into_iter().skip(1) {
            // Merge file information
            merged.files.extend(result.files);
            
            // Merge symbols
            merged.symbols.extend(result.symbols);
            
            // Merge dependencies
            merged.dependencies.extend(result.dependencies);
            
            // Update statistics
            merged.total_files += result.total_files;
            merged.total_lines += result.total_lines;
        }

        Ok(merged)
    }

    /// Check if file is supported for analysis
    fn is_supported_file(&self, path: &Path) -> bool {
        if let Some(extension) = path.extension() {
            let ext = extension.to_string_lossy().to_lowercase();
            matches!(ext.as_str(), "rs" | "js" | "ts" | "py" | "c" | "cpp" | "cc" | "cxx" | "h" | "hpp" | "go")
        } else {
            false
        }
    }

    /// Check if directory should be skipped
    fn should_skip_directory(&self, path: &Path) -> bool {
        if let Some(name) = path.file_name() {
            let name_str = name.to_string_lossy();
            matches!(name_str.as_ref(), "target" | "node_modules" | ".git" | "build" | "dist" | "__pycache__")
        } else {
            false
        }
    }

    /// Calculate cache memory usage
    fn calculate_cache_memory_usage(&self) -> usize {
        self.cache.len() * (std::mem::size_of::<CacheEntry>() + std::mem::size_of::<PathBuf>() + 50) // Approximate
    }

    /// Get current performance metrics
    pub fn get_metrics(&self) -> PerformanceMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// Clear cache to free memory
    pub fn clear_cache(&mut self) {
        let cache_size = self.calculate_cache_memory_usage();
        self.cache.clear();
        self.memory_tracker.fetch_sub(cache_size, Ordering::Relaxed);
        
        let mut metrics = self.metrics.lock().unwrap();
        metrics.cache_hits = 0;
        metrics.cache_misses = 0;
    }

    /// Optimize memory usage by cleaning up old cache entries
    pub fn optimize_memory(&mut self) -> Result<usize> {
        let mut freed_bytes = 0;
        let current_time = Instant::now();
        let ttl = Duration::from_secs(self.config.cache_ttl);

        // Remove expired entries
        let expired_keys: Vec<_> = self.cache
            .iter()
            .filter(|entry| current_time.duration_since(entry.timestamp) > ttl)
            .map(|entry| entry.key().clone())
            .collect();

        for key in expired_keys {
            if let Some((_, entry)) = self.cache.remove(&key) {
                freed_bytes += std::mem::size_of::<CacheEntry>() + 
                             std::mem::size_of::<PathBuf>() + 
                             key.as_os_str().len();
            }
        }

        self.memory_tracker.fetch_sub(freed_bytes, Ordering::Relaxed);
        Ok(freed_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_performance_config_default() {
        let config = PerformanceConfig::default();
        assert!(config.max_threads > 0);
        assert_eq!(config.chunk_size, 100);
        assert!(config.enable_memory_optimization);
        assert!(config.enable_caching);
        assert!(config.enable_incremental);
    }

    #[test]
    fn test_optimized_analyzer_creation() {
        let analysis_config = AnalysisConfig::default();
        let perf_config = PerformanceConfig::default();
        let analyzer = OptimizedAnalyzer::new(analysis_config, perf_config);

        let metrics = analyzer.get_metrics();
        assert_eq!(metrics.total_files, 0);
        assert_eq!(metrics.processed_files, 0);
        assert_eq!(metrics.cache_hits, 0);
        assert_eq!(metrics.cache_misses, 0);
    }

    #[test]
    fn test_memory_stats() {
        let stats = MemoryStats {
            total_allocated: 1024,
            peak_usage: 2048,
            current_usage: 512,
            cache_usage: 256,
            files_in_memory: 10,
        };

        assert_eq!(stats.total_allocated, 1024);
        assert_eq!(stats.peak_usage, 2048);
        assert_eq!(stats.current_usage, 512);
        assert_eq!(stats.cache_usage, 256);
        assert_eq!(stats.files_in_memory, 10);
    }

    #[test]
    fn test_file_hash_calculation() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.rs");
        let content = "fn main() { println!(\"Hello, world!\"); }";

        fs::write(&file_path, content).unwrap();

        let analysis_config = AnalysisConfig::default();
        let perf_config = PerformanceConfig::default();
        let analyzer = OptimizedAnalyzer::new(analysis_config, perf_config);

        let hash1 = analyzer.calculate_file_hash(&file_path).unwrap();
        let hash2 = analyzer.calculate_file_hash(&file_path).unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_supported_file_detection() {
        let analysis_config = AnalysisConfig::default();
        let perf_config = PerformanceConfig::default();
        let analyzer = OptimizedAnalyzer::new(analysis_config, perf_config);

        assert!(analyzer.is_supported_file(Path::new("test.rs")));
        assert!(analyzer.is_supported_file(Path::new("test.js")));
        assert!(analyzer.is_supported_file(Path::new("test.py")));
        assert!(analyzer.is_supported_file(Path::new("test.c")));
        assert!(analyzer.is_supported_file(Path::new("test.cpp")));
        assert!(analyzer.is_supported_file(Path::new("test.go")));
        assert!(analyzer.is_supported_file(Path::new("test.ts")));

        assert!(!analyzer.is_supported_file(Path::new("test.txt")));
        assert!(!analyzer.is_supported_file(Path::new("test.md")));
        assert!(!analyzer.is_supported_file(Path::new("test")));
    }

    #[test]
    fn test_directory_skip_detection() {
        let analysis_config = AnalysisConfig::default();
        let perf_config = PerformanceConfig::default();
        let analyzer = OptimizedAnalyzer::new(analysis_config, perf_config);

        assert!(analyzer.should_skip_directory(Path::new("target")));
        assert!(analyzer.should_skip_directory(Path::new("node_modules")));
        assert!(analyzer.should_skip_directory(Path::new(".git")));
        assert!(analyzer.should_skip_directory(Path::new("build")));
        assert!(analyzer.should_skip_directory(Path::new("dist")));
        assert!(analyzer.should_skip_directory(Path::new("__pycache__")));

        assert!(!analyzer.should_skip_directory(Path::new("src")));
        assert!(!analyzer.should_skip_directory(Path::new("lib")));
        assert!(!analyzer.should_skip_directory(Path::new("tests")));
    }

    #[test]
    fn test_cache_operations() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.rs");
        let content = "fn main() {}";

        fs::write(&file_path, content).unwrap();

        let analysis_config = AnalysisConfig::default();
        let perf_config = PerformanceConfig::default();
        let analyzer = OptimizedAnalyzer::new(analysis_config, perf_config);

        // Initially no cache entry
        let cached = analyzer.get_cached_result(&file_path).unwrap();
        assert!(cached.is_none());

        // Cache a result
        let result = AnalysisResult::default();
        analyzer.cache_result(&file_path, &result).unwrap();

        // Should find cached entry
        let cached = analyzer.get_cached_result(&file_path).unwrap();
        assert!(cached.is_some());
    }

    #[test]
    fn test_memory_optimization() {
        let analysis_config = AnalysisConfig::default();
        let perf_config = PerformanceConfig {
            cache_ttl: 0, // Immediate expiration for testing
            ..PerformanceConfig::default()
        };
        let mut analyzer = OptimizedAnalyzer::new(analysis_config, perf_config);

        // Add some cache entries
        let temp_dir = TempDir::new().unwrap();
        for i in 0..5 {
            let file_path = temp_dir.path().join(format!("test{}.rs", i));
            fs::write(&file_path, "fn main() {}").unwrap();

            let result = AnalysisResult::default();
            analyzer.cache_result(&file_path, &result).unwrap();
        }

        // Wait a bit to ensure expiration
        std::thread::sleep(std::time::Duration::from_millis(10));

        // Optimize memory should free expired entries
        let freed = analyzer.optimize_memory().unwrap();
        assert!(freed > 0);
    }

    #[test]
    fn test_cache_clear() {
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.rs");
        fs::write(&file_path, "fn main() {}").unwrap();

        let analysis_config = AnalysisConfig::default();
        let perf_config = PerformanceConfig::default();
        let mut analyzer = OptimizedAnalyzer::new(analysis_config, perf_config);

        // Cache a result
        let result = AnalysisResult::default();
        analyzer.cache_result(&file_path, &result).unwrap();

        // Verify cache has entry
        assert!(analyzer.get_cached_result(&file_path).unwrap().is_some());

        // Clear cache
        analyzer.clear_cache();

        // Verify cache is empty
        assert!(analyzer.get_cached_result(&file_path).unwrap().is_none());

        let metrics = analyzer.get_metrics();
        assert_eq!(metrics.cache_hits, 0);
        assert_eq!(metrics.cache_misses, 0);
    }

    #[test]
    fn test_performance_metrics_tracking() {
        let analysis_config = AnalysisConfig::default();
        let perf_config = PerformanceConfig::default();
        let analyzer = OptimizedAnalyzer::new(analysis_config, perf_config);

        let metrics = analyzer.get_metrics();
        assert_eq!(metrics.total_files, 0);
        assert_eq!(metrics.processed_files, 0);
        assert_eq!(metrics.failed_files, 0);
        assert_eq!(metrics.cache_hits, 0);
        assert_eq!(metrics.cache_misses, 0);
        assert_eq!(metrics.memory_stats.current_usage, 0);
    }
}
