use crate::{SyntaxTree, Result};
use std::collections::HashMap;
use tree_sitter::Node;

/// Represents a taint source (where untrusted data enters the system)
#[derive(Debug, Clone, PartialEq)]
pub struct TaintSource {
    /// Source identifier
    pub id: String,
    /// Variable or parameter name
    pub name: String,
    /// Source type (user input, file, network, etc.)
    pub source_type: TaintSourceType,
    /// Location in source code
    pub location: TaintLocation,
    /// Confidence level of taint detection
    pub confidence: f64,
}

/// Types of taint sources
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSourceType {
    /// User input (HTTP parameters, form data, etc.)
    UserInput,
    /// File input
    FileInput,
    /// Network input
    NetworkInput,
    /// Environment variables
    Environment,
    /// Command line arguments
    CommandLine,
    /// Database query results
    Database,
    /// External API responses
    ExternalApi,
}

/// Represents a taint sink (where tainted data could cause vulnerabilities)
#[derive(Debug, Clone, PartialEq)]
pub struct TaintSink {
    /// Sink identifier
    pub id: String,
    /// Function or operation name
    pub name: String,
    /// Sink type (SQL query, command execution, etc.)
    pub sink_type: TaintSinkType,
    /// Location in source code
    pub location: TaintLocation,
    /// Vulnerability type if tainted data reaches this sink
    pub vulnerability_type: VulnerabilityType,
}

/// Types of taint sinks
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum TaintSinkType {
    /// SQL query execution
    SqlQuery,
    /// Command execution
    CommandExecution,
    /// File operations
    FileOperation,
    /// HTML output (XSS)
    HtmlOutput,
    /// HTTP headers
    HttpHeader,
    /// Logging operations
    Logging,
    /// Serialization
    Serialization,
}

/// Vulnerability types that can result from taint flow
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum VulnerabilityType {
    SqlInjection,
    CommandInjection,
    CrossSiteScripting,
    PathTraversal,
    HeaderInjection,
    LogInjection,
    DeserializationAttack,
}

/// Location information for taint analysis
#[derive(Debug, Clone, PartialEq)]
pub struct TaintLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
    pub function: Option<String>,
}

/// Represents a data flow path from source to sink
#[derive(Debug, Clone)]
pub struct TaintFlow {
    /// Source of the taint
    pub source: TaintSource,
    /// Sink where taint ends up
    pub sink: TaintSink,
    /// Path through the code (variable assignments, function calls, etc.)
    pub path: Vec<TaintStep>,
    /// Confidence level of the flow
    pub confidence: f64,
    /// Whether the flow is sanitized
    pub is_sanitized: bool,
    /// Sanitization methods applied
    pub sanitizers: Vec<String>,
}

/// A step in the taint flow path
#[derive(Debug, Clone)]
pub struct TaintStep {
    /// Type of step
    pub step_type: TaintStepType,
    /// Variable or function name
    pub name: String,
    /// Location of the step
    pub location: TaintLocation,
    /// Whether this step sanitizes the data
    pub is_sanitizer: bool,
    /// Sanitization method if applicable
    pub sanitizer_method: Option<String>,
}

/// Types of taint flow steps
#[derive(Debug, Clone, PartialEq)]
pub enum TaintStepType {
    /// Variable assignment
    Assignment,
    /// Function call
    FunctionCall,
    /// Function parameter
    Parameter,
    /// Return value
    Return,
    /// Array/object access
    Access,
    /// String concatenation
    Concatenation,
    /// Type conversion
    Conversion,
}

/// Taint analysis engine
pub struct TaintAnalyzer {
    language: String,
    /// Known taint sources for the language
    sources: HashMap<String, TaintSourceType>,
    /// Known taint sinks for the language
    sinks: HashMap<String, (TaintSinkType, VulnerabilityType)>,
    /// Known sanitization functions
    sanitizers: HashMap<String, Vec<VulnerabilityType>>,
}

impl TaintAnalyzer {
    /// Create a new taint analyzer for the specified language
    pub fn new(language: &str) -> Self {
        let mut analyzer = Self {
            language: language.to_string(),
            sources: HashMap::new(),
            sinks: HashMap::new(),
            sanitizers: HashMap::new(),
        };
        
        analyzer.initialize_language_rules();
        analyzer
    }
    
    /// Initialize language-specific taint sources, sinks, and sanitizers
    fn initialize_language_rules(&mut self) {
        match self.language.as_str() {
            "rust" => self.initialize_rust_rules(),
            "javascript" | "typescript" => self.initialize_javascript_rules(),
            "python" => self.initialize_python_rules(),
            "c" | "cpp" | "c++" => self.initialize_c_rules(),
            "go" => self.initialize_go_rules(),
            _ => self.initialize_generic_rules(),
        }
    }
    
    /// Initialize Rust-specific taint rules
    fn initialize_rust_rules(&mut self) {
        // Taint sources
        self.sources.insert("std::env::args".to_string(), TaintSourceType::CommandLine);
        self.sources.insert("std::env::var".to_string(), TaintSourceType::Environment);
        self.sources.insert("std::fs::read_to_string".to_string(), TaintSourceType::FileInput);
        self.sources.insert("reqwest::get".to_string(), TaintSourceType::NetworkInput);
        self.sources.insert("actix_web::HttpRequest".to_string(), TaintSourceType::UserInput);
        
        // Taint sinks
        self.sinks.insert("sqlx::query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("diesel::sql_query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("std::process::Command".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("std::fs::write".to_string(), (TaintSinkType::FileOperation, VulnerabilityType::PathTraversal));
        
        // Sanitizers
        self.sanitizers.insert("html_escape::encode_text".to_string(), vec![VulnerabilityType::CrossSiteScripting]);
        self.sanitizers.insert("regex::escape".to_string(), vec![VulnerabilityType::SqlInjection]);
        self.sanitizers.insert("shell_escape::escape".to_string(), vec![VulnerabilityType::CommandInjection]);
    }
    
    /// Initialize JavaScript/TypeScript-specific taint rules
    fn initialize_javascript_rules(&mut self) {
        // Taint sources
        self.sources.insert("process.argv".to_string(), TaintSourceType::CommandLine);
        self.sources.insert("process.env".to_string(), TaintSourceType::Environment);
        self.sources.insert("fs.readFileSync".to_string(), TaintSourceType::FileInput);
        self.sources.insert("fetch".to_string(), TaintSourceType::NetworkInput);
        self.sources.insert("req.query".to_string(), TaintSourceType::UserInput);
        self.sources.insert("req.body".to_string(), TaintSourceType::UserInput);
        self.sources.insert("req.params".to_string(), TaintSourceType::UserInput);
        
        // Taint sinks
        self.sinks.insert("mysql.query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("pg.query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("child_process.exec".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("eval".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("document.write".to_string(), (TaintSinkType::HtmlOutput, VulnerabilityType::CrossSiteScripting));
        self.sinks.insert("innerHTML".to_string(), (TaintSinkType::HtmlOutput, VulnerabilityType::CrossSiteScripting));
        
        // Sanitizers
        self.sanitizers.insert("escape".to_string(), vec![VulnerabilityType::CrossSiteScripting]);
        self.sanitizers.insert("validator.escape".to_string(), vec![VulnerabilityType::CrossSiteScripting]);
        self.sanitizers.insert("mysql.escape".to_string(), vec![VulnerabilityType::SqlInjection]);
        self.sanitizers.insert("shell-escape".to_string(), vec![VulnerabilityType::CommandInjection]);
    }
    
    /// Initialize Python-specific taint rules
    fn initialize_python_rules(&mut self) {
        // Taint sources
        self.sources.insert("sys.argv".to_string(), TaintSourceType::CommandLine);
        self.sources.insert("os.environ".to_string(), TaintSourceType::Environment);
        self.sources.insert("open".to_string(), TaintSourceType::FileInput);
        self.sources.insert("requests.get".to_string(), TaintSourceType::NetworkInput);
        self.sources.insert("request.args".to_string(), TaintSourceType::UserInput);
        self.sources.insert("request.form".to_string(), TaintSourceType::UserInput);
        
        // Taint sinks
        self.sinks.insert("cursor.execute".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("os.system".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("subprocess.call".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("eval".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        
        // Sanitizers
        self.sanitizers.insert("html.escape".to_string(), vec![VulnerabilityType::CrossSiteScripting]);
        self.sanitizers.insert("pymysql.escape_string".to_string(), vec![VulnerabilityType::SqlInjection]);
        self.sanitizers.insert("shlex.quote".to_string(), vec![VulnerabilityType::CommandInjection]);
    }
    
    /// Initialize C/C++-specific taint rules
    fn initialize_c_rules(&mut self) {
        // Taint sources
        self.sources.insert("argv".to_string(), TaintSourceType::CommandLine);
        self.sources.insert("getenv".to_string(), TaintSourceType::Environment);
        self.sources.insert("fgets".to_string(), TaintSourceType::FileInput);
        self.sources.insert("scanf".to_string(), TaintSourceType::UserInput);
        
        // Taint sinks
        self.sinks.insert("mysql_query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("system".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("exec".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("printf".to_string(), (TaintSinkType::HtmlOutput, VulnerabilityType::CrossSiteScripting));
        
        // Sanitizers
        self.sanitizers.insert("mysql_real_escape_string".to_string(), vec![VulnerabilityType::SqlInjection]);
    }
    
    /// Initialize Go-specific taint rules
    fn initialize_go_rules(&mut self) {
        // Taint sources
        self.sources.insert("os.Args".to_string(), TaintSourceType::CommandLine);
        self.sources.insert("os.Getenv".to_string(), TaintSourceType::Environment);
        self.sources.insert("ioutil.ReadFile".to_string(), TaintSourceType::FileInput);
        self.sources.insert("http.Get".to_string(), TaintSourceType::NetworkInput);
        
        // Taint sinks
        self.sinks.insert("db.Query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("exec.Command".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("fmt.Fprintf".to_string(), (TaintSinkType::HtmlOutput, VulnerabilityType::CrossSiteScripting));
        
        // Sanitizers
        self.sanitizers.insert("html.EscapeString".to_string(), vec![VulnerabilityType::CrossSiteScripting]);
        self.sanitizers.insert("url.QueryEscape".to_string(), vec![VulnerabilityType::SqlInjection]);
    }
    
    /// Initialize generic taint rules for unknown languages
    fn initialize_generic_rules(&mut self) {
        // Generic patterns that might apply to multiple languages
        self.sources.insert("input".to_string(), TaintSourceType::UserInput);
        self.sources.insert("read".to_string(), TaintSourceType::FileInput);
        self.sources.insert("get".to_string(), TaintSourceType::NetworkInput);
        
        self.sinks.insert("query".to_string(), (TaintSinkType::SqlQuery, VulnerabilityType::SqlInjection));
        self.sinks.insert("exec".to_string(), (TaintSinkType::CommandExecution, VulnerabilityType::CommandInjection));
        self.sinks.insert("write".to_string(), (TaintSinkType::HtmlOutput, VulnerabilityType::CrossSiteScripting));
    }
    
    /// Perform taint analysis on a syntax tree
    pub fn analyze(&self, tree: &SyntaxTree) -> Result<Vec<TaintFlow>> {
        let mut flows = Vec::new();
        
        // Find all taint sources in the code
        let sources = self.find_taint_sources(tree)?;
        
        // Find all taint sinks in the code
        let sinks = self.find_taint_sinks(tree)?;
        
        // For each source, try to find flows to sinks
        for source in &sources {
            let source_flows = self.trace_taint_flows(tree, source, &sinks)?;
            flows.extend(source_flows);
        }
        
        Ok(flows)
    }
    
    /// Find all taint sources in the syntax tree
    fn find_taint_sources(&self, tree: &SyntaxTree) -> Result<Vec<TaintSource>> {
        let mut sources = Vec::new();
        self.traverse_for_sources(tree.inner().root_node(), &mut sources, None)?;
        Ok(sources)
    }
    
    /// Find all taint sinks in the syntax tree
    fn find_taint_sinks(&self, tree: &SyntaxTree) -> Result<Vec<TaintSink>> {
        let mut sinks = Vec::new();
        self.traverse_for_sinks(tree.inner().root_node(), &mut sinks, None)?;
        Ok(sinks)
    }
    
    /// Recursively traverse AST to find taint sources
    fn traverse_for_sources(&self, node: Node, sources: &mut Vec<TaintSource>, current_function: Option<&str>) -> Result<()> {
        // Check if this node represents a taint source
        if let Some(source) = self.identify_taint_source(node, current_function)? {
            sources.push(source);
        }
        
        // Update current function context
        let function_name = if self.is_function_definition(node) {
            self.extract_function_name(node)
        } else {
            current_function.map(|s| s.to_string())
        };
        
        // Traverse children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.traverse_for_sources(cursor.node(), sources, function_name.as_deref())?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// Recursively traverse AST to find taint sinks
    fn traverse_for_sinks(&self, node: Node, sinks: &mut Vec<TaintSink>, current_function: Option<&str>) -> Result<()> {
        // Check if this node represents a taint sink
        if let Some(sink) = self.identify_taint_sink(node, current_function)? {
            sinks.push(sink);
        }
        
        // Update current function context
        let function_name = if self.is_function_definition(node) {
            self.extract_function_name(node)
        } else {
            current_function.map(|s| s.to_string())
        };
        
        // Traverse children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.traverse_for_sinks(cursor.node(), sinks, function_name.as_deref())?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    /// Identify if a node represents a taint source
    fn identify_taint_source(&self, node: Node, current_function: Option<&str>) -> Result<Option<TaintSource>> {
        let node_kind = node.kind();
        
        // Check for function calls that are taint sources
        if self.is_function_call(node_kind) {
            if let Some(function_name) = self.extract_function_call_name(node) {
                if let Some(source_type) = self.sources.get(&function_name) {
                    return Ok(Some(TaintSource {
                        id: format!("source_{}_{}", node.start_position().row, node.start_position().column),
                        name: function_name,
                        source_type: source_type.clone(),
                        location: TaintLocation {
                            file: "current_file".to_string(), // Would be passed in real implementation
                            line: node.start_position().row + 1,
                            column: node.start_position().column,
                            function: current_function.map(|s| s.to_string()),
                        },
                        confidence: 0.9,
                    }));
                }
            }
        }
        
        // Check for variable access that might be tainted
        if self.is_identifier(node_kind) {
            let identifier = node.utf8_text(b"").unwrap_or("");
            if self.is_likely_user_input_variable(identifier) {
                return Ok(Some(TaintSource {
                    id: format!("var_{}_{}", node.start_position().row, node.start_position().column),
                    name: identifier.to_string(),
                    source_type: TaintSourceType::UserInput,
                    location: TaintLocation {
                        file: "current_file".to_string(),
                        line: node.start_position().row + 1,
                        column: node.start_position().column,
                        function: current_function.map(|s| s.to_string()),
                    },
                    confidence: 0.6,
                }));
            }
        }
        
        Ok(None)
    }
    
    /// Identify if a node represents a taint sink
    fn identify_taint_sink(&self, node: Node, current_function: Option<&str>) -> Result<Option<TaintSink>> {
        let node_kind = node.kind();
        
        // Check for function calls that are taint sinks
        if self.is_function_call(node_kind) {
            if let Some(function_name) = self.extract_function_call_name(node) {
                if let Some((sink_type, vuln_type)) = self.sinks.get(&function_name) {
                    return Ok(Some(TaintSink {
                        id: format!("sink_{}_{}", node.start_position().row, node.start_position().column),
                        name: function_name,
                        sink_type: sink_type.clone(),
                        location: TaintLocation {
                            file: "current_file".to_string(),
                            line: node.start_position().row + 1,
                            column: node.start_position().column,
                            function: current_function.map(|s| s.to_string()),
                        },
                        vulnerability_type: vuln_type.clone(),
                    }));
                }
            }
        }
        
        Ok(None)
    }
    
    /// Check if node kind represents a function call
    fn is_function_call(&self, node_kind: &str) -> bool {
        match self.language.as_str() {
            "rust" => matches!(node_kind, "call_expression"),
            "javascript" | "typescript" => matches!(node_kind, "call_expression"),
            "python" => matches!(node_kind, "call"),
            "c" | "cpp" | "c++" => matches!(node_kind, "call_expression"),
            "go" => matches!(node_kind, "call_expression"),
            _ => node_kind.contains("call"),
        }
    }
    
    /// Check if node kind represents an identifier
    fn is_identifier(&self, node_kind: &str) -> bool {
        node_kind == "identifier"
    }
    
    /// Check if node represents a function definition
    fn is_function_definition(&self, node: Node) -> bool {
        let node_kind = node.kind();
        match self.language.as_str() {
            "rust" => matches!(node_kind, "function_item"),
            "javascript" | "typescript" => matches!(node_kind, "function_declaration" | "function_expression"),
            "python" => matches!(node_kind, "function_definition"),
            "c" | "cpp" | "c++" => matches!(node_kind, "function_definition"),
            "go" => matches!(node_kind, "function_declaration"),
            _ => node_kind.contains("function"),
        }
    }
    
    /// Extract function name from function call node
    fn extract_function_call_name(&self, node: Node) -> Option<String> {
        // This is a simplified implementation
        // In practice, would need to handle method calls, qualified names, etc.
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            let function_node = cursor.node();
            if let Ok(name) = function_node.utf8_text(b"") {
                return Some(name.to_string());
            }
        }
        None
    }
    
    /// Extract function name from function definition node
    fn extract_function_name(&self, node: Node) -> Option<String> {
        // Simplified implementation
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if child.kind() == "identifier" {
                    if let Ok(name) = child.utf8_text(b"") {
                        return Some(name.to_string());
                    }
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        None
    }
    
    /// Check if variable name suggests user input
    fn is_likely_user_input_variable(&self, name: &str) -> bool {
        let name_lower = name.to_lowercase();
        let user_input_patterns = [
            "input", "request", "req", "params", "query", "body", "form",
            "user", "client", "external", "untrusted", "raw"
        ];
        
        user_input_patterns.iter().any(|&pattern| name_lower.contains(pattern))
    }
    
    /// Trace taint flows from a source to potential sinks
    fn trace_taint_flows(&self, _tree: &SyntaxTree, source: &TaintSource, sinks: &[TaintSink]) -> Result<Vec<TaintFlow>> {
        let mut flows = Vec::new();
        
        // This is a simplified implementation
        // In practice, would need sophisticated data flow analysis
        for sink in sinks {
            // Check if source and sink are in the same function or have data flow connection
            if self.has_potential_flow(source, sink) {
                let flow = TaintFlow {
                    source: source.clone(),
                    sink: sink.clone(),
                    path: vec![], // Would be populated with actual data flow analysis
                    confidence: 0.7,
                    is_sanitized: false,
                    sanitizers: vec![],
                };
                flows.push(flow);
            }
        }
        
        Ok(flows)
    }
    
    /// Check if there's a potential flow between source and sink
    fn has_potential_flow(&self, source: &TaintSource, sink: &TaintSink) -> bool {
        // Simplified heuristic - same function or close proximity
        source.location.function == sink.location.function ||
        (source.location.line as i32 - sink.location.line as i32).abs() < 50
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parser;

    #[test]
    fn test_taint_analyzer_creation() {
        let analyzer = TaintAnalyzer::new("rust");
        assert_eq!(analyzer.language, "rust");
        assert!(!analyzer.sources.is_empty());
        assert!(!analyzer.sinks.is_empty());
    }

    #[test]
    fn test_javascript_taint_sources() {
        let analyzer = TaintAnalyzer::new("javascript");
        assert!(analyzer.sources.contains_key("req.query"));
        assert!(analyzer.sinks.contains_key("mysql.query"));
    }

    #[test]
    fn test_python_taint_analysis() {
        let analyzer = TaintAnalyzer::new("python");
        assert!(analyzer.sources.contains_key("request.args"));
        assert!(analyzer.sinks.contains_key("cursor.execute"));
    }
}
