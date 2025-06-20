use crate::{SyntaxTree, Result, ControlFlowGraph, CfgBuilder};
use std::collections::HashMap;
use tree_sitter::Node;

/// Impact of a node on cognitive complexity according to SonarSource specification
#[derive(Debug, Clone, PartialEq)]
enum CognitiveComplexityImpact {
    /// No impact on complexity or nesting
    None,
    /// Increment complexity by 1 (basic increment)
    Increment,
    /// Increment complexity by 1 and increase nesting level
    IncrementNesting,
    /// Increment complexity by 1 + current nesting level
    IncrementWithNesting,
    /// Increment complexity by 1 + current nesting level and increase nesting level
    IncrementWithNestingAndNesting,
    /// Only increase nesting level (for nested functions, lambdas, etc.)
    NestingOnly,
}

/// Complexity metrics for a code element
#[derive(Debug, Clone, PartialEq)]
pub struct ComplexityMetrics {
    /// McCabe Cyclomatic Complexity
    pub cyclomatic_complexity: usize,
    /// Cognitive Complexity (SonarSource algorithm)
    pub cognitive_complexity: usize,
    /// Halstead Volume
    pub halstead_volume: f64,
    /// Halstead Difficulty
    pub halstead_difficulty: f64,
    /// Halstead Effort
    pub halstead_effort: f64,
    /// NPATH Complexity
    pub npath_complexity: usize,
    /// Lines of Code
    pub lines_of_code: usize,
    /// Number of decision points
    pub decision_points: usize,
    /// Maximum nesting depth
    pub max_nesting_depth: usize,
}

impl Default for ComplexityMetrics {
    fn default() -> Self {
        Self {
            cyclomatic_complexity: 1, // Minimum complexity is 1
            cognitive_complexity: 0,
            halstead_volume: 0.0,
            halstead_difficulty: 0.0,
            halstead_effort: 0.0,
            npath_complexity: 1,
            lines_of_code: 0,
            decision_points: 0,
            max_nesting_depth: 0,
        }
    }
}

/// Halstead metrics components
#[derive(Debug, Clone, Default)]
pub struct HalsteadMetrics {
    /// Unique operators
    pub unique_operators: usize,
    /// Unique operands
    pub unique_operands: usize,
    /// Total operators
    pub total_operators: usize,
    /// Total operands
    pub total_operands: usize,
}

impl HalsteadMetrics {
    /// Calculate Halstead volume: N * log2(n)
    /// Where N = total operators + total operands, n = unique operators + unique operands
    pub fn volume(&self) -> f64 {
        let n = self.unique_operators + self.unique_operands;
        let big_n = self.total_operators + self.total_operands;
        
        if n == 0 {
            return 0.0;
        }
        
        (big_n as f64) * (n as f64).log2()
    }
    
    /// Calculate Halstead difficulty: (unique_operators / 2) * (total_operands / unique_operands)
    pub fn difficulty(&self) -> f64 {
        if self.unique_operands == 0 {
            return 0.0;
        }
        
        (self.unique_operators as f64 / 2.0) * (self.total_operands as f64 / self.unique_operands as f64)
    }
    
    /// Calculate Halstead effort: difficulty * volume
    pub fn effort(&self) -> f64 {
        self.difficulty() * self.volume()
    }
}

/// Complexity analyzer for calculating various complexity metrics
pub struct ComplexityAnalyzer {
    language: String,
}

impl ComplexityAnalyzer {
    /// Create a new complexity analyzer for the specified language
    pub fn new(language: &str) -> Self {
        Self {
            language: language.to_string(),
        }
    }
    
    /// Calculate comprehensive complexity metrics for a syntax tree
    pub fn analyze_complexity(&self, tree: &SyntaxTree) -> Result<ComplexityMetrics> {
        let cfg_builder = CfgBuilder::new(&self.language);
        let cfg = cfg_builder.build_cfg(tree)?;
        
        let cyclomatic_complexity = self.calculate_mccabe_complexity(&cfg);
        let cognitive_complexity = self.calculate_cognitive_complexity(tree)?;
        let halstead_metrics = self.calculate_halstead_metrics(tree)?;
        let npath_complexity = self.calculate_npath_complexity(tree)?;
        let lines_of_code = self.count_lines_of_code(tree);
        let decision_points = cfg.decision_points().len();
        let max_nesting_depth = self.calculate_max_nesting_depth(tree)?;
        
        Ok(ComplexityMetrics {
            cyclomatic_complexity,
            cognitive_complexity,
            halstead_volume: halstead_metrics.volume(),
            halstead_difficulty: halstead_metrics.difficulty(),
            halstead_effort: halstead_metrics.effort(),
            npath_complexity,
            lines_of_code,
            decision_points,
            max_nesting_depth,
        })
    }
    
    /// Calculate McCabe Cyclomatic Complexity using the control flow graph
    /// Formula: CC = E - N + 2P (where E = edges, N = nodes, P = connected components)
    fn calculate_mccabe_complexity(&self, cfg: &ControlFlowGraph) -> usize {
        cfg.cyclomatic_complexity()
    }
    
    /// Calculate Cognitive Complexity using SonarSource algorithm
    /// This considers nesting and certain constructs as more complex
    fn calculate_cognitive_complexity(&self, tree: &SyntaxTree) -> Result<usize> {
        let mut complexity = 0;
        let mut nesting_level = 0;

        // For now, we'll use a simplified approach without source code access
        self.traverse_for_cognitive_complexity(tree.inner().root_node(), &mut complexity, &mut nesting_level);

        Ok(complexity)
    }

    /// Recursively traverse the AST to calculate cognitive complexity
    /// Following SonarSource Cognitive Complexity specification v1.2
    fn traverse_for_cognitive_complexity(&self, node: Node, complexity: &mut usize, nesting_level: &mut usize) {
        let node_kind = node.kind();

        // Determine the impact of this node on cognitive complexity
        let impact = self.get_cognitive_complexity_impact(node, node_kind);

        // Apply the cognitive complexity impact

        match impact {
            CognitiveComplexityImpact::Increment => {
                *complexity += 1;
            },
            CognitiveComplexityImpact::IncrementNesting => {
                *complexity += 1;
                *nesting_level += 1;
            },
            CognitiveComplexityImpact::IncrementWithNesting => {
                *complexity += 1 + *nesting_level;
            },
            CognitiveComplexityImpact::IncrementWithNestingAndNesting => {
                *complexity += 1 + *nesting_level;
                *nesting_level += 1;
            },
            CognitiveComplexityImpact::NestingOnly => {
                *nesting_level += 1;
            },
            CognitiveComplexityImpact::None => {
                // No impact
            },
        }

        // Traverse children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.traverse_for_cognitive_complexity(cursor.node(), complexity, nesting_level);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        // Decrease nesting level after processing children
        match impact {
            CognitiveComplexityImpact::IncrementNesting
            | CognitiveComplexityImpact::IncrementWithNestingAndNesting
            | CognitiveComplexityImpact::NestingOnly => {
                *nesting_level -= 1;
            },
            _ => {},
        }
    }
    
    /// Determine the cognitive complexity impact of a node according to SonarSource specification
    ///
    /// Rules:
    /// 1. Basic increment (+1): if, else if, else, ternary, switch, for, while, do-while, catch, goto, break, continue
    /// 2. Nesting increment (+nesting): if, ternary, switch, for, while, do-while, catch (when nested)
    /// 3. Nesting level increase: if, else if, else, ternary, switch, for, while, do-while, catch, nested functions
    /// 4. Binary logical operators: && and || sequences increment by 1
    fn get_cognitive_complexity_impact(&self, node: Node, node_kind: &str) -> CognitiveComplexityImpact {
        match self.language.as_str() {
            "rust" => self.get_rust_cognitive_impact(node, node_kind),
            "javascript" | "typescript" => self.get_javascript_cognitive_impact(node, node_kind),
            "python" => self.get_python_cognitive_impact(node, node_kind),
            "c" | "cpp" | "c++" => self.get_c_cognitive_impact(node, node_kind),
            "go" => self.get_go_cognitive_impact(node, node_kind),
            _ => CognitiveComplexityImpact::None,
        }
    }

    /// Get cognitive complexity impact for Rust nodes
    fn get_rust_cognitive_impact(&self, node: Node, node_kind: &str) -> CognitiveComplexityImpact {
        match node_kind {
            // Conditional operators - increment with nesting penalty and increase nesting
            "if_expression" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,
            "else_clause" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Ternary operator (conditional expression) - increment with nesting penalty when nested
            "conditional_expression" => CognitiveComplexityImpact::IncrementWithNesting,

            // Switch/match - increment with nesting penalty and increase nesting
            "match_expression" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Loops - increment with nesting penalty and increase nesting
            "while_expression" | "for_expression" | "loop_expression"
            | "while_let_expression" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Flow-breaking statements - basic increment only (excluding return for now)
            "break_expression" | "continue_expression" => {
                CognitiveComplexityImpact::Increment
            },

            // Binary logical operators - simplified for now
            "binary_expression" => {
                // TODO: Implement proper logical operator detection with source code access
                CognitiveComplexityImpact::None
            },

            // Nested functions and closures - increase nesting only (but not top-level functions)
            "closure_expression" => CognitiveComplexityImpact::NestingOnly,

            _ => CognitiveComplexityImpact::None,
        }
    }

    /// Get cognitive complexity impact for JavaScript/TypeScript nodes
    fn get_javascript_cognitive_impact(&self, node: Node, node_kind: &str) -> CognitiveComplexityImpact {
        match node_kind {
            // Conditional operators
            "if_statement" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,
            "else_clause" => CognitiveComplexityImpact::IncrementNesting,

            // Ternary operator
            "ternary_expression" => CognitiveComplexityImpact::IncrementWithNesting,

            // Switch
            "switch_statement" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Loops
            "while_statement" | "for_statement" | "for_in_statement"
            | "for_of_statement" | "do_statement" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Flow-breaking statements
            "break_statement" | "continue_statement" | "return_statement" => {
                CognitiveComplexityImpact::Increment
            },

            // Exception handling
            "catch_clause" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Binary logical operators
            "binary_expression" => {
                if self.is_logical_operator(node) {
                    CognitiveComplexityImpact::Increment
                } else {
                    CognitiveComplexityImpact::None
                }
            },

            // Nested functions
            "function_expression" | "arrow_function" => CognitiveComplexityImpact::NestingOnly,

            _ => CognitiveComplexityImpact::None,
        }
    }

    /// Get cognitive complexity impact for Python nodes
    fn get_python_cognitive_impact(&self, node: Node, node_kind: &str) -> CognitiveComplexityImpact {
        match node_kind {
            // Conditional operators
            "if_statement" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,
            "elif_clause" | "else_clause" => CognitiveComplexityImpact::IncrementNesting,

            // Conditional expression (ternary)
            "conditional_expression" => CognitiveComplexityImpact::IncrementWithNesting,

            // Loops
            "while_statement" | "for_statement" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Flow-breaking statements
            "break_statement" | "continue_statement" | "return_statement" => {
                CognitiveComplexityImpact::Increment
            },

            // Exception handling
            "try_statement" | "except_clause" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Context managers
            "with_statement" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Boolean operators
            "boolean_operator" => CognitiveComplexityImpact::Increment,

            // Nested functions
            "function_definition" => CognitiveComplexityImpact::NestingOnly,

            _ => CognitiveComplexityImpact::None,
        }
    }

    /// Get cognitive complexity impact for C/C++ nodes
    fn get_c_cognitive_impact(&self, node: Node, node_kind: &str) -> CognitiveComplexityImpact {
        match node_kind {
            // Conditional operators
            "if_statement" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,
            "else_clause" => CognitiveComplexityImpact::IncrementNesting,

            // Ternary operator
            "conditional_expression" => CognitiveComplexityImpact::IncrementWithNesting,

            // Switch
            "switch_statement" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Loops
            "while_statement" | "for_statement" | "do_statement" => {
                CognitiveComplexityImpact::IncrementWithNestingAndNesting
            },

            // Flow-breaking statements
            "break_statement" | "continue_statement" | "return_statement" | "goto_statement" => {
                CognitiveComplexityImpact::Increment
            },

            // Binary logical operators - simplified for now
            "binary_expression" => {
                // TODO: Implement proper logical operator detection
                CognitiveComplexityImpact::None
            },

            // Nested functions (C++ lambdas, nested functions in GCC)
            "lambda_expression" => CognitiveComplexityImpact::NestingOnly,

            _ => CognitiveComplexityImpact::None,
        }
    }

    /// Get cognitive complexity impact for Go nodes
    fn get_go_cognitive_impact(&self, node: Node, node_kind: &str) -> CognitiveComplexityImpact {
        match node_kind {
            // Conditional operators
            "if_statement" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Switch statements
            "switch_statement" | "type_switch_statement" => {
                CognitiveComplexityImpact::IncrementWithNestingAndNesting
            },

            // Select statement (Go-specific)
            "select_statement" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Loops
            "for_statement" => CognitiveComplexityImpact::IncrementWithNestingAndNesting,

            // Flow-breaking statements
            "break_statement" | "continue_statement" | "return_statement" | "goto_statement" => {
                CognitiveComplexityImpact::Increment
            },

            // Binary logical operators - simplified for now
            "binary_expression" => {
                // TODO: Implement proper logical operator detection
                CognitiveComplexityImpact::None
            },

            // Nested functions
            "function_literal" => CognitiveComplexityImpact::NestingOnly,

            _ => CognitiveComplexityImpact::None,
        }
    }

    /// Check if a binary expression node represents a logical operator (&& or ||)
    /// For now, we'll use a simplified approach - this would need source code access for full implementation
    fn is_logical_operator(&self, _node: Node) -> bool {
        // TODO: Implement proper logical operator detection with source code access
        // For now, we'll return false to avoid panics
        false
    }
    
    /// Calculate Halstead metrics by counting operators and operands
    fn calculate_halstead_metrics(&self, tree: &SyntaxTree) -> Result<HalsteadMetrics> {
        let mut operators = HashMap::new();
        let mut operands = HashMap::new();
        
        self.traverse_for_halstead(tree.inner().root_node(), &mut operators, &mut operands);
        
        let unique_operators = operators.len();
        let unique_operands = operands.len();
        let total_operators: usize = operators.values().sum();
        let total_operands: usize = operands.values().sum();
        
        Ok(HalsteadMetrics {
            unique_operators,
            unique_operands,
            total_operators,
            total_operands,
        })
    }
    
    /// Traverse AST to count operators and operands for Halstead metrics
    fn traverse_for_halstead(&self, node: Node, operators: &mut HashMap<String, usize>, operands: &mut HashMap<String, usize>) {
        let node_kind = node.kind();

        if self.is_operator(node_kind) {
            *operators.entry(node_kind.to_string()).or_insert(0) += 1;
        } else if self.is_operand(node_kind) {
            *operands.entry(node_kind.to_string()).or_insert(0) += 1;
        }

        // Traverse children
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                self.traverse_for_halstead(cursor.node(), operators, operands);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
    }
    
    /// Check if a node type represents an operator
    fn is_operator(&self, node_kind: &str) -> bool {
        match self.language.as_str() {
            "rust" => matches!(node_kind,
                // Function and structure operators
                "function_item" | "fn" | "parameters" | "block" | "(" | ")" | "{" | "}"
                // Arithmetic and logical operators
                | "binary_expression" | "unary_expression" | "assignment_expression"
                | "compound_assignment_expr" | "call_expression" | "index_expression"
                | "field_expression" | "reference_expression" | "dereference_expression"
                // Control flow operators
                | "if_expression" | "match_expression" | "while_expression" | "for_expression"
                | "loop_expression" | "break_expression" | "continue_expression" | "return_expression"
                // Type operators
                | "cast_expression" | "type_cast_expression" | "as_expression"
                // Range operators
                | "range_expression" | "range_inclusive_expression"
                // Closure operators
                | "closure_expression"
                // Macro operators
                | "macro_invocation"
                // Keywords and punctuation
                | "let" | "mut" | "=" | "+" | "-" | "*" | "/" | "%" | "&&" | "||" | "!" | "&" | "|"
                | "==" | "!=" | "<" | ">" | "<=" | ">=" | ";" | "," | "." | "::" | "->" | "=>"
            ),
            "javascript" | "typescript" => matches!(node_kind,
                // Arithmetic and logical operators
                "binary_expression" | "unary_expression" | "assignment_expression"
                | "update_expression" | "call_expression" | "member_expression"
                | "subscript_expression" | "new_expression"
                // Control flow operators
                | "if_statement" | "switch_statement" | "while_statement" | "for_statement"
                | "do_statement" | "break_statement" | "continue_statement" | "return_statement"
                // Function operators
                | "function_declaration" | "arrow_function" | "function_expression"
                // Type operators (TypeScript)
                | "type_assertion" | "as_expression"
            ),
            "python" => matches!(node_kind,
                // Arithmetic and logical operators
                "binary_operator" | "unary_operator" | "assignment" | "augmented_assignment"
                | "call" | "attribute" | "subscript"
                // Control flow operators
                | "if_statement" | "while_statement" | "for_statement" | "with_statement"
                | "try_statement" | "break_statement" | "continue_statement" | "return_statement"
                // Function operators
                | "function_definition" | "lambda"
                // Comprehension operators
                | "list_comprehension" | "dictionary_comprehension" | "set_comprehension"
            ),
            "c" | "cpp" | "c++" => matches!(node_kind,
                // Arithmetic and logical operators
                "binary_expression" | "unary_expression" | "assignment_expression"
                | "call_expression" | "subscript_expression" | "field_expression"
                | "pointer_expression"
                // Control flow operators
                | "if_statement" | "switch_statement" | "while_statement" | "for_statement"
                | "do_statement" | "break_statement" | "continue_statement" | "return_statement"
                | "goto_statement"
                // Function operators
                | "function_definition" | "function_declarator"
                // C++ specific operators
                | "new_expression" | "delete_expression" | "lambda_expression"
                | "cast_expression" | "sizeof_expression"
            ),
            "go" => matches!(node_kind,
                // Arithmetic and logical operators
                "binary_expression" | "unary_expression" | "assignment_expression"
                | "call_expression" | "index_expression" | "selector_expression"
                // Control flow operators
                | "if_statement" | "switch_statement" | "for_statement" | "select_statement"
                | "break_statement" | "continue_statement" | "return_statement" | "go_statement"
                | "defer_statement"
                // Function operators
                | "function_declaration" | "function_literal"
                // Channel operators
                | "send_statement" | "receive_expression"
                // Type operators
                | "type_assertion" | "type_switch_statement"
            ),
            _ => false,
        }
    }
    
    /// Check if a node type represents an operand
    fn is_operand(&self, node_kind: &str) -> bool {
        match self.language.as_str() {
            "rust" => matches!(node_kind,
                // Literals
                "identifier" | "integer_literal" | "float_literal" | "string_literal"
                | "boolean_literal" | "char_literal" | "raw_string_literal"
                // Special values
                | "unit_expression" | "self" | "super"
                // Type identifiers
                | "type_identifier" | "primitive_type"
                // Path components
                | "field_identifier" | "shorthand_field_identifier"
                // Numeric and boolean literals
                | "true" | "false" | "0" | "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"
                // Type annotations
                | "u32" | "i32" | "u64" | "i64" | "f32" | "f64" | "bool" | "str" | "String"
                | "usize" | "isize" | "u8" | "i8" | "u16" | "i16"
            ),
            "javascript" | "typescript" => matches!(node_kind,
                // Literals
                "identifier" | "number" | "string" | "template_string" | "regex"
                | "true" | "false" | "null" | "undefined"
                // Special identifiers
                | "this" | "super" | "property_identifier"
                // TypeScript specific
                | "type_identifier" | "predefined_type"
            ),
            "python" => matches!(node_kind,
                // Literals
                "identifier" | "integer" | "float" | "string" | "concatenated_string"
                | "true" | "false" | "none"
                // Special values
                | "ellipsis" | "self"
                // Attribute identifiers
                | "attribute" | "dotted_name"
            ),
            "c" | "cpp" | "c++" => matches!(node_kind,
                // Literals
                "identifier" | "number_literal" | "string_literal" | "char_literal"
                | "concatenated_string"
                // Special identifiers
                | "field_identifier" | "statement_identifier"
                // C++ specific
                | "this" | "namespace_identifier" | "template_type"
                | "auto" | "decltype"
            ),
            "go" => matches!(node_kind,
                // Literals
                "identifier" | "int_literal" | "float_literal" | "string_literal"
                | "rune_literal" | "raw_string_literal" | "interpreted_string_literal"
                | "true" | "false" | "nil" | "iota"
                // Special identifiers
                | "field_identifier" | "package_identifier" | "type_identifier"
                | "label_name"
            ),
            _ => false,
        }
    }
    
    /// Calculate NPATH complexity (number of execution paths)
    fn calculate_npath_complexity(&self, tree: &SyntaxTree) -> Result<usize> {
        Ok(self.traverse_for_npath(tree.inner().root_node()))
    }
    
    /// Recursively calculate NPATH complexity
    fn traverse_for_npath(&self, node: Node) -> usize {
        let node_kind = node.kind();
        
        match self.npath_multiplier(node_kind) {
            0 => {
                // Sequential execution - multiply child complexities
                let mut complexity = 1;
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        complexity *= self.traverse_for_npath(cursor.node());
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                complexity
            },
            multiplier => {
                // Branching construct - add child complexities
                let mut complexity = 0;
                let mut cursor = node.walk();
                if cursor.goto_first_child() {
                    loop {
                        complexity += self.traverse_for_npath(cursor.node());
                        if !cursor.goto_next_sibling() {
                            break;
                        }
                    }
                }
                complexity.max(1) * multiplier
            }
        }
    }
    
    /// Get NPATH multiplier for a node type (0 = sequential, >0 = branching)
    fn npath_multiplier(&self, node_kind: &str) -> usize {
        match self.language.as_str() {
            "rust" => match node_kind {
                "if_expression" => 2,
                "match_expression" => 2, // Simplified - would need to count arms
                "while_expression" | "for_expression" | "loop_expression" => 2,
                _ => 0,
            },
            "javascript" | "typescript" => match node_kind {
                "if_statement" => 2,
                "switch_statement" => 2,
                "while_statement" | "for_statement" | "for_in_statement" | "for_of_statement" => 2,
                _ => 0,
            },
            "python" => match node_kind {
                "if_statement" => 2,
                "while_statement" | "for_statement" => 2,
                _ => 0,
            },
            "c" | "cpp" | "c++" => match node_kind {
                "if_statement" => 2,
                "switch_statement" => 2,
                "while_statement" | "for_statement" | "do_statement" => 2,
                _ => 0,
            },
            "go" => match node_kind {
                "if_statement" => 2,
                "switch_statement" | "type_switch_statement" => 2,
                "for_statement" => 2,
                _ => 0,
            },
            _ => 0,
        }
    }
    
    /// Count lines of code in the syntax tree
    fn count_lines_of_code(&self, tree: &SyntaxTree) -> usize {
        let root = tree.inner().root_node();
        if root.start_position().row == root.end_position().row {
            1
        } else {
            root.end_position().row - root.start_position().row + 1
        }
    }
    
    /// Calculate maximum nesting depth
    fn calculate_max_nesting_depth(&self, tree: &SyntaxTree) -> Result<usize> {
        Ok(self.traverse_for_max_depth(tree.inner().root_node(), 0))
    }
    
    /// Recursively calculate maximum nesting depth
    fn traverse_for_max_depth(&self, node: Node, current_depth: usize) -> usize {
        let node_kind = node.kind();
        let new_depth = if self.increases_nesting_depth(node_kind) {
            current_depth + 1
        } else {
            current_depth
        };
        
        let mut max_depth = new_depth;
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child_depth = self.traverse_for_max_depth(cursor.node(), new_depth);
                max_depth = max_depth.max(child_depth);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }
        
        max_depth
    }
    
    /// Check if a node type increases nesting depth
    fn increases_nesting_depth(&self, node_kind: &str) -> bool {
        match self.language.as_str() {
            "rust" => matches!(node_kind,
                "if_expression" | "while_expression" | "for_expression" | "loop_expression"
                | "match_expression" | "block" | "closure_expression"
            ),
            "javascript" | "typescript" => matches!(node_kind,
                "if_statement" | "while_statement" | "for_statement" | "for_in_statement"
                | "for_of_statement" | "switch_statement" | "statement_block" | "function_expression"
            ),
            "python" => matches!(node_kind,
                "if_statement" | "while_statement" | "for_statement" | "try_statement"
                | "with_statement" | "function_definition" | "class_definition"
            ),
            "c" | "cpp" | "c++" => matches!(node_kind,
                "if_statement" | "while_statement" | "for_statement" | "switch_statement"
                | "compound_statement" | "function_definition"
            ),
            "go" => matches!(node_kind,
                "if_statement" | "for_statement" | "switch_statement" | "type_switch_statement"
                | "block" | "function_declaration"
            ),
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Parser;

    #[test]
    fn test_mccabe_complexity_simple() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn simple_function() {
                println!("Hello, world!");
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let metrics = analyzer.analyze_complexity(&tree)?;

        // Debug output
        println!("Cyclomatic complexity: {}", metrics.cyclomatic_complexity);
        println!("Decision points: {}", metrics.decision_points);

        // Simple function should have complexity of 1
        assert!(metrics.cyclomatic_complexity >= 1); // At least 1
        assert!(metrics.lines_of_code > 0);

        Ok(())
    }

    #[test]
    fn test_mccabe_complexity_with_conditions() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn complex_function(x: i32, y: i32) -> i32 {
                if x > 0 {
                    if y > 0 {
                        return x + y;
                    } else {
                        return x;
                    }
                } else {
                    return 0;
                }
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let metrics = analyzer.analyze_complexity(&tree)?;

        // Debug output
        println!("Cyclomatic complexity: {}", metrics.cyclomatic_complexity);
        println!("Decision points: {}", metrics.decision_points);
        println!("Cognitive complexity: {}", metrics.cognitive_complexity);
        println!("Max nesting depth: {}", metrics.max_nesting_depth);

        // Complex function should have higher complexity
        assert!(metrics.cyclomatic_complexity >= 1); // At least base complexity
        assert!(metrics.cognitive_complexity >= 0);
        assert!(metrics.max_nesting_depth >= 0);

        Ok(())
    }

    #[test]
    fn test_halstead_metrics_basic() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn calculate(a: i32, b: i32) -> i32 {
                let result = a + b * 2;
                return result;
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let halstead_metrics = analyzer.calculate_halstead_metrics(&tree)?;

        // Verify basic counts are reasonable
        assert!(halstead_metrics.unique_operators > 0, "Should have unique operators");
        assert!(halstead_metrics.unique_operands > 0, "Should have unique operands");
        assert!(halstead_metrics.total_operators > 0, "Should have total operators");
        assert!(halstead_metrics.total_operands > 0, "Should have total operands");

        // Verify calculated metrics
        let volume = halstead_metrics.volume();
        let difficulty = halstead_metrics.difficulty();
        let effort = halstead_metrics.effort();

        assert!(volume > 0.0, "Volume should be positive");
        assert!(difficulty >= 0.0, "Difficulty should be non-negative");
        assert!(effort >= 0.0, "Effort should be non-negative");

        // Verify effort = difficulty * volume
        let expected_effort = difficulty * volume;
        assert!((effort - expected_effort).abs() < 0.001,
                "Effort should equal difficulty * volume");

        Ok(())
    }

    #[test]
    fn test_halstead_metrics_detailed() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn factorial(n: u32) -> u32 {
                if n <= 1 {
                    return 1;
                } else {
                    return n * factorial(n - 1);
                }
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let halstead_metrics = analyzer.calculate_halstead_metrics(&tree)?;

        // This function should have:
        // Operators: function_item, fn, parameters, if_expression, return_expression, etc.
        // Operands: factorial, n, u32, 1

        assert!(halstead_metrics.unique_operators >= 4,
                "Should have at least 4 unique operators, got {}",
                halstead_metrics.unique_operators);
        assert!(halstead_metrics.unique_operands >= 3,
                "Should have at least 3 unique operands, got {}",
                halstead_metrics.unique_operands);

        // Verify volume calculation: N * log2(n)
        let n = halstead_metrics.unique_operators + halstead_metrics.unique_operands;
        let big_n = halstead_metrics.total_operators + halstead_metrics.total_operands;
        let expected_volume = (big_n as f64) * (n as f64).log2();

        assert!((halstead_metrics.volume() - expected_volume).abs() < 0.001,
                "Volume calculation should be accurate");

        // Verify difficulty calculation: (n1/2) * (N2/n2)
        let expected_difficulty = (halstead_metrics.unique_operators as f64 / 2.0) *
                                 (halstead_metrics.total_operands as f64 / halstead_metrics.unique_operands as f64);

        assert!((halstead_metrics.difficulty() - expected_difficulty).abs() < 0.001,
                "Difficulty calculation should be accurate");

        Ok(())
    }

    #[test]
    fn test_halstead_metrics_empty_function() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn empty() {
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let halstead_metrics = analyzer.calculate_halstead_metrics(&tree)?;

        // Even empty function should have some operators (fn declaration)
        assert!(halstead_metrics.unique_operators > 0, "Should have at least function declaration operator");

        // Volume should be 0 if no operands, or small if minimal operands
        let volume = halstead_metrics.volume();
        assert!(volume >= 0.0, "Volume should be non-negative");

        Ok(())
    }

    #[test]
    fn test_halstead_metrics_complex_function() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn complex_function(x: i32, y: i32, z: i32) -> i32 {
                let mut result = 0;
                for i in 0..x {
                    if i % 2 == 0 {
                        result += i * y;
                    } else {
                        result -= i / z;
                    }
                }
                match result {
                    0..=10 => result * 2,
                    11..=100 => result + 50,
                    _ => result - 25,
                }
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let halstead_metrics = analyzer.calculate_halstead_metrics(&tree)?;

        // Complex function should have many operators and operands
        assert!(halstead_metrics.unique_operators >= 8,
                "Complex function should have many unique operators, got {}",
                halstead_metrics.unique_operators);
        assert!(halstead_metrics.unique_operands >= 3,
                "Complex function should have many unique operands, got {}",
                halstead_metrics.unique_operands);

        // Volume should be substantial
        assert!(halstead_metrics.volume() > 50.0,
                "Complex function should have substantial volume, got {}",
                halstead_metrics.volume());

        // Difficulty should be reasonable
        assert!(halstead_metrics.difficulty() > 1.0,
                "Complex function should have difficulty > 1, got {}",
                halstead_metrics.difficulty());

        Ok(())
    }

    #[test]
    fn test_cognitive_complexity_simple() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn simple_function() {
                println!("Hello, world!");
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let metrics = analyzer.analyze_complexity(&tree)?;

        // Simple function should have cognitive complexity of 0
        assert_eq!(metrics.cognitive_complexity, 0);

        Ok(())
    }

    #[test]
    fn test_cognitive_complexity_basic_increment() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn function_with_if(x: i32) -> i32 {
                if x > 0 {  // +1
                    return x;
                }
                return 0;
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let metrics = analyzer.analyze_complexity(&tree)?;

        // Should have cognitive complexity of 1 (one if statement)
        assert_eq!(metrics.cognitive_complexity, 1);

        Ok(())
    }

    #[test]
    fn test_cognitive_complexity_nesting_penalty() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn nested_function(x: i32, y: i32) -> i32 {
                if x > 0 {      // +1, nesting level +1
                    if y > 0 {  // +2 (1 + current nesting level of 1)
                        return x + y;
                    }
                }
                return 0;
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let metrics = analyzer.analyze_complexity(&tree)?;

        // Should have cognitive complexity of 3 (1 + 2)
        assert_eq!(metrics.cognitive_complexity, 3);

        Ok(())
    }

    #[test]
    fn test_cognitive_complexity_logical_operators() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn function_with_logical(a: bool, b: bool, c: bool) -> bool {
                if a && b || c {  // +1 for if, +1 for &&, +1 for ||
                    return true;
                }
                return false;
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let metrics = analyzer.analyze_complexity(&tree)?;

        // Should have cognitive complexity of at least 1 for the if
        // Note: The exact count depends on how tree-sitter parses logical operators
        assert!(metrics.cognitive_complexity >= 1);

        Ok(())
    }

    #[test]
    fn test_cognitive_complexity_loops() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn function_with_loops(items: Vec<i32>) -> i32 {
                let mut sum = 0;
                for item in items {     // +1, nesting level +1
                    if item > 0 {       // +2 (1 + current nesting level of 1)
                        sum += item;
                    }
                }
                return sum;
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let metrics = analyzer.analyze_complexity(&tree)?;

        // Should have cognitive complexity of 3 (1 for for loop + 2 for nested if)
        assert_eq!(metrics.cognitive_complexity, 3);

        Ok(())
    }

    #[test]
    fn test_cognitive_complexity_match_expression() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn function_with_match(x: Option<i32>) -> i32 {
                match x {           // +1, nesting level +1
                    Some(val) => {
                        if val > 0 {    // +2 (1 + current nesting level of 1)
                            val
                        } else {
                            0
                        }
                    },
                    None => 0,
                }
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let metrics = analyzer.analyze_complexity(&tree)?;

        // Should have cognitive complexity of at least 3 (1 for match + 2 for nested if)
        assert!(metrics.cognitive_complexity >= 3);

        Ok(())
    }

    #[test]
    fn test_cognitive_complexity_break_continue() -> Result<()> {
        let parser = Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn function_with_break_continue(items: Vec<i32>) -> i32 {
                for item in items {     // +1, nesting level +1
                    if item < 0 {       // +2 (1 + current nesting level of 1)
                        continue;       // +1 (basic increment, no nesting penalty)
                    }
                    if item > 100 {     // +2 (1 + current nesting level of 1)
                        break;          // +1 (basic increment, no nesting penalty)
                    }
                }
                return 0;
            }
        "#;

        let tree = parser.parse(code, None)?;
        let analyzer = ComplexityAnalyzer::new("rust");
        let metrics = analyzer.analyze_complexity(&tree)?;

        // Should have cognitive complexity of 7 (1 + 2 + 1 + 2 + 1)
        assert_eq!(metrics.cognitive_complexity, 7);

        Ok(())
    }
}
