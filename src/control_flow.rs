use crate::{SyntaxTree, Result};
use petgraph::graph::{DiGraph, NodeIndex};
use std::collections::HashMap;


/// Represents a node in the control flow graph
#[derive(Debug, Clone, PartialEq)]
pub enum CfgNodeType {
    /// Entry point of a function or block
    Entry,
    /// Exit point of a function or block
    Exit,
    /// Basic block containing sequential statements
    BasicBlock {
        statements: Vec<String>,
        start_byte: usize,
        end_byte: usize,
    },
    /// Conditional branch (if, while, for, etc.)
    Branch {
        condition: String,
        node_type: String,
        start_byte: usize,
    },
    /// Function call
    Call {
        function_name: String,
        arguments: Vec<String>,
        start_byte: usize,
    },
    /// Return statement
    Return {
        value: Option<String>,
        start_byte: usize,
    },
}

/// Control Flow Graph representation
#[derive(Debug, Clone)]
pub struct ControlFlowGraph {
    /// The underlying directed graph
    pub graph: DiGraph<CfgNodeType, ()>,
    /// Entry node index
    pub entry: NodeIndex,
    /// Exit node index
    pub exit: NodeIndex,
    /// Mapping from source byte positions to graph nodes
    pub byte_to_node: HashMap<usize, NodeIndex>,
}

/// Control Flow Graph builder
pub struct CfgBuilder {
    language: String,
}

impl CfgBuilder {
    /// Create a new CFG builder for the specified language
    pub fn new(language: &str) -> Self {
        Self {
            language: language.to_string(),
        }
    }

    /// Build a control flow graph from an AST
    pub fn build_cfg(&self, tree: &SyntaxTree) -> Result<ControlFlowGraph> {
        let mut graph = DiGraph::new();
        let mut byte_to_node = HashMap::new();

        // Create entry and exit nodes
        let entry = graph.add_node(CfgNodeType::Entry);
        let exit = graph.add_node(CfgNodeType::Exit);

        // Find function definitions and build CFGs for each
        let functions = self.find_functions(tree)?;

        if functions.is_empty() {
            // If no functions found, build CFG for the entire file
            self.build_cfg_for_node(&mut graph, &mut byte_to_node, tree.inner().root_node(), entry, exit)?;
        } else {
            // Build CFG for the first function (can be extended for multiple functions)
            if let Some(function_node) = functions.first() {
                self.build_cfg_for_function(&mut graph, &mut byte_to_node, *function_node, entry, exit)?;
            }
        }

        Ok(ControlFlowGraph {
            graph,
            entry,
            exit,
            byte_to_node,
        })
    }

    /// Find function definitions in the AST
    fn find_functions<'a>(&self, tree: &'a SyntaxTree) -> Result<Vec<tree_sitter::Node<'a>>> {
        let function_kinds = match self.language.as_str() {
            "rust" => vec!["function_item", "impl_item"],
            "javascript" | "typescript" => vec!["function_declaration", "function_expression", "arrow_function", "method_definition"],
            "python" => vec!["function_definition", "async_function_definition"],
            "c" | "cpp" | "c++" => vec!["function_definition"],
            "go" => vec!["function_declaration", "method_declaration"],
            _ => vec!["function_declaration", "function_definition"],
        };

        let mut functions = Vec::new();
        let mut cursor = tree.inner().root_node().walk();

        self.traverse_for_functions(&mut cursor, &function_kinds, &mut functions);

        Ok(functions)
    }

    /// Traverse the AST to find function nodes
    fn traverse_for_functions<'a>(&self, cursor: &mut tree_sitter::TreeCursor<'a>, function_kinds: &[&str], functions: &mut Vec<tree_sitter::Node<'a>>) {
        let node = cursor.node();
        
        if function_kinds.contains(&node.kind()) {
            functions.push(node);
        }

        if cursor.goto_first_child() {
            loop {
                self.traverse_for_functions(cursor, function_kinds, functions);
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
            cursor.goto_parent();
        }
    }

    /// Build CFG for a specific function
    fn build_cfg_for_function(
        &self,
        graph: &mut DiGraph<CfgNodeType, ()>,
        byte_to_node: &mut HashMap<usize, NodeIndex>,
        function_node: tree_sitter::Node<'_>,
        entry: NodeIndex,
        exit: NodeIndex,
    ) -> Result<()> {
        // Find the function body
        let body = self.find_function_body(function_node)?;
        
        if let Some(body_node) = body {
            self.build_cfg_for_node(graph, byte_to_node, body_node, entry, exit)?;
        }

        Ok(())
    }

    /// Find the body of a function
    fn find_function_body<'a>(&self, function_node: tree_sitter::Node<'a>) -> Result<Option<tree_sitter::Node<'a>>> {
        let body_kinds = match self.language.as_str() {
            "rust" => vec!["block"],
            "javascript" | "typescript" => vec!["statement_block"],
            "python" => vec!["block"],
            "c" | "cpp" | "c++" => vec!["compound_statement"],
            "go" => vec!["block"],
            _ => vec!["block", "statement_block", "compound_statement"],
        };

        let mut cursor = function_node.walk();
        
        if cursor.goto_first_child() {
            loop {
                let node = cursor.node();
                if body_kinds.contains(&node.kind()) {
                    return Ok(Some(node));
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        Ok(None)
    }

    /// Build CFG for a specific AST node
    fn build_cfg_for_node(
        &self,
        graph: &mut DiGraph<CfgNodeType, ()>,
        byte_to_node: &mut HashMap<usize, NodeIndex>,
        node: tree_sitter::Node<'_>,
        entry: NodeIndex,
        exit: NodeIndex,
    ) -> Result<()> {
        match node.kind() {
            // Control flow statements
            kind if self.is_conditional(kind) => {
                self.build_conditional_cfg(graph, byte_to_node, node, entry, exit)?;
            }
            kind if self.is_loop(kind) => {
                self.build_loop_cfg(graph, byte_to_node, node, entry, exit)?;
            }
            kind if self.is_return(kind) => {
                self.build_return_cfg(graph, byte_to_node, node, entry, exit)?;
            }
            // Sequential statements
            _ => {
                self.build_sequential_cfg(graph, byte_to_node, node, entry, exit)?;
            }
        }

        Ok(())
    }

    /// Check if a node kind represents a conditional statement
    fn is_conditional(&self, kind: &str) -> bool {
        match self.language.as_str() {
            "rust" => matches!(kind, "if_expression" | "match_expression"),
            "javascript" | "typescript" => matches!(kind, "if_statement" | "switch_statement" | "conditional_expression"),
            "python" => matches!(kind, "if_statement" | "conditional_expression"),
            "c" | "cpp" | "c++" => matches!(kind, "if_statement" | "switch_statement" | "conditional_expression"),
            "go" => matches!(kind, "if_statement" | "switch_statement"),
            _ => kind.contains("if") || kind.contains("switch") || kind.contains("conditional"),
        }
    }

    /// Check if a node kind represents a loop statement
    fn is_loop(&self, kind: &str) -> bool {
        match self.language.as_str() {
            "rust" => matches!(kind, "for_expression" | "while_expression" | "loop_expression" | "while_let_expression"),
            "javascript" | "typescript" => matches!(kind, "for_statement" | "for_in_statement" | "for_of_statement" | "while_statement" | "do_statement"),
            "python" => matches!(kind, "for_statement" | "while_statement"),
            "c" | "cpp" | "c++" => matches!(kind, "for_statement" | "while_statement" | "do_statement"),
            "go" => matches!(kind, "for_statement"),
            _ => kind.contains("for") || kind.contains("while") || kind.contains("loop"),
        }
    }

    /// Check if a node kind represents a return statement
    fn is_return(&self, kind: &str) -> bool {
        kind.contains("return")
    }

    /// Build CFG for conditional statements
    fn build_conditional_cfg(
        &self,
        graph: &mut DiGraph<CfgNodeType, ()>,
        byte_to_node: &mut HashMap<usize, NodeIndex>,
        node: tree_sitter::Node<'_>,
        entry: NodeIndex,
        exit: NodeIndex,
    ) -> Result<()> {
        let condition_text = format!("{:?}", node.kind());
        let branch_node = graph.add_node(CfgNodeType::Branch {
            condition: condition_text,
            node_type: node.kind().to_string(),
            start_byte: node.start_byte(),
        });

        byte_to_node.insert(node.start_byte(), branch_node);
        graph.add_edge(entry, branch_node, ());

        // Process child nodes (then/else branches)
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                self.build_cfg_for_node(graph, byte_to_node, child, branch_node, exit)?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        graph.add_edge(branch_node, exit, ());
        Ok(())
    }

    /// Build CFG for loop statements
    fn build_loop_cfg(
        &self,
        graph: &mut DiGraph<CfgNodeType, ()>,
        byte_to_node: &mut HashMap<usize, NodeIndex>,
        node: tree_sitter::Node<'_>,
        entry: NodeIndex,
        exit: NodeIndex,
    ) -> Result<()> {
        let condition_text = format!("{:?}", node.kind());
        let loop_node = graph.add_node(CfgNodeType::Branch {
            condition: condition_text,
            node_type: node.kind().to_string(),
            start_byte: node.start_byte(),
        });

        byte_to_node.insert(node.start_byte(), loop_node);
        graph.add_edge(entry, loop_node, ());

        // Loop back edge
        graph.add_edge(loop_node, loop_node, ());

        // Process loop body
        let mut cursor = node.walk();
        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                self.build_cfg_for_node(graph, byte_to_node, child, loop_node, loop_node)?;
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        graph.add_edge(loop_node, exit, ());
        Ok(())
    }

    /// Build CFG for return statements
    fn build_return_cfg(
        &self,
        graph: &mut DiGraph<CfgNodeType, ()>,
        byte_to_node: &mut HashMap<usize, NodeIndex>,
        node: tree_sitter::Node<'_>,
        entry: NodeIndex,
        exit: NodeIndex,
    ) -> Result<()> {
        let return_value = format!("{:?}", node.kind());
        let return_node = graph.add_node(CfgNodeType::Return {
            value: if return_value.is_empty() { None } else { Some(return_value) },
            start_byte: node.start_byte(),
        });

        byte_to_node.insert(node.start_byte(), return_node);
        graph.add_edge(entry, return_node, ());
        graph.add_edge(return_node, exit, ());

        Ok(())
    }

    /// Build CFG for sequential statements
    fn build_sequential_cfg(
        &self,
        graph: &mut DiGraph<CfgNodeType, ()>,
        byte_to_node: &mut HashMap<usize, NodeIndex>,
        node: tree_sitter::Node<'_>,
        entry: NodeIndex,
        exit: NodeIndex,
    ) -> Result<()> {
        let mut statements = Vec::new();
        let mut cursor = node.walk();

        if cursor.goto_first_child() {
            loop {
                let child = cursor.node();
                if !self.is_control_flow_node(child.kind()) {
                    let statement = format!("{:?}", child.kind());
                    statements.push(statement);
                } else {
                    // Handle control flow nodes recursively
                    self.build_cfg_for_node(graph, byte_to_node, child, entry, exit)?;
                }
                if !cursor.goto_next_sibling() {
                    break;
                }
            }
        }

        if !statements.is_empty() {
            let basic_block = graph.add_node(CfgNodeType::BasicBlock {
                statements,
                start_byte: node.start_byte(),
                end_byte: node.end_byte(),
            });

            byte_to_node.insert(node.start_byte(), basic_block);
            graph.add_edge(entry, basic_block, ());
            graph.add_edge(basic_block, exit, ());
        }

        Ok(())
    }

    /// Check if a node represents a control flow construct
    fn is_control_flow_node(&self, kind: &str) -> bool {
        self.is_conditional(kind) || self.is_loop(kind) || self.is_return(kind)
    }
}

impl ControlFlowGraph {
    /// Calculate the cyclomatic complexity of the CFG
    pub fn cyclomatic_complexity(&self) -> usize {
        // McCabe's formula: CC = E - N + 2P
        // Where E = edges, N = nodes, P = connected components
        let edges = self.graph.edge_count();
        let nodes = self.graph.node_count();
        let components = 1; // Assuming single connected component for now

        if nodes <= 2 {
            return 1; // Minimum complexity for entry/exit only
        }

        // For a simple linear flow with entry and exit, complexity should be 1
        // Decision points add to complexity
        let decision_points = self.decision_points().len();
        1 + decision_points
    }

    /// Get all decision points in the CFG
    pub fn decision_points(&self) -> Vec<NodeIndex> {
        self.graph
            .node_indices()
            .filter(|&idx| {
                matches!(
                    self.graph[idx],
                    CfgNodeType::Branch { .. }
                )
            })
            .collect()
    }

    /// Get the number of paths through the CFG (NPATH complexity)
    pub fn npath_complexity(&self) -> usize {
        // Simplified NPATH calculation
        // In practice, this would require more sophisticated path counting
        let decision_points = self.decision_points().len();
        if decision_points == 0 {
            1
        } else {
            2_usize.pow(decision_points as u32)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cfg_construction_rust() -> Result<()> {
        let parser = crate::Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn test_function(x: i32) -> i32 {
                if x > 0 {
                    return x * 2;
                } else {
                    return 0;
                }
            }
        "#;

        let tree = parser.parse(code, None)?;
        let builder = CfgBuilder::new("rust");
        let cfg = builder.build_cfg(&tree)?;

        assert!(cfg.graph.node_count() > 2); // At least entry and exit
        assert!(cfg.cyclomatic_complexity() >= 2); // At least one decision point

        Ok(())
    }

    #[test]
    fn test_cfg_cyclomatic_complexity() -> Result<()> {
        let parser = crate::Parser::new(crate::Language::Rust)?;
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
        let builder = CfgBuilder::new("rust");
        let cfg = builder.build_cfg(&tree)?;

        // Should have higher complexity due to nested conditions
        assert!(cfg.cyclomatic_complexity() >= 3);

        Ok(())
    }

    #[test]
    fn test_cfg_decision_points() -> Result<()> {
        let parser = crate::Parser::new(crate::Language::Rust)?;
        let code = r#"
            fn test_loops(n: i32) -> i32 {
                let mut sum = 0;
                for i in 0..n {
                    if i % 2 == 0 {
                        sum += i;
                    }
                }
                return sum;
            }
        "#;

        let tree = parser.parse(code, None)?;
        let builder = CfgBuilder::new("rust");
        let cfg = builder.build_cfg(&tree)?;

        let decision_points = cfg.decision_points();
        assert!(!decision_points.is_empty()); // Should have at least one decision point

        Ok(())
    }
}
