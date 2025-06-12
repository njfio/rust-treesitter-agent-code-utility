use rust_tree_sitter::{CodebaseAnalyzer, build_call_graph, build_module_graph};
use std::fs;

#[test]
fn call_graph_simple() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    fs::write(temp.path().join("util.rs"), "pub fn helper() {}")?;
    fs::write(temp.path().join("main.rs"), "mod util; fn main() { util::helper(); }")?;

    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(temp.path())?;
    let graph = build_call_graph(&result);
    let dot = graph.to_dot();
    assert!(dot.contains("main.rs::main"));
    assert!(dot.contains("util.rs::helper"));
    assert!(dot.contains("main.rs::main"));
    Ok(())
}

#[test]
fn module_graph_simple() -> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    fs::write(temp.path().join("moda.rs"), "pub fn a() {}")?;
    fs::write(temp.path().join("modb.rs"), "use crate::moda; fn b() { moda::a(); }")?;

    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(temp.path())?;
    let graph = build_module_graph(&result);
    let dot = graph.to_dot();
    assert!(dot.contains("modb.rs"));
    assert!(dot.contains("moda"));
    Ok(())
}
