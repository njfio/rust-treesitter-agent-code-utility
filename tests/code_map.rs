use assert_cmd::Command;
use serde_json::Value;

fn parse_json_from_output(output: &[u8]) -> Value {
    let text = String::from_utf8_lossy(output);
    let start = text.find('{').unwrap_or(0);
    serde_json::from_str(&text[start..]).unwrap()
}

#[test]
fn cli_generates_tree_map_json() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("tree-sitter-cli")?
        .args(["map", "test_files", "--map-type", "tree", "--format", "json", "--max-depth", "2"])
        .output()?;
    assert!(output.status.success());
    let json = parse_json_from_output(&output.stdout);
    assert!(json.get("files").is_some());
    Ok(())
}

#[test]
fn cli_generates_symbol_map_json() -> Result<(), Box<dyn std::error::Error>> {
    let output = Command::cargo_bin("tree-sitter-cli")?
        .args(["map", "test_files", "--map-type", "symbols", "--format", "json"])
        .output()?;
    assert!(output.status.success());
    let json = parse_json_from_output(&output.stdout);
    assert!(json.as_object().map(|o| !o.is_empty()).unwrap_or(false));
    Ok(())
}
