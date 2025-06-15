use rust_tree_sitter::{CodebaseAnalyzer, Language, Parser};
use std::fs;
use tempfile::TempDir;

#[test]
fn test_enhanced_python_symbol_extraction() -> Result<(), Box<dyn std::error::Error>> {
    // Create a comprehensive Python test file
    let python_code = r#"
"""Module docstring for testing."""

import os
from typing import List, Dict, Optional
import asyncio

# Global variable
GLOBAL_CONSTANT = "test"
_private_global = 42

class BaseClass:
    """Base class docstring."""
    
    def __init__(self, value: int):
        """Initialize the base class."""
        self.value = value
    
    def regular_method(self) -> str:
        """Regular method docstring."""
        return f"Value: {self.value}"
    
    @property
    def value_property(self) -> int:
        """Property getter."""
        return self._value
    
    @staticmethod
    def static_method() -> str:
        """Static method."""
        return "static"
    
    @classmethod
    def class_method(cls) -> 'BaseClass':
        """Class method."""
        return cls(0)

@dataclass
class DataClass:
    """A dataclass example."""
    name: str
    age: int = 0

class DerivedClass(BaseClass):
    """Derived class with async methods."""
    
    async def async_method(self) -> None:
        """Async method docstring."""
        await asyncio.sleep(0.1)
    
    def _private_method(self):
        """Private method."""
        pass

async def async_function(data: List[str]) -> Dict[str, int]:
    """Async function with type hints."""
    return {item: len(item) for item in data}

def typed_function(x: int, y: Optional[str] = None) -> bool:
    """Function with comprehensive type hints."""
    return x > 0 and y is not None

# Lambda functions
process_data = lambda x: x * 2
filter_func = lambda items: [item for item in items if item > 0]

# Context manager usage
def file_processor():
    with open("test.txt", "r") as f:
        content = f.read()
    return content

class MetaExample(type):
    """Metaclass example."""
    pass

class WithMeta(metaclass=MetaExample):
    """Class with metaclass."""
    pass
"#;

    // Create temporary directory and file
    let temp_dir = TempDir::new()?;
    let python_file = temp_dir.path().join("test_module.py");
    fs::write(&python_file, python_code)?;

    // Analyze the file
    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_file(&python_file)?;

    // Verify symbols were extracted
    assert!(!result.symbols.is_empty(), "Should extract symbols from Python file");

    // Check for different symbol types
    let symbol_kinds: Vec<&str> = result.symbols.iter()
        .map(|s| s.kind.as_str())
        .collect();

    // Verify we have various symbol types
    assert!(symbol_kinds.contains(&"function"), "Should extract regular functions");
    assert!(symbol_kinds.contains(&"async_function"), "Should extract async functions");
    assert!(symbol_kinds.contains(&"class"), "Should extract classes");
    assert!(symbol_kinds.contains(&"dataclass"), "Should extract dataclasses");
    assert!(symbol_kinds.contains(&"property"), "Should extract properties");
    assert!(symbol_kinds.contains(&"static_method"), "Should extract static methods");
    assert!(symbol_kinds.contains(&"class_method"), "Should extract class methods");
    assert!(symbol_kinds.contains(&"method"), "Should extract methods");
    assert!(symbol_kinds.contains(&"lambda"), "Should extract lambda functions");
    assert!(symbol_kinds.contains(&"typed_function"), "Should extract typed functions");
    assert!(symbol_kinds.contains(&"variable"), "Should extract global variables");
    assert!(symbol_kinds.contains(&"import") || symbol_kinds.contains(&"from_import"), 
           "Should extract imports");

    // Check specific symbols
    let symbol_names: Vec<&str> = result.symbols.iter()
        .map(|s| s.name.as_str())
        .collect();

    assert!(symbol_names.iter().any(|name| name.contains("BaseClass")), 
           "Should extract BaseClass");
    assert!(symbol_names.iter().any(|name| name.contains("async_function")), 
           "Should extract async_function");
    assert!(symbol_names.iter().any(|name| name.contains("typed_function")), 
           "Should extract typed_function with type info");
    assert!(symbol_names.iter().any(|name| name.contains("GLOBAL_CONSTANT")), 
           "Should extract global constants");

    // Verify public/private classification
    let public_symbols: Vec<_> = result.symbols.iter()
        .filter(|s| s.is_public)
        .collect();
    let private_symbols: Vec<_> = result.symbols.iter()
        .filter(|s| !s.is_public)
        .collect();

    assert!(!public_symbols.is_empty(), "Should have public symbols");
    assert!(!private_symbols.is_empty(), "Should have private symbols");

    // Check that private symbols start with underscore
    for symbol in private_symbols {
        if symbol.kind == "method" || symbol.kind == "function" || symbol.kind == "variable" {
            assert!(symbol.name.contains("_private") || symbol.name.starts_with('_') || 
                   symbol.kind == "import" || symbol.kind == "from_import" ||
                   symbol.kind == "lambda" || symbol.kind == "context_manager",
                   "Private symbol should start with underscore or be import/lambda: {}", symbol.name);
        }
    }

    println!("Successfully extracted {} symbols from Python file", result.symbols.len());
    println!("Symbol types found: {:?}", symbol_kinds);

    Ok(())
}
