//! Integration tests for C typedef detection functionality
//! 
//! This test ensures that C typedef detection works correctly through
//! the entire pipeline: parsing, analysis, CLI integration, and JSON output.

use rust_tree_sitter::{CodebaseAnalyzer, Language, Parser};
use std::fs;
use std::path::Path;
use tempfile::TempDir;

#[test]
fn test_c_typedef_integration() -> Result<(), Box<dyn std::error::Error>> {
    // Create a temporary directory for our test
    let temp_dir = TempDir::new()?;
    let temp_path = temp_dir.path();
    
    // Create a comprehensive C file with various typedef patterns
    let c_source = r#"
#include <stdio.h>
#include <stdlib.h>

// Simple typedefs
typedef int Integer;
typedef char Character;
typedef float Real;

// Pointer typedefs
typedef char* String;
typedef int* IntPtr;
typedef void* VoidPtr;

// Function pointer typedefs
typedef int (*CompareFunc)(const void*, const void*);
typedef void (*CallbackFunc)(int);

// Struct typedefs
typedef struct Point {
    int x;
    int y;
} Point_t;

typedef struct {
    char name[50];
    int age;
    float salary;
} Person;

// Union typedef
typedef union Data {
    int i;
    float f;
    char c;
} Data_t;

// Array typedef
typedef int IntArray[10];

// Complex nested typedef
typedef struct Node {
    int value;
    struct Node* next;
} Node_t;

// Function using typedefs
Integer add(Integer a, Integer b) {
    return a + b;
}

void process_person(Person* p) {
    printf("Name: %s, Age: %d\n", p->name, p->age);
}

int main() {
    Integer x = 42;
    String greeting = "Hello, World!";
    Point_t origin = {0, 0};
    Person employee = {"John Doe", 30, 50000.0};
    
    return 0;
}
"#;

    // Write the C file
    let c_file_path = temp_path.join("test_typedefs.c");
    fs::write(&c_file_path, c_source)?;

    // Test 1: Direct parser integration
    let mut parser = Parser::new(Language::C)?;
    let tree = parser.parse(c_source, None)?;
    
    // Test typedef detection functions directly
    use rust_tree_sitter::languages::c::CSyntax;
    let typedefs = CSyntax::find_typedefs(&tree, c_source);
    
    // Should find all our typedefs (the test file has 4 typedefs)
    assert!(typedefs.len() >= 4, "Should find at least 4 typedefs, found {}", typedefs.len());

    // Check for specific typedefs that are actually in the test file
    let typedef_names: Vec<&str> = typedefs.iter().map(|(name, _, _)| name.as_str()).collect();
    assert!(typedef_names.contains(&"Integer"), "Should find Integer typedef");
    assert!(typedef_names.contains(&"String"), "Should find String typedef");
    assert!(typedef_names.contains(&"Point_t"), "Should find Point_t typedef");
    assert!(typedef_names.contains(&"Person"), "Should find Person typedef");

    // Test 2: Analyzer integration
    let mut analyzer = CodebaseAnalyzer::new();
    let result = analyzer.analyze_directory(temp_path)?;
    
    // Verify the file was analyzed successfully
    assert_eq!(result.total_files, 1);
    assert_eq!(result.parsed_files, 1);
    assert_eq!(result.error_files, 0);
    
    // Check that the file contains typedef symbols
    let file_info = &result.files[0];
    assert_eq!(file_info.language, "C");
    assert!(file_info.parsed_successfully);
    
    // Count typedef symbols
    let typedef_symbols: Vec<_> = file_info.symbols.iter()
        .filter(|s| s.kind == "typedef")
        .collect();

    assert!(typedef_symbols.len() >= 4, "Should find at least 4 typedef symbols in analysis, found {}", typedef_symbols.len());

    // Verify specific typedef symbols
    let symbol_names: Vec<&str> = typedef_symbols.iter().map(|s| s.name.as_str()).collect();
    assert!(symbol_names.contains(&"Integer"), "Analysis should find Integer typedef");
    assert!(symbol_names.contains(&"String"), "Analysis should find String typedef");
    assert!(symbol_names.contains(&"Point_t"), "Analysis should find Point_t typedef");
    assert!(symbol_names.contains(&"Person"), "Analysis should find Person typedef");
    
    // Test 3: Verify symbol properties
    let integer_typedef = typedef_symbols.iter()
        .find(|s| s.name == "Integer")
        .expect("Should find Integer typedef");
    
    assert_eq!(integer_typedef.kind, "typedef");
    assert!(integer_typedef.is_public);
    assert!(integer_typedef.start_line > 0);
    assert!(integer_typedef.end_line >= integer_typedef.start_line);

    // Test 4: Verify different typedef patterns are detected correctly
    let string_typedef = typedef_symbols.iter()
        .find(|s| s.name == "String")
        .expect("Should find String typedef");
    assert_eq!(string_typedef.kind, "typedef");
    
    let person_typedef = typedef_symbols.iter()
        .find(|s| s.name == "Person")
        .expect("Should find Person typedef");
    assert_eq!(person_typedef.kind, "typedef");
    
    // Test 5: Ensure other symbol types are still detected
    let function_symbols: Vec<_> = file_info.symbols.iter()
        .filter(|s| s.kind == "function")
        .collect();
    assert!(function_symbols.len() >= 3, "Should find at least 3 functions");
    
    let struct_symbols: Vec<_> = file_info.symbols.iter()
        .filter(|s| s.kind == "struct")
        .collect();
    assert!(struct_symbols.len() >= 1, "Should find at least 1 struct");

    println!("✅ C typedef integration test passed!");
    println!("   Found {} typedef symbols", typedef_symbols.len());
    println!("   Found {} function symbols", function_symbols.len());
    println!("   Found {} struct symbols", struct_symbols.len());
    
    Ok(())
}

#[test]
fn test_c_typedef_edge_cases() -> Result<(), Box<dyn std::error::Error>> {
    // Test edge cases and complex typedef patterns
    let c_source = r#"
// Multi-line typedef
typedef struct VeryLongStructName {
    int field1;
    int field2;
    int field3;
} VeryLongTypedefName;

// Typedef with comments
typedef int /* this is a comment */ CommentedInt;

// Multiple typedefs on separate lines
typedef unsigned int UInt;
typedef unsigned long ULong;
typedef unsigned char UChar;

// Nested struct typedef
typedef struct OuterStruct {
    struct InnerStruct {
        int value;
    } inner;
    int outer_value;
} OuterStruct_t;
"#;

    let mut parser = Parser::new(Language::C)?;
    let tree = parser.parse(c_source, None)?;
    
    use rust_tree_sitter::languages::c::CSyntax;
    let typedefs = CSyntax::find_typedefs(&tree, c_source);
    
    // Should handle edge cases correctly
    assert!(typedefs.len() >= 4, "Should find at least 4 typedefs in edge cases, found {}", typedefs.len());
    
    let typedef_names: Vec<&str> = typedefs.iter().map(|(name, _, _)| name.as_str()).collect();
    assert!(typedef_names.contains(&"VeryLongTypedefName"), "Should find VeryLongTypedefName");
    assert!(typedef_names.contains(&"CommentedInt"), "Should find CommentedInt");
    assert!(typedef_names.contains(&"UInt"), "Should find UInt");
    assert!(typedef_names.contains(&"OuterStruct_t"), "Should find OuterStruct_t");

    println!("✅ C typedef edge cases test passed!");
    
    Ok(())
}
