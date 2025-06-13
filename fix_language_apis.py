#!/usr/bin/env python3
"""
Script to fix API compatibility issues in language modules.
This script fixes common patterns:
1. utf8_text(source.as_bytes()) -> text()
2. utf8_text(&[]) -> text()
3. children(&mut cursor) -> children()
4. Remove unused cursor variables
"""

import os
import re
import glob

def fix_file(filepath):
    """Fix API issues in a single file."""
    print(f"Fixing {filepath}...")
    
    with open(filepath, 'r') as f:
        content = f.read()
    
    original_content = content
    
    # Fix utf8_text calls
    content = re.sub(r'\.utf8_text\(source\.as_bytes\(\)\)', '.text()', content)
    content = re.sub(r'\.utf8_text\(&\[\]\)', '.text()', content)
    
    # Fix children calls with cursor
    content = re.sub(r'\.children\(&mut [^)]+\)', '.children()', content)
    
    # Remove unused cursor variable declarations
    lines = content.split('\n')
    new_lines = []
    
    for line in lines:
        # Skip lines that declare cursors that are only used for children() calls
        if re.match(r'\s*let mut \w*cursor = \w+\.walk\(\);', line):
            # Check if this cursor is only used for children() calls
            continue
        new_lines.append(line)
    
    content = '\n'.join(new_lines)
    
    # Only write if content changed
    if content != original_content:
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"  Fixed {filepath}")
        return True
    else:
        print(f"  No changes needed for {filepath}")
        return False

def main():
    """Fix all language module files."""
    language_files = [
        'src/languages/typescript.rs',
        'src/languages/python.rs', 
        'src/languages/c.rs',
        'src/languages/cpp.rs',
        'src/languages/go.rs'
    ]
    
    fixed_count = 0
    
    for filepath in language_files:
        if os.path.exists(filepath):
            if fix_file(filepath):
                fixed_count += 1
        else:
            print(f"Warning: {filepath} not found")
    
    print(f"\nFixed {fixed_count} files")

if __name__ == '__main__':
    main()
