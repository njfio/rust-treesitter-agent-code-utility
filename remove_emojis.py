#!/usr/bin/env python3
"""
Script to remove emojis from the comprehensive_todo_list.md file.
This will help resolve markdown linting issues caused by emoji characters.
"""

import re
import sys
from pathlib import Path

def remove_emojis(text):
    """
    Remove emoji characters from text using regex patterns.
    This covers most common emoji ranges in Unicode.
    """
    # Define emoji patterns
    emoji_patterns = [
        r'[\U0001F600-\U0001F64F]',  # emoticons
        r'[\U0001F300-\U0001F5FF]',  # symbols & pictographs
        r'[\U0001F680-\U0001F6FF]',  # transport & map symbols
        r'[\U0001F1E0-\U0001F1FF]',  # flags (iOS)
        r'[\U00002702-\U000027B0]',  # dingbats
        r'[\U000024C2-\U0001F251]',  # enclosed characters
        r'[\U0001F900-\U0001F9FF]',  # supplemental symbols
        r'[\U0001FA70-\U0001FAFF]',  # symbols and pictographs extended-A
        r'[\U00002600-\U000026FF]',  # miscellaneous symbols
        r'[\U00002700-\U000027BF]',  # dingbats
    ]
    
    # Combine all patterns
    combined_pattern = '|'.join(emoji_patterns)
    
    # Remove emojis
    cleaned_text = re.sub(combined_pattern, '', text)

    # Process line by line to preserve structure
    lines = cleaned_text.split('\n')
    cleaned_lines = []

    for line in lines:
        # Clean up any double spaces that might result from emoji removal
        line = re.sub(r' +', ' ', line)

        # If line starts with space(s) followed by a heading or list item, clean it up
        if re.match(r'^\s+(#{1,6}\s|[-*]\s|\d+\.\s)', line):
            line = line.lstrip()

        # Remove trailing spaces
        line = line.rstrip()

        cleaned_lines.append(line)

    return '\n'.join(cleaned_lines)

def main():
    """Main function to process the comprehensive_todo_list.md file."""
    
    # Define the file path
    file_path = Path('comprehensive_todo_list.md')
    
    # Check if file exists
    if not file_path.exists():
        print(f"Error: {file_path} not found!")
        sys.exit(1)
    
    print(f"Processing {file_path}...")
    
    try:
        # Read the original file
        with open(file_path, 'r', encoding='utf-8') as f:
            original_content = f.read()
        
        # Remove emojis
        cleaned_content = remove_emojis(original_content)
        
        # Create backup of original file
        backup_path = file_path.with_suffix('.md.backup')
        with open(backup_path, 'w', encoding='utf-8') as f:
            f.write(original_content)
        print(f"Backup created: {backup_path}")
        
        # Write cleaned content back to original file
        with open(file_path, 'w', encoding='utf-8') as f:
            f.write(cleaned_content)
        
        print(f"✅ Successfully removed emojis from {file_path}")
        print(f"📁 Original file backed up as {backup_path}")
        
        # Show some statistics
        original_lines = len(original_content.split('\n'))
        cleaned_lines = len(cleaned_content.split('\n'))
        
        print(f"\nStatistics:")
        print(f"  Original file: {len(original_content)} characters, {original_lines} lines")
        print(f"  Cleaned file:  {len(cleaned_content)} characters, {cleaned_lines} lines")
        print(f"  Difference:    {len(original_content) - len(cleaned_content)} characters removed")
        
    except Exception as e:
        print(f"Error processing file: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
