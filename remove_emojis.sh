#!/bin/bash

# Script to remove emojis from comprehensive_todo_list.md
# This uses sed to remove common emoji characters while preserving file structure

FILE="comprehensive_todo_list.md"
BACKUP="${FILE}.backup"

echo "Processing $FILE..."

# Create backup
cp "$FILE" "$BACKUP"
echo "Backup created: $BACKUP"

# Remove emojis using sed
# This removes common emoji ranges and specific emoji characters
sed -i '' \
    -e 's/🎉//g' \
    -e 's/✅//g' \
    -e 's/🚨//g' \
    -e 's/🔧//g' \
    -e 's/🚀//g' \
    -e 's/🏗️//g' \
    -e 's/📦//g' \
    -e 's/🔍//g' \
    -e 's/📋//g' \
    -e 's/🎯//g' \
    -e 's/🐛//g' \
    -e 's/🔒//g' \
    -e 's/🧪//g' \
    -e 's/📊//g' \
    -e 's/🌐//g' \
    -e 's/🔄//g' \
    -e 's/📈//g' \
    -e 's/📁//g' \
    "$FILE"

echo "✓ Successfully removed emojis from $FILE"
echo "Original file backed up as $BACKUP"

# Show statistics
ORIGINAL_SIZE=$(wc -c < "$BACKUP")
NEW_SIZE=$(wc -c < "$FILE")
ORIGINAL_LINES=$(wc -l < "$BACKUP")
NEW_LINES=$(wc -l < "$FILE")

echo ""
echo "Statistics:"
echo "  Original file: $ORIGINAL_SIZE characters, $ORIGINAL_LINES lines"
echo "  Cleaned file:  $NEW_SIZE characters, $NEW_LINES lines"
echo "  Difference:    $((ORIGINAL_SIZE - NEW_SIZE)) characters removed"
