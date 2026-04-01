# tests/test_pipeline.py

import json
from pipeline import run_compiler

SAMPLE_VULNERABLE = """
import sqlite3

username = input("Enter username: ")
password = "secret123"
query = "SELECT * FROM users WHERE name='" + username + "'"

conn = sqlite3.connect("db.sqlite")
cursor = conn.cursor()
cursor.execute(query)
"""

def test_full_pipeline():
    result = run_compiler(SAMPLE_VULNERABLE)

    print("=== Pipeline Output ===")
    print(f"Success: {result.success}")
    print(f"Syntax errors: {result.syntax_errors}")
    print(f"Semantic errors: {result.semantic_errors}")
    print(f"\nSymbol Table:")
    for name, entry in result.symbol_table.items():
        print(f"  {name:15} kind={entry['kind']:12} source={entry['source']}")

    # Assertions
    assert result.success == True
    assert result.symbol_table["username"]["source"] == "user_input"
    assert result.symbol_table["password"]["source"] == "hardcoded"
    assert result.symbol_table["query"]["source"] == "user_input"  # tainted!
    print("\nPASS: full pipeline works correctly")
    print("Student B will correctly flag 'query' as dangerous.")

if __name__ == "__main__":
    test_full_pipeline()


""" Run this and you should see output like:

Symbol Table:
  username        kind=variable    source=user_input
  password        kind=variable    source=hardcoded
  query           kind=variable    source=user_input   ← tainted!
  conn            kind=variable    source=function_return
  cursor          kind=variable    source=function_return """