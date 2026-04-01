# tests/test_both_languages.py

import json
from pipeline import run_compiler

PYTHON_CODE = """
import sqlite3
username = input("Enter username: ")
password = "admin123"
query = "SELECT * FROM users WHERE name='" + username + "'"
conn = sqlite3.connect("mydb.db")
cursor = conn.cursor()
cursor.execute(query)
"""

C_CODE = """
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    gets(buffer);
    printf("Hello %s", buffer);
    return 0;
}
"""

def test_python():
    print("=" * 40)
    print("TESTING PYTHON CODE")
    print("=" * 40)
    result = run_compiler(PYTHON_CODE, language="python")
    print(f"Language  : {result.language}")
    print(f"Success   : {result.success}")
    print(f"Tokens    : {len(result.tokens)} found")
    print(f"Syn errors: {result.syntax_errors}")
    print(f"Sem errors: {result.semantic_errors}")
    print("\nSymbol Table:")
    for name, entry in result.symbol_table.items():
        print(f"  {name:15} source={entry['source']}")

    assert result.success == True
    assert result.symbol_table["username"]["source"] == "user_input"
    assert result.symbol_table["password"]["source"] == "hardcoded"
    assert result.symbol_table["query"]["source"]    == "user_input"
    print("\nPASS: Python pipeline correct\n")


def test_c():
    print("=" * 40)
    print("TESTING C CODE")
    print("=" * 40)
    result = run_compiler(C_CODE, language="c")
    print(f"Language  : {result.language}")
    print(f"Success   : {result.success}")
    print(f"Tokens    : {len(result.tokens)} found")
    print(f"Syn errors: {result.syntax_errors}")
    print(f"Sem errors: {result.semantic_errors}")
    print("\nSymbol Table:")
    for name, entry in result.symbol_table.items():
        print(f"  {name:15} source={entry['source']}")
    print("\nDangerous calls in AST:")
    for call in result.ast.get("dangerous_calls", []):
        print(f"  Line {call['lineno']}: {call['function']}()")

    assert len(result.ast.get("dangerous_calls", [])) > 0
    assert any("gets" in e["message"] for e in result.semantic_errors)
    print("\nPASS: C pipeline correct\n")


def test_auto_detect():
    print("=" * 40)
    print("TESTING AUTO LANGUAGE DETECTION")
    print("=" * 40)
    py_result = run_compiler(PYTHON_CODE)
    c_result  = run_compiler(C_CODE)
    assert py_result.language == "python"
    assert c_result.language  == "c"
    print("PASS: auto-detection works\n")


def print_handoff_json():
    """Print what Student B will receive — so you can verify it looks right."""
    result = run_compiler(PYTHON_CODE, language="python")
    handoff = {
        "language":       result.language,
        "success":        result.success,
        "syntax_errors":  result.syntax_errors,
        "semantic_errors": result.semantic_errors,
        "symbol_table":   result.symbol_table,
        "dangerous_calls": result.ast.get("dangerous_calls", [])
    }
    print("=" * 40)
    print("HANDOFF JSON (what Student B receives):")
    print("=" * 40)
    print(json.dumps(handoff, indent=2))


if __name__ == "__main__":
    test_python()
    test_c()
    test_auto_detect()
    print_handoff_json()