# tests/test_semantic.py

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from lexer import run_lexer
from parser import run_parser
from semantic import SemanticAnalyzer

def run(code):
    tokens, _ = run_lexer(code)
    ast_dict, _ = run_parser(code, tokens)
    analyzer = SemanticAnalyzer()
    return analyzer.analyze(ast_dict, code)

def test_hardcoded_variable():
    sym, errs = run('x = 42')
    assert sym["x"]["source"] == "hardcoded"
    print("PASS: hardcoded source detected")

def test_user_input_source():
    sym, errs = run('name = input("Enter name: ")')
    assert sym["name"]["source"] == "user_input"
    print("PASS: user_input source detected")

def test_tainted_concatenation():
    sym, errs = run('u = input()\nq = "SELECT * FROM users WHERE id=" + u')
    assert sym["q"]["source"] == "user_input"
    print("PASS: tainted concatenation tracked")

def test_function_registered():
    sym, errs = run('def greet(name):\n    return name')
    assert "greet" in sym
    assert sym["greet"]["kind"] == "function"
    assert "name" in sym
    assert sym["name"]["kind"] == "parameter"
    print("PASS: function and parameter registered")

def test_file_read_source():
    sym, errs = run('data = open("file.txt").read()')
    assert sym["data"]["source"] == "file_read"
    print("PASS: file_read source detected")

if __name__ == "__main__":
    test_hardcoded_variable()
    test_user_input_source()
    test_tainted_concatenation()
    test_function_registered()
    test_file_read_source()
    print("\nAll semantic tests passed.")
