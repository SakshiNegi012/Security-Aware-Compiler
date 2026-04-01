# tests/test_parser.py

from lexer import run_lexer
from parser import run_parser

def test_simple_assignment_ast():
    code = "x = 42"
    tokens, _ = run_lexer(code)
    ast_dict, errors = run_parser(code, tokens)
    assert errors == []
    assert ast_dict["_type"] == "Module"
    print("PASS: simple AST built")

def test_function_def_in_ast():
    code = "def greet(name):\n    return name"
    tokens, _ = run_lexer(code)
    ast_dict, errors = run_parser(code, tokens)
    assert errors == []
    body = ast_dict["body"][0]
    assert body["_type"] == "FunctionDef"
    assert body["name"] == "greet"
    print("PASS: function def in AST")

def test_syntax_error_caught():
    code = "def broken(:\n    pass"
    tokens, _ = run_lexer(code)
    ast_dict, errors = run_parser(code, tokens)
    assert len(errors) > 0
    assert errors[0]["line"] == 1
    print("PASS: syntax error line reported")

def test_line_numbers_in_ast():
    code = "x = 1\ny = 2"
    tokens, _ = run_lexer(code)
    ast_dict, errors = run_parser(code, tokens)
    stmts = ast_dict["body"]
    assert stmts[0]["lineno"] == 1
    assert stmts[1]["lineno"] == 2
    print("PASS: line numbers in AST nodes")

if __name__ == "__main__":
    test_simple_assignment_ast()
    test_function_def_in_ast()
    test_syntax_error_caught()
    test_line_numbers_in_ast()
    print("\nAll parser tests passed.")