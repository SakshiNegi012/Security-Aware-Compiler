# tests/test_lexer.py

from lexer import run_lexer

def test_basic_assignment():
    code = 'x = 10'
    tokens, errors = run_lexer(code)
    assert errors == []
    assert tokens[0].type == "IDENTIFIER" and tokens[0].value == "x"
    assert tokens[1].type == "OPERATOR"   and tokens[1].value == "="
    assert tokens[2].type == "NUMBER"     and tokens[2].value == "10"
    print("PASS: basic assignment")

def test_keyword_detection():
    code = 'if x == 5:'
    tokens, errors = run_lexer(code)
    assert tokens[0].type == "KEYWORD" and tokens[0].value == "if"
    print("PASS: keyword detection")

def test_string_literal():
    code = 'name = "hello"'
    tokens, errors = run_lexer(code)
    string_tok = [t for t in tokens if t.type == "STRING_LITERAL"]
    assert len(string_tok) == 1
    print("PASS: string literal")

def test_line_numbers():
    code = "x = 1\ny = 2\nz = 3"
    tokens, errors = run_lexer(code)
    identifiers = [t for t in tokens if t.type == "IDENTIFIER"]
    assert identifiers[0].line == 1  # x
    assert identifiers[1].line == 2  # y
    assert identifiers[2].line == 3  # z
    print("PASS: line numbers correct")

def test_syntax_error():
    code = 'x = "unclosed string'
    tokens, errors = run_lexer(code)
    assert len(errors) > 0
    print("PASS: syntax error caught")

if __name__ == "__main__":
    test_basic_assignment()
    test_keyword_detection()
    test_string_literal()
    test_line_numbers()
    test_syntax_error()
    print("\nAll lexer tests passed.")