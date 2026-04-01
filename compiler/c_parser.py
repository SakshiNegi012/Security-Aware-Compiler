# c_parser.py

import re
from shared.models import Token

def run_c_parser(source_code: str, tokens: list) -> tuple[dict, list]:
    """
    Builds a simplified AST for C code using pattern matching.
    Returns: (ast_dict, syntax_errors)
    """
    syntax_errors = []
    ast = {
        "_type": "CProgram",
        "functions": [],
        "includes": [],
        "variables": [],
        "dangerous_calls": []
    }

    lines = source_code.split('\n')

    # Check balanced braces
    open_count  = source_code.count('{')
    close_count = source_code.count('}')
    if open_count != close_count:
        syntax_errors.append({
            "line": len(lines),
            "col": 0,
            "message": f"Unbalanced braces: {open_count} open, {close_count} close"
        })

    # Check balanced parentheses
    if source_code.count('(') != source_code.count(')'):
        syntax_errors.append({
            "line": 0,
            "col": 0,
            "message": "Unbalanced parentheses"
        })

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()

        # Detect #include
        inc = re.match(r'#include\s*[<"](.+)[>"]', stripped)
        if inc:
            ast["includes"].append({
                "lineno": i,
                "file": inc.group(1)
            })

        # Detect function definitions e.g. int main() or void foo(int x)
        func = re.match(
            r'(int|void|float|double|char)\s+(\w+)\s*\(([^)]*)\)\s*\{?', stripped)
        if func:
            ast["functions"].append({
                "lineno":      i,
                "return_type": func.group(1),
                "name":        func.group(2),
                "params":      func.group(3)
            })

        # Detect variable declarations e.g. int x; or char buf[100];
        var = re.match(
            r'(int|float|double|char|long|short|unsigned)\s+(\w+)'
            r'(\[(\d+)\])?\s*[=;]', stripped)
        if var:
            ast["variables"].append({
                "lineno":   i,
                "type":     var.group(1),
                "name":     var.group(2),
                "is_array": var.group(3) is not None,
                "size":     var.group(4)
            })

        # Detect dangerous function calls
        danger = re.findall(
            r'\b(gets|strcpy|strcat|sprintf|scanf|system|exec|popen)\s*\(', stripped)
        for fn in danger:
            ast["dangerous_calls"].append({
                "lineno":   i,
                "function": fn
            })

        # Detect missing semicolons (basic check)
        if (stripped and
                not stripped.startswith('//') and
                not stripped.startswith('#') and
                not stripped.startswith('{') and
                not stripped.startswith('}') and
                not stripped.endswith('{') and
                not stripped.endswith('}') and
                not stripped.endswith(';') and
                not stripped.endswith(',') and
                re.match(r'.+=.+', stripped)):  # looks like a statement
            syntax_errors.append({
                "line":    i,
                "col":     len(stripped),
                "message": f"Possible missing semicolon at line {i}"
            })

    return ast, syntax_errors