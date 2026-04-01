# parser.py

import ast as pyast
from shared.models import CompilerOutput

def run_parser(source_code: str, tokens: list) -> tuple[dict, list]:
    """
    Returns: (ast_dict, syntax_errors)
    ast_dict: JSON-serializable nested dictionary
    syntax_errors: list of {line, col, message}
    """
    syntax_errors = []
    ast_dict = {}

    try:
        tree = pyast.parse(source_code, mode='exec')
        ast_dict = ast_to_dict(tree)

    except SyntaxError as e:
        syntax_errors.append({
            "line":    e.lineno or 0,
            "col":     e.offset or 0,
            "message": f"Syntax error: {e.msg}"
        })

    return ast_dict, syntax_errors


def ast_to_dict(node) -> dict:
    """Recursively convert AST nodes to a plain dictionary."""
    if isinstance(node, pyast.AST):
        result = {"_type": type(node).__name__}

        # Attach line number if the node has it
        if hasattr(node, "lineno"):
            result["lineno"] = node.lineno

        for field_name, field_value in pyast.iter_fields(node):
            result[field_name] = ast_to_dict(field_value)

        return result

    elif isinstance(node, list):
        return [ast_to_dict(item) for item in node]

    else:
        return node  # int, str, None — return as-is