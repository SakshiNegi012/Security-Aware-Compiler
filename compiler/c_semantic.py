# c_semantic.py

from shared.models import SymbolEntry

DANGEROUS_FUNCTIONS = {
    "gets", "strcpy", "strcat", "sprintf",
    "system", "exec", "popen", "scanf"
}

USER_INPUT_FUNCTIONS = {"scanf", "gets", "fgets", "getchar"}

def run_c_semantic(ast_dict: dict, source_code: str) -> tuple[dict, list]:
    """
    Builds symbol table from C AST.
    Returns: (symbol_table, semantic_errors)
    """
    symbol_table   = {}
    semantic_errors = []
    lines = source_code.split('\n')

    # Register all functions
    for func in ast_dict.get("functions", []):
        symbol_table[func["name"]] = vars(SymbolEntry(
            name=func["name"],
            kind="function",
            declared_line=func["lineno"],
            value_type=func["return_type"],
            source="hardcoded"
        ))

        # Register parameters
        if func["params"].strip():
            for param in func["params"].split(','):
                param = param.strip()
                parts = param.split()
                if len(parts) >= 2:
                    param_name = parts[-1].strip('*')
                    symbol_table[param_name] = vars(SymbolEntry(
                        name=param_name,
                        kind="parameter",
                        declared_line=func["lineno"],
                        value_type=parts[0],
                        source="unknown"
                    ))

    # Register variables
    for var in ast_dict.get("variables", []):
        line_text = lines[var["lineno"] - 1].strip()

        # Determine source
        if any(f in line_text for f in USER_INPUT_FUNCTIONS):
            source = "user_input"
        elif "=" in line_text and '"' in line_text:
            source = "hardcoded"
        elif "=" in line_text:
            source = "function_return"
        else:
            source = "unknown"

        symbol_table[var["name"]] = vars(SymbolEntry(
            name=var["name"],
            kind="variable",
            declared_line=var["lineno"],
            value_type=var["type"],
            source=source
        ))

    # Flag dangerous function calls as semantic warnings
    for call in ast_dict.get("dangerous_calls", []):
        semantic_errors.append({
            "line":    call["lineno"],
            "message": f"Dangerous function '{call['function']}' detected — "
                       f"potential buffer overflow risk"
        })

    return symbol_table, semantic_errors