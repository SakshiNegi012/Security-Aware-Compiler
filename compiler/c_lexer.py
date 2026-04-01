# c_lexer.py

import re
from shared.models import Token

# All C token patterns in priority order
C_TOKEN_PATTERNS = [
    ("PREPROCESSOR", r'#\s*(include|define|ifdef|ifndef|endif|pragma)[^\n]*'),
    ("COMMENT",        r'//[^\n]*|/\*[\s\S]*?\*/'),
    ("STRING_LITERAL", r'"([^"\\]|\\.)*"'),
    ("CHAR_LITERAL",   r"'([^'\\]|\\.)'"),
    ("NUMBER",         r'\b\d+(\.\d+)?\b'),
    ("KEYWORD",        r'\b(int|float|double|char|void|if|else|while|for|'
                       r'do|return|break|continue|struct|typedef|include|'
                       r'define|printf|scanf|gets|strcpy|strcat|malloc|'
                       r'free|main|switch|case|default|const|static|'
                       r'unsigned|signed|long|short|NULL|extern)\b'),
    ("IDENTIFIER",     r'\b[a-zA-Z_][a-zA-Z0-9_]*\b'),
    ("OPERATOR",       r'==|!=|<=|>=|&&|\|\||[+\-*/%=<>&|!^~]'),
    ("PUNCTUATION",    r'[{}()\[\];:,.]'),
    ("NEWLINE",        r'\n'),
    ("WHITESPACE",     r'[ \t\r]+'),
    ("UNKNOWN",        r'.'),
]

# Compile all patterns into one big regex
MASTER_PATTERN = re.compile(
    '|'.join(f'(?P<{name}>{pattern})'
             for name, pattern in C_TOKEN_PATTERNS)
)

# Dangerous C functions Student B needs to flag
DANGEROUS_C_FUNCTIONS = {
    "gets", "strcpy", "strcat", "sprintf", "scanf",
    "system", "exec", "popen"
}

def run_c_lexer(source_code: str) -> tuple[list, list]:
    """
    Returns: (tokens, errors)
    """
    tokens = []
    errors = []
    line_number = 1

    for match in MASTER_PATTERN.finditer(source_code):
        token_type = match.lastgroup
        token_value = match.group()

        # Count line numbers
        if token_type == "NEWLINE":
            line_number += 1
            continue

        # Skip whitespace and comments
        if token_type in ("WHITESPACE", "COMMENT", "PREPROCESSOR"):
            continue

        if token_type == "UNKNOWN":
            errors.append({
                "line": line_number,
                "message": f"Unrecognized character: {token_value!r}"
            })
            continue

        # Flag dangerous functions right at lexer stage
        if token_type == "IDENTIFIER" and token_value in DANGEROUS_C_FUNCTIONS:
            token_type = "DANGEROUS_FUNCTION"

        tokens.append(Token(
            type=token_type,
            value=token_value,
            line=line_number,
            column=match.start()
        ))

    return tokens, errors