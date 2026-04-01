# lexer.py

import tokenize
import io
from shared.models import Token, CompilerOutput

# Map Python's token type numbers to your readable names
TOKEN_TYPE_MAP = {
    tokenize.NAME:      "IDENTIFIER",
    tokenize.STRING:    "STRING_LITERAL",
    tokenize.NUMBER:    "NUMBER",
    tokenize.OP:        "OPERATOR",
    tokenize.NEWLINE:   "NEWLINE",
    tokenize.COMMENT:   "COMMENT",
    tokenize.ENDMARKER: "EOF",
}

# Python reserved words — treat these as KEYWORD, not IDENTIFIER
KEYWORDS = {
    "if", "else", "elif", "while", "for", "def", "class",
    "return", "import", "from", "in", "not", "and", "or",
    "True", "False", "None", "try", "except", "with", "as",
    "pass", "break", "continue", "raise", "lambda", "yield"
}

def run_lexer(source_code: str) -> tuple[list, list]:
    """
    Returns: (tokens, errors)
    tokens: list of Token objects
    errors: list of {line, message} dicts
    """
    tokens = []
    errors = []

    try:
        source_bytes = source_code.encode("utf-8")
        reader = io.BytesIO(source_bytes)
        token_gen = tokenize.tokenize(reader.readline)

        for tok in token_gen:
            tok_type_num = tok.type
            tok_value    = tok.string
            tok_line     = tok.start[0]
            tok_col      = tok.start[1]

            # Skip types we don't care about
            if tok_type_num in (tokenize.ENCODING, tokenize.NL,
                                tokenize.INDENT, tokenize.DEDENT):
                continue

            # Remap keywords
            if tok_type_num == tokenize.NAME and tok_value in KEYWORDS:
                readable_type = "KEYWORD"
            else:
                readable_type = TOKEN_TYPE_MAP.get(tok_type_num, "UNKNOWN")

            tokens.append(Token(
                type=readable_type,
                value=tok_value,
                line=tok_line,
                column=tok_col
            ))

    except tokenize.TokenError as e:
        errors.append({
            "line": e.args[1][0] if len(e.args) > 1 else 0,
            "message": f"Lexer error: {e.args[0]}"
        })

    return tokens, errors