# shared/models.py

from dataclasses import dataclass, field

@dataclass
class Token:
    type: str       # "IDENTIFIER", "STRING_LITERAL", "KEYWORD", "NUMBER",
                    # "OPERATOR", "PUNCTUATION", "NEWLINE", "EOF"
    value: str      # exact text from source: "input", "=", "SELECT", etc.
    line: int       # line number (starts at 1)
    column: int     # column number (starts at 0)

    def __repr__(self):
        return f"Token({self.type}, {self.value!r}, L{self.line})"


@dataclass
class SymbolEntry:
    name: str
    kind: str           # "variable", "function", "parameter"
    declared_line: int
    value_type: str     # "str", "int", "unknown"
    source: str         # ← MOST IMPORTANT for Student B
                        # "user_input"  → came from input() call
                        # "file_read"   → came from open()/read()
                        # "hardcoded"   → assigned a literal value
                        # "function_return" → result of a function call
                        # "unknown"     → can't determine

@dataclass
class CompilerOutput:
    source_code: str
    success: bool = False

    tokens: list = field(default_factory=list)          # list[Token]
    ast: dict = field(default_factory=dict)             # nested dict

    symbol_table: dict = field(default_factory=dict)    # name → SymbolEntry
    syntax_errors: list = field(default_factory=list)   # [{line, message}]
    semantic_errors: list = field(default_factory=list) # [{line, message}]