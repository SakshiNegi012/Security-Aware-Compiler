# pipeline.py

from shared.models import CompilerOutput
from lexer import run_lexer
from parser import run_parser
from semantic import SemanticAnalyzer
from c_lexer import run_c_lexer
from c_parser import run_c_parser
from c_semantic import run_c_semantic
from analyzer import SecurityAnalyzer

def detect_language(source_code: str) -> str:
    """Auto-detect if code is Python or C."""
    c_indicators = [
        '#include', 'int main(', 'printf(', 'scanf(',
        'void ', '};', '->'
    ]
    score = sum(1 for indicator in c_indicators
                if indicator in source_code)
    return "c" if score >= 2 else "python"


def run_compiler(source_code: str, language: str = "auto") -> CompilerOutput:
    output = CompilerOutput(source_code=source_code)

    if language == "auto":
        language = detect_language(source_code)

    output.language = language

    if language == "python":
        _run_python_pipeline(source_code, output)
    else:
        _run_c_pipeline(source_code, output)

    return output


def _run_python_pipeline(source_code: str, output: CompilerOutput):
    # Phase 1: Lexical Analysis
    tokens, lex_errors = run_lexer(source_code)
    output.tokens = tokens
    if lex_errors:
        output.syntax_errors.extend(lex_errors)
        output.success = False
        return

    # Phase 2: Syntax Analysis
    ast_dict, syn_errors = run_parser(source_code, tokens)
    output.ast = ast_dict
    if syn_errors:
        output.syntax_errors.extend(syn_errors)
        output.success = False
        return

    # Phase 3: Semantic Analysis
    analyzer = SemanticAnalyzer()
    symbol_table, sem_errors = analyzer.analyze(ast_dict, source_code)
    output.symbol_table = symbol_table
    output.semantic_errors = sem_errors

    # Phase 4: Security Analysis
    if output.success:
        import ast as python_ast
        try:
            tree = python_ast.parse(source_code)
            security_analyzer = SecurityAnalyzer()
            security_issues = security_analyzer.analyze(tree)
            
            # Add security analysis to AST output
            output.ast["dangerous_calls"] = [issue.to_dict() for issue in security_issues]
            output.ast["security_issues"] = [issue.to_dict() for issue in security_issues]
        except Exception as e:
            output.ast["security_errors"] = str(e)

    output.success = True


def _run_c_pipeline(source_code: str, output: CompilerOutput):
    # Phase 1: Lexical Analysis
    tokens, lex_errors = run_c_lexer(source_code)
    output.tokens = tokens
    if lex_errors:
        output.syntax_errors.extend(lex_errors)

    # Phase 2: Syntax Analysis (continue even with minor lex errors for C)
    ast_dict, syn_errors = run_c_parser(source_code, tokens)
    output.ast = ast_dict
    output.syntax_errors.extend(syn_errors)

    # Phase 3: Semantic Analysis
    symbol_table, sem_errors = run_c_semantic(ast_dict, source_code)
    output.symbol_table = symbol_table
    output.semantic_errors = sem_errors

    # Phase 4: Security Analysis (basic C security checks)
    if len(output.syntax_errors) == 0:
        dangerous_calls = []
        
        # Check for dangerous C functions with line numbers
        dangerous_functions = ['strcpy', 'strcat', 'sprintf', 'gets', 'scanf']
        lines = source_code.split('\n')
        
        for func in dangerous_functions:
            for line_num, line in enumerate(lines, 1):
                if func in line:
                    dangerous_calls.append({
                        "type": "DANGEROUS_FUNCTION",
                        "function": func,
                        "lineno": line_num,
                        "message": f"Use of dangerous function {func} can lead to buffer overflow",
                        "severity": "HIGH"
                    })
        
        output.ast["dangerous_calls"] = dangerous_calls
        output.ast["security_issues"] = dangerous_calls

    output.success = len(output.syntax_errors) == 0
