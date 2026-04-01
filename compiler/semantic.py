# semantic.py

import ast as pyast
from shared.models import SymbolEntry

USER_INPUT_FUNCTIONS  = {"input", "sys.stdin.read", "request.form.get",
                         "request.args.get", "request.json.get"}
FILE_READ_FUNCTIONS   = {"open", "read", "readline", "readlines"}

class SemanticAnalyzer(pyast.NodeVisitor):

    def __init__(self):
        self.symbol_table    = {}
        self.semantic_errors = []
        self.current_scope   = "global"

    def analyze(self, ast_dict: dict, source_code: str) -> tuple[dict, list]:
        tree = pyast.parse(source_code)
        self.visit(tree)
        serializable = {
            name: vars(entry)
            for name, entry in self.symbol_table.items()
        }
        return serializable, self.semantic_errors

    def visit_Assign(self, node):
        source   = self._determine_source(node.value)
        val_type = self._determine_type(node.value)
        for target in node.targets:
            if isinstance(target, pyast.Name):
                self.symbol_table[target.id] = SymbolEntry(
                    name=target.id,
                    kind="variable",
                    declared_line=node.lineno,
                    value_type=val_type,
                    source=source
                )
        self.generic_visit(node)

    def visit_FunctionDef(self, node):
        self.symbol_table[node.name] = SymbolEntry(
            name=node.name,
            kind="function",
            declared_line=node.lineno,
            value_type="function",
            source="hardcoded"
        )
        for arg in node.args.args:
            self.symbol_table[arg.arg] = SymbolEntry(
                name=arg.arg,
                kind="parameter",
                declared_line=node.lineno,
                value_type="unknown",
                source="unknown"
            )
        self.generic_visit(node)

    def _determine_source(self, value_node) -> str:
        if value_node is None:
            return "unknown"
        if isinstance(value_node, pyast.Call):
            func_name = self._get_call_name(value_node)
            if func_name in USER_INPUT_FUNCTIONS:
                return "user_input"
            if func_name in FILE_READ_FUNCTIONS:
                return "file_read"
            return "function_return"
        if isinstance(value_node, (pyast.Constant, pyast.Str, pyast.Num)):
            return "hardcoded"
        if isinstance(value_node, pyast.Name):
            entry = self.symbol_table.get(value_node.id)
            return entry.source if entry else "unknown"
        if isinstance(value_node, pyast.BinOp):
            left_src  = self._determine_source(value_node.left)
            right_src = self._determine_source(value_node.right)
            if "user_input" in (left_src, right_src):
                return "user_input"
            return left_src
        return "unknown"

    def _determine_type(self, value_node) -> str:
        if isinstance(value_node, pyast.Constant):
            return type(value_node.value).__name__
        if isinstance(value_node, pyast.Call):
            return "unknown"
        return "unknown"

    def _get_call_name(self, call_node) -> str:
        if isinstance(call_node.func, pyast.Name):
            return call_node.func.id
        if isinstance(call_node.func, pyast.Attribute):
            return call_node.func.attr
        return ""