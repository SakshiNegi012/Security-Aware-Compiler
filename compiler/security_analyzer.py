import ast

class SecurityIssue:
    def __init__(self, vuln_type, line, severity, message, fix):
        self.vuln_type = vuln_type
        self.line      = line
        self.severity  = severity   # "HIGH" / "MEDIUM" / "LOW"
        self.message   = message
        self.fix       = fix

    def to_dict(self):
        return {
            "type":     self.vuln_type,
            "line":     self.line,
            "severity": self.severity,
            "message":  self.message,
            "fix":      self.fix
        }


class SecurityAnalyzer(ast.NodeVisitor):
    def __init__(self):
        self.issues = []   # all detected issues go here

    def analyze(self, tree):
        self.visit(tree)
        return [i.to_dict() for i in self.issues]

    def add_issue(self, node, vuln_type, severity, message, fix):
        self.issues.append(SecurityIssue(
            vuln_type, node.lineno, severity, message, fix
        ))