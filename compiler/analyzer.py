"""
Security Analysis Module
========================
Walks the AST of Python source code and detects common
security vulnerabilities. Returns a list of issues with
line numbers, severity, and fix recommendations.
"""

import ast


# ─────────────────────────────────────────────
#  Data class for a single security issue
# ─────────────────────────────────────────────

class SecurityIssue:
    def __init__(self, vuln_type, line, severity, message, fix):
        self.vuln_type = vuln_type   # e.g. "SQL_INJECTION"
        self.line      = line        # line number in source code
        self.severity  = severity    # "HIGH", "MEDIUM", or "LOW"
        self.message   = message     # human-readable description
        self.fix       = fix         # recommendation

    def to_dict(self):
        return {
            "type":     self.vuln_type,
            "line":     self.line,
            "severity": self.severity,
            "message":  self.message,
            "fix":      self.fix
        }

    def __repr__(self):
        return (f"[{self.severity}] Line {self.line} | "
                f"{self.vuln_type}: {self.message}")


# ─────────────────────────────────────────────
#  Main analyzer class
# ─────────────────────────────────────────────

class SecurityAnalyzer(ast.NodeVisitor):
    """
    Visits every node in the AST.
    Each visit_* method checks for one category of vulnerability.
    """

    # Variable names that suggest sensitive data
    SENSITIVE_NAMES = [
        "password", "passwd", "pwd", "secret", "api_key",
        "apikey", "token", "private_key", "privatekey",
        "credentials", "auth_token", "access_token", "db_password"
    ]

    # SQL execution methods
    SQL_EXECUTE_METHODS = ["execute", "executemany", "executescript"]

    # Dangerous shell/process methods
    SHELL_METHODS = ["system", "popen", "run", "call", "Popen"]

    def __init__(self):
        self.issues = []

    def analyze(self, tree):
        """Entry point — call this with a parsed AST."""
        self.visit(tree)
        return [issue.to_dict() for issue in self.issues]

    def add_issue(self, node, vuln_type, severity, message, fix):
        """Helper to record a detected issue."""
        line = getattr(node, "lineno", 0)
        self.issues.append(
            SecurityIssue(vuln_type, line, severity, message, fix)
        )


    # ──────────────────────────────────────────
    #  RULE 1 — Hardcoded Secrets
    #  Detects: password = "abc123"
    # ──────────────────────────────────────────

    def visit_Assign(self, node):
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id.lower()

                # Check if variable name suggests sensitive data
                if any(s in var_name for s in self.SENSITIVE_NAMES):

                    # Check if the value assigned is a plain string
                    if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                        self.add_issue(
                            node,
                            vuln_type="HARDCODED_SECRET",
                            severity="HIGH",
                            message=(
                                f"Hardcoded secret detected in variable '{target.id}'. "
                                f"The value is stored in plain text in the source code."
                            ),
                            fix=(
                                "Never hardcode secrets. Use environment variables instead:\n"
                                "  import os\n"
                                f"  {target.id} = os.environ.get('{target.id.upper()}')"
                            )
                        )

        # Must call this so the visitor keeps walking child nodes
        self.generic_visit(node)


    # ──────────────────────────────────────────
    #  RULE 2 — Unsafe eval() and exec()
    #  Detects: eval(input(...))  /  exec(user_data)
    # ──────────────────────────────────────────

    def visit_Call(self, node):

        # --- eval() and exec() ---
        if isinstance(node.func, ast.Name):
            if node.func.id in ("eval", "exec"):
                self.add_issue(
                    node,
                    vuln_type="UNSAFE_EVAL",
                    severity="HIGH",
                    message=(
                        f"'{node.func.id}()' executes arbitrary code. "
                        "If user input reaches this call, attackers can run any command."
                    ),
                    fix=(
                        f"Remove {node.func.id}(). Use specific, safe alternatives:\n"
                        "  - For math: use the 'math' module or 'ast.literal_eval()'\n"
                        "  - For JSON: use 'json.loads()'\n"
                        "  - For config: use 'configparser'"
                    )
                )

        if isinstance(node.func, ast.Attribute):

            # --- pickle.loads() — unsafe deserialization ---
            if (node.func.attr == "loads"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "pickle"):
                self.add_issue(
                    node,
                    vuln_type="UNSAFE_DESERIALIZATION",
                    severity="HIGH",
                    message=(
                        "'pickle.loads()' can execute arbitrary code when "
                        "deserializing untrusted or user-supplied data."
                    ),
                    fix=(
                        "Replace pickle with safe alternatives:\n"
                        "  - Use 'json.loads()' for structured data\n"
                        "  - Use 'ast.literal_eval()' for simple Python literals"
                    )
                )

            # --- Weak cryptographic hash functions ---
            if (node.func.attr in ("md5", "sha1")
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "hashlib"):
                self.add_issue(
                    node,
                    vuln_type="WEAK_CRYPTO",
                    severity="MEDIUM",
                    message=(
                        f"'hashlib.{node.func.attr}()' is a weak hash algorithm. "
                        "MD5 and SHA1 are broken and must not be used for passwords or signatures."
                    ),
                    fix=(
                        "Use a strong algorithm:\n"
                        "  - For general hashing: hashlib.sha256() or hashlib.sha512()\n"
                        "  - For passwords: use 'bcrypt' or 'hashlib.pbkdf2_hmac()'"
                    )
                )

            # --- SQL Injection via string concatenation ---
            if node.func.attr in self.SQL_EXECUTE_METHODS and node.args:
                query_arg = node.args[0]

                # Dangerous: "SELECT * FROM users WHERE id=" + user_id
                if isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Add):
                    self.add_issue(
                        node,
                        vuln_type="SQL_INJECTION",
                        severity="HIGH",
                        message=(
                            "SQL query built using string concatenation (+). "
                            "An attacker can manipulate the query to access or destroy data."
                        ),
                        fix=(
                            "Use parameterized queries (never build SQL with +):\n"
                            "  BAD:  cursor.execute('SELECT * FROM users WHERE id=' + uid)\n"
                            "  GOOD: cursor.execute('SELECT * FROM users WHERE id=?', (uid,))"
                        )
                    )

                # Dangerous: f"SELECT * FROM users WHERE id={user_id}"
                if isinstance(query_arg, ast.JoinedStr):
                    self.add_issue(
                        node,
                        vuln_type="SQL_INJECTION",
                        severity="HIGH",
                        message=(
                            "SQL query built using an f-string. "
                            "F-strings in SQL queries allow SQL injection attacks."
                        ),
                        fix=(
                            "Use parameterized queries (never use f-strings in SQL):\n"
                            "  BAD:  cursor.execute(f'SELECT * FROM users WHERE id={uid}')\n"
                            "  GOOD: cursor.execute('SELECT * FROM users WHERE id=?', (uid,))"
                        )
                    )

                # Dangerous: "SELECT * FROM users WHERE id=%s" % user_id
                if isinstance(query_arg, ast.BinOp) and isinstance(query_arg.op, ast.Mod):
                    self.add_issue(
                        node,
                        vuln_type="SQL_INJECTION",
                        severity="HIGH",
                        message=(
                            "SQL query built using % string formatting. "
                            "This allows SQL injection attacks."
                        ),
                        fix=(
                            "Use parameterized queries:\n"
                            "  BAD:  cursor.execute('SELECT * FROM users WHERE id=%s' % uid)\n"
                            "  GOOD: cursor.execute('SELECT * FROM users WHERE id=%s', (uid,))"
                        )
                    )

            # --- Command Injection via os.system / os.popen ---
            if node.func.attr in ("system", "popen"):
                # Flag if argument is not a plain string literal
                if node.args and not isinstance(node.args[0], ast.Constant):
                    self.add_issue(
                        node,
                        vuln_type="COMMAND_INJECTION",
                        severity="HIGH",
                        message=(
                            f"'os.{node.func.attr}()' called with a dynamic argument. "
                            "If user input reaches this, attackers can run system commands."
                        ),
                        fix=(
                            "Use subprocess with a list of arguments (never a string):\n"
                            "  BAD:  os.system('ls ' + user_input)\n"
                            "  GOOD: subprocess.run(['ls', user_input], shell=False)"
                        )
                    )

        # Keep walking child nodes
        self.generic_visit(node)


    # ──────────────────────────────────────────
    #  RULE 3 — Unsafe use of assert for security
    #  Detects: assert user == "admin"  (can be disabled with -O flag)
    # ──────────────────────────────────────────

    def visit_Assert(self, node):
        # Heuristic: if assert contains "admin", "auth", "login" it may be
        # used as a security check — which is dangerous
        source_hint = ast.dump(node.test).lower()
        if any(word in source_hint for word in ("admin", "auth", "login", "permission", "role")):
            self.add_issue(
                node,
                vuln_type="ASSERT_SECURITY_CHECK",
                severity="MEDIUM",
                message=(
                    "'assert' used for what appears to be a security check. "
                    "assert statements are removed when Python runs with the -O flag."
                ),
                fix=(
                    "Replace assert with an explicit if/raise:\n"
                    "  BAD:  assert user == 'admin'\n"
                    "  GOOD: if user != 'admin': raise PermissionError('Access denied')"
                )
            )
        self.generic_visit(node)


# ─────────────────────────────────────────────
#  Quick manual test — run this file directly
# ─────────────────────────────────────────────

if __name__ == "__main__":
    sample_code = """
import hashlib
import pickle
import os

# Vulnerability 1: hardcoded password
password = "supersecret123"

# Vulnerability 2: SQL injection via f-string
def get_user(uid):
    cursor.execute(f"SELECT * FROM users WHERE id={uid}")

# Vulnerability 3: unsafe eval
def run_command():
    eval(input("Enter expression: "))

# Vulnerability 4: weak crypto
def hash_password(pw):
    return hashlib.md5(pw.encode()).hexdigest()

# Vulnerability 5: unsafe deserialization
def load_data(raw_bytes):
    return pickle.loads(raw_bytes)

# Vulnerability 6: command injection
def list_files(folder):
    os.system("ls " + folder)
"""

    tree = ast.parse(sample_code)
    analyzer = SecurityAnalyzer()
    issues = analyzer.analyze(tree)

    print(f"\n{'='*55}")
    print(f"  Security Analysis Report — {len(issues)} issues found")
    print(f"{'='*55}\n")

    for i, issue in enumerate(issues, 1):
        print(f"[{i}] {issue['severity']} — {issue['type']}")
        print(f"    Line    : {issue['line']}")
        print(f"    Problem : {issue['message']}")
        print(f"    Fix     : {issue['fix']}")
        print()