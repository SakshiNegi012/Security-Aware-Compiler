"""
Test Suite for Security Analysis Module
========================================
Run with:   python tests/test_security.py

Each test has:
  - A VULNERABLE code snippet  → must trigger the rule
  - A SAFE code snippet        → must NOT trigger (no false positives)
"""

import ast
import sys
import os

# Add parent folder to path so we can import the analyzer
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from analyzer import SecurityAnalyzer


# ─────────────────────────────────────────────
#  Helper
# ─────────────────────────────────────────────

def run(code):
    """Parse code and return list of detected issues."""
    tree = ast.parse(code)
    return SecurityAnalyzer().analyze(tree)

def types(issues):
    """Return just the vulnerability type names from a result list."""
    return [i["type"] for i in issues]

passed = 0
failed = 0

def check(name, condition):
    global passed, failed
    if condition:
        print(f"  ✓  {name}")
        passed += 1
    else:
        print(f"  ✗  FAILED: {name}")
        failed += 1


# ─────────────────────────────────────────────
#  Test Group 1 — Hardcoded Secrets
# ─────────────────────────────────────────────

print("\n── Hardcoded Secrets ──────────────────────────")

# Should detect
code = 'password = "abc123"'
check("password = string literal → detected",
      "HARDCODED_SECRET" in types(run(code)))

code = 'api_key = "sk-abc123xyz"'
check("api_key = string literal → detected",
      "HARDCODED_SECRET" in types(run(code)))

code = 'db_password = "hunter2"'
check("db_password = string literal → detected",
      "HARDCODED_SECRET" in types(run(code)))

# Should NOT detect (no false positives)
code = 'username = "admin"'
check("username = string → NOT flagged (no false positive)",
      "HARDCODED_SECRET" not in types(run(code)))

code = 'count = 42'
check("count = number → NOT flagged",
      "HARDCODED_SECRET" not in types(run(code)))

code = 'password = os.environ.get("PASSWORD")'
check("password from env var → NOT flagged",
      "HARDCODED_SECRET" not in types(run(code)))


# ─────────────────────────────────────────────
#  Test Group 2 — Unsafe eval / exec
# ─────────────────────────────────────────────

print("\n── Unsafe eval / exec ─────────────────────────")

code = 'eval(input("Enter: "))'
check("eval(input()) → detected",
      "UNSAFE_EVAL" in types(run(code)))

code = 'exec(user_data)'
check("exec(variable) → detected",
      "UNSAFE_EVAL" in types(run(code)))

code = 'x = eval("1 + 1")'
check("eval with literal string → still detected (rule flags all eval)",
      "UNSAFE_EVAL" in types(run(code)))


# ─────────────────────────────────────────────
#  Test Group 3 — SQL Injection
# ─────────────────────────────────────────────

print("\n── SQL Injection ───────────────────────────────")

code = 'cursor.execute("SELECT * FROM users WHERE id=" + uid)'
check("SQL with string concat (+) → detected",
      "SQL_INJECTION" in types(run(code)))

code = 'cursor.execute(f"SELECT * FROM users WHERE id={uid}")'
check("SQL with f-string → detected",
      "SQL_INJECTION" in types(run(code)))

code = 'cursor.execute("SELECT * FROM users WHERE id=%s" % uid)'
check("SQL with % formatting → detected",
      "SQL_INJECTION" in types(run(code)))

# Safe parameterized query — should NOT detect
code = 'cursor.execute("SELECT * FROM users WHERE id=?", (uid,))'
check("Parameterized query → NOT flagged (correct usage)",
      "SQL_INJECTION" not in types(run(code)))


# ─────────────────────────────────────────────
#  Test Group 4 — Weak Crypto
# ─────────────────────────────────────────────

print("\n── Weak Crypto ─────────────────────────────────")

code = 'import hashlib\nhashlib.md5(b"password")'
check("hashlib.md5() → detected",
      "WEAK_CRYPTO" in types(run(code)))

code = 'import hashlib\nhashlib.sha1(b"password")'
check("hashlib.sha1() → detected",
      "WEAK_CRYPTO" in types(run(code)))

code = 'import hashlib\nhashlib.sha256(b"password")'
check("hashlib.sha256() → NOT flagged (strong algorithm)",
      "WEAK_CRYPTO" not in types(run(code)))


# ─────────────────────────────────────────────
#  Test Group 5 — Unsafe Deserialization
# ─────────────────────────────────────────────

print("\n── Unsafe Deserialization ──────────────────────")

code = 'import pickle\npickle.loads(raw_data)'
check("pickle.loads() → detected",
      "UNSAFE_DESERIALIZATION" in types(run(code)))

code = 'import json\njson.loads(raw_data)'
check("json.loads() → NOT flagged (safe alternative)",
      "UNSAFE_DESERIALIZATION" not in types(run(code)))


# ─────────────────────────────────────────────
#  Test Group 6 — Command Injection
# ─────────────────────────────────────────────

print("\n── Command Injection ───────────────────────────")

code = 'import os\nos.system("ls " + folder)'
check("os.system() with concat → detected",
      "COMMAND_INJECTION" in types(run(code)))

code = 'import os\nos.system("ls /tmp")'
check("os.system() with plain string → NOT flagged",
      "COMMAND_INJECTION" not in types(run(code)))


# ─────────────────────────────────────────────
#  Test Group 7 — Multiple vulnerabilities
# ─────────────────────────────────────────────

print("\n── Multiple Vulnerabilities in One File ────────")

code = """
password = "abc123"
eval(input("Enter code: "))
cursor.execute("SELECT * FROM users WHERE id=" + uid)
import hashlib
hashlib.md5(b"test")
"""
issues = run(code)
check("All 4 vulnerabilities detected in one file",
      len(issues) >= 4)
check("Correct line numbers are present",
      all(i["line"] > 0 for i in issues))
check("All have severity field",
      all(i["severity"] in ("HIGH","MEDIUM","LOW") for i in issues))


# ─────────────────────────────────────────────
#  Summary
# ─────────────────────────────────────────────

print(f"\n{'='*50}")
print(f"  Results: {passed} passed, {failed} failed")
print(f"{'='*50}\n")

if failed == 0:
    print("  All tests passed! Your security module works correctly.\n")
else:
    print(f"  {failed} test(s) failed. Check the rules above.\n")
    sys.exit(1)