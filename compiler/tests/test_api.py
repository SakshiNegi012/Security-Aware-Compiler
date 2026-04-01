# tests/test_api.py

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import requests
import json

BASE_URL = "http://127.0.0.1:5000"

def test_python_code():
    code = """
username = input("Enter name: ")
password = "secret123"
query = "SELECT * FROM users WHERE name='" + username + "'"
"""
    response = requests.post(f"{BASE_URL}/analyze",
                             json={"code": code, "language": "python"})
    data = response.json()

    print("=== Python Test ===")
    print(f"Language : {data['language']}")
    print(f"Success  : {data['success']}")
    print(f"Tokens   : {data['total_tokens']}")
    print(f"Summary  : {data['summary']}")
    print(f"Symbols  :")
    for name, info in data["symbol_table"].items():
        print(f"  {name:15} source={info['source']}")

    assert data["success"] == True
    assert data["symbol_table"]["username"]["source"] == "user_input"
    assert data["symbol_table"]["query"]["source"]    == "user_input"
    assert data["summary"]["has_user_input_vars"]     == True
    print("PASS: Python API test\n")


def test_c_code():
    code = """
#include <stdio.h>
int main() {
    char buffer[10];
    gets(buffer);
    return 0;
}
"""
    response = requests.post(f"{BASE_URL}/analyze",
                             json={"code": code, "language": "c"})
    data = response.json()

    print("=== C Test ===")
    print(f"Language       : {data['language']}")
    print(f"Semantic errors: {data['semantic_errors']}")
    print(f"Dangerous calls: {data['dangerous_calls']}")

    assert data["language"] == "c"
    assert len(data["dangerous_calls"]) > 0
    print("PASS: C API test\n")


def test_empty_code():
    response = requests.post(f"{BASE_URL}/analyze",
                             json={"code": ""})
    assert response.status_code == 400
    print("PASS: empty code rejected\n")


if __name__ == "__main__":
    test_python_code()
    test_c_code()
    test_empty_code()
    print("All API tests passed.")