# app.py

import sys
import os
sys.path.insert(0, os.path.dirname(__file__))

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
from pipeline import run_compiler

app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)   # allows frontend to call this API

@app.route("/", methods=["GET"])
def home():
    return send_from_directory('frontend', 'index.html')

@app.route("/api", methods=["GET"])
def api_status():
    return jsonify({"status": "Security Aware Compiler API is running"})

@app.route("/analyze", methods=["POST"])
def analyze():
    data = request.get_json()

    if not data or "code" not in data:
        return jsonify({"error": "No code provided"}), 400

    source_code = data["code"]
    language    = data.get("language", "auto")  # optional, defaults to auto

    if not source_code.strip():
        return jsonify({"error": "Empty code submitted"}), 400

    # Run your compiler pipeline
    result = run_compiler(source_code, language=language)

    # Build response
    response = {
        "language":        result.language,
        "success":         result.success,
        "total_tokens":    len(result.tokens),
        "tokens":          [{"type": t.type, "value": t.value, "line": t.line, "column": t.column} for t in result.tokens],
        "syntax_errors":   result.syntax_errors,
        "semantic_errors": result.semantic_errors,
        "symbol_table":    result.symbol_table,
        "dangerous_calls": result.ast.get("dangerous_calls", []),
        "summary": {
            "total_syntax_errors":   len(result.syntax_errors),
            "total_semantic_errors": len(result.semantic_errors),
            "total_symbols":         len(result.symbol_table),
            "has_user_input_vars":   any(
                v["source"] == "user_input"
                for v in result.symbol_table.values()
            )
        }
    }

    return jsonify(response)

if __name__ == "__main__":
    app.run(debug=True, port=5000)