// js/app.js — Security Aware Compiler Frontend Logic

const API_URL = '/analyze';

// ── Sample code snippets ──────────────────────────────────────
const SAMPLES = {
  python: `import sqlite3

# User input (tainted source)
username = input("Enter your username: ")
password = "admin123"

# Dangerous: user input concatenated into SQL
query = "SELECT * FROM users WHERE name='" + username + "'"

conn   = sqlite3.connect("mydb.db")
cursor = conn.cursor()
cursor.execute(query)
results = cursor.fetchall()
print(results)
`,
  c: `#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    char password[] = "secret123";

    printf("Enter your name: ");
    gets(buffer);

    printf("Hello, %s\\n", buffer);
    return 0;
}
`
};

// ── DOM refs ──────────────────────────────────────────────────
const codeInput     = document.getElementById('codeInput');
const lineNumbers   = document.getElementById('lineNumbers');
const languageSel   = document.getElementById('language');
const analyzeBtn    = document.getElementById('analyzeBtn');
const btnText       = document.getElementById('btnText');
const btnSpinner    = document.getElementById('btnSpinner');
const clearBtn      = document.getElementById('clearBtn');
const loadSampleBtn = document.getElementById('loadSampleBtn');
const lineCount     = document.getElementById('lineCount');
const charCount     = document.getElementById('charCount');
const detectedLang  = document.getElementById('detectedLang');
const idleState     = document.getElementById('idleState');
const resultsState  = document.getElementById('resultsState');

// ── Line numbers ──────────────────────────────────────────────
function updateLineNumbers() {
  const lines = codeInput.value.split('\n').length;
  lineNumbers.textContent = Array.from({length: lines}, (_, i) => i + 1).join('\n');
}

function updateStats() {
  const code  = codeInput.value;
  const lines = code.split('\n').length;
  const chars = code.length;
  lineCount.textContent = `${lines} line${lines !== 1 ? 's' : ''}`;
  charCount.textContent = `${chars} char${chars !== 1 ? 's' : ''}`;

  if (!code.trim()) {
    detectedLang.textContent = 'No code';
    return;
  }
  const cScore = ['#include','int main','printf','scanf','->','{'].filter(k => code.includes(k)).length;
  detectedLang.textContent = cScore >= 2 ? 'Detected: C' : 'Detected: Python';
}

codeInput.addEventListener('input', () => {
  updateLineNumbers();
  updateStats();
});

codeInput.addEventListener('scroll', () => {
  lineNumbers.scrollTop = codeInput.scrollTop;
});

// Tab key support in editor
codeInput.addEventListener('keydown', e => {
  if (e.key === 'Tab') {
    e.preventDefault();
    const start = codeInput.selectionStart;
    const end   = codeInput.selectionEnd;
    codeInput.value = codeInput.value.substring(0, start) + '    ' + codeInput.value.substring(end);
    codeInput.selectionStart = codeInput.selectionEnd = start + 4;
    updateLineNumbers();
  }
});

// ── Clear ─────────────────────────────────────────────────────
clearBtn.addEventListener('click', () => {
  codeInput.value = '';
  updateLineNumbers();
  updateStats();
  showIdle();
});

// ── Load Sample ───────────────────────────────────────────────
loadSampleBtn.addEventListener('click', () => {
  const lang = languageSel.value === 'c' ? 'c' : 'python';
  codeInput.value = SAMPLES[lang];
  updateLineNumbers();
  updateStats();
});

// ── Tab switching ─────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));
    tab.classList.add('active');
    document.getElementById('tab-' + tab.dataset.tab).classList.remove('hidden');
  });
});

// ── Show / hide states ────────────────────────────────────────
function showIdle() {
  idleState.classList.remove('hidden');
  resultsState.classList.add('hidden');
}

function showResults() {
  idleState.classList.add('hidden');
  resultsState.classList.remove('hidden');
}

// ── Analyze ───────────────────────────────────────────────────
analyzeBtn.addEventListener('click', async () => {
  const code = codeInput.value.trim();
  if (!code) { alert('Please enter some code first.'); return; }

  // Loading state
  analyzeBtn.disabled = true;
  btnText.textContent = 'Analyzing...';
  btnSpinner.classList.remove('hidden');
  showResults();
  setStatus('Analyzing...', 'warning');

  try {
    const res = await fetch(API_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code, language: languageSel.value })
    });

    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || 'Server error');
    }

    const data = await res.json();
    renderResults(data);

  } catch (err) {
    setStatus('Connection failed — is Flask running?', 'error');
    renderConnectionError(err.message);
  } finally {
    analyzeBtn.disabled = false;
    btnText.textContent = 'Analyze Code';
    btnSpinner.classList.add('hidden');
  }
});

// ── Render all results ────────────────────────────────────────
function renderResults(data) {
  // Status bar
  const hasErrors   = data.syntax_errors.length > 0;
  const hasWarnings = data.semantic_errors.length > 0 || data.dangerous_calls.length > 0;
  const statusType  = hasErrors ? 'error' : hasWarnings ? 'warning' : 'success';
  const statusMsg   = hasErrors
    ? `Compilation failed — ${data.syntax_errors.length} error(s)`
    : hasWarnings
      ? `Compiled with ${data.semantic_errors.length + data.dangerous_calls.length} warning(s)`
      : 'Compiled successfully — no issues found';

  setStatus(statusMsg, statusType);

  // Lang + token tags
  document.getElementById('langTag').textContent   = data.language.toUpperCase();
  document.getElementById('tokenTag').textContent  = `${data.total_tokens} tokens`;

  // Summary cards
  const secCount = buildSecurityIssues(data).length;
  document.getElementById('cardTokens').textContent   = data.total_tokens;
  document.getElementById('cardSymbols').textContent  = data.summary.total_symbols;
  document.getElementById('cardWarnings').textContent = secCount;
  document.getElementById('cardErrors').textContent   = data.summary.total_syntax_errors;

  // Render each tab
  renderSecurity(data);
  renderSymbols(data.symbol_table);
  renderTokens(data.tokens || []);
  renderErrors(data.syntax_errors, data.semantic_errors);
  renderAST(data);

  // Switch to security tab
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.add('hidden'));
  document.querySelector('[data-tab="security"]').classList.add('active');
  document.getElementById('tab-security').classList.remove('hidden');
}

// ── Status bar helper ─────────────────────────────────────────
function setStatus(msg, type) {
  const dot  = document.getElementById('statusDot');
  const text = document.getElementById('statusText');
  dot.className  = 'status-dot ' + (type || '');
  text.textContent = msg;
}

// ── Build security issue list from API data ───────────────────
function buildSecurityIssues(data) {
  const issues = [];

  // From symbol table — user input variables
  Object.entries(data.symbol_table || {}).forEach(([name, sym]) => {
    if (sym.source === 'user_input') {
      issues.push({
        type:     'Unsafe Input Source',
        severity: 'HIGH',
        line:     sym.declared_line,
        desc:     `Variable "${name}" holds user-controlled input. If passed to a database query, file operation, or system call without sanitization, it can lead to injection attacks.`,
        rec:      'Always validate and sanitize user input before use. Use parameterized queries for database operations.'
      });
    }
    if (sym.source === 'hardcoded' && sym.kind === 'variable' &&
        /pass|secret|key|token|pwd|credential/i.test(name)) {
      issues.push({
        type:     'Hardcoded Sensitive Data',
        severity: 'HIGH',
        line:     sym.declared_line,
        desc:     `Variable "${name}" appears to contain a hardcoded secret or credential. Hardcoded secrets can be extracted by anyone who reads the source code or decompiles the binary.`,
        rec:      'Store secrets in environment variables or a secrets manager. Use os.environ.get("SECRET_KEY") instead.'
      });
    }
  });

  // SQL injection — user input + query pattern
  const symVals = Object.values(data.symbol_table || {});
  const hasUserInput = symVals.some(s => s.source === 'user_input');
  const hasQuery     = symVals.some(s => s.source === 'user_input' &&
                       /query|sql|cmd|command/i.test(s.name));
  if (hasUserInput && hasQuery) {
    const qSym = symVals.find(s => s.source === 'user_input' && /query|sql/i.test(s.name));
    issues.push({
      type:     'SQL Injection Risk',
      severity: 'HIGH',
      line:     qSym ? qSym.declared_line : 0,
      desc:     'A variable containing user input is being used in what appears to be a SQL query. This allows attackers to manipulate the query and access or destroy database data.',
      rec:      'Use parameterized queries: cursor.execute("SELECT * FROM users WHERE name = ?", (username,))'
    });
  }

  // Dangerous C function calls
  (data.dangerous_calls || []).forEach(call => {
    const dangerMap = {
      gets:    { sev: 'HIGH',   desc: 'gets() reads input with no length limit, directly causing buffer overflow.', rec: 'Use fgets(buffer, sizeof(buffer), stdin) instead.' },
      strcpy:  { sev: 'HIGH',   desc: 'strcpy() copies without bounds checking, risking buffer overflow.', rec: 'Use strncpy(dest, src, sizeof(dest)-1) instead.' },
      strcat:  { sev: 'HIGH',   desc: 'strcat() concatenates without bounds checking.', rec: 'Use strncat(dest, src, sizeof(dest)-strlen(dest)-1) instead.' },
      sprintf: { sev: 'MEDIUM', desc: 'sprintf() can overflow the destination buffer.', rec: 'Use snprintf(buf, sizeof(buf), ...) instead.' },
      scanf:   { sev: 'MEDIUM', desc: 'scanf() without width specifier can overflow buffers.', rec: 'Use scanf("%9s", buffer) with explicit width limits.' },
      system:  { sev: 'HIGH',   desc: 'system() executes shell commands — command injection risk.', rec: 'Avoid system(). Use execv() with sanitized arguments if shell is needed.' },
    };
    const info = dangerMap[call.function] || { sev: 'MEDIUM', desc: `${call.function}() is a dangerous function.`, rec: 'Review usage and replace with a safe alternative.' };
    issues.push({
      type:     `Buffer Overflow Risk — ${call.function}()`,
      severity: info.sev,
      line:     call.lineno,
      desc:     info.desc,
      rec:      info.rec
    });
  });

  // Semantic warnings from compiler
  (data.semantic_errors || []).forEach(err => {
    if (!issues.some(i => i.line === err.line)) {
      issues.push({
        type:     'Compiler Security Warning',
        severity: 'MEDIUM',
        line:     err.line,
        desc:     err.message,
        rec:      'Review this line and replace with a safer alternative function or pattern.'
      });
    }
  });

  return issues;
}

// ── Render Security Tab ───────────────────────────────────────
function renderSecurity(data) {
  const container = document.getElementById('securityList');
  const issues    = buildSecurityIssues(data);

  if (issues.length === 0) {
    container.innerHTML = `
      <div class="no-issues">
        <div class="no-issues-icon">&#10004;</div>
        No security issues detected. Code looks safe!
      </div>`;
    return;
  }

  // Sort: HIGH first
  const order = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
  issues.sort((a, b) => (order[a.severity] || 99) - (order[b.severity] || 99));

  container.innerHTML = issues.map(issue => {
    const sev      = issue.severity.toLowerCase();
    const cardCls  = `sec-card sec-card-${sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : 'low'}`;
    const sevCls   = `sev-badge sev-${sev === 'high' ? 'high' : sev === 'medium' ? 'medium' : 'low'}`;
    const lineTag  = issue.line ? `Line ${issue.line}` : '';
    return `
      <div class="${cardCls}">
        <div class="sec-card-header">
          <div class="sec-card-title">
            <span class="${sevCls}">${issue.severity}</span>
            ${issue.type}
          </div>
          ${lineTag ? `<span class="sec-line-tag">${lineTag}</span>` : ''}
        </div>
        <div class="sec-card-body">
          <div class="sec-desc">${issue.desc}</div>
          <div class="sec-rec-label">&#10003; Recommendation</div>
          <div class="sec-rec">${issue.rec}</div>
        </div>
      </div>`;
  }).join('');
}

// ── Render Symbol Table ───────────────────────────────────────
function renderSymbols(symbolTable) {
  const tbody = document.getElementById('symbolBody');
  const entries = Object.values(symbolTable || {});

  if (entries.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" style="text-align:center;color:var(--text2);padding:20px">No symbols found</td></tr>';
    return;
  }

  tbody.innerHTML = entries.map(sym => {
    const srcClass = {
      user_input:      'src-user',
      hardcoded:       'src-hard',
      file_read:       'src-file',
      function_return: 'src-func',
    }[sym.source] || 'src-unk';

    const srcLabel = {
      user_input:      '⚠ user_input',
      hardcoded:       '⚡ hardcoded',
      file_read:       '📄 file_read',
      function_return: '↩ func_return',
      unknown:         '? unknown',
    }[sym.source] || sym.source;

    return `
      <tr>
        <td style="color:var(--accent);font-weight:500">${sym.name}</td>
        <td>${sym.kind}</td>
        <td>${sym.value_type || '—'}</td>
        <td>${sym.declared_line}</td>
        <td class="${srcClass}">${srcLabel}</td>
      </tr>`;
  }).join('');
}

// ── Render Tokens Tab ─────────────────────────────────────────
function renderTokens(tokens) {
  const tbody = document.getElementById('tokenBody');

  if (!tokens.length) {
    tbody.innerHTML = '<tr><td colspan="4" style="text-align:center;color:var(--text2);padding:20px">No token data available</td></tr>';
    return;
  }

  const colorMap = {
    KEYWORD:           'tok-keyword',
    STRING_LITERAL:    'tok-string',
    NUMBER:            'tok-number',
    IDENTIFIER:        'tok-ident',
    OPERATOR:          'tok-op',
    DANGEROUS_FUNCTION:'tok-danger',
  };

  tbody.innerHTML = tokens.slice(0, 500).map(tok => {
    const cls = colorMap[tok.type] || 'tok-default';
    const val = String(tok.value).replace(/</g,'&lt;').replace(/>/g,'&gt;');
    return `
      <tr>
        <td>${tok.line}</td>
        <td>${tok.column}</td>
        <td class="${cls}">${tok.type}</td>
        <td class="${cls}">${val}</td>
      </tr>`;
  }).join('');

  if (tokens.length > 500) {
    tbody.innerHTML += `<tr><td colspan="4" style="text-align:center;color:var(--text2);padding:10px">
      ... and ${tokens.length - 500} more tokens</td></tr>`;
  }
}

// ── Render Errors Tab ─────────────────────────────────────────
function renderErrors(syntaxErrors, semanticErrors) {
  const container = document.getElementById('errorsList');
  const all = [
    ...syntaxErrors.map(e  => ({...e, kind: 'syntax'})),
    ...semanticErrors.map(e => ({...e, kind: 'semantic'})),
  ];

  if (all.length === 0) {
    container.innerHTML = '<div class="no-errors">&#10003; No errors or warnings found</div>';
    return;
  }

  container.innerHTML = all.map(err => `
    <div class="error-item error-${err.kind}">
      <div class="error-line">${err.kind.toUpperCase()} · Line ${err.line || '?'}</div>
      ${err.message}
    </div>`).join('');
}

// ── Render AST Tab ────────────────────────────────────────────
function renderAST(data) {
  const view = document.getElementById('astView');
  const summary = {
    language:       data.language,
    success:        data.success,
    total_tokens:   data.total_tokens,
    symbol_count:   data.summary.total_symbols,
    dangerous_calls: data.dangerous_calls,
    ast_type:       data.ast?._type || data.ast?.['_type'] || 'CProgram',
    includes:       data.ast?.includes || [],
    functions:      data.ast?.functions || [],
  };
  view.textContent = JSON.stringify(summary, null, 2);
}

// ── Connection error ──────────────────────────────────────────
function renderConnectionError(msg) {
  document.getElementById('securityList').innerHTML = `
    <div class="sec-card sec-card-high">
      <div class="sec-card-header">
        <div class="sec-card-title">
          <span class="sev-badge sev-high">ERROR</span>
          Cannot connect to compiler API
        </div>
      </div>
      <div class="sec-card-body">
        <div class="sec-desc">${msg}</div>
        <div class="sec-rec-label">Fix</div>
        <div class="sec-rec">Make sure Flask is running: python app.py</div>
      </div>
    </div>`;
}

// ── Init ──────────────────────────────────────────────────────
updateLineNumbers();
updateStats();