import pytest

from nialame.scanner_js import JsParseError, parse_javascript_source, scan_javascript_source


def test_parses_simple_function():
    source = "function greet(name) { return 'Hello ' + name; }"
    ast = parse_javascript_source(source)
    assert ast["type"] == "Program"
    assert ast["body"][0]["type"] == "FunctionDeclaration"
    assert ast["body"][0]["id"]["name"] == "greet"


def test_parses_variable_declaration():
    source = "const x = 42;"
    ast = parse_javascript_source(source)
    assert ast["body"][0]["type"] == "VariableDeclaration"
    assert ast["body"][0]["kind"] == "const"


def test_invalid_syntax_raises_js_parse_error():
    with pytest.raises(JsParseError):
        parse_javascript_source("function broken( {")


def test_empty_source_parses_to_empty_program():
    ast = parse_javascript_source("")
    assert ast["type"] == "Program"
    assert ast["body"] == []
def test_detects_eval():
    source = "function run(input) { return eval(input); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-EVAL-001" for f in findings)


def test_detects_function_constructor():
    source = "function make(input) { return new Function(input); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-EVAL-001" for f in findings)


def test_detects_command_injection_dynamic():
    source = "const { exec } = require('child_process'); function run(cmd) { child_process.exec('ls ' + cmd); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-CMD-001" for f in findings)


def test_detects_innerhtml_xss():
    source = "function render(name) { el.innerHTML = name; }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-XSS-001" for f in findings)


def test_no_false_positive_innerhtml_literal():
    source = "function render() { el.innerHTML = '<b>static</b>'; }"
    findings = scan_javascript_source(source)
    assert not any(f.rule_id == "NIA-JS-XSS-001" for f in findings)


def test_detects_document_write_xss():
    source = "function render(name) { document.write('Hello ' + name); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-XSS-002" for f in findings)


def test_detects_weak_hash_js():
    source = "function hash(data) { return crypto.createHash('md5').update(data).digest('hex'); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-CRYPTO-001" for f in findings)


def test_detects_weak_random_token():
    source = "function makeToken() { const token = Math.random(); return token; }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-RANDOM-001" for f in findings)


def test_detects_jwt_algorithm_none():
    source = "function check(token) { jwt.verify(token, secret, { algorithms: ['none'] }); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-JWT-001" for f in findings)


def test_detects_dynamic_require():
    source = "function load(name) { return require(name); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-IMPORT-001" for f in findings)


def test_no_false_positive_static_require():
    source = "const fs = require('fs');"
    findings = scan_javascript_source(source)
    assert not any(f.rule_id == "NIA-JS-IMPORT-001" for f in findings)


def test_detects_path_traversal_js():
    source = "function readUserFile(filename) { fs.readFileSync('/data/' + filename); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-PATH-001" for f in findings)


def test_detects_hardcoded_secret_js():
    source = "function connect() { const password = 'hunter2super'; return password; }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-SECRET-001" for f in findings)


def test_no_false_positive_safe_js_code():
    source = "function add(a, b) { return a + b; }"
    findings = scan_javascript_source(source)
    assert findings == []
