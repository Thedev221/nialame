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


def test_detects_sql_injection_query():
    source = "function get(userId) { db.query('SELECT * FROM users WHERE id=' + userId); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-SQLI-001" for f in findings)


def test_detects_shell_true():
    source = "function run(cmd) { child_process.spawn(cmd, { shell: true }); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-CMD-002" for f in findings)


def test_detects_node_serialize_unserialize():
    source = "function load(data) { return serialize.unserialize(data); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-DESER-001" for f in findings)


def test_detects_open_redirect_js():
    source = "function go(target) { res.redirect(target); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-REDIRECT-001" for f in findings)


def test_no_false_positive_static_redirect_js():
    source = "function go() { res.redirect('/home'); }"
    findings = scan_javascript_source(source)
    assert not any(f.rule_id == "NIA-JS-REDIRECT-001" for f in findings)


def test_detects_xxe_libxmljs():
    source = "function parse(xml) { return libxmljs.parseXml(xml, { noent: true }); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-XXE-001" for f in findings)


def test_detects_jwt_hardcoded_secret():
    source = "function sign(payload) { return jwt.sign(payload, 'my-super-secret-key'); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-JWT-002" for f in findings)


def test_detects_zip_slip_js():
    source = "function extract(zip) { zip.extractAllTo('/tmp/out'); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-ZIPSLIP-001" for f in findings)


def test_detects_prototype_pollution():
    source = "function merge(key, obj) { obj[key]['__proto__'] = {}; }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-PROTO-001" for f in findings)


def test_detects_insecure_cookie():
    source = "function setAuth(res, token) { res.cookie('session', token); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-COOKIE-001" for f in findings)


def test_no_false_positive_secure_cookie():
    source = "function setAuth(res, token) { res.cookie('session', token, { httpOnly: true, secure: true }); }"
    findings = scan_javascript_source(source)
    assert not any(f.rule_id == "NIA-JS-COOKIE-001" for f in findings)


def test_detects_cors_wildcard_setheader():
    source = "function handle(res) { res.setHeader('Access-Control-Allow-Origin', '*'); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-CORS-001" for f in findings)


def test_detects_header_injection():
    source = "function handle(res, name) { res.setHeader('X-User', name); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-HEADER-001" for f in findings)


def test_detects_tls_reject_unauthorized_false():
    source = "function connect() { return https.request({ rejectUnauthorized: false }); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-TLS-001" for f in findings)


def test_detects_vm_run_in_new_context():
    source = "function run(code) { return vm.runInNewContext(code); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-VM-001" for f in findings)


def test_detects_yaml_load_js():
    source = "function load(data) { return yaml.load(data); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-YAML-001" for f in findings)


def test_detects_ssti_ejs():
    source = "function render(name) { return ejs.render('Hello ' + name); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-SSTI-001" for f in findings)


def test_detects_process_env_exposed():
    source = "function handler(req, res) { res.json(process.env); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-EXPOSE-001" for f in findings)


def test_detects_ssrf_axios():
    source = "function fetchUrl(userUrl) { return axios.get('http://internal/' + userUrl); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-SSRF-001" for f in findings)


def test_detects_mass_assignment():
    source = "function update(user, req) { Object.assign(user, req.body); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-MASSASSIGN-001" for f in findings)


def test_detects_deprecated_create_cipher():
    source = "function encrypt(key) { return crypto.createCipher('aes192', key); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-CRYPTO-002" for f in findings)


def test_detects_dynamic_path_join():
    source = "function build(userPath) { return path.join('/data', userPath); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-PATH-002" for f in findings)


def test_detects_legacy_buffer_constructor():
    source = "function make(size) { return new Buffer(size); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-BUFFER-001" for f in findings)


def test_detects_hardcoded_session_secret():
    source = "function setup(app) { app.use(session({ secret: 'my-hardcoded-secret' })); }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-SESSION-001" for f in findings)


def test_detects_timing_unsafe_comparison_js():
    source = "function check(password, stored) { if (password === stored) { return true; } return false; }"
    findings = scan_javascript_source(source)
    assert any(f.rule_id == "NIA-JS-TIMING-001" for f in findings)


def test_no_false_positive_safe_js_code():
    source = "function add(a, b) { return a + b; }"
    findings = scan_javascript_source(source)
    assert findings == []
