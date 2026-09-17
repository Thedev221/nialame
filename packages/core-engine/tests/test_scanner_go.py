import pytest

from nialame.scanner_go import GoParseError, parse_go_source, scan_go_source


def test_parses_simple_function():
    source = """package main

func greet(name string) string {
	return "Hello " + name
}
"""
    result = parse_go_source(source)
    assert "call_sites" in result


def test_invalid_syntax_raises_go_parse_error():
    with pytest.raises(GoParseError):
        parse_go_source("package main\nfunc broken( {")


def test_detects_command_injection_dynamic():
    source = """package main

import "os/exec"

func run(cmd string) {
	exec.Command("sh", "-c", "prefix " + cmd).Run()
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-CMD-001" for f in findings)


def test_no_false_positive_static_command():
    source = """package main

import "os/exec"

func run() {
	exec.Command("ls", "-la").Run()
}
"""
    findings = scan_go_source(source)
    assert not any(f.rule_id == "NIA-GO-CMD-001" for f in findings)


def test_detects_weak_hash_md5():
    source = """package main

import "crypto/md5"

func hash(data []byte) [16]byte {
	return md5.Sum(data)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-CRYPTO-001" for f in findings)


def test_detects_weak_random():
    source = """package main

import "math/rand"

func token() int {
	return rand.Intn(1000000)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-RANDOM-001" for f in findings)


def test_detects_dynamic_path_open():
    source = """package main

import "os"

func read(userPath string) {
	os.Open("/data/" + userPath)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-PATH-001" for f in findings)


def test_detects_dynamic_filepath_join():
    source = """package main

import "path/filepath"

func build(userPath string) string {
	return filepath.Join("/data", "prefix" + userPath)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-PATH-002" for f in findings)


def test_detects_sql_injection_query():
    source = """package main

func get(db *sql.DB, userId string) {
	db.Query("SELECT * FROM users WHERE id=" + userId)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-SQLI-001" for f in findings)


def test_detects_ssrf_http_get():
    source = """package main

import "net/http"

func fetch(userUrl string) {
	http.Get("http://internal/" + userUrl)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-SSRF-001" for f in findings)


def test_detects_open_redirect_go():
    source = """package main

import "net/http"

func go_redirect(w http.ResponseWriter, r *http.Request, target string) {
	http.Redirect(w, r, "prefix" + target, http.StatusFound)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-REDIRECT-001" for f in findings)


def test_detects_weak_cipher_des():
    source = """package main

import "crypto/des"

func encrypt(key []byte) {
	des.NewCipher(key)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-CRYPTO-002" for f in findings)


def test_detects_weak_hash_md4():
    source = """package main

import "golang.org/x/crypto/md4"

func hash() {
	md4.New()
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-CRYPTO-003" for f in findings)


def test_detects_xxe_xml_unmarshal():
    source = """package main

import "encoding/xml"

func parse(data []byte, v interface{}) {
	xml.Unmarshal(data, v)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-XXE-001" for f in findings)


def test_detects_plugin_open():
    source = """package main

import "plugin"

func load(path string) {
	plugin.Open(path)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-PLUGIN-001" for f in findings)


def test_detects_template_html_bypass():
    source = """package main

import "html/template"

func render(userInput string) template.HTML {
	return template.HTML(userInput)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-TEMPLATE-001" for f in findings)


def test_detects_insecure_ssh_host_key():
    source = """package main

import "golang.org/x/crypto/ssh"

func config() {
	ssh.InsecureIgnoreHostKey()
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-SSH-001" for f in findings)


def test_detects_zip_slip_go():
    source = """package main

import "archive/zip"

func extract(path string) {
	zip.OpenReader(path)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-ZIPSLIP-001" for f in findings)


def test_detects_unsafe_pointer():
    source = """package main

import "unsafe"

func convert(p unsafe.Pointer) {
	unsafe.Pointer(p)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-UNSAFE-001" for f in findings)


def test_detects_http_listen_no_tls():
    source = """package main

import "net/http"

func serve() {
	http.ListenAndServe(":8080", nil)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-LISTEN-001" for f in findings)


def test_detects_jwt_parse_without_algorithm_check():
    source = """package main

import "github.com/golang-jwt/jwt"

func check(tokenString string) {
	jwt.Parse(tokenString, nil)
}
"""
    findings = scan_go_source(source)
    assert any(f.rule_id == "NIA-GO-JWT-001" for f in findings)


def test_no_false_positive_safe_go_code():
    source = """package main

func add(a int, b int) int {
	return a + b
}
"""
    findings = scan_go_source(source)
    assert findings == []
