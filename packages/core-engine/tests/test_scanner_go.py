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


def test_no_false_positive_safe_go_code():
    source = """package main

func add(a int, b int) int {
	return a + b
}
"""
    findings = scan_go_source(source)
    assert findings == []
