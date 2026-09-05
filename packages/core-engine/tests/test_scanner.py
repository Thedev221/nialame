import pytest

from nialame.scanner import find_enclosing_symbol, scan_python_source


def test_detects_sql_injection_via_fstring():
    source = (
        "def get_user(user_id):\n"
        "    query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
        "    return db.execute(query)\n"
    )
    findings = scan_python_source(source)
    rule_ids = {f.rule_id for f in findings}
    assert "NIA-SQLI-001" in rule_ids
    finding = next(f for f in findings if f.rule_id == "NIA-SQLI-001")
    assert finding.enclosing_symbol == "get_user"
    assert finding.severity.value == "critical"


def test_detects_sql_injection_via_concatenation():
    source = (
        "def search(term):\n"
        "    q = \"SELECT * FROM items WHERE name = '\" + term + \"'\"\n"
        "    return q\n"
    )
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-SQLI-001" for f in findings)


def test_detects_pickle_loads():
    source = (
        "import pickle\n\n"
        "def load(data):\n"
        "    return pickle.loads(data)\n"
    )
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-DESER-001" for f in findings)

def test_detects_pickle_load():
    source = (
        "import pickle\n\n"
        "def load(file):\n"
        "    return pickle.load(file)\n"
    )

    findings = scan_python_source(source)

    assert any(f.rule_id == "NIA-DESER-001" for f in findings)


def test_detects_os_system():
    source = "import os\n\ndef run(cmd):\n    os.system(cmd)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-CMD-001" for f in findings)


def test_detects_eval():
    source = "def compute(expr):\n    return eval(expr)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-EVAL-001" for f in findings)


def test_detects_weak_hash_md5():
    source = "import hashlib\n\ndef hash_password(pw):\n    return hashlib.md5(pw.encode()).hexdigest()\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-CRYPTO-001" for f in findings)


def test_detects_weak_hash_sha1():
    source = "import hashlib\n\ndef sign(data):\n    return hashlib.sha1(data).hexdigest()\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-CRYPTO-001" for f in findings)


def test_no_false_positive_on_strong_hash():
    source = "import hashlib\n\ndef hash_password(pw):\n    return hashlib.sha256(pw.encode()).hexdigest()\n"
    findings = scan_python_source(source)
    assert not any(f.rule_id == "NIA-CRYPTO-001" for f in findings)


def test_detects_subprocess_popen():
    source = "import subprocess\n\ndef run(cmd):\n    subprocess.Popen(cmd, shell=True)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-CMD-003" for f in findings)


def test_detects_unverified_tls_context():
    source = "import ssl\n\ndef make_context():\n    return ssl._create_unverified_context()\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-TLS-001" for f in findings)


def test_no_false_positive_on_safe_code():
    source = (
        "def add(a, b):\n"
        "    return a + b\n\n"
        "def greet(name):\n"
        "    return f'Hello {name}'\n"
    )
    findings = scan_python_source(source)
    assert findings == []


def test_invalid_syntax_raises():
    with pytest.raises(SyntaxError):
        scan_python_source("def broken(:\n    pass")


def test_find_enclosing_symbol():
    source = (
        "def outer():\n"
        "    def inner():\n"
        "        x = 1\n"
        "        return x\n"
        "    return inner()\n"
    )
    assert find_enclosing_symbol(source, 3) == "inner"

