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


def test_detects_os_popen():
    source = "import os\n\ndef run(cmd):\n    return os.popen(cmd)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-CMD-004" for f in findings)


def test_detects_pickle_load():
    source = "import pickle\n\ndef load(f):\n    return pickle.load(f)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-DESER-001" for f in findings)


def test_detects_xxe_fromstring():
    # NOTE: le scanner ne résout pas encore les alias d'import
    # (ex. `import ... as ET`) — limitation connue, backlog futur.
    source = "import xml.etree.ElementTree\n\ndef parse(data):\n    return xml.etree.ElementTree.fromstring(data)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-XXE-001" for f in findings)


def test_detects_insecure_mktemp():
    source = "import tempfile\n\ndef make_temp():\n    return tempfile.mktemp()\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-TMPFILE-001" for f in findings)


def test_detects_yaml_unsafe_load():
    source = "import yaml\n\ndef load(data):\n    return yaml.unsafe_load(data)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-DESER-003" for f in findings)


def test_detects_marshal_loads():
    source = "import marshal\n\ndef load(data):\n    return marshal.loads(data)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-DESER-004" for f in findings)


def test_detects_jsonpickle_decode():
    source = "import jsonpickle\n\ndef load(data):\n    return jsonpickle.decode(data)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-DESER-005" for f in findings)


def test_detects_paramiko_auto_add_policy():
    source = "import paramiko\n\ndef connect(client):\n    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-SSH-001" for f in findings)


def test_detects_weak_cipher_des():
    source = "from Crypto.Cipher import DES\n\ndef encrypt(key):\n    return DES.new(key)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-CRYPTO-002" for f in findings)


def test_detects_weak_cipher_rc4():
    source = "from Crypto.Cipher import ARC4\n\ndef encrypt(key):\n    return ARC4.new(key)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-CRYPTO-002" for f in findings)


def test_detects_deprecated_ssl_wrap_socket():
    source = "import ssl\n\ndef wrap(sock):\n    return ssl.wrap_socket(sock)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-TLS-002" for f in findings)


def test_detects_hardcoded_secret():
    source = "def connect():\n    password = 'hunter2super'\n    return password\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-SECRET-001" for f in findings)


def test_no_false_positive_on_secret_from_env():
    source = "import os\n\ndef connect():\n    password = os.environ.get('DB_PASSWORD')\n    return password\n"
    findings = scan_python_source(source)
    assert not any(f.rule_id == "NIA-SECRET-001" for f in findings)


def test_detects_weak_random_for_token():
    source = "import random\n\ndef make_token():\n    token = random.random()\n    return token\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-RANDOM-001" for f in findings)


def test_detects_timing_unsafe_comparison():
    source = "def check(password, stored):\n    if password == stored:\n        return True\n    return False\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-TIMING-001" for f in findings)


def test_detects_debug_mode_django():
    source = "DEBUG = True\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-DEBUG-001" for f in findings)


def test_detects_debug_mode_flask_run():
    source = "def start(app):\n    app.run(debug=True)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-DEBUG-001" for f in findings)


def test_detects_path_traversal_via_fstring():
    source = "def read_file(filename):\n    with open(f'/data/{filename}') as f:\n        return f.read()\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-PATH-001" for f in findings)


def test_no_false_positive_on_static_path():
    source = "def read_config():\n    with open('/etc/app/config.json') as f:\n        return f.read()\n"
    findings = scan_python_source(source)
    assert not any(f.rule_id == "NIA-PATH-001" for f in findings)


def test_detects_ssti_jinja2():
    source = (
        "from jinja2 import Template\n\n"
        "def render(name):\n"
        "    return Template('Hello ' + name + '!').render()\n"
    )
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-SSTI-001" for f in findings)


def test_detects_ssrf_requests_dynamic_url():
    source = (
        "import requests\n\n"
        "def fetch(user_url):\n"
        "    return requests.get('http://internal/' + user_url)\n"
    )
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-SSRF-002" for f in findings)


def test_detects_requests_verify_false():
    source = (
        "import requests\n\n"
        "def fetch(url):\n"
        "    return requests.get(url, verify=False)\n"
    )
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-TLS-003" for f in findings)


def test_detects_open_redirect():
    source = (
        "def go(target):\n"
        "    return redirect(target)\n"
    )
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-REDIRECT-001" for f in findings)


def test_no_false_positive_on_static_redirect():
    source = (
        "def go():\n"
        "    return redirect('/home')\n"
    )
    findings = scan_python_source(source)
    assert not any(f.rule_id == "NIA-REDIRECT-001" for f in findings)


def test_detects_zip_slip():
    source = (
        "import zipfile\n\n"
        "def extract(path):\n"
        "    with zipfile.ZipFile(path) as z:\n"
        "        z.extractall('/tmp/output')\n"
    )
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-ZIPSLIP-001" for f in findings)


def test_detects_subprocess_run_shell_true():
    source = "import subprocess\n\ndef run(cmd):\n    subprocess.run(cmd, shell=True)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-CMD-005" for f in findings)


def test_detects_jwt_verify_false():
    source = "import jwt\n\ndef decode(token):\n    return jwt.decode(token, verify=False)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-JWT-001" for f in findings)


def test_detects_lxml_resolve_entities():
    source = (
        "from lxml import etree\n\n"
        "def make_parser():\n"
        "    return etree.XMLParser(resolve_entities=True)\n"
    )
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-XXE-002" for f in findings)


def test_detects_cors_wildcard():
    source = "def setup(app):\n    CORS(app, origins='*')\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-CORS-001" for f in findings)


def test_detects_aes_ecb_mode():
    source = (
        "from Crypto.Cipher import AES\n\n"
        "def encrypt(key):\n"
        "    return AES.new(key, AES.MODE_ECB)\n"
    )
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-CRYPTO-004" for f in findings)


def test_detects_shelve_open():
    source = "import shelve\n\ndef load(path):\n    return shelve.open(path)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-DESER-006" for f in findings)


def test_detects_pickle_unpickler():
    source = "import pickle\n\ndef load(f):\n    return pickle.Unpickler(f)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-DESER-007" for f in findings)


def test_detects_dynamic_import():
    source = "import importlib\n\ndef load(name):\n    return importlib.import_module(name)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-IMPORT-001" for f in findings)


def test_detects_urlretrieve():
    source = "import urllib.request\n\ndef fetch(url):\n    return urllib.request.urlretrieve(url)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-INTEGRITY-001" for f in findings)


def test_detects_symlink():
    source = "import os\n\ndef link(src, dst):\n    os.symlink(src, dst)\n"
    findings = scan_python_source(source)
    assert any(f.rule_id == "NIA-SYMLINK-001" for f in findings)


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

