import pytest

from nialame.scanner_js import JsParseError, parse_javascript_source


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
