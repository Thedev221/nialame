from nialame.llm import _sanitize_replacement_lines


def test_removes_markdown_fence_with_language():
    lines = ["```python", "    return 1", "```"]
    assert _sanitize_replacement_lines(lines) == ["return 1"]


def test_removes_bare_markdown_fence():
    lines = ["```", "    return 1", "```"]
    assert _sanitize_replacement_lines(lines) == ["return 1"]


def test_dedents_over_indented_code():
    lines = ["        return 1"]
    assert _sanitize_replacement_lines(lines) == ["return 1"]


def test_preserves_relative_indentation():
    lines = ["    if True:", "        return 1"]
    assert _sanitize_replacement_lines(lines) == ["if True:", "    return 1"]


def test_no_change_on_clean_code():
    lines = ["    return 1"]
    assert _sanitize_replacement_lines(lines) == ["return 1"]


def test_empty_list_stays_empty():
    assert _sanitize_replacement_lines([]) == []


def test_reapplies_base_indent_for_single_line():
    lines = ["return eval(formula)"]
    assert _sanitize_replacement_lines(lines, base_indent="    ") == ["    return eval(formula)"]


def test_reapplies_base_indent_preserving_relative_structure():
    lines = ["if True:", "    return 1"]
    assert _sanitize_replacement_lines(lines, base_indent="    ") == ["    if True:", "        return 1"]


def test_base_indent_not_applied_to_blank_lines():
    lines = ["return 1", "", "return 2"]
    assert _sanitize_replacement_lines(lines, base_indent="    ") == ["    return 1", "", "    return 2"]
