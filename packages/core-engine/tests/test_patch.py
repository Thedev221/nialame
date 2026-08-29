from nialame.models import DocumentRef, Range, SuggestedPatch
from nialame.patch import build_unified_diff, compute_sha256, validate_and_apply_patch


def _doc(content: str, version: int = 1) -> DocumentRef:
    return DocumentRef(uri="file:///app.py", version=version, sha256=compute_sha256(content), content=content)


def test_rejects_patch_with_stale_hash():
    original = "def f():\n    return 1\n"
    doc = _doc(original)
    patch = SuggestedPatch(
        finding_rule_id="NIA-EVAL-001",
        document_sha256="0" * 64,  # hash volontairement obsolète
        document_version=1,
        anchor_range=Range(start_line=2, start_column=0, end_line=2, end_column=12),
        unified_diff="--- a/x\n+++ b/x\n@@\n-    return 1\n+    return 2\n",
    )
    outcome = validate_and_apply_patch(doc, patch)
    assert outcome.valid is False
    assert any("hash" in r.lower() for r in outcome.reasons)


def test_rejects_patch_with_stale_version():
    original = "def f():\n    return 1\n"
    doc = _doc(original, version=5)
    patch = SuggestedPatch(
        finding_rule_id="NIA-EVAL-001",
        document_sha256=doc.sha256,
        document_version=4,
        anchor_range=Range(start_line=2, start_column=0, end_line=2, end_column=12),
        unified_diff="--- a/x\n+++ b/x\n@@\n-    return 1\n+    return 2\n",
    )
    outcome = validate_and_apply_patch(doc, patch)
    assert outcome.valid is False
    assert any("version" in r.lower() for r in outcome.reasons)


def test_rejects_patch_producing_invalid_syntax():
    original = "def f():\n    return 1\n"
    doc = _doc(original)
    patch = SuggestedPatch(
        finding_rule_id="NIA-EVAL-001",
        document_sha256=doc.sha256,
        document_version=1,
        anchor_range=Range(start_line=2, start_column=0, end_line=2, end_column=12),
        unified_diff="--- a/x\n+++ b/x\n@@\n-    return 1\n+    return (\n",
    )
    outcome = validate_and_apply_patch(doc, patch)
    assert outcome.valid is False
    assert any("invalide" in r.lower() for r in outcome.reasons)


def test_accepts_valid_patch_fixing_eval():
    original = "def compute(expr):\n    return eval(expr)\n"
    doc = _doc(original)
    patch = SuggestedPatch(
        finding_rule_id="NIA-EVAL-001",
        document_sha256=doc.sha256,
        document_version=1,
        anchor_range=Range(start_line=2, start_column=0, end_line=2, end_column=25),
        unified_diff=(
            "--- a/app.py\n+++ b/app.py\n@@\n"
            "-    return eval(expr)\n"
            "+    raise NotImplementedError('eval disabled')\n"
        ),
    )
    outcome = validate_and_apply_patch(doc, patch)
    assert outcome.valid is True
    assert outcome.patched_source is not None
    assert "eval(" not in outcome.patched_source


def test_build_unified_diff_contains_markers():
    diff = build_unified_diff("a = 1\n", "a = 2\n", file_label="app.py")
    assert "-a = 1" in diff
    assert "+a = 2" in diff
