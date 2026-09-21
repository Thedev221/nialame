import { PatchApplier } from "../src/services/patchApplier";
import { window, workspace } from "vscode";
import { hashDocumentContent } from "../src/services/documentHasher";
import { SuggestedPatch } from "../src/types/api";

function makeFakeDocument(content: string, uri: string, version: number) {
  return {
    getText: () => content,
    uri: { toString: () => uri },
    version,
    languageId: "python",
  } as any;
}

function makePatch(overrides: Partial<SuggestedPatch> = {}): SuggestedPatch {
  return {
    finding_rule_id: "NIA-EVAL-001",
    document_sha256: "hash-obsolete",
    document_version: 1,
    anchor_range: { start_line: 2, start_column: 0, end_line: 2, end_column: 10 },
    unified_diff: "--- a/x\n+++ b/x\n@@\n-old\n+new_line\n",
    human_review_required: true,
    assumptions: [],
    validations_performed: [],
    ...overrides,
  };
}

describe("PatchApplier", () => {
  beforeEach(() => {
    jest.clearAllMocks();
  });

  it("refuse le patch si le hash ne correspond pas au document actuel — sans même appeler le serveur", async () => {
    const apiClient = { validatePatch: jest.fn() } as any;
    const applier = new PatchApplier(apiClient);

    const doc = makeFakeDocument("contenu actuel différent", "file:///app.py", 1);
    const patch = makePatch({ document_sha256: "hash-qui-ne-correspond-pas", document_version: 1 });

    const result = await applier.previewAndApply(doc, patch);

    expect(result).toBe(false);
    expect(window.showWarningMessage).toHaveBeenCalled();
    expect(apiClient.validatePatch).not.toHaveBeenCalled();
  });

  it("refuse le patch si la version ne correspond pas", async () => {
    const apiClient = { validatePatch: jest.fn() } as any;
    const applier = new PatchApplier(apiClient);

    const doc = makeFakeDocument("x", "file:///app.py", 5);
    const patch = makePatch({ document_sha256: hashDocumentContent("x"), document_version: 1 });

    const result = await applier.previewAndApply(doc, patch);

    expect(result).toBe(false);
    expect(apiClient.validatePatch).not.toHaveBeenCalled();
  });

  it("refuse le patch si le serveur le juge invalide", async () => {
    const doc = makeFakeDocument("y", "file:///app.py", 1);
    const patch = makePatch({ document_sha256: hashDocumentContent("y"), document_version: 1 });

    const apiClient = {
      validatePatch: jest.fn().mockResolvedValue({ valid: false, reasons: ["syntaxe invalide"] }),
    } as any;
    const applier = new PatchApplier(apiClient);

    const result = await applier.previewAndApply(doc, patch);

    expect(result).toBe(false);
    expect(window.showErrorMessage).toHaveBeenCalledWith(expect.stringContaining("syntaxe invalide"));
  });

  it("n'applique rien si l'utilisateur annule la prévisualisation", async () => {
    const doc = makeFakeDocument("z", "file:///app.py", 1);
    const patch = makePatch({ document_sha256: hashDocumentContent("z"), document_version: 1 });

    const apiClient = {
      validatePatch: jest.fn().mockResolvedValue({ valid: true, reasons: [] }),
    } as any;
    (workspace.openTextDocument as jest.Mock).mockResolvedValue({ uri: "fake-diff-uri" });
    (window.showInformationMessage as jest.Mock).mockResolvedValue("Annuler");

    const applier = new PatchApplier(apiClient);
    const result = await applier.previewAndApply(doc, patch);

    expect(result).toBe(false);
    expect(workspace.applyEdit).not.toHaveBeenCalled();
  });

  it("applique le patch via WorkspaceEdit si tout est valide et confirmé par l'utilisateur", async () => {
    const doc = makeFakeDocument("z", "file:///app.py", 1);
    const patch = makePatch({ document_sha256: hashDocumentContent("z"), document_version: 1 });

    const apiClient = {
      validatePatch: jest.fn().mockResolvedValue({ valid: true, reasons: [] }),
    } as any;
    (workspace.openTextDocument as jest.Mock).mockResolvedValue({ uri: "fake-diff-uri" });
    (window.showInformationMessage as jest.Mock).mockResolvedValue("Appliquer");
    (workspace.applyEdit as jest.Mock).mockResolvedValue(true);

    const applier = new PatchApplier(apiClient);
    const result = await applier.previewAndApply(doc, patch);

    expect(result).toBe(true);
    expect(workspace.applyEdit).toHaveBeenCalled();
  });
});
