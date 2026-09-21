import { createHash } from "crypto";
import {
  hashDocumentContent,
  hashDocument,
  fingerprintDocument,
  matchesFingerprint,
} from "../src/services/documentHasher";

// Un faux document minimal, suffisant pour les fonctions testées —
// pas besoin d'un vrai vscode.TextDocument pour ça.
function makeFakeDocument(content: string, uri: string, version: number) {
  return {
    getText: () => content,
    uri: { toString: () => uri },
    version,
  } as any;
}

describe("hashDocumentContent", () => {
  it("produit le même hash SHA-256 que la bibliothèque crypto directement", () => {
    const content = "print('hello')";
    const expected = createHash("sha256").update(content, "utf8").digest("hex");
    expect(hashDocumentContent(content)).toBe(expected);
  });

  it("produit des hash différents pour des contenus différents", () => {
    expect(hashDocumentContent("a")).not.toBe(hashDocumentContent("b"));
  });

  it("est déterministe (même entrée -> même sortie)", () => {
    const content = "x = 1";
    expect(hashDocumentContent(content)).toBe(hashDocumentContent(content));
  });
});

describe("hashDocument", () => {
  it("hash le texte du document, pas autre chose", () => {
    const doc = makeFakeDocument("y = 2", "file:///test.py", 1);
    expect(hashDocument(doc)).toBe(hashDocumentContent("y = 2"));
  });
});

describe("fingerprintDocument", () => {
  it("capture uri, version et sha256 corrects", () => {
    const doc = makeFakeDocument("z = 3", "file:///app.py", 5);
    const fingerprint = fingerprintDocument(doc);

    expect(fingerprint.uri).toBe("file:///app.py");
    expect(fingerprint.version).toBe(5);
    expect(fingerprint.sha256).toBe(hashDocumentContent("z = 3"));
  });
});

describe("matchesFingerprint", () => {
  it("retourne true si uri, version et contenu correspondent exactement", () => {
    const doc = makeFakeDocument("safe = True", "file:///app.py", 2);
    const fingerprint = fingerprintDocument(doc);

    expect(matchesFingerprint(doc, fingerprint)).toBe(true);
  });

  it("retourne false si le contenu a changé (même version, hash différent)", () => {
    const original = makeFakeDocument("v1", "file:///app.py", 1);
    const fingerprint = fingerprintDocument(original);

    const changed = makeFakeDocument("v2 — modifié", "file:///app.py", 1);
    expect(matchesFingerprint(changed, fingerprint)).toBe(false);
  });

  it("retourne false si la version a changé", () => {
    const doc = makeFakeDocument("content", "file:///app.py", 1);
    const fingerprint = fingerprintDocument(doc);

    const newerVersion = makeFakeDocument("content", "file:///app.py", 2);
    expect(matchesFingerprint(newerVersion, fingerprint)).toBe(false);
  });

  it("retourne false si l'uri a changé", () => {
    const doc = makeFakeDocument("content", "file:///a.py", 1);
    const fingerprint = fingerprintDocument(doc);

    const otherFile = makeFakeDocument("content", "file:///b.py", 1);
    expect(matchesFingerprint(otherFile, fingerprint)).toBe(false);
  });
});
