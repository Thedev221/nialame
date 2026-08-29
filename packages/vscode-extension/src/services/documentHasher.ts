import { createHash } from "crypto";
import * as vscode from "vscode";

/**
 * Calcule le SHA-256 du contenu d'un document, utilisé pour ancrer
 * chaque requête et chaque patch à un état précis du fichier.
 */
export function hashDocumentContent(content: string): string {
  return createHash("sha256").update(content, "utf8").digest("hex");
}

export function hashDocument(document: vscode.TextDocument): string {
  return hashDocumentContent(document.getText());
}

export interface DocumentFingerprint {
  uri: string;
  version: number;
  sha256: string;
}

export function fingerprintDocument(document: vscode.TextDocument): DocumentFingerprint {
  return {
    uri: document.uri.toString(),
    version: document.version,
    sha256: hashDocument(document),
  };
}

/**
 * Vérifie qu'un document n'a pas changé depuis qu'une empreinte a été prise.
 * Utilisé avant toute application de patch.
 */
export function matchesFingerprint(document: vscode.TextDocument, fingerprint: DocumentFingerprint): boolean {
  if (document.uri.toString() !== fingerprint.uri) {
    return false;
  }
  if (document.version !== fingerprint.version) {
    return false;
  }
  return hashDocument(document) === fingerprint.sha256;
}
