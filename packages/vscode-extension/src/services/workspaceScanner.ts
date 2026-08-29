import * as vscode from "vscode";
import { CoreApiClient } from "./coreApiClient";
import { fingerprintDocument } from "./documentHasher";
import { Finding } from "../types/api";

const MAX_FILES_PER_SCAN = 200;
const MAX_CONCURRENT_SCANS = 4;

export interface WorkspaceScanResult {
  fileUri: vscode.Uri;
  findings: Finding[];
}

/**
 * Scanne les fichiers Python du workspace (limité en nombre et en
 * concurrence) en réutilisant le endpoint /api/v1/scan par fichier.
 * Ne modifie jamais les fichiers ; en lecture seule.
 */
export class WorkspaceScanner {
  constructor(private readonly apiClient: CoreApiClient) {}

  async scanWorkspace(progress?: vscode.Progress<{ message?: string; increment?: number }>): Promise<WorkspaceScanResult[]> {
    const files = await vscode.workspace.findFiles("**/*.py", "**/{node_modules,.venv,venv,.git}/**", MAX_FILES_PER_SCAN);

    const results: WorkspaceScanResult[] = [];
    const increment = 100 / Math.max(files.length, 1);

    for (let i = 0; i < files.length; i += MAX_CONCURRENT_SCANS) {
      const batch = files.slice(i, i + MAX_CONCURRENT_SCANS);
      const batchResults = await Promise.all(
        batch.map(async (fileUri) => {
          progress?.report({ message: vscode.workspace.asRelativePath(fileUri), increment });
          try {
            const document = await vscode.workspace.openTextDocument(fileUri);
            const fingerprint = fingerprintDocument(document);
            const response = await this.apiClient.scan({
              uri: fingerprint.uri,
              version: fingerprint.version,
              sha256: fingerprint.sha256,
              content: document.getText(),
            });
            return { fileUri, findings: response.findings };
          } catch {
            return { fileUri, findings: [] as Finding[] };
          }
        })
      );
      results.push(...batchResults);
    }

    return results.filter((r) => r.findings.length > 0);
  }
}
