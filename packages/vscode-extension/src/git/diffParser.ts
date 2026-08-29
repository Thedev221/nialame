export interface ParsedDiffFile {
  path: string;
  addedLines: string[];
}

/**
 * Parse un unified diff pour en extraire, par fichier, les lignes
 * ajoutées. Utilisé uniquement pour décider quels fichiers envoyer au
 * Core Engine — l'analyse AST elle-même se fait toujours côté backend.
 */
export function parseUnifiedDiff(diffText: string): ParsedDiffFile[] {
  const files: ParsedDiffFile[] = [];
  let current: ParsedDiffFile | null = null;

  for (const line of diffText.split("\n")) {
    if (line.startsWith("+++ b/")) {
      current = { path: line.slice("+++ b/".length), addedLines: [] };
      files.push(current);
      continue;
    }
    if (line.startsWith("+++ /dev/null")) {
      current = null;
      continue;
    }
    if (current && line.startsWith("+") && !line.startsWith("+++")) {
      current.addedLines.push(line.slice(1));
    }
  }

  return files;
}

export function extractChangedPythonFiles(diffText: string): string[] {
  return parseUnifiedDiff(diffText)
    .map((f) => f.path)
    .filter((path) => path.endsWith(".py"));
}
