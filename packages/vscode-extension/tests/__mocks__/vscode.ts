// Mock enrichi du module "vscode" pour les tests nécessitant les APIs
// de fenêtre, de workspace et d'édition. Chaque fonction est un
// jest.fn() configurable individuellement dans chaque test.

export const window = {
  showWarningMessage: jest.fn(),
  showErrorMessage: jest.fn(),
  showInformationMessage: jest.fn(),
};

export const workspace = {
  openTextDocument: jest.fn(),
  applyEdit: jest.fn(),
};

export const commands = {
  executeCommand: jest.fn(),
};

export class Position {
  constructor(public line: number, public character: number) {}
}

export class Range {
  constructor(public start: Position, public end: Position) {}
}

export class WorkspaceEdit {
  private edits: Array<{ uri: unknown; range: Range; newText: string }> = [];
  replace(uri: unknown, range: Range, newText: string): void {
    this.edits.push({ uri, range, newText });
  }
  getEdits() {
    return this.edits;
  }
}
