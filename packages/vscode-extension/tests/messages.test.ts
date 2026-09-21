import { parseWebviewMessage, InvalidWebviewMessageError } from "../src/webview/messages";

describe("parseWebviewMessage", () => {
  it("accepte un message sendChatMessage valide", () => {
    const raw = {
      command: "sendChatMessage",
      requestId: "abc-123",
      mode: "ask",
      scope: "current_file",
      message: "bonjour",
    };
    expect(() => parseWebviewMessage(raw)).not.toThrow();
    expect(parseWebviewMessage(raw)).toEqual(raw);
  });

  it("accepte un message openLocation valide", () => {
    const raw = { command: "openLocation", uriHash: "abc", line: 10, column: 2 };
    expect(() => parseWebviewMessage(raw)).not.toThrow();
  });

  it("accepte un message markFalsePositive valide", () => {
    const raw = { command: "markFalsePositive", ruleId: "NIA-EVAL-001" };
    expect(() => parseWebviewMessage(raw)).not.toThrow();
  });

  it("rejette une commande absente de l'allowlist (sécurité)", () => {
    const raw = { command: "executeShellCommand", cmd: "rm -rf /" };
    expect(() => parseWebviewMessage(raw)).toThrow(InvalidWebviewMessageError);
  });

  it("rejette un message sans propriété 'command'", () => {
    expect(() => parseWebviewMessage({ foo: "bar" })).toThrow(InvalidWebviewMessageError);
  });

  it("rejette une valeur qui n'est pas un objet (null)", () => {
    expect(() => parseWebviewMessage(null)).toThrow(InvalidWebviewMessageError);
  });

  it("rejette une valeur qui n'est pas un objet (string)", () => {
    expect(() => parseWebviewMessage("juste une chaîne")).toThrow(InvalidWebviewMessageError);
  });

  it("rejette une valeur qui n'est pas un objet (nombre)", () => {
    expect(() => parseWebviewMessage(42)).toThrow(InvalidWebviewMessageError);
  });

  it("rejette un command qui n'est pas une chaîne", () => {
    expect(() => parseWebviewMessage({ command: 123 })).toThrow(InvalidWebviewMessageError);
  });

  it("le message d'erreur inclut le contenu du message rejeté, pour le debug", () => {
    try {
      parseWebviewMessage({ command: "commandeInterdite" });
      fail("aurait dû lever une erreur");
    } catch (err) {
      expect(err).toBeInstanceOf(InvalidWebviewMessageError);
      expect((err as Error).message).toContain("commandeInterdite");
    }
  });
});
