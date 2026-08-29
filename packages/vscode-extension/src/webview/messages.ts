import { WebviewToExtensionMessage, isKnownWebviewMessage } from "../types/ui";

export class InvalidWebviewMessageError extends Error {}

/**
 * Point d'entrée unique de validation des messages reçus depuis la
 * Webview. La Webview est traitée comme une source non fiable : tout
 * message dont la commande n'est pas dans l'allowlist est rejeté.
 */
export function parseWebviewMessage(raw: unknown): WebviewToExtensionMessage {
  if (!isKnownWebviewMessage(raw)) {
    throw new InvalidWebviewMessageError(
      `Message Webview refusé (commande inconnue ou format invalide): ${JSON.stringify(raw)}`
    );
  }
  return raw;
}
