import { randomUUID } from "crypto";

/**
 * Associe chaque requête sortante à un AbortController et à la version
 * de document au moment de l'envoi. Toute réponse qui arrive après
 * qu'une version plus récente ait été observée est ignorée : on ne
 * veut jamais afficher un résultat d'analyse obsolète sur un document
 * qui a changé depuis.
 */
export class RequestManager {
  private readonly inFlight = new Map<string, { controller: AbortController; documentVersion: number; documentUri: string }>();
  private readonly latestVersionByUri = new Map<string, number>();

  beginRequest(documentUri: string, documentVersion: number): { requestId: string; signal: AbortSignal } {
    const requestId = randomUUID();
    const controller = new AbortController();
    this.inFlight.set(requestId, { controller, documentVersion, documentUri });

    const currentLatest = this.latestVersionByUri.get(documentUri) ?? -1;
    if (documentVersion > currentLatest) {
      this.latestVersionByUri.set(documentUri, documentVersion);
    }

    return { requestId, signal: controller.signal };
  }

  /** Retourne true si la réponse à requestId doit encore être appliquée à l'UI. */
  isStillRelevant(requestId: string): boolean {
    const entry = this.inFlight.get(requestId);
    if (!entry) {
      return false;
    }
    const latest = this.latestVersionByUri.get(entry.documentUri) ?? entry.documentVersion;
    return entry.documentVersion >= latest;
  }

  complete(requestId: string): void {
    this.inFlight.delete(requestId);
  }

  cancel(requestId: string): void {
    const entry = this.inFlight.get(requestId);
    entry?.controller.abort();
    this.inFlight.delete(requestId);
  }

  cancelAllForDocument(documentUri: string): void {
    for (const [requestId, entry] of this.inFlight.entries()) {
      if (entry.documentUri === documentUri) {
        entry.controller.abort();
        this.inFlight.delete(requestId);
      }
    }
  }
}
