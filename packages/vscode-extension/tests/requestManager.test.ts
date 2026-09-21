import { RequestManager } from "../src/services/requestManager";

describe("RequestManager", () => {
  it("beginRequest retourne un requestId et un signal non encore abort", () => {
    const manager = new RequestManager();
    const { requestId, signal } = manager.beginRequest("file:///a.py", 1);

    expect(requestId).toBeTruthy();
    expect(signal.aborted).toBe(false);
  });

  it("isStillRelevant retourne true pour la dernière version connue d'un document", () => {
    const manager = new RequestManager();
    const { requestId } = manager.beginRequest("file:///a.py", 1);

    expect(manager.isStillRelevant(requestId)).toBe(true);
  });

  it("isStillRelevant retourne false pour une requête obsolète après une version plus récente", () => {
    const manager = new RequestManager();
    const { requestId: oldRequestId } = manager.beginRequest("file:///a.py", 1);
    manager.beginRequest("file:///a.py", 2); // nouvelle version du même document

    expect(manager.isStillRelevant(oldRequestId)).toBe(false);
  });

  it("isStillRelevant retourne false pour un requestId inconnu", () => {
    const manager = new RequestManager();
    expect(manager.isStillRelevant("id-qui-n-existe-pas")).toBe(false);
  });

  it("complete() retire la requête du suivi", () => {
    const manager = new RequestManager();
    const { requestId } = manager.beginRequest("file:///a.py", 1);
    manager.complete(requestId);

    expect(manager.isStillRelevant(requestId)).toBe(false);
  });

  it("cancel() déclenche le signal d'annulation (AbortSignal)", () => {
    const manager = new RequestManager();
    const { requestId, signal } = manager.beginRequest("file:///a.py", 1);
    manager.cancel(requestId);

    expect(signal.aborted).toBe(true);
  });

  it("cancel() retire aussi la requête du suivi", () => {
    const manager = new RequestManager();
    const { requestId } = manager.beginRequest("file:///a.py", 1);
    manager.cancel(requestId);

    expect(manager.isStillRelevant(requestId)).toBe(false);
  });

  it("cancelAllForDocument() annule uniquement les requêtes du bon document", () => {
    const manager = new RequestManager();
    const { requestId: reqA, signal: signalA } = manager.beginRequest("file:///a.py", 1);
    const { signal: signalB } = manager.beginRequest("file:///b.py", 1);

    manager.cancelAllForDocument("file:///a.py");

    expect(signalA.aborted).toBe(true);
    expect(signalB.aborted).toBe(false);
    expect(manager.isStillRelevant(reqA)).toBe(false);
  });

  it("des documents différents ont des versions suivies indépendamment", () => {
    const manager = new RequestManager();
    manager.beginRequest("file:///a.py", 5);
    const { requestId: reqB } = manager.beginRequest("file:///b.py", 1);

    // La requête sur b.py (version 1) doit rester pertinente même si
    // a.py est déjà à une version bien plus haute — versions indépendantes.
    expect(manager.isStillRelevant(reqB)).toBe(true);
  });
});
