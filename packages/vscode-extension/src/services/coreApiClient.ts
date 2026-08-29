import { getSettings } from "./settings";
import {
  ChatRequest,
  ChatResponse,
  GitDiffReviewResponse,
  PatchValidateResponse,
  ScanRequest,
  ScanResponse,
  SuggestedPatch,
  DocumentRef,
} from "../types/api";

export class CoreApiError extends Error {
  constructor(message: string, readonly status?: number) {
    super(message);
    this.name = "CoreApiError";
  }
}

async function postJson<TResponse>(
  path: string,
  body: unknown,
  signal?: AbortSignal
): Promise<TResponse> {
  const { coreEngineUrl } = getSettings();
  const url = `${coreEngineUrl}${path}`;

  let response: Response;
  try {
    response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal,
    });
  } catch (err) {
    throw new CoreApiError(
      `Impossible de contacter le Core Engine (${url}). Vérifiez qu'il tourne en local. Détail: ${String(err)}`
    );
  }

  if (!response.ok) {
    const text = await response.text().catch(() => "");
    throw new CoreApiError(`Core Engine a répondu ${response.status}: ${text}`, response.status);
  }

  return (await response.json()) as TResponse;
}

/** Client du Core Engine. Toutes les méthodes respectent allow_llm=false par défaut. */
export class CoreApiClient {
  async scan(document: DocumentRef, signal?: AbortSignal): Promise<ScanResponse> {
    const { allowLlm } = getSettings();
    const request: ScanRequest = { language: "python", document, allow_llm: allowLlm };
    return postJson<ScanResponse>("/api/v1/scan", request, signal);
  }

  async chat(request: ChatRequest, signal?: AbortSignal): Promise<ChatResponse> {
    const { allowLlm } = getSettings();
    const withOptions: ChatRequest = {
      ...request,
      options: { provider: "ollama", allow_llm: allowLlm, ...request.options },
    };
    return postJson<ChatResponse>("/api/v1/chat", withOptions, signal);
  }

  async reviewGitDiff(unifiedDiff: string, changedFiles: string[], signal?: AbortSignal): Promise<GitDiffReviewResponse> {
    return postJson<GitDiffReviewResponse>(
      "/api/v1/review/git-diff",
      { unified_diff: unifiedDiff, changed_files: changedFiles, allow_llm: false },
      signal
    );
  }

  async validatePatch(document: DocumentRef, patch: SuggestedPatch, signal?: AbortSignal): Promise<PatchValidateResponse> {
    return postJson<PatchValidateResponse>("/api/v1/patch/validate", { document, patch }, signal);
  }
}
