// Messages échangés entre l'extension (host) et la Webview.
// Toute donnée reçue depuis la Webview doit être validée avant usage
// (voir webview/messages.ts) : la Webview est une source non fiable.

import { ChatMode, ChatScope, Finding, SuggestedPatch } from "./api";

export type ExtensionToWebviewMessage =
  | { type: "chatResponse"; requestId: string; answerMarkdown: string; findings: Finding[]; patches: SuggestedPatch[]; warnings: string[]; privacy: { llmUsed: boolean; provider: string | null } }
  | { type: "chatError"; requestId: string; message: string }
  | { type: "scanStarted"; requestId: string }
  | { type: "scanCompleted"; findings: Finding[] }
  | { type: "privacyStatus"; localMode: boolean; provider: string | null; llmEnabled: boolean };

export type WebviewToExtensionMessage =
  | { command: "sendChatMessage"; requestId: string; mode: ChatMode; scope: ChatScope; message: string }
  | { command: "openLocation"; uriHash: string; line: number; column: number }
  | { command: "previewDiff"; patchId: string }
  | { command: "applyPatch"; patchId: string }
  | { command: "copyToClipboard"; text: string }
  | { command: "retry"; requestId: string }
  | { command: "markFalsePositive"; ruleId: string }
  | { command: "ignoreRuleInFile"; ruleId: string }
  | { command: "explainWhy"; ruleId: string };

export const ALLOWED_WEBVIEW_COMMANDS: ReadonlySet<string> = new Set([
  "sendChatMessage",
  "openLocation",
  "previewDiff",
  "applyPatch",
  "copyToClipboard",
  "retry",
  "markFalsePositive",
  "ignoreRuleInFile",
  "explainWhy",
]);

export function isKnownWebviewMessage(value: unknown): value is WebviewToExtensionMessage {
  if (typeof value !== "object" || value === null) {
    return false;
  }
  const candidate = value as { command?: unknown };
  return typeof candidate.command === "string" && ALLOWED_WEBVIEW_COMMANDS.has(candidate.command);
}
