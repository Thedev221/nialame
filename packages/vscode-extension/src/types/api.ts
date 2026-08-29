// Types miroir des contrats Pydantic exposés par le Core Engine.
// Toute évolution du schéma côté Python doit être répercutée ici.

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ConfidenceLevel = "high" | "medium" | "low";
export type ChatMode = "ask" | "explain" | "debug" | "security" | "fix" | "review";
export type ChatScope =
  | "selection"
  | "current_file"
  | "open_files"
  | "workspace"
  | "git_diff"
  | "pull_request";

export interface Range {
  start_line: number;
  start_column: number;
  end_line: number;
  end_column: number;
}

export interface DocumentRef {
  uri: string;
  version: number;
  sha256: string;
  content?: string;
}

export interface Finding {
  rule_id: string;
  cwe?: string | null;
  severity: Severity;
  confidence: ConfidenceLevel;
  message: string;
  explanation: string;
  proof: string;
  location: Range;
  enclosing_symbol?: string | null;
  tier: "tier1_deterministic" | "tier2_llm";
}

export interface SuggestedPatch {
  finding_rule_id: string;
  document_sha256: string;
  document_version: number;
  anchor_range: Range;
  unified_diff: string;
  human_review_required: boolean;
  assumptions: string[];
  validations_performed: string[];
}

export interface ScanRequest {
  language: "python";
  document: DocumentRef;
  allow_llm: boolean;
}

export interface ScanResponse {
  request_id: string;
  document_sha256: string;
  findings: Finding[];
  suggested_patches: SuggestedPatch[];
  warnings: string[];
  llm_used: boolean;
}

export interface ChatOptions {
  provider: "ollama" | "cloud_byok";
  allow_llm: boolean;
}

export interface ChatContext {
  git_diff?: string | null;
  open_file_summaries: string[];
  repository_metadata?: { name?: string | null; branch?: string | null } | null;
}

export interface ChatRequest {
  conversation_id?: string;
  mode: ChatMode;
  scope: ChatScope;
  message: string;
  language: "python";
  document?: DocumentRef;
  selection?: Range;
  context?: ChatContext;
  options?: ChatOptions;
}

export interface Reference {
  uri_hash: string;
  range: Range;
  label: string;
}

export interface PrivacyMetadata {
  llm_used: boolean;
  provider: string | null;
  context_redacted: boolean;
  redaction_types: string[];
  context_scope: string;
}

export interface ChatResponse {
  request_id: string;
  conversation_id: string;
  answer_markdown: string;
  references: Reference[];
  findings: Finding[];
  suggested_patches: SuggestedPatch[];
  warnings: string[];
  privacy: PrivacyMetadata;
}

export interface PatchValidateResponse {
  request_id: string;
  valid: boolean;
  reasons: string[];
  new_findings_introduced: Finding[];
}

export interface GitDiffReviewResponse {
  request_id: string;
  results: { file_path: string; findings: Finding[] }[];
  warnings: string[];
}
