import { spawn } from "child_process";

const ALLOWED_GIT_ARGS: ReadonlySet<string> = new Set([
  "status --porcelain",
  "diff --no-ext-diff",
  "diff --cached --no-ext-diff",
  "rev-parse --show-toplevel",
  "branch --show-current",
]);

const GIT_COMMAND_TIMEOUT_MS = 10_000;
const MAX_STDOUT_BYTES = 5 * 1024 * 1024;

export class GitCommandError extends Error {}

/**
 * Accès aux informations Git via un fallback CLI strictement borné
 * (allowlist, pas de shell, timeout, limite de taille de sortie).
 *
 * NOTE MVP: l'API Git intégrée de VS Code (`vscode.git`) a été évaluée
 * mais son typage réel diverge selon le contexte d'appel (ex.
 * `diffWithHEAD()` sans chemin retourne un `Change[]`, pas une
 * chaîne) — l'intégrer proprement demande plus de travail qu'un MVP
 * ne le justifie. Le fallback CLI, plus prévisible, est donc la seule
 * voie utilisée pour l'instant.
 */
export class GitService {
  async initialize(): Promise<void> {
    // Point d'extension réservé pour une future intégration de l'API
    // Git officielle de VS Code.
  }

  async getWorkingTreeDiff(workspaceRoot: string): Promise<string> {
    return this.runGitFallback(workspaceRoot, ["diff", "--no-ext-diff"]);
  }

  async getCurrentBranch(workspaceRoot: string): Promise<string> {
    return this.runGitFallback(workspaceRoot, ["branch", "--show-current"]);
  }

  /**
   * Fallback CLI strictement borné. N'utilise jamais de shell
   * (`child_process.spawn` sans `shell: true`), n'accepte que des
   * arguments d'une allowlist explicite, et applique un timeout ainsi
   * qu'une limite de taille de sortie.
   */
  private runGitFallback(cwd: string, args: string[]): Promise<string> {
    const joined = args.join(" ");
    const allowed = Array.from(ALLOWED_GIT_ARGS).some((prefix) => joined === prefix || joined.startsWith(prefix));
    if (!allowed) {
      throw new GitCommandError(`Commande git non autorisée: git ${joined}`);
    }

    return new Promise((resolve, reject) => {
      const child = spawn("git", args, { cwd, shell: false });
      let stdout = "";
      let stderr = "";
      let killedForTimeout = false;

      const timeout = setTimeout(() => {
        killedForTimeout = true;
        child.kill();
      }, GIT_COMMAND_TIMEOUT_MS);

      child.stdout.on("data", (chunk: Buffer) => {
        if (stdout.length < MAX_STDOUT_BYTES) {
          stdout += chunk.toString("utf8");
        }
      });
      child.stderr.on("data", (chunk: Buffer) => {
        stderr += chunk.toString("utf8");
      });

      child.on("error", (err) => {
        clearTimeout(timeout);
        reject(new GitCommandError(`Impossible d'exécuter git: ${err.message}`));
      });

      child.on("close", (code) => {
        clearTimeout(timeout);
        if (killedForTimeout) {
          reject(new GitCommandError(`Commande git interrompue après ${GIT_COMMAND_TIMEOUT_MS}ms`));
          return;
        }
        if (code !== 0) {
          reject(new GitCommandError(`git ${joined} a échoué (code ${code}): ${stderr}`));
          return;
        }
        resolve(stdout);
      });
    });
  }
}
