import * as vscode from "vscode";

function generateNonce(): string {
  let text = "";
  const possible = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  for (let i = 0; i < 32; i++) {
    text += possible.charAt(Math.floor(Math.random() * possible.length));
  }
  return text;
}

/**
 * Construit le HTML de la Webview avec une CSP restrictive :
 * - aucun script/style inline non autorisé (nonce requis) ;
 * - aucune ressource distante ;
 * - aucun accès réseau direct depuis la Webview (tout passe par
 *   l'extension via postMessage).
 */
export function buildWebviewHtml(webview: vscode.Webview, extensionUri: vscode.Uri): string {
  const nonce = generateNonce();
  const scriptUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, "media", "main.js"));
  const styleUri = webview.asWebviewUri(vscode.Uri.joinPath(extensionUri, "media", "styles.css"));

  const csp = [
    `default-src 'none'`,
    `img-src ${webview.cspSource} https: data:`,
    `style-src ${webview.cspSource} 'nonce-${nonce}'`,
    `script-src 'nonce-${nonce}'`,
    `font-src ${webview.cspSource}`,
  ].join("; ");

  return `<!DOCTYPE html>
<html lang="fr">
<head>
  <meta charset="UTF-8" />
  <meta http-equiv="Content-Security-Policy" content="${csp}" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <link href="${styleUri}" rel="stylesheet" nonce="${nonce}" />
  <title>Nialame AI</title>
</head>
<body>
  <div id="root">
    <div id="privacy-banner" class="privacy-banner">Mode local — LLM désactivé</div>
    <div id="mode-scope-bar">
      <select id="mode-select" aria-label="Mode">
        <option value="ask">Ask</option>
        <option value="explain">Explain</option>
        <option value="debug">Debug</option>
        <option value="security">Security</option>
        <option value="fix">Fix</option>
        <option value="review">Review</option>
      </select>
      <select id="scope-select" aria-label="Portée">
        <option value="selection">Selected code</option>
        <option value="current_file">Current file</option>
        <option value="open_files">Open files</option>
        <option value="workspace">Workspace</option>
        <option value="git_diff">Git diff</option>
        <option value="pull_request">Pull request</option>
      </select>
    </div>
    <div id="messages" role="log" aria-live="polite"></div>
    <div id="input-bar">
      <textarea id="chat-input" placeholder="Posez une question sur votre code…" aria-label="Message"></textarea>
      <button id="send-button" aria-label="Envoyer">Envoyer</button>
      <button id="cancel-button" aria-label="Annuler" hidden>Annuler</button>
    </div>
  </div>
  <script nonce="${nonce}" src="${scriptUri}"></script>
</body>
</html>`;
}
