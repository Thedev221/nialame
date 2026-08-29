(function () {
  const vscode = acquireVsCodeApi();

  const messagesEl = document.getElementById("messages");
  const inputEl = document.getElementById("chat-input");
  const sendButton = document.getElementById("send-button");
  const cancelButton = document.getElementById("cancel-button");
  const modeSelect = document.getElementById("mode-select");
  const scopeSelect = document.getElementById("scope-select");
  const privacyBanner = document.getElementById("privacy-banner");

  function escapeHtml(text) {
    const div = document.createElement("div");
    div.textContent = text;
    return div.innerHTML;
  }

  function renderSafeMarkdown(markdown) {
    let html = escapeHtml(markdown);
    html = html.replace(/```([\s\S]*?)```/g, (_m, code) => `<pre><code>${code}</code></pre>`);
    html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
    html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
    html = html.replace(/\n/g, "<br/>");
    return html;
  }

  function appendMessage(role, html) {
    const el = document.createElement("div");
    el.className = `message message-${role}`;
    el.innerHTML = html;
    messagesEl.appendChild(el);
    messagesEl.scrollTop = messagesEl.scrollHeight;
    return el;
  }

  let pendingRequestId = null;

  function setLoading(isLoading) {
    sendButton.disabled = isLoading;
    cancelButton.hidden = !isLoading;
    inputEl.disabled = isLoading;
  }

  function appendFindingCard(finding) {
    const card = document.createElement("div");
    card.className = `finding-card severity-${finding.severity}`;
    card.innerHTML = `
      <div class="finding-header">
        <span class="finding-rule">${escapeHtml(finding.rule_id)}</span>
        <span class="finding-severity">${escapeHtml(finding.severity)}</span>
      </div>
      <div class="finding-message">${escapeHtml(finding.message)}</div>
      <div class="finding-actions">
        <button data-action="openLocation" data-line="${finding.location.start_line}">Open location</button>
        <button data-action="fixFinding" data-rule="${escapeHtml(finding.rule_id)}">Fix</button>
        <button data-action="explainWhy" data-rule="${escapeHtml(finding.rule_id)}">Explain why</button>
        <button data-action="markFalsePositive" data-rule="${escapeHtml(finding.rule_id)}">Mark as false positive</button>
      </div>
    `;
    messagesEl.appendChild(card);

    card.querySelectorAll("button[data-action]").forEach((btn) => {
      btn.addEventListener("click", () => {
        const action = btn.getAttribute("data-action");
        if (action === "openLocation") {
          vscode.postMessage({
            command: "openLocation",
            uriHash: "",
            line: Number(btn.getAttribute("data-line")),
            column: 0,
          });
        } else if (action === "fixFinding") {
          const ruleId = btn.getAttribute("data-rule");
          pendingRequestId = crypto.randomUUID();
          appendMessage("user", escapeHtml(`Corriger ${ruleId}`));
          setLoading(true);
          vscode.postMessage({
            command: "sendChatMessage",
            requestId: pendingRequestId,
            mode: "fix",
            scope: "current_file",
            message: `Propose un patch pour corriger le finding ${ruleId}.`,
          });
        } else if (action === "markFalsePositive") {
          vscode.postMessage({ command: "markFalsePositive", ruleId: btn.getAttribute("data-rule") });
        } else if (action === "explainWhy") {
          vscode.postMessage({ command: "explainWhy", ruleId: btn.getAttribute("data-rule") });
        }
      });
    });
  }

  sendButton.addEventListener("click", () => {
    const text = inputEl.value.trim();
    if (!text) {
      return;
    }
    pendingRequestId = crypto.randomUUID();
    appendMessage("user", escapeHtml(text));
    setLoading(true);

    vscode.postMessage({
      command: "sendChatMessage",
      requestId: pendingRequestId,
      mode: modeSelect.value,
      scope: scopeSelect.value,
      message: text,
    });
    inputEl.value = "";
  });

  cancelButton.addEventListener("click", () => {
    if (pendingRequestId) {
      vscode.postMessage({ command: "retry", requestId: pendingRequestId });
    }
    setLoading(false);
  });

  window.addEventListener("message", (event) => {
    const message = event.data;
    switch (message.type) {
      case "privacyStatus":
        privacyBanner.textContent = message.llmEnabled
          ? `LLM actif — provider: ${message.provider}`
          : "Mode local — LLM désactivé";
        break;
      case "scanStarted":
        setLoading(true);
        break;
      case "chatResponse":
        setLoading(false);
        appendMessage("assistant", renderSafeMarkdown(message.answerMarkdown));
        for (const finding of message.findings) {
          appendFindingCard(finding);
        }
        break;
      case "chatError":
        setLoading(false);
        appendMessage("error", escapeHtml(message.message));
        break;
      case "scanCompleted":
        for (const finding of message.findings) {
          appendFindingCard(finding);
        }
        break;
      default:
        break;
    }
  });
})();
