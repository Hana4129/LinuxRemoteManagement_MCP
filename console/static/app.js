"use strict";
/* 社内管理コンソール UI ロジック (vanilla JS, 外部CDN不要) */
const API = "/api";
const state = { meta: null, nodes: [], tokens: [], auto: true, timer: null, csrf: null };
const MUTATING = new Set(["POST", "PUT", "PATCH", "DELETE"]);

const $ = (s, c = document) => c.querySelector(s);
const $$ = (s, c = document) => Array.from(c.querySelectorAll(s));

function toast(msg, kind = "ok") {
  const box = $("#toast");
  box.textContent = msg;
  box.className = "toast show" + (kind === "err" ? " err" : "");
  clearTimeout(box._t);
  box._t = setTimeout(() => (box.className = "toast"), 2600);
}
function fmtDate(iso) {
  if (!iso) return "-";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString("ja-JP", { year: "numeric", month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function esc(s) {
  if (s == null) return "";
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
async function fetchJSON(url, opt = {}) {
  const method = opt.method || "GET";
  const headers = { "Content-Type": "application/json", ...(opt.headers || {}) };
  if (state.csrf && MUTATING.has(method)) headers["X-CSRF-Token"] = state.csrf;
  let r = await fetch(url, { ...opt, method, headers });
  // 401/403 (セッション切れ・CSRF失敗): ブラウザログインが有効なら復旧を試みる
  if ((r.status === 401 || r.status === 403) && !url.startsWith("/api/auth/")) {
    const me = await fetch("/api/auth/me", { headers: { "Accept": "application/json" }, redirect: "error" }).catch(() => null);
    if (me && me.ok) {
      const body = await me.json();
      if (body.csrf_token && body.csrf_token !== state.csrf) {
        state.csrf = body.csrf_token;
        headers["X-CSRF-Token"] = state.csrf;
        r = await fetch(url, { ...opt, method, headers }); // CSRFトークン再取得後に1回リトライ
      }
    } else if (me && me.status !== 404) {
      // セッション切れ → ログイン画面へ
      location.href = "/api/auth/login";
      return Promise.reject(new Error("再ログインが必要です"));
    }
    // me.status === 404 はブラウザログイン無効 (Basic認証ベース) のため従来どおり
  }
  if (!r.ok) {
    let detail = r.statusText;
    try { detail = (await r.json()).detail || detail; } catch (e) { detail = await r.text() || detail; }
    throw new Error(`HTTP ${r.status}: ${detail}`);
  }
  return r.json();
}
async function checkAuth() {
  /* OIDCブラウザログイン有効時: セッション確認とCSRFトークン取得を行う。
     /api/auth/me が404を返す場合 (ブラウザログイン無効) はBasic認証ダイアログに委譲する。 */
  const me = await fetch("/api/auth/me", { headers: { "Accept": "application/json" }, redirect: "error" }).catch(() => null);
  if (me && me.status === 404) return;
  if (!me || !me.ok) { location.href = "/api/auth/login"; return; }
  let body;
  try { body = await me.json(); } catch (e) { return; }
  if (!body.authenticated) { location.href = "/api/auth/login"; return; }
  state.csrf = body.csrf_token || null;
  const info = $("#auth-info");
  if (info) {
    info.innerHTML = `<span class="auth-user">${esc(body.display_name || body.subject)}</span><button class="btn logout-btn" id="logout-btn" type="button">ログアウト</button>`;
    const btn = $("#logout-btn");
    if (btn) btn.addEventListener("click", async () => {
      try { await fetch("/api/auth/logout", { method: "POST" }); } catch (e) { /* ignore */ }
      location.href = "/";
    });
  }
}
const STATUS_CLASS = { running: "badge-running", auth_error: "badge-auth_error", http_error: "badge-http_error", not_responding: "badge-not_responding", unreachable: "badge-unreachable", no_token: "badge-no_token", error: "badge-error" };
function badgeStatus(klass, label) { return `<span class="badge ${STATUS_CLASS[klass] || "badge-error"}">${esc(label)}</span>`; }
function badgeEnv(env) {
  const m = { production: ["badge-prod", "本番"], staging: ["badge-stg", "検証"], development: ["badge-dev", "開発"] };
  const [cls, text] = m[env] || ["badge-dev", env];
  return `<span class="badge ${cls}">${text}</span>`;
}
function humanExp(exp) { if (!exp) return "無期限"; const d = new Date(exp); return Number.isNaN(d.getTime()) ? exp : d.toLocaleDateString("ja-JP"); }

/* ---- access management ---- */
async function loadPrincipals() {
  const tb = $("#principals-tbody");
  if (!tb) return;
  try {
    const data = await fetchJSON(API + "/principals");
    const principals = data.principals || [];
    const rows = await Promise.all(principals.map(async (p) => {
      const permissions = await fetchJSON(API + `/principals/${encodeURIComponent(p.id)}/permissions`);
      return { ...p, permissions: permissions.permissions || [] };
    }));
    tb.innerHTML = rows.length ? rows.map(principalRowHtml).join("") : '<tr><td colspan="6" class="loading">0 principals</td></tr>';
    $("#principal-summary").innerHTML = `<span class="badge badge-enabled">有効: ${rows.filter((p) => p.enabled).length}</span> <span class="badge badge-revoked">合計: ${rows.length}</span>`;
  } catch (e) { tb.innerHTML = `<tr><td colspan="6" class="loading">${esc(e.message)}</td></tr>`; }
}
function principalRowHtml(p) {
  const perms = p.permissions.length ? p.permissions.map((x) => `${esc(x.server_id)}:${esc(x.scope)}`).join(" ") : "-";
  const status = p.enabled ? '<span class="badge badge-enabled">有効</span>' : '<span class="badge badge-revoked">無効</span>';
  const disable = p.enabled ? `<button class="btn danger" data-access-action="disable-principal" data-id="${esc(p.id)}" type="button">無効化</button>` : "";
  return `<tr><td><code>${esc(p.subject)}</code></td><td>${esc(p.display_name)}</td><td>${esc(p.role)}</td><td>${status}</td><td>${perms}</td><td>${disable} <button class="btn" data-access-action="grant" data-id="${esc(p.id)}" type="button">権限付与</button></td></tr>`;
}
async function createPrincipal(e) {
  e.preventDefault();
  try {
    await fetchJSON(API + "/principals", { method: "POST", body: JSON.stringify({ subject: $("#p-subject").value.trim(), display_name: $("#p-name").value.trim(), role: $("#p-role").value }) });
    $("#principal-dialog").close(); toast("Principalを作成しました", "ok"); loadPrincipals();
  } catch (err) { toast(err.message, "err"); }
}
function grantPrincipal(id) {
  $("#g-server").value = "";
  $("#g-scope").value = "readonly";
  $("#grant-dialog").showModal();
  $("#grant-form").dataset.principalId = id;
}
function disablePrincipal(id) {
  confirmAction("Principal無効化", "principalと紐付くMCP tokenを無効化しますか。", async () => {
    try { await fetchJSON(API + `/principals/${encodeURIComponent(id)}/disable`, { method: "POST" }); toast("無効化しました", "ok"); loadPrincipals(); loadTokens(); }
    catch (e) { toast(e.message, "err"); }
  });
}
async function loadAgentCredentials() {
  const tb = $("#agent-credentials-tbody");
  if (!tb) return;
  try {
    const data = await fetchJSON(API + "/agent-credentials");
    tb.innerHTML = (data.credentials || []).map((c) => `<tr><td>${esc(c.name)}</td><td>${esc(c.server_id)}</td><td><code>${esc(c.agent_token_id)}</code></td><td>${c.active ? '<span class="badge badge-enabled">有効</span>' : '<span class="badge badge-revoked">無効</span>'}</td><td>${c.active ? `<button class="btn danger" data-access-action="revoke-agent" data-id="${esc(c.id)}" type="button">失効</button>` : ""}</td></tr>`).join("") || '<tr><td colspan="5" class="loading">0 credentials</td></tr>';
  } catch (e) { tb.innerHTML = `<tr><td colspan="5" class="loading">${esc(e.message)}</td></tr>`; }
}
async function registerAgentCredential(e) {
  e.preventDefault();
  try {
    await fetchJSON(API + "/agent-credentials", { method: "POST", body: JSON.stringify({ server_id: $("#agent-server-id").value.trim(), name: $("#agent-credential-name").value.trim(), agent_token_id: $("#agent-token-id").value.trim(), token: $("#agent-token").value }) });
    e.target.reset(); toast("Agent credentialを登録しました", "ok"); loadAgentCredentials();
  } catch (err) { toast(err.message, "err"); }
}
function revokeAgentCredential(id) {
  confirmAction("Agent credential失効", "Agent側にも失効を同期します。続行しますか。", async () => {
    try { await fetchJSON(API + `/agent-credentials/${encodeURIComponent(id)}/revoke`, { method: "POST" }); toast("失効しました", "ok"); loadAgentCredentials(); }
    catch (e) { toast(e.message, "err"); }
  });
}

/* ---- nodes ---- */
async function loadNodes() {
  const tb = $("#nodes-tbody");
  try {
    const data = await fetchJSON(API + "/nodes");
    state.nodes = data.nodes;
    tb.innerHTML = state.nodes.length ? "" : '<tr><td colspan="11" class="loading">ノードが未登録</td></tr>';
    state.nodes.forEach((n) => { const tr = document.createElement("tr"); tr.innerHTML = nodeRowHtml(n); tb.appendChild(tr); });
    const sum = data.summary;
    $("#node-summary").innerHTML = `<span class="badge badge-running">稼働中: ${sum.running || 0}</span> <strong>${sum.total || 0}</strong> 台 <span class="badge badge-error">問題: ${sum.problems || 0}</span>`;
  } catch (e) { tb.innerHTML = `<tr><td colspan="11" class="loading">${esc(e.message)}</td></tr>`; }
}
function nodeRowHtml(n) {
  const os = n.os ? (n.os.os || "—") : "—";
  const kernel = n.os ? (n.os.kernel || "—") : "—";
  const host = n.os ? (n.os.hostname || "—") : "—";
  const uptime = n.os ? n.os.uptime_human : "—";
  const resp = n.latency_ms != null ? `${n.latency_ms} ms` : "—";
  const agent = n.agent_version || "—";
  let nameCell = `<strong>${esc(n.name)}</strong><div class="small">${esc(n.id)}</div>`;
  if (n.error) nameCell += `<div class="err" style="color:#cf222e;font-size:11px">${esc(n.error)}</div>`;
  const deleteBtn = `<button class="btn danger" data-action="delete-node" data-node-id="${esc(n.id)}" type="button" style="font-size:11px">Delete</button>`;
  return `<td>${nameCell}</td><td>${badgeEnv(n.env)}</td><td>${badgeStatus(n.install_status, n.install_status_label)}</td>
    <td>${esc(os)}</td><td>${esc(kernel)}</td><td>${esc(host)}</td><td>${esc(uptime)}</td>
    <td>${esc(agent)}</td><td>${esc(resp)}</td><td>${fmtDate(n.checked_at)}</td><td>${deleteBtn}</td>`;
}

/* ---- tokens ---- */
function countActive(t) { return t.filter((x) => x.active).length; }
async function loadTokens() {
  const tb = $("#tokens-tbody");
  try {
    const data = await fetchJSON(API + "/tokens");
    state.tokens = data.tokens;
    tb.innerHTML = state.tokens.length ? "" : '<tr><td colspan="10" class="loading">0 件</td></tr>';
    state.tokens.forEach((t) => { const tr = document.createElement("tr"); tr.innerHTML = tokenRowHtml(t); tb.appendChild(tr); });
    $("#token-summary").innerHTML = `<span class="badge badge-enabled">有効: ${countActive(state.tokens)}</span> <span class="badge badge-revoked">失効済み: ${state.tokens.length - countActive(state.tokens)}</span>`;
  } catch (e) { tb.innerHTML = `<tr><td colspan="10" class="loading">${esc(e.message)}</td></tr>`; }
}
function tokenRowHtml(t) {
  let stateBadge;
  if (!t.enabled) stateBadge = `<span class="badge badge-revoked">失効済み</span>`;
  else if (t.expired) stateBadge = `<span class="badge badge-expired">期限切れ</span>`;
  else stateBadge = `<span class="badge badge-enabled">有効</span>`;
  const scopeLabel = t.scope === "operator" ? "operator" : "readonly";
  const servers = (t.server_ids || []).map(esc).join(" ");
  const scopeCls = t.scope === "operator" ? "badge-error" : "badge-running";
  const btn = (t.enabled && !t.expired)
    ? `<button class="btn danger" data-action="revoke" data-id="${t.id}" type="button" style="font-size:12px">失効</button>`
    : `<button class="btn" data-action="delete" data-id="${t.id}" type="button" style="font-size:12px">削除</button>`;
  return `<td>${esc(t.name)}</td><td>${esc(t.id)}</td><td><code>${esc(t.prefix)}</code></td>
    <td><span class="badge ${scopeCls}">${scopeLabel}</span></td><td>${esc(servers)}</td>
    <td>${fmtDate(t.created_at)}</td><td>${humanExp(t.expires_at)}</td><td>${fmtDate(t.last_used_at)}</td>
    <td>${stateBadge}</td><td>${btn}</td>`;
}

/* ---- dialogs ---- */
function openIssueDialog() {
  $("#t-name").value = "";
  $("#t-scope").value = "readonly";
  $("#t-exp").value = "";
  const box = $("#t-servers");
  box.innerHTML = "";
  (state.meta && state.meta.servers ? state.meta.servers : []).forEach((s) => {
    const id = `srv-${s.id}`;
    const lab = document.createElement("label");
    lab.htmlFor = id;
    const inp = document.createElement("input");
    inp.type = "checkbox";
    inp.name = "servers";
    inp.value = s.id;
    inp.id = id;
    inp.checked = false;
    lab.appendChild(inp);
    lab.appendChild(document.createTextNode(" " + (s.name || s.id) + " "));
    const span = document.createElement("span");
    span.className = "small";
    span.textContent = "(" + s.env + ")";
    lab.appendChild(span);
    box.appendChild(lab);
  });
  $("#token-dialog").showModal();
}
function submitIssue(e) {
  e.preventDefault();
  const name = $("#t-name").value.trim();
  const scope = $("#t-scope").value;
  const servers = Array.from(document.querySelectorAll('#issue-form input[name="servers"]:checked')).map((i) => i.value);
  const exp = $("#t-exp").value;
  if (!name) { toast("名前を入力してください", "err"); return; }
  if (!servers.length) { toast("対象サーバーを選択してください", "err"); return; }
  const payload = { name, scope, server_ids: servers, expires_in_days: exp ? Number(exp) : null };
  fetchJSON(API + "/tokens", { method: "POST", body: JSON.stringify(payload) })
    .then((r) => showTokenResult(r.token, r.record))
    .catch((e) => { toast(e.message, "err"); $("#token-dialog").close(); });
}
function showTokenResult(raw, rec) {
  $("#token-dialog").close();
  $("#raw-token").textContent = raw;
  $("#token-result").showModal();
  toast("トークンを発行しました (この画面でしか表示されません)", "ok");
  loadTokens();
}
function confirmAction(title, body, onOk) {
  $("#confirm-title").textContent = title;
  $("#confirm-body").textContent = body;
  $("#confirm-ok").onclick = () => { $("#confirm-dialog").close(); onOk(); };
  $("#confirm-cancel").onclick = () => { $("#confirm-dialog").close(); };
  $("#confirm-dialog").showModal();
}
async function doRevoke(id) {
  confirmAction("トークン失効確認", "このトークンを失効しますか。失効後 Agent への認証は即座に無効化されます。", async () => {
    try { await fetchJSON(API + `/tokens/${id}/revoke`, { method: "POST" }); toast("失効しました", "ok"); loadTokens(); }
    catch (e) { toast(e.message, "err"); }
  });
}
async function doDelete(id) {
  confirmAction("削除確認", "このトークンレコードを完全に削除しますか。取り戻せません。", async () => {
    try { await fetchJSON(API + `/tokens/${id}`, { method: "DELETE" }); toast("削除しました", "ok"); loadTokens(); }
    catch (e) { toast(e.message, "err"); }
  });
}
function renderHelp() {
  const c = $("#mcp-config-snippet");
  if (!state.meta) { c.textContent = "読み込み中…"; return; }
  const httpLine = state.meta.mcp?.http_enabled
    ? `      // MCP-over-HTTP: http://127.0.0.1:8443${state.meta.mcp.http_path || "/mcp"}`
    : "";
  const lines = [
    "{",
    '  "mcpServers": {',
    '    "linux-remote-management": {',
    '      "command": "python -m app.mcp_entry",',
    '      "cwd": "/path/to/mcp-server"',
    httpLine,
    "    }",
    "  }",
    "}",
  ];
  c.innerHTML = "<code>" + lines.map(esc).join("\n") + "</code>";
}

/* ---- wiring ---- */
function setupTabs() {
  $$(".tab").forEach((b) => b.addEventListener("click", () => {
    $$(".tab").forEach((x) => x.classList.remove("active"));
    b.classList.add("active");
    $$(".tab-panel").forEach((x) => x.classList.remove("active"));
    $("#tab-" + b.dataset.tab).classList.add("active");
  }));
}
/* ---- approvals ---- */
function approvalStatusBadge(s) {
  const m = { pending: "badge-stg", approved: "badge-running", rejected: "badge-revoked", executed: "badge-enabled", expired: "badge-expired" };
  return `<span class="badge ${m[s] || "badge-revoked"}">${esc(s)}</span>`;
}
async function loadApprovals() {
  const tb = $("#approvals-tbody");
  if (!tb) return;
  try {
    const data = await fetchJSON(API + "/approvals");
    const items = data.approvals || [];
    tb.innerHTML = items.length ? "" : '<tr><td colspan="10" class="loading">0 requests</td></tr>';
    items.forEach((a) => {
      const tr = document.createElement("tr");
      let actions = "";
      if (a.status === "pending") {
        actions = `<button class="btn primary" data-approval-action="approve" data-id="${esc(a.id)}" type="button" style="font-size:12px">Approve</button> `
          + `<button class="btn danger" data-approval-action="reject" data-id="${esc(a.id)}" type="button" style="font-size:12px">Reject</button>`;
      } else if (a.status === "pending" || a.status === "approved") {
        actions = `<button class="btn" data-approval-action="delete" data-id="${esc(a.id)}" type="button" style="font-size:12px">Delete</button>`;
      }
      tr.innerHTML = `<td><code>${esc(a.id)}</code></td><td>${esc(a.server_id)}</td><td>${esc(a.service)}</td>`
        + `<td>${esc(a.reason || "-")}</td><td>${esc(a.requested_by || "-")}</td>`
        + `<td>${fmtDate(a.requested_at)}</td><td>${fmtDate(a.expires_at)}</td>`
        + `<td>${approvalStatusBadge(a.status)}</td><td>${esc(a.approver || "-")}</td><td>${actions}</td>`;
      tb.appendChild(tr);
    });
    const pending = items.filter((a) => a.status === "pending").length;
    $("#approval-summary").innerHTML = `<span class="badge badge-stg">Pending: ${pending}</span> <span class="badge badge-revoked">Total: ${items.length}</span>`;
  } catch (e) { tb.innerHTML = `<tr><td colspan="10" class="loading">${esc(e.message)}</td></tr>`; }
}
function startApprovalAuto() {
  if (state.approvalTimer) clearInterval(state.approvalTimer);
  state.approvalTimer = setInterval(() => {
    const chk = $("#approval-auto-reload");
    if (chk && chk.checked) loadApprovals();
  }, 10000);
}
async function doApproveAction(action, id) {
  const okMsg = { approve: "Approved", reject: "Rejected", delete: "Deleted" }[action] || "Done";
  const doIt = async () => {
    try {
      if (action === "delete") await fetchJSON(API + `/approvals/${id}`, { method: "DELETE" });
      else await fetchJSON(API + `/approvals/${id}/${action}`, { method: "POST", body: JSON.stringify({}) });
      toast(okMsg, "ok"); loadApprovals();
    } catch (e) { toast(e.message, "err"); }
  };
  if (action === "approve") confirmAction("Approve restart?", `Approve ${id}? The MCP client can then execute restart_service once.`, doIt);
  else doIt();
}


/* ---- add node ---- */
function openAddNodeDialog() {
  $("#n-id").value = "";
  $("#n-name").value = "";
  $("#n-url").value = "";
  $("#n-env").value = "development";
  $("#n-desc").value = "";
  $("#n-issue-token").checked = false;
  $("#n-token-name").value = "";
  $("#n-token-scope").value = "readonly";
  $("#n-token-expires").value = "30";
  $("#token-options").style.display = "none";
  $("#add-node-dialog").showModal();
}

$("#n-issue-token").addEventListener("change", (e) => {
  $("#token-options").style.display = e.target.checked ? "block" : "none";
});

$("#add-node-form").onsubmit = async (e) => {
  e.preventDefault();
  const payload = {
    id: $("#n-id").value.trim(),
    name: $("#n-name").value.trim(),
    url: $("#n-url").value.trim(),
    env: $("#n-env").value,
    description: $("#n-desc").value.trim(),
    issue_token: $("#n-issue-token").checked,
    token_name: $("#n-issue-token").checked ? $("#n-token-name").value.trim() || null : null,
    token_scope: $("#n-token-scope").value,
    token_expires_in_days: $("#n-issue-token").checked && $("#n-token-expires").value ? Number($("#n-token-expires").value) : null,
  };
  try {
    const result = await fetchJSON(API + "/servers", { method: "POST", body: JSON.stringify(payload) });
    $("#add-node-dialog").close();
    if (result.token) {
      $("#raw-token").textContent = result.token;
      $("#token-result").showModal();
      toast("Node added. Token issued (shown once).", "ok");
    } else {
      toast("Node added", "ok");
    }
    loadNodes();
    loadTokens();
  } catch (err) {
    toast(err.message, "err");
  }
};

$("#t-cancel").onclick = () => $("#token-dialog").close();
$("#p-cancel").onclick = () => $("#principal-dialog").close();
$("#n-cancel").onclick = () => $("#add-node-dialog").close();

async function doDeleteNode(nodeId) {
  confirmAction("Delete Node", `Delete node '${nodeId}'? Related tokens will be revoked. This cannot be undone.`, async () => {
    try {
      await fetchJSON(API + "/servers/" + encodeURIComponent(nodeId), { method: "DELETE" });
      toast("Node deleted", "ok");
      loadNodes();
      loadTokens();
    } catch (e) {
      toast(e.message, "err");
    }
  });
}

function startAuto() {
  if (state.timer) clearInterval(state.timer);
  state.timer = setInterval(() => { if (state.auto) { loadNodes(); loadTokens(); } }, 30000);
}
async function init() {
  setupTabs();
  await checkAuth();
  try { state.meta = await fetchJSON(API + "/meta"); $("#app-version").textContent = "v" + (state.meta.version || "0.1.0"); renderHelp(); }
  catch (e) { toast(e.message, "err"); }
  $("#reload-nodes").onclick = () => loadNodes();
  const addBtn = $("#add-node-btn");
  if (addBtn) addBtn.onclick = () => openAddNodeDialog();
  const nodesTbody = $("#nodes-tbody");
  if (nodesTbody) {
    nodesTbody.addEventListener("click", (e) => {
      const btn = e.target.closest('button[data-action="delete-node"]');
      if (!btn) return;
      doDeleteNode(btn.dataset.nodeId);
    });
  }
  $("#reload-tokens").onclick = () => loadTokens();
  $("#open-token-dialog").onclick = () => openIssueDialog();
  $("#reload-principals").onclick = () => { loadPrincipals(); loadAgentCredentials(); };
  $("#open-principal-dialog").onclick = () => { $("#principal-form").reset(); $("#principal-dialog").showModal(); };
  $("#principal-form").onsubmit = createPrincipal;
  $("#grant-form").onsubmit = (e) => {
    e.preventDefault();
    const id = $("#grant-form").dataset.principalId;
    const serverId = $("#g-server").value.trim();
    const scope = $("#g-scope").value;
    if (!serverId) { toast("Server IDを入力してください", "err"); return; }
    fetchJSON(API + `/principals/${encodeURIComponent(id)}/permissions`, { method: "POST", body: JSON.stringify({ server_id: serverId, scope }) })
      .then(() => { toast("権限を付与しました", "ok"); loadPrincipals(); $("#grant-dialog").close(); })
      .catch((e) => toast(e.message, "err"));
  };
  $("#g-cancel").onclick = () => $("#grant-dialog").close();
  $("#agent-credential-form").onsubmit = registerAgentCredential;
  $("#principals-tbody").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-access-action]");
    if (!btn) return;
    if (btn.dataset.accessAction === "grant") grantPrincipal(btn.dataset.id);
    if (btn.dataset.accessAction === "disable-principal") disablePrincipal(btn.dataset.id);
  });
  $("#agent-credentials-tbody").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-access-action=\"revoke-agent\"]");
    if (btn) revokeAgentCredential(btn.dataset.id);
  });
  $("#auto-reload").onchange = (e) => { state.auto = e.target.checked; };
  $("#issue-form").onsubmit = submitIssue;
  $("#copy-token").addEventListener("click", async () => {
    try { await navigator.clipboard.writeText($("#raw-token").textContent); toast("クリップボードにコピーしました", "ok"); }
    catch (e) { toast("コピー失敗: " + e, "err"); }
  });
  $("#close-result").onclick = () => $("#token-result").close();
  $("#tokens-tbody").addEventListener("click", (e) => {
    const btn = e.target.closest("button[data-action]");
    if (!btn) return;
    const id = btn.dataset.id;
    if (btn.dataset.action === "revoke") doRevoke(id);
    else if (btn.dataset.action === "delete") doDelete(id);
  });
  await Promise.all([
    loadNodes().catch((e) => toast("Nodes load error: " + e.message, "err")),
    loadTokens().catch((e) => toast("Tokens load error: " + e.message, "err")),
    loadPrincipals().catch((e) => toast("Principals load error: " + e.message, "err")),
    loadAgentCredentials().catch((e) => toast("Credentials load error: " + e.message, "err")),
    loadApprovals().catch((e) => toast("Approvals load error: " + e.message, "err")),
  ]);
  startAuto();
  startApprovalAuto();
  const approvalsTbody = $("#approvals-tbody");
  if (approvalsTbody) {
    approvalsTbody.addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-approval-action]");
      if (!btn) return;
      doApproveAction(btn.dataset.approvalAction, btn.dataset.id);
    });
  }
  const reloadApprovalsBtn = $("#reload-approvals");
  if (reloadApprovalsBtn) reloadApprovalsBtn.onclick = () => loadApprovals();
}
document.addEventListener("DOMContentLoaded", init);
