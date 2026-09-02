"use strict";
/* 社内管理コンソール UI ロジック (vanilla JS, 外部CDN不要) */
const API = "/api";
const state = { meta: null, nodes: [], tokens: [], auto: true, timer: null };

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
  return d.toLocaleString("ja-JP", { year: "numeric", month: 2, day: 2, hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
function esc(s) {
  if (s == null) return "";
  return String(s).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
async function fetchJSON(url, opt = {}) {
  const headers = { "Content-Type": "application/json", ...(opt.headers || {}) };
  const r = await fetch(url, { ...opt, headers });
  if (!r.ok) {
    let detail = r.statusText;
    try { detail = (await r.json()).detail || detail; } catch (e) { detail = await r.text() || detail; }
    throw new Error(`HTTP ${r.status}: ${detail}`);
  }
  return r.json();
}
const STATUS_CLASS = { running: "badge-running", auth_error: "badge-auth_error", http_error: "badge-http_error", not_responding: "badge-not_responding", unreachable: "badge-unreachable", no_token: "badge-no_token", error: "badge-error" };
function badgeStatus(klass, label) { return `<span class="badge ${STATUS_CLASS[klass] || "badge-error"}">${esc(label)}</span>`; }
function badgeEnv(env) {
  const m = { production: ["badge-prod", "本番"], staging: ["badge-stg", "検証"], development: ["badge-dev", "開発"] };
  const [cls, text] = m[env] || ["badge-dev", env];
  return `<span class="badge ${cls}">${text}</span>`;
}
function humanExp(exp) { if (!exp) return "無期限"; const d = new Date(exp); return Number.isNaN(d.getTime()) ? exp : d.toLocaleDateString("ja-JP"); }

/* ---- nodes ---- */
async function loadNodes() {
  const tb = $("#nodes-tbody");
  try {
    const data = await fetchJSON(API + "/nodes");
    state.nodes = data.nodes;
    tb.innerHTML = state.nodes.length ? "" : '<tr><td colspan="10" class="loading">ノードが未登録</td></tr>';
    state.nodes.forEach((n) => { const tr = document.createElement("tr"); tr.innerHTML = nodeRowHtml(n); tb.appendChild(tr); });
    const sum = data.summary;
    $("#node-summary").innerHTML = `<span class="badge badge-running">稼働中: ${sum.running || 0}</span> <strong>${sum.total || 0}</strong> 台 <span class="badge badge-error">問題: ${sum.problems || 0}</span>`;
  } catch (e) { tb.innerHTML = `<tr><td colspan="10" class="loading">${esc(e.message)}</td></tr>`; }
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
  return `<td>${nameCell}</td><td>${badgeEnv(n.env)}</td><td>${badgeStatus(n.install_status, n.install_status_label)}</td>
    <td>${esc(os)}</td><td>${esc(kernel)}</td><td>${esc(host)}</td><td>${esc(uptime)}</td>
    <td>${esc(agent)}</td><td>${esc(resp)}</td><td>${fmtDate(n.checked_at)}</td>`;
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
    lab.innerHTML = `<input type="checkbox" name="servers" value="${esc(s.id)}" id="${id}"> ${esc(s.name || s.id)} <span class="small">(${esc(s.env)})</span>`;
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
      else await fetchJSON(API + `/approvals/${id}/${action}`, { method: "POST", body: JSON.stringify({ approver: "console" }) });
      toast(okMsg, "ok"); loadApprovals();
    } catch (e) { toast(e.message, "err"); }
  };
  if (action === "approve") confirmAction("Approve restart?", `Approve ${id}? The MCP client can then execute restart_service once.`, doIt);
  else doIt();
}

function startAuto() {
  if (state.timer) clearInterval(state.timer);
  state.timer = setInterval(() => { if (state.auto) { loadNodes(); loadTokens(); } }, 30000);
}
async function init() {
  setupTabs();
  try { state.meta = await fetchJSON(API + "/meta"); $("#app-version").textContent = "v" + (state.meta.version || "0.1.0"); renderHelp(); }
  catch (e) { toast(e.message, "err"); }
  $("#reload-nodes").onclick = () => loadNodes();
  $("#reload-tokens").onclick = () => loadTokens();
  $("#open-token-dialog").onclick = () => openIssueDialog();
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
  await Promise.all([loadNodes(), loadTokens(), loadApprovals()]);
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
