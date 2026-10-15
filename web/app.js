// Secure RAG Assistant web interface.
// Security notes:
// - Sign-in uses a session cookie that is HttpOnly: this script cannot read it, so an injected
//   script could not steal it. Nothing is kept in localStorage or sessionStorage.
// - Model output and document text are untrusted: they are inserted with textContent, never as HTML.
"use strict";

const REASONS = {
  prompt_injection: { title: "Blocked: prompt injection", css: "blocked" },
  not_in_documents: { title: "No answer in your documents", css: "refused" },
  no_citation: { title: "Answer hidden: no valid source", css: "refused" },
  output_blocked: { title: "Blocked by the output filter", css: "blocked" },
};
const SOURCE_NAMES = { owasp: "OWASP Top 10", nist: "NIST SP 800-53", internal: "Internal" };
const ROLES = ["public", "staff", "security-admin", "admin"];
const EVENT_LABELS = {
  login_failed: "Failed sign-in", account_locked: "Account locked", mfa_failed: "Wrong MFA code",
  blocked_injection: "Injection blocked", auth_failed: "Invalid API key", ip_blocked: "Address blocked",
  csrf_blocked: "Cross-site request", rate_limited: "Rate limit", user_created: "Account created",
  user_updated: "Account changed", login_refused_locked: "Sign-in while locked",
};

const state = { user: null, documents: [], stats: { total: 0, answered: 0, refused: 0, blocked: 0, latency: [] } };
const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers, credentials: "same-origin" });
  let data = null;
  try { data = await response.json(); } catch { /* empty body */ }
  return { status: response.status, data };
}

function detail(data, fallback) {
  if (data && typeof data.detail === "string") return data.detail;
  return fallback;
}

// ---------- Sign-in ----------
function showAuthStep(step) {
  $("login-form").hidden = step !== "login";
  $("mfa-setup-form").hidden = step !== "setup";
  $("mfa-form").hidden = step !== "code";
  $("auth-error").hidden = true;
  const focus = { login: "username", setup: "setup-code", code: "mfa-code" }[step];
  setTimeout(() => $(focus).focus(), 0);
}

function authError(message) {
  const box = $("auth-error");
  box.textContent = message;
  box.hidden = false;
}

async function submitLogin(event) {
  event.preventDefault();
  const { status, data } = await api("/auth/login", {
    method: "POST",
    body: JSON.stringify({ username: $("username").value.trim(), password: $("password").value }),
  });
  $("password").value = "";
  if (status !== 200) return authError(detail(data, "Sign-in failed."));
  if (data.status === "ok") return enterApp();
  if (data.status === "mfa_setup") {
    const setup = await api("/auth/mfa/setup");
    $("mfa-secret").textContent = setup.data.secret.replace(/(.{4})/g, "$1 ").trim();
    $("mfa-qr").src = "/auth/mfa/qr.svg?t=" + Date.now();
    return showAuthStep("setup");
  }
  showAuthStep("code");
}

async function submitCode(event, inputId) {
  event.preventDefault();
  const input = $(inputId);
  const { status, data } = await api("/auth/mfa", { method: "POST", body: JSON.stringify({ code: input.value.trim() }) });
  input.value = "";
  if (status === 200) return enterApp();
  if (status === 401 && detail(data, "") !== "Invalid code") {
    showAuthStep("login");
    return authError(detail(data, "Please sign in again."));
  }
  authError("Invalid code. Check the time on your phone and try again.");
}

async function signOut() {
  await api("/auth/logout", { method: "POST" });
  state.user = null;
  $("chat").replaceChildren();
  $("app-screen").hidden = true;
  $("auth-screen").hidden = false;
  showAuthStep("login");
}

// ---------- Application ----------
async function enterApp() {
  const { status, data } = await api("/me");
  if (status !== 200) {
    $("auth-screen").hidden = false;
    $("app-screen").hidden = true;
    return showAuthStep("login");
  }
  state.user = data;
  $("auth-screen").hidden = true;
  $("app-screen").hidden = false;
  $("user-name").textContent = data.name;
  $("user-avatar").textContent = data.name.slice(0, 1).toUpperCase();
  $("user-roles").replaceChildren(
    ...data.roles.map((r) => el("span", "role" + (r === "security-admin" || r === "admin" ? " admin" : ""), r)),
  );
  $("tabs").hidden = !data.admin;
  switchView("assistant");
  loadHealth();
  await loadDocuments();
  $("question").focus();
}

async function loadHealth() {
  const badge = $("mode-badge");
  const { status, data } = await api("/health");
  if (status !== 200) {
    badge.className = "badge down";
    badge.textContent = "API unreachable";
    return;
  }
  badge.className = "badge " + (data.mode === "local" ? "local" : "cloud");
  badge.textContent = data.mode === "local" ? "Local mode: data stays on this machine" : "Cloud mode: personal data masked";
  $("fact-model").textContent = data.model;
  $("fact-index").textContent = `${data.documents} docs, ${data.chunks} chunks`;
  const integrity = $("fact-integrity");
  const labels = { verified: "Verified", rebuilt: "Rebuilt at start (demo)", failed: "Failed" };
  integrity.textContent = labels[data.integrity] || data.integrity;
  integrity.className = data.integrity === "failed" ? "fail" : "good";
}

async function loadDocuments() {
  const { status, data } = await api("/documents");
  if (status !== 200) return;
  const order = { internal: 0, owasp: 1, nist: 2 };
  state.documents = data.sort(
    (a, b) => order[a.source] - order[b.source] || a.reference.localeCompare(b.reference, undefined, { numeric: true }),
  );
  $("docs-count").textContent = state.documents.length;
  renderDocuments($("docs-filter").value);
}

function renderDocuments(filter) {
  const needle = filter.trim().toLowerCase();
  const kind = (ref) => (ref.match(/\.(pdf|docx|xlsx)$/i) || [])[1];
  const items = state.documents
    .filter((d) => !needle || d.title.toLowerCase().includes(needle))
    .map((d) => {
      const li = el("li");
      const ext = d.source === "internal" ? kind(d.reference) : null;
      li.append(
        el("span", "tag " + d.source, ext ? ext : d.source),
        el("span", null, d.title.replace(/^(OWASP Top 10|NIST SP 800-53) /, "")),
      );
      return li;
    });
  $("docs-list").replaceChildren(...items);
  if (!items.length) $("docs-list").append(el("li", null, "No document for your roles."));
}

function switchView(view) {
  $("view-assistant").hidden = view !== "assistant";
  $("view-admin").hidden = view !== "admin";
  document.querySelectorAll(".tab").forEach((t) => t.classList.toggle("active", t.dataset.view === view));
  $("page-title").textContent = view === "admin" ? "Administration" : "Ask the standards";
  $("page-subtitle").textContent =
    view === "admin"
      ? "Accounts, roles, MFA and security events. Every change is written to the audit log."
      : "OWASP Top 10:2025, NIST SP 800-53 and your internal policies (PDF, Word, Excel). Every statement comes with its source.";
  if (view === "admin") loadAdmin();
}

// ---------- Chat ----------
function addUserMessage(text) {
  const node = $("tpl-user").content.cloneNode(true);
  node.querySelector(".bubble").textContent = text;
  $("chat").append(node);
}

function addPending() {
  const wrap = el("div", "msg assistant");
  const card = el("div", "card");
  const typing = el("div", "typing");
  typing.append(el("i"), el("i"), el("i"));
  card.append(el("div", "meta", "Searching your documents and asking the local model…"), typing);
  wrap.append(card);
  $("chat").append(wrap);
  return wrap;
}

function renderAnswerText(container, text, sourcesByLabel) {
  for (const part of text.split(/(\[S\d+\])/g)) {
    const match = part.match(/^\[(S\d+)\]$/);
    if (match && sourcesByLabel[match[1]]) {
      const cite = el("button", "cite", match[1]);
      cite.type = "button";
      cite.title = sourcesByLabel[match[1]].title;
      cite.addEventListener("click", () => {
        const target = sourcesByLabel[match[1]].node;
        target.open = true;
        target.classList.add("flash");
        target.scrollIntoView({ behavior: "smooth", block: "nearest" });
        setTimeout(() => target.classList.remove("flash"), 1200);
      });
      container.append(cite);
    } else if (part) {
      container.append(document.createTextNode(part));
    }
  }
}

function wireFeedback(node, answerId) {
  const buttons = node.querySelectorAll(".fb");
  const box = node.querySelector(".feedback");
  buttons.forEach((button) =>
    button.addEventListener("click", async () => {
      buttons.forEach((b) => (b.disabled = true));
      const { status } = await api("/feedback", {
        method: "POST",
        body: JSON.stringify({ answer_id: answerId, helpful: button.dataset.helpful === "true" }),
      });
      button.classList.add("chosen");
      box.prepend(el("span", null, status === 200 ? "Thanks " : "Not saved "));
    }),
  );
}

function addAnswer(pending, result) {
  const node = $("tpl-answer").content.cloneNode(true);
  const card = node.querySelector(".card");
  const status = node.querySelector(".status-line");
  const answer = node.querySelector(".answer");
  const meta = node.querySelector(".meta");
  const sourcesBox = node.querySelector(".sources");

  if (result.error) {
    card.classList.add("error");
    status.textContent = "Error";
    answer.textContent = result.error;
    node.querySelector(".feedback").remove();
  } else {
    const sourcesByLabel = {};
    for (const s of result.sources) {
      const src = $("tpl-source").content.cloneNode(true);
      const details = src.querySelector("details");
      src.querySelector(".label").textContent = s.label;
      src.querySelector(".title").textContent = s.title;
      src.querySelector(".kind").textContent = SOURCE_NAMES[s.source] || s.source;
      src.querySelector(".bar i").style.width = Math.max(0, Math.min(1, s.score)) * 100 + "%";
      src.querySelector(".sim em").textContent = s.score.toFixed(2);
      src.querySelector(".section").textContent = s.section ? "Section: " + s.section : "";
      src.querySelector(".excerpt").textContent = s.excerpt;
      const link = src.querySelector(".link");
      if (s.url && /^https:\/\//.test(s.url)) link.href = s.url;
      else link.remove();
      sourcesByLabel[s.label] = { node: details, title: s.title };
      sourcesBox.append(src);
    }
    if (result.refused) {
      const reason = REASONS[result.reason] || { title: "Refused", css: "refused" };
      card.classList.add(reason.css);
      status.textContent = reason.title;
      answer.textContent = result.answer;
    } else {
      status.textContent = `Answer · ${result.sources.length} source${result.sources.length > 1 ? "s" : ""}`;
      renderAnswerText(answer, result.answer, sourcesByLabel);
    }
    let info = `${(result.latency_ms / 1000).toFixed(1)} s · ${result.mode} mode`;
    if (result.masked_entities) info += ` · ${result.masked_entities} values masked before sending`;
    meta.textContent = info;
    wireFeedback(node, result.id);
  }
  pending.replaceWith(node);
}

function updateStats(result) {
  const s = state.stats;
  s.total += 1;
  if (!result.error) {
    if (!result.refused) s.answered += 1;
    else if (result.reason === "prompt_injection") s.blocked += 1;
    else s.refused += 1;
    s.latency.push(result.latency_ms);
  }
  $("kpi-total").textContent = s.total;
  $("kpi-answered").textContent = s.answered;
  $("kpi-refused").textContent = s.refused;
  $("kpi-blocked").textContent = s.blocked;
  if (s.latency.length) {
    const avg = s.latency.reduce((a, b) => a + b, 0) / s.latency.length / 1000;
    $("kpi-latency").textContent = avg.toFixed(1) + " s";
  }
}

async function ask(question) {
  question = question.trim();
  if (question.length < 3 || !state.user) return;
  $("question").value = "";
  $("ask-button").disabled = true;
  addUserMessage(question);
  const pending = addPending();
  pending.scrollIntoView({ behavior: "smooth" });

  let result;
  try {
    const { status, data } = await api("/ask", { method: "POST", body: JSON.stringify({ question }) });
    if (status === 200) result = data;
    else if (status === 401) {
      result = { error: "Your session has expired. Please sign in again." };
      setTimeout(signOut, 1500);
    } else if (status === 429) result = { error: "Too many requests. Wait a minute and try again." };
    else result = { error: detail(data, `Error ${status}`) };
  } catch {
    result = { error: "The API could not be reached." };
  }
  addAnswer(pending, result);
  updateStats(result);
  $("ask-button").disabled = false;
  $("chat").lastElementChild.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ---------- Administration ----------
function pill(text, css) {
  return el("span", "pill" + (css ? " " + css : ""), text);
}

function actionButton(label, change, danger) {
  const b = el("button", "small-btn" + (danger ? " danger" : ""), label);
  b.type = "button";
  b.dataset.change = JSON.stringify(change);
  return b;
}

async function loadAdmin() {
  const [users, overview] = await Promise.all([api("/admin/users"), api("/admin/overview")]);
  if (users.status !== 200) return;
  const rows = users.data.map((u) => {
    const tr = el("tr");
    tr.dataset.user = u.name;
    const name = el("td");
    name.append(el("strong", null, u.name));
    if (u.service) name.append(" ", pill("service account"));
    const roles = el("td");
    roles.append(...u.roles.map((r) => pill(r)));
    const mfa = el("td");
    mfa.append(u.service ? pill("API key") : u.mfa_enabled ? pill("enabled", "ok") : pill("not set up", "warn"));
    const status = el("td");
    status.append(u.disabled ? pill("disabled", "bad") : u.locked ? pill("locked", "bad") : pill("active", "ok"));
    const actions = el("td");
    if (u.name !== state.user.name) {
      actions.append(actionButton(u.disabled ? "Enable" : "Disable", { disabled: !u.disabled }, !u.disabled));
    }
    if (u.locked) actions.append(actionButton("Unlock", { unlock: true }));
    if (u.mfa_enabled && u.name !== state.user.name) actions.append(actionButton("Reset MFA", { reset_mfa: true }, true));
    tr.append(name, roles, mfa, status, actions);
    return tr;
  });
  $("users-body").replaceChildren(...rows);

  if (overview.status === 200) {
    const o = overview.data;
    $("adm-helpful").textContent = o.feedback.helpful;
    $("adm-unhelpful").textContent = o.feedback.not_helpful;
    $("adm-failed").textContent = (o.events.login_failed || 0) + (o.events.mfa_failed || 0) + (o.events.auth_failed || 0);
    const events = o.recent_security_events.map((e) => {
      const tr = el("tr");
      const who = e.target ? `${e.user || ""} → ${e.target}` : e.user || "–";
      tr.append(
        el("td", null, (e.ts || "").replace("T", " ").replace("+00:00", "")),
        el("td", null, EVENT_LABELS[e.event] || e.event),
        el("td", null, who),
        el("td", null, e.client_ip || "–"),
      );
      return tr;
    });
    $("events-body").replaceChildren(...(events.length ? events : [el("tr")]));
    $("skipped-block").hidden = !o.skipped_files.length;
    $("skipped-list").replaceChildren(...o.skipped_files.map((f) => el("li", null, `${f.file}: ${f.reason}`)));
  }
}

async function adminAction(event) {
  const button = event.target.closest(".small-btn");
  if (!button) return;
  const name = button.closest("tr").dataset.user;
  const change = JSON.parse(button.dataset.change);
  if (change.reset_mfa && !confirm(`Reset MFA for ${name}? They will set it up again at their next sign-in.`)) return;
  const { status, data } = await api(`/admin/users/${encodeURIComponent(name)}`, {
    method: "PATCH",
    body: JSON.stringify(change),
  });
  adminMessage(status === 200 ? `${name} updated.` : detail(data, "Change refused."), status === 200);
  loadAdmin();
}

async function createUser(event) {
  event.preventDefault();
  const roles = [...document.querySelectorAll("#new-user-form input[type=checkbox]:checked")].map((c) => c.value);
  const body = { username: $("new-username").value.trim(), password: $("new-password").value, roles };
  const { status, data } = await api("/admin/users", { method: "POST", body: JSON.stringify(body) });
  if (status === 201) {
    $("new-username").value = "";
    $("new-password").value = "";
    adminMessage(`Account ${data.name} created. Give them the temporary password; they set up MFA at first sign-in.`, true);
    loadAdmin();
  } else {
    adminMessage(detail(data, "Account not created."), false);
  }
}

function adminMessage(text, ok) {
  const box = $("admin-msg");
  box.textContent = text;
  box.className = "hint " + (ok ? "ok" : "bad");
}

// ---------- Events ----------
document.addEventListener("DOMContentLoaded", () => {
  $("login-form").addEventListener("submit", submitLogin);
  $("mfa-setup-form").addEventListener("submit", (e) => submitCode(e, "setup-code"));
  $("mfa-form").addEventListener("submit", (e) => submitCode(e, "mfa-code"));
  $("mfa-cancel").addEventListener("click", signOut);
  $("signout").addEventListener("click", signOut);
  $("docs-filter").addEventListener("input", (e) => renderDocuments(e.target.value));
  document.querySelectorAll(".tab").forEach((t) => t.addEventListener("click", () => switchView(t.dataset.view)));
  document.querySelectorAll(".example").forEach((b) => b.addEventListener("click", () => ask(b.dataset.q)));
  $("users-body").addEventListener("click", adminAction);
  $("new-user-form").addEventListener("submit", createUser);
  $("ask-form").addEventListener("submit", (e) => {
    e.preventDefault();
    ask($("question").value);
  });
  const box = $("question");
  box.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && !e.shiftKey) {
      e.preventDefault();
      ask(box.value);
    }
  });
  box.addEventListener("input", () => {
    box.style.height = "auto";
    box.style.height = Math.min(box.scrollHeight, 160) + "px";
  });
  setInterval(() => state.user && loadHealth(), 30000);
  enterApp(); // an existing session (cookie) goes straight to the assistant
});
