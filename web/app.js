// Secure RAG Assistant web interface.
// Security notes:
// - The API key is kept in memory only (never in localStorage or cookies). A reload signs you out.
// - Model output and document text are untrusted: they are inserted with textContent, never innerHTML.
"use strict";

const REASONS = {
  prompt_injection: { title: "Blocked: prompt injection", css: "blocked" },
  not_in_documents: { title: "No answer in your documents", css: "refused" },
  no_citation: { title: "Answer hidden: no valid source", css: "refused" },
  output_blocked: { title: "Blocked by the output filter", css: "blocked" },
};
const SOURCE_NAMES = { owasp: "OWASP Top 10", nist: "NIST SP 800-53", internal: "Internal" };

const state = { key: null, user: null, documents: [], stats: { total: 0, answered: 0, refused: 0, blocked: 0, latency: [] } };
const $ = (id) => document.getElementById(id);

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (state.key) headers["X-API-Key"] = state.key;
  if (options.body) headers["Content-Type"] = "application/json";
  const response = await fetch(path, { ...options, headers });
  let data = null;
  try { data = await response.json(); } catch { /* empty body */ }
  return { status: response.status, data };
}

// ---------- Status ----------
async function loadHealth() {
  const badge = $("mode-badge");
  try {
    const { status, data } = await api("/health");
    if (status !== 200) throw new Error();
    badge.className = "badge " + (data.mode === "local" ? "local" : "cloud");
    badge.textContent = data.mode === "local" ? "Local mode: data stays on this machine" : "Cloud mode: personal data masked";
    $("fact-model").textContent = data.model;
    $("fact-index").textContent = `${data.documents} docs, ${data.chunks} chunks`;
    const integrity = $("fact-integrity");
    integrity.textContent = data.integrity === "ok" ? "Verified" : "Failed";
    integrity.className = data.integrity === "ok" ? "good" : "fail";
  } catch {
    badge.className = "badge down";
    badge.textContent = "API unreachable";
  }
}

// ---------- Sign in ----------
async function signIn(key) {
  state.key = key;
  const { status, data } = await api("/me");
  if (status !== 200) {
    state.key = null;
    const error = $("signin-error");
    error.textContent = status === 429 ? "Too many attempts, wait a minute." : "Invalid API key.";
    error.hidden = false;
    return;
  }
  state.user = data;
  $("signin-error").hidden = true;
  $("api-key").value = "";
  $("signin-panel").hidden = true;
  $("user-panel").hidden = false;
  $("docs-panel").hidden = false;
  $("user-name").textContent = data.name;
  $("user-avatar").textContent = data.name.slice(0, 1).toUpperCase();
  const roles = $("user-roles");
  roles.replaceChildren(...data.roles.map((r) => el("span", "role" + (r === "security-admin" ? " admin" : ""), r)));
  $("question").disabled = false;
  $("ask-button").disabled = false;
  document.querySelectorAll(".example").forEach((b) => (b.disabled = false));
  $("welcome").querySelector("h2").textContent = "Try a question";
  $("question").focus();
  await loadDocuments();
}

function signOut() {
  state.key = null;
  state.user = null;
  $("signin-panel").hidden = false;
  $("user-panel").hidden = true;
  $("docs-panel").hidden = true;
  $("question").disabled = true;
  $("ask-button").disabled = true;
  document.querySelectorAll(".example").forEach((b) => (b.disabled = true));
}

async function loadDocuments() {
  const { status, data } = await api("/documents");
  if (status !== 200) return;
  const order = { internal: 0, owasp: 1, nist: 2 };
  state.documents = data.sort((a, b) => order[a.source] - order[b.source] || a.reference.localeCompare(b.reference, undefined, { numeric: true }));
  $("docs-count").textContent = state.documents.length;
  renderDocuments("");
}

function renderDocuments(filter) {
  const needle = filter.trim().toLowerCase();
  const items = state.documents
    .filter((d) => !needle || d.title.toLowerCase().includes(needle))
    .map((d) => {
      const li = el("li");
      li.append(el("span", "tag " + d.source, d.source), el("span", null, d.title.replace(/^(OWASP Top 10|NIST SP 800-53) /, "")));
      return li;
    });
  $("docs-list").replaceChildren(...items);
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
  // Turn [S1] markers into buttons that jump to the matching source.
  const parts = text.split(/(\[S\d+\])/g);
  for (const part of parts) {
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
  if (question.length < 3 || !state.key) return;
  $("welcome").hidden = true;
  $("question").value = "";
  $("ask-button").disabled = true;
  addUserMessage(question);
  const pending = addPending();
  pending.scrollIntoView({ behavior: "smooth" });

  let result;
  try {
    const { status, data } = await api("/ask", { method: "POST", body: JSON.stringify({ question }) });
    if (status === 200) result = data;
    else if (status === 429) result = { error: "Too many requests. Wait a minute and try again." };
    else if (status === 401) { result = { error: "Your session is no longer valid. Sign in again." }; signOut(); }
    else result = { error: (data && data.detail && (typeof data.detail === "string" ? data.detail : "Invalid question.")) || `Error ${status}` };
  } catch {
    result = { error: "The API could not be reached." };
  }
  addAnswer(pending, result);
  updateStats(result);
  $("ask-button").disabled = !state.key;
  $("chat").lastElementChild.scrollIntoView({ behavior: "smooth", block: "start" });
}

// ---------- Events ----------
document.addEventListener("DOMContentLoaded", () => {
  loadHealth();
  setInterval(loadHealth, 30000);
  document.querySelectorAll(".example").forEach((b) => {
    b.disabled = true;
    b.addEventListener("click", () => ask(b.dataset.q));
  });
  $("signin-form").addEventListener("submit", (e) => {
    e.preventDefault();
    signIn($("api-key").value.trim());
  });
  $("signout").addEventListener("click", signOut);
  $("docs-filter").addEventListener("input", (e) => renderDocuments(e.target.value));
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
});
