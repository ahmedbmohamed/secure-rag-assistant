"""Streamlit chat interface. It talks only to the API, never to the database or the LLM directly.

streamlit run ui/app.py
"""

import os

import httpx
import streamlit as st

API_URL = os.environ.get("SRAG_API_URL", "http://localhost:8000")
SOURCE_LABELS = {"owasp": "OWASP Top 10", "nist": "NIST SP 800-53", "internal": "Internal document"}
REASON_LABELS = {
    "prompt_injection": "Blocked: prompt injection",
    "not_in_documents": "No answer in your documents",
    "no_citation": "Answer without a source, hidden",
    "output_blocked": "Blocked by the output filter",
}
EXAMPLES = [
    "How do I prevent SQL injection?",
    "What does AC-2 require for account management?",
    "Can employees put restricted customer data into an external AI service?",
    "How should a compromised workstation be contained?",
]

st.set_page_config(page_title="Secure RAG Assistant", page_icon=":material/shield_lock:", layout="wide")
st.markdown(
    """
    <style>
    .block-container {padding-top: 2rem; max-width: 1100px;}
    .badge {display:inline-block;padding:4px 10px;border-radius:999px;font-size:0.82rem;font-weight:600;}
    .local {background:#DCFCE7;color:#166534;border:1px solid #86EFAC;}
    .cloud {background:#FEF3C7;color:#92400E;border:1px solid #FCD34D;}
    .role {background:#E0E7FF;color:#3730A3;border:1px solid #A5B4FC;margin-right:4px;}
    .src {font-size:0.85rem;color:#475569;}
    </style>
    """,
    unsafe_allow_html=True,
)


def api(method: str, path: str, key: str, **kwargs) -> httpx.Response:
    return httpx.request(method, f"{API_URL}{path}", headers={"X-API-Key": key}, timeout=180, **kwargs)


@st.cache_data(ttl=30)
def health() -> dict | None:
    try:
        return httpx.get(f"{API_URL}/health", timeout=5).json()
    except httpx.HTTPError:
        return None


with st.sidebar:
    st.subheader("Sign in")
    key = st.text_input("API key", type="password", help="Created by scripts/create_users.py")
    me = None
    if key:
        r = api("GET", "/me", key)
        if r.status_code == 200:
            me = r.json()
        else:
            st.error("Invalid API key")
    info = health()
    st.divider()
    if info:
        css, label = (
            ("local", "Local mode: data stays on this machine")
            if info["mode"] == "local"
            else (
                "cloud",
                "Cloud mode: personal data is masked before sending",
            )
        )
        st.markdown(f'<span class="badge {css}">{label}</span>', unsafe_allow_html=True)
        st.caption(f"Model: {info['model']}  \nIndex: {info['documents']} documents, {info['chunks']} chunks")
        st.caption(f"Index integrity: {info['integrity']}")
    else:
        st.error("API unreachable")
    if me:
        st.divider()
        st.markdown(f"**{me['name']}**")
        st.markdown(" ".join(f'<span class="badge role">{r}</span>' for r in me["roles"]), unsafe_allow_html=True)
        docs = api("GET", "/documents", key).json()
        internal = [d["title"] for d in docs if d["source"] == "internal"]
        st.caption(f"You can search {len(docs)} documents.")
        if internal:
            st.caption("Internal: " + ", ".join(internal))
        if st.button("Clear conversation", use_container_width=True):
            st.session_state.history = []

st.title("Secure RAG Assistant")
st.caption(
    "Answers questions on OWASP Top 10, NIST SP 800-53 and internal policies, with a source for every statement. "
    "Prompt injection is blocked, access rights are enforced in the search, "
    "and nothing leaves the machine in local mode."
)

if not me:
    st.info("Enter your API key in the sidebar to start.")
    st.stop()

st.session_state.setdefault("history", [])


def render(entry: dict) -> None:
    data = entry["answer"]
    if data.get("error"):
        st.error(data["error"])
        return
    if data["refused"]:
        st.warning(f"**{REASON_LABELS.get(data['reason'], data['reason'])}**  \n{data['answer']}")
    else:
        st.markdown(data["answer"])
    meta = f"{data['latency_ms'] / 1000:.1f} s · {data['mode']} mode"
    if data["masked_entities"]:
        meta += f" · {data['masked_entities']} values masked before sending"
    st.caption(meta)
    for s in data["sources"]:
        title = f"{s['label']} · {s['title']}" + (f" · {s['section']}" if s["section"] else "")
        with st.expander(title):
            st.markdown(
                f'<div class="src">{SOURCE_LABELS.get(s["source"], s["source"])} · similarity {s["score"]:.2f}</div>',
                unsafe_allow_html=True,
            )
            st.text(s["excerpt"])
            if s["url"]:
                st.markdown(f"[Open the source]({s['url']})")


if not st.session_state.history:
    cols = st.columns(len(EXAMPLES))
    for col, example in zip(cols, EXAMPLES, strict=True):
        if col.button(example, use_container_width=True):
            st.session_state.pending = example

for entry in st.session_state.history:
    with st.chat_message("user"):
        st.markdown(entry["question"])
    with st.chat_message("assistant"):
        render(entry)

question = st.chat_input("Ask about a control, a risk or a policy") or st.session_state.pop("pending", None)
if question:
    with st.chat_message("user"):
        st.markdown(question)
    with st.chat_message("assistant"), st.spinner("Searching the documents..."):
        r = api("POST", "/ask", key, json={"question": question})
        if r.status_code == 200:
            answer = r.json()
        elif r.status_code == 429:
            answer = {"error": "Too many requests. Wait a minute and try again."}
        else:
            answer = {"error": r.json().get("detail", f"Error {r.status_code}")}
        entry = {"question": question, "answer": answer}
        render(entry)
    st.session_state.history.append(entry)
