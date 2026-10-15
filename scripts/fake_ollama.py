"""A stand-in for the Ollama API, used only by the CI smoke test.

It answers /api/chat by quoting the first sentences of source [S1] with a citation, so the whole
chain (API, retrieval, prompt, citation check) can be tested without downloading a model.
It is not a language model and is never used in the real deployment.

    python scripts/fake_ollama.py 11434
"""

import json
import re
import sys
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "fake-extractive"


def answer(messages: list[dict]) -> str:
    user = next((m["content"] for m in reversed(messages) if m.get("role") == "user"), "")
    match = re.search(r"\[S1\]\n\[[^\]]*\]\n(.+?)(?:\n\n\[S2\]|\n\nQuestion:)", user, re.S)
    if not match:
        return "NOT_FOUND"
    text = " ".join(match.group(1).split())
    sentences = re.split(r"(?<=[.!?])\s+", text)
    return " ".join(sentences[:2]) + " [S1]"


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: bytes, ctype: str = "application/json") -> None:
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        if self.path == "/api/tags":
            payload = {"models": [{"name": MODEL, "model": MODEL, "digest": "0" * 64}]}
            return self._send(200, json.dumps(payload).encode())
        return self._send(200, b"Ollama is running", "text/plain")

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length", 0))
        request = json.loads(self.rfile.read(length) or b"{}")
        if self.path != "/api/chat":
            return self._send(404, b"{}")
        now = datetime.now(UTC).isoformat()
        content = answer(request.get("messages", []))
        final = {
            "model": request.get("model", MODEL),
            "created_at": now,
            "message": {"role": "assistant", "content": ""},
            "done": True,
            "done_reason": "stop",
            "total_duration": 1,
            "eval_count": len(content.split()),
            "prompt_eval_count": 1,
        }
        if request.get("stream", True):
            first = {**final, "message": {"role": "assistant", "content": content}, "done": False}
            first.pop("done_reason")
            body = (json.dumps(first) + "\n" + json.dumps(final) + "\n").encode()
            return self._send(200, body, "application/x-ndjson")
        final["message"]["content"] = content
        return self._send(200, json.dumps(final).encode())

    def log_message(self, *args) -> None:
        pass


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 11434
    ThreadingHTTPServer(("127.0.0.1", port), Handler).serve_forever()
