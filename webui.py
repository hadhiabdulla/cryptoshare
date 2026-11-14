"""CryptoShare web UI - polished product surface for the AI-pipeline demo.

Served by the CLIENT process (127.0.0.1:8788), separate from the relay
process (127.0.0.1:8787). Every value shown comes from a REAL run of the
pipeline: real AES-256-GCM, real Shamir 2-of-3 (pycryptodome), real rows on
the relay's SQLite store, real IBM watsonx.ai call. No mock data.

Trust boundary is rendered explicitly: device (plaintext, master key,
shares 1+2) / relay (ciphertext + one share only) / provider (plaintext at
inference - documented limitation, shown amber on purpose).
"""
import json
import os
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer

import crypto_core as cc
import llm_watsonx

RELAY = os.environ.get("RELAY", "http://127.0.0.1:8787")
PORT = int(os.environ.get("WEBUI_PORT", "8788"))
STATIC = os.path.join(os.path.dirname(__file__), "webui_static")


def _post(path, payload):
    req = urllib.request.Request(
        RELAY + path, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    return json.loads(urllib.request.urlopen(req).read())


def _get(path):
    return json.loads(urllib.request.urlopen(RELAY + path).read())


def _hexblob(blob, direction, share):
    return {
        "direction": direction,
        "ciphertext": blob["ciphertext"].hex(),
        "wrapped_key": blob["wrapped_key"].hex(),
        "nonce_ct": blob["nonce_ct"].hex(),
        "nonce_wrap": blob["nonce_wrap"].hex(),
        "share": [share[0], share[1].hex()],
    }


def _unhexblob(d):
    return {k: bytes.fromhex(d[k]) for k in ("ciphertext", "wrapped_key", "nonce_ct", "nonce_wrap")}


def run_pipeline(question: str) -> dict:
    """One genuine end-to-end run; returns every artifact the UI shows."""
    out = {"question": question}
    K = os.urandom(32)
    shares = cc.split_secret(K, 2, 3)

    # share MATERIAL is never sent to the UI - only index, size and custody
    out["shares"] = [
        {"index": s[0], "bytes": len(s[1]),
         "held_by": "device" if s[0] in (1, 2) else "relay"}
        for s in shares
    ]

    blob_q = cc.encrypt_message(K, question.encode())
    out["prompt_blob"] = {
        "ciphertext_prefix": blob_q["ciphertext"][:16].hex(),
        "ciphertext_bytes": len(blob_q["ciphertext"]),
        "wrapped_key_prefix": blob_q["wrapped_key"][:12].hex(),
        "nonce_ct": blob_q["nonce_ct"].hex(),
        "nonce_wrap": blob_q["nonce_wrap"].hex(),
    }
    row_q = _post("/store", _hexblob(blob_q, "prompt->agent", shares[2]))["id"]
    out["prompt_row"] = row_q

    served = _get(f"/fetch?id={row_q}")
    K_back = cc.combine_shares(shares[:2])
    assert K_back == K
    plaintext_q = cc.decrypt_message(K_back, _unhexblob(served))
    assert plaintext_q.decode() == question
    out["recovered"] = True

    t0 = time.time()
    answer = llm_watsonx.ask(plaintext_q.decode())
    out["llm"] = {"model": llm_watsonx.MODEL, "latency_ms": int((time.time() - t0) * 1000),
                  "answer": answer}

    blob_a = cc.encrypt_message(K, answer.encode())
    row_a = _post("/store", _hexblob(blob_a, "agent->user", shares[2]))["id"]
    out["answer_row"] = row_a
    out["answer_blob"] = {
        "ciphertext_prefix": blob_a["ciphertext"][:16].hex(),
        "ciphertext_bytes": len(blob_a["ciphertext"]),
    }
    return out


LAST_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".last_run.json")


def _load_last():
    try:
        with open(LAST_FILE) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_last(data):
    try:
        with open(LAST_FILE, "w") as f:
            json.dump(data, f)
    except Exception:
        pass


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        data = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/" or self.path.startswith("/index"):
            with open(os.path.join(STATIC, "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        elif self.path == "/api/rows":
            try:
                self._send(200, json.dumps({"rows": _get("/rows.json")["rows"]}))
            except Exception as e:
                self._send(502, json.dumps({"error": f"relay unreachable: {e}"}))
        elif self.path == "/api/last":
            self._send(200, json.dumps(_load_last()))
        elif self.path == "/api/status":
            try:
                _get("/rows.json")
                relay = True
            except Exception:
                relay = False
            self._send(200, json.dumps({
                "relay": relay, "model": llm_watsonx.MODEL,
                "llm_configured": bool(os.environ.get("WATSONX_API_KEY")),
            }))
        else:
            self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if self.path != "/api/run":
            self._send(404, json.dumps({"error": "not found"}))
            return
        try:
            n = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(n) or b"{}")
            question = (body.get("prompt") or "").strip()[:2000]
            if not question:
                self._send(400, json.dumps({"error": "empty prompt"}))
                return
            result = run_pipeline(question)
            _save_last(result)
            self._send(200, json.dumps(result))
        except Exception as e:
            self._send(500, json.dumps({"error": str(e)}))


if __name__ == "__main__":
    print(f"CryptoShare web UI on http://127.0.0.1:{PORT} (relay: {RELAY})")
    HTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
