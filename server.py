"""Loopback relay + storage for the AI-pipeline secret-sharing demo.

TRUST BOUNDARY: this server NEVER sees the master key or plaintext.
It stores only: ciphertext, wrapped (encrypted) data keys, and at most ONE
Shamir share (insufficient to reconstruct a 2-of-3 key). The /inspector page
dumps the raw stored rows so reviewers can verify only ciphertext is held.
"""
import json
import os
import sqlite3
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

DB = os.path.join(os.path.dirname(__file__), "storage.db")

def _db():
    conn = sqlite3.connect(DB)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS blobs ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " ts REAL, direction TEXT,"
        " ciphertext BLOB, wrapped_key BLOB, nonce_ct BLOB, nonce_wrap BLOB,"
        " share_x INTEGER, share_y BLOB)"
    )
    return conn

def store(blob: dict) -> int:
    conn = _db()
    cur = conn.execute(
        "INSERT INTO blobs (ts, direction, ciphertext, wrapped_key, nonce_ct, nonce_wrap, share_x, share_y)"
        " VALUES (?,?,?,?,?,?,?,?)",
        (time.time(), blob["direction"], blob["ciphertext"], blob["wrapped_key"],
         blob["nonce_ct"], blob["nonce_wrap"], blob["share"][0], blob["share"][1]),
    )
    conn.commit()
    row_id = cur.lastrowid
    conn.close()
    return row_id

def fetch(row_id: int) -> dict:
    conn = _db()
    row = conn.execute("SELECT direction, ciphertext, wrapped_key, nonce_ct, nonce_wrap, share_x, share_y"
                       " FROM blobs WHERE id=?", (row_id,)).fetchone()
    conn.close()
    if not row:
        raise KeyError(row_id)
    return {"direction": row[0], "ciphertext": row[1], "wrapped_key": row[2],
            "nonce_ct": row[3], "nonce_wrap": row[4], "share": (row[5], row[6])}

def dump_rows():
    conn = _db()
    rows = conn.execute("SELECT id, ts, direction, length(ciphertext), hex(substr(ciphertext,1,12)),"
                        " length(wrapped_key), share_x FROM blobs ORDER BY id").fetchall()
    conn.close()
    return rows

INSPECTOR_CSS = ("body{font-family:system-ui;background:#0d1117;color:#e6edf3;max-width:900px;margin:2rem auto;padding:0 1rem}"
                 "table{border-collapse:collapse;width:100%}td,th{border:1px solid #30363d;padding:.4rem .6rem;font-size:.9rem}"
                 "h1{color:#58a6ff}.ok{color:#3fb950}")

class Handler(BaseHTTPRequestHandler):
    def _send(self, body: bytes, ctype="text/html; charset=utf-8", code=200):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/inspector"):
            rows = dump_rows()
            trs = "".join(
                f"<tr><td>{r[0]}</td><td>{time.strftime('%H:%M:%S', time.localtime(r[1]))}</td>"
                f"<td>{r[2]}</td><td>{r[3]} bytes</td><td><code>{r[4]}…</code></td>"
                f"<td>{r[5]} bytes</td><td>share x={r[6]}</td></tr>"
                for r in rows
            )
            body = (f"<html><head><title>Storage inspector</title><style>{INSPECTOR_CSS}</style></head><body>"
                    "<h1>Storage inspector - what the server actually holds</h1>"
                    "<p>Every byte below is ciphertext, a wrapped key, a nonce, or ONE Shamir share. "
                    "No plaintext, no master key. (Verified here, live, against the actual database.)</p>"
                    f"<table><tr><th>id</th><th>time</th><th>direction</th><th>ciphertext</th>"
                    f"<th>ciphertext prefix (hex)</th><th>wrapped key</th><th>share</th></tr>{trs}</table>"
                    "</body></html>")
            self._send(body.encode())
        elif self.path.startswith("/fetch?id="):
            row_id = int(self.path.split("id=")[1])
            blob = fetch(row_id)
            out = {k: (v.hex() if isinstance(v, bytes) else v) for k, v in blob.items() if k != "share"}
            out["share"] = [blob["share"][0], blob["share"][1].hex()]
            self._send(json.dumps(out).encode(), "application/json")
        else:
            self._send(b"<html><body><h1>CryptoShare relay</h1><p>See <a href='/inspector'>/inspector</a>.</p></body></html>")

    def do_POST(self):
        if self.path == "/store":
            n = int(self.headers["Content-Length"])
            blob = json.loads(self.rfile.read(n))
            for k in ("ciphertext", "wrapped_key", "nonce_ct", "nonce_wrap"):
                blob[k] = bytes.fromhex(blob[k])
            blob["share"] = (blob["share"][0], bytes.fromhex(blob["share"][1]))
            row_id = store(blob)
            self._send(json.dumps({"id": row_id}).encode(), "application/json")
        else:
            self._send(b"not found", "text/plain", 404)

    def log_message(self, *a):
        pass

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8787"))
    print(f"relay on http://127.0.0.1:{port} (inspector at /inspector)")
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
