"""Client side of the AI-pipeline secret-sharing demo - the ONLY component
that ever sees plaintext or the whole master key.

Flow: generate K -> split 2-of-3 -> encrypt prompt -> relay stores ciphertext
(+ one share only) -> client retrieves ciphertext, recombines shares held
client-side, decrypts, sends plaintext to the hosted LLM over its API ->
encrypts the response -> relay stores ciphertext again.

The hosted LLM provider necessarily sees plaintext at inference. That is a
documented limitation of this architecture, not a solved problem: SSS removes
server-side key custody, not inference-time exposure. Provider logs/retention
are outside our control and outside this design's protection.
"""
import json
import os
import urllib.request

import crypto_core as cc

RELAY = os.environ.get("RELAY", "http://127.0.0.1:8787")


def _post(path: str, payload: dict) -> dict:
    req = urllib.request.Request(
        RELAY + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    return json.loads(urllib.request.urlopen(req).read())


def _get(path: str) -> dict:
    return json.loads(urllib.request.urlopen(RELAY + path).read())


def _hexblob(blob: dict, direction: str, share) -> dict:
    return {
        "direction": direction,
        "ciphertext": blob["ciphertext"].hex(),
        "wrapped_key": blob["wrapped_key"].hex(),
        "nonce_ct": blob["nonce_ct"].hex(),
        "nonce_wrap": blob["nonce_wrap"].hex(),
        "share": [share[0], share[1].hex()],
    }


def _unhexblob(data: dict) -> dict:
    return {
        "ciphertext": bytes.fromhex(data["ciphertext"]),
        "wrapped_key": bytes.fromhex(data["wrapped_key"]),
        "nonce_ct": bytes.fromhex(data["nonce_ct"]),
        "nonce_wrap": bytes.fromhex(data["nonce_wrap"]),
    }


def ask_agent(question: str) -> str:
    # 1. master key lives here only; split 2-of-3, one share goes to the relay
    K = os.urandom(32)
    shares = cc.split_secret(K, 2, 3)
    relay_share = shares[2]           # third share: to relay (insufficient alone)
    local_shares = shares[:2]         # two shares stay on the user's device

    # 2. encrypt the prompt; relay stores only ciphertext + wrapped key + one share
    blob_q = cc.encrypt_message(K, question.encode())
    row_q = _post("/store", _hexblob(blob_q, "prompt->agent", relay_share))["id"]

    # 3. retrieve as the server would serve it; reconstruct locally; decrypt locally
    served = _get(f"/fetch?id={row_q}")
    K_back = cc.combine_shares(local_shares)   # relay share is NOT needed to prove relay can't
    assert K_back == K
    plaintext_q = cc.decrypt_message(K_back, _unhexblob(served))

    # 4. plaintext crosses to the hosted LLM here (documented exposure point)
    answer = call_llm(plaintext_q.decode())

    # 5. encrypt the answer; relay stores ciphertext only
    blob_a = cc.encrypt_message(K, answer.encode())
    _post("/store", _hexblob(blob_a, "agent->user", relay_share))
    return answer


def call_llm(prompt: str) -> str:
    """Hosted LLM call. Wired to IBM watsonx.ai (free Lite plan) when
    WATSONX_API_KEY + WATSONX_PROJECT_ID are set; otherwise refuses loudly -
    no fabricated agent responses in this demo."""
    api_key = os.environ.get("WATSONX_API_KEY")
    if not api_key:
        raise RuntimeError(
            "No hosted LLM credentials configured (WATSONX_API_KEY unset). "
            "The demo does not fake the agent step."
        )
    import llm_watsonx
    return llm_watsonx.ask(prompt)


if __name__ == "__main__":
    import sys
    q = " ".join(sys.argv[1:]) or "Summarize: what is Shamir secret sharing?"
    print("Q:", q)
    print("A:", ask_agent(q))
