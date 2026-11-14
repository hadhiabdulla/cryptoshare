"""Core crypto for the AI-pipeline secret-sharing track prototype.

Trust boundary: this module is the CLIENT side. The master key never leaves
here whole; only AES-GCM ciphertext and individual Shamir shares go out.
SSS removes server-side key custody. It does NOT remove the hosted LLM's
inference-time plaintext exposure (documented limitation, see ARCHITECTURE.md).
"""
import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Shamir's Secret Sharing from pycryptodome (vetted implementation - the
# organizer explicitly allows pre-made algorithms incl. SSS). Its security
# properties (k-1 shares reveal nothing) come from the published scheme and
# the library's review, not from our own ad-hoc tests.
from Crypto.Protocol.SecretSharing import Shamir as _Shamir

def split_secret(secret: bytes, k: int, n: int):
    """Split a secret into n shares, any k reconstruct. Returns [(x, y_bytes)]."""
    if not (1 < k <= n <= 255):
        raise ValueError("need 1 < k <= n <= 255")
    if len(secret) % 16:
        raise ValueError("secret must be a multiple of 16 bytes")
    shares = [(x, b"") for x in range(1, n + 1)]
    for off in range(0, len(secret), 16):
        for x, share in _Shamir.split(k, n, secret[off:off + 16]):
            shares[x - 1] = (x, shares[x - 1][1] + share)
    return shares

def combine_shares(shares):
    """Reconstruct the secret from k or more (x, y_bytes) shares."""
    xs = [s[0] for s in shares]
    if len(set(xs)) != len(xs):
        raise ValueError("duplicate shares")
    L = len(shares[0][1])
    if any(len(s[1]) != L for s in shares) or L % 16:
        raise ValueError("bad share length")
    out = bytearray()
    for off in range(0, L, 16):
        chunk = [(x, y[off:off + 16]) for x, y in shares]
        out += _Shamir.combine(chunk)
    return bytes(out)

# --- Envelope encryption: per-message data key wrapped by the master key ---

def encrypt_message(master_key: bytes, plaintext: bytes):
    data_key = os.urandom(32)
    nonce1, nonce2 = os.urandom(12), os.urandom(12)
    ciphertext = AESGCM(data_key).encrypt(nonce1, plaintext, None)
    wrapped = AESGCM(master_key).encrypt(nonce2, data_key, None)
    return {"ciphertext": ciphertext, "wrapped_key": wrapped,
            "nonce_ct": nonce1, "nonce_wrap": nonce2}

def decrypt_message(master_key: bytes, blob: dict):
    data_key = AESGCM(master_key).decrypt(blob["nonce_wrap"], blob["wrapped_key"], None)
    return AESGCM(data_key).decrypt(blob["nonce_ct"], blob["ciphertext"], None)


if __name__ == "__main__":
    K = os.urandom(32)
    shares = split_secret(K, 2, 3)
    assert combine_shares(shares[:2]) == K, "2-of-3 (shares 1,2) failed"
    assert combine_shares([shares[0], shares[2]]) == K, "2-of-3 (shares 1,3) failed"
    assert combine_shares(shares[1:]) == K, "2-of-3 (shares 2,3) failed"
    assert combine_shares(shares) == K, "3-of-3 failed"
    blob = encrypt_message(K, "Is this offer a scam?".encode())
    assert decrypt_message(K, blob) == b"Is this offer a scam?"
    # server-side view check: no plaintext or whole key anywhere in the blob
    assert b"scam" not in blob["ciphertext"] and K not in blob["wrapped_key"]
    # a single share must NOT reconstruct the secret
    assert combine_shares([shares[0]]) != K, "single share leaked the secret!"
    print("round-trip OK: SSS 2-of-3 + AES-256-GCM envelope")
