# CryptoShare: split-key encrypted LLM relay

A local LLM pipeline prototype for the Mathematics for Systems Security hackathon (AI pipeline track). Prompts are AES-256-GCM encrypted on the user's device, and the relay server stores only ciphertext plus one Shamir share - never enough to rebuild the 2-of-3 key.

## What it does

- On the user's device: the prompt is encrypted with AES-256-GCM before anything leaves. The 256-bit master key is split with Shamir's Secret Sharing (2-of-3). The device is the trusted component: it holds the shares and sees plaintext.
- On the relay server (loopback, 127.0.0.1): only ciphertext, wrapped data keys, nonces, and at most one Shamir share are persisted. One share of a 2-of-3 split carries no information about the key, so the relay's storage alone cannot decrypt anything.
- At the hosted LLM (IBM watsonx.ai, `ibm/granite-4-h-small`): the client recovers the prompt locally from shares 1+2, sends it as an ordinary API request, and encrypts the response before storing it.
- A built-in `/inspector` page dumps the actual database rows persisted during a demo run, so a reviewer can see that what the server stored for those runs is ciphertext, wrapped keys, nonces, and one share - not plaintext. This verifies what was persisted in the demo; it is not a proof about every possible server process or future version.

## What it does NOT do

The hosted model provider necessarily receives plaintext at inference time, and its logging and retention are outside this design. Secret sharing removes the need to trust our server's storage with the key; it does not remove the provider's inference-time exposure. Fully homomorphic encryption is the usual answer to that problem; it is future work here, not a solved part.

## How it's built

- Python 3 client and loopback relay over HTTP; SQLite as the relay store, deliberately simple so the inspector view stays readable.
- The organizer explicitly permits this for the AI pipeline track: "Participants may use pre created cryptographic algorithm and secret sharing mechanisms such as SSS (Shamir's secret sharing)" (hackathon page, https://mathematics-systems-security.devpost.com/).
- AES-256-GCM from the `cryptography` library; Shamir's Secret Sharing from `pycryptodome` - both vetted, widely reviewed implementations. Security properties cited come from the published schemes, not from this project's own tests.
- Concrete composition: pycryptodome's Shamir operates on 16-byte secrets, so the 32-byte master key is split as two independent 16-byte blocks (each block is Shamir-split 2-of-3) and recombined block-wise. Each message gets its own random data key (AES-256-GCM), wrapped under the master key, so stored blobs are independent.
- A web UI on the loopback machine walks the pipeline live: what stays on the device, what the relay persists, and the documented inference-exposure boundary.

## Run it

```bash
pip install cryptography pycryptodome rich requests
python3 server.py            # loopback relay on 127.0.0.1:8787, SQLite store, /inspector page
export WATSONX_API_KEY=...   # IBM Cloud API key with access to a watsonx.ai deployment space
export WATSONX_SPACE_ID=...  # deployment space associated with a Watson Machine Learning instance
python3 tui.py "Your sample prompt here"
```

The TUI encrypts the prompt locally, stores the ciphertext row on the relay, recovers the plaintext locally from two shares, calls the hosted model, and stores the encrypted answer. Open http://127.0.0.1:8787/inspector to see the persisted rows.

The watsonx call targets the `us-south` region and the `ibm/granite-4-h-small` model, which is available on the free Lite plan. The relay is loopback-only by design: there is no deployed server, so no real user data is ever at stake. See ARCHITECTURE.md for the full design and threat model.
