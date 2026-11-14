# CryptoShare - working title (Math for Systems Security, AI pipeline track)

## Trust boundaries (honest, no overclaiming)

- The **user's device** is the only trusted component. It holds the master key and
  sees plaintext.
- **Our application server** (relay + storage) never holds the master key and never
  sees plaintext. Its database/object storage holds ONLY ciphertext. (This claim is
  made only after implementation and actual storage inspection.)
- The **hosted LLM provider** (OpenAI/Gemini/Bedrock via API) necessarily receives
  plaintext at inference time. Its logging and retention are outside our control and
  outside this architecture's protection. We do not claim otherwise.
- **Shamir's Secret Sharing (SSS)** splits the master key so no single server-side
  component can reconstruct it. SSS removes key custody from the server; it does NOT
  remove the provider's inference-time plaintext exposure. That exposure is a
  documented limitation, not a solved problem. (FHE is one possible approach to
  confidential inference, listed as optional by the organizer; we do not claim it is
  the only one.)

## Flow

1. Client generates a random 256-bit master key K (never transmitted whole).
2. K is split via SSS (k-of-n, e.g. 2-of-3). Shares go to independent share-holders
   (e.g. user's own devices / a share service); the server stores at most one share
   and cannot reconstruct K alone.
3. Each prompt is encrypted client-side with AES-256-GCM under a per-message data key,
   itself wrapped by K. Only ciphertext + wrapped key leave the device.
4. Server stores ciphertext only. Storage inspection (dev tools / DB dump) is the
   verification that no plaintext is persisted on our side.
5. To get an answer, the client retrieves ciphertext, unwraps locally, and the
   plaintext prompt is sent to the LLM API from a boundary the user controls;
   the response is encrypted client-side before storage.
6. Stored history on the provider is out of scope (documented limitation above).

## Demo surface (per organizer: loopback website or TUI)

- Minimal local web app: encrypt -> store -> list ciphertext -> decrypt flow,
  with a visible storage inspector proving only ciphertext is persisted.
- Short screen-capture video: encrypted input fed to agent, storage shown as ciphertext.

## Stack

- Python 3, `cryptography` (AES-256-GCM) and `pycryptodome` (Shamir's Secret
  Sharing) - both vetted, widely reviewed libraries. The organizer explicitly
  allows pre-made algorithms including SSS. Security properties cited for this
  project come from the published schemes and the libraries' review, not from
  our own ad-hoc tests.
- `rich` for the TUI; `sqlite3` for the relay's ciphertext-only store;
  IBM watsonx.ai (granite-4-h-small) as the hosted LLM in the demo.
