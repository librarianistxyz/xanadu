# Xanadu (`.xnd`) Formal Wire & Cryptography Specification (v1)

This specification defines the canonical wire formats, cryptographic primitives, and trust rules shared across:
- **Python Node (`xnd-hub/`)**
- **Rust Core (`xnd-core/`)**
- **Android Native Node (`xnd-android/`)**
- **Public Read-Only Gateway (`xnd-gateway/`)**

Any implementation claiming Xanadu v1 interoperability MUST produce and verify byte-identical hashes, signatures, E2EE envelopes, and sync bundles.

---

## 1. Domain Naming & Anti-Squatting Trust Model

### 1.1 Valid `.xnd` Domain Syntax
Domains MUST be lowercase ASCII and match:
```regex
^(?:[a-z0-9](?:[a-z0-9]|-(?=[a-z0-9])){0,62}\.)+xnd$
```
Maximum total length: `253` characters.

### 1.2 Canonical Key-Fingerprint Fallback (`<name>.<short-pubkey>.xnd`)
Because `.xnd` has no central DNS registrar, two peers may claim the same human-readable name (e.g. `alice.xnd`) with different Ed25519 keys.
- **Short Key Fingerprint:** `pub_hex[0:4] + "-" + pub_hex[4:8]` (lowercase hex).
- **Canonical Domain:** `<stem>.<pub_hex[0:8]>.xnd` (e.g. `alice.8a88e3dd.xnd`), matching:
  ```regex
  ^([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.([0-9a-f]{8,16})\.xnd$
  ```
- **First-Seen Pinning:** A node pins the first valid `pubkey_hex` observed for `alice.xnd`. Subsequent updates for `alice.xnd` from a **different** `pubkey_hex` MUST NOT overwrite `alice.xnd`; they are routed to `alice.<pub_hex[0:8]>.xnd` and recorded as a conflict.
- **Signature Domain Rule:** When verifying a canonical alias `alice.<pub_hex[0:8]>.xnd`, implementations MUST check the Ed25519 signature against `alice.<pub_hex[0:8]>.xnd` and, if that fails, against the base domain `alice.xnd`.

---

## 2. Content Addressing & Canonical Signing Strings

### 2.1 Content Hash (`sha256`)
- Algorithm: `SHA-256` over the raw UTF-8 bytes of the document `content` (or capsule `bundle_payload`), encoded as **64 lowercase hex characters**.
- For `kind == "capsule"`, `bundle_payload` is canonical JSON:
  ```json
  {"backend_py":"...","files":{"index.html":"..."}}
  ```
  with keys sorted (`sort_keys=True` in Python) when published from `xnd-hub`.

### 2.2 Canonical Ed25519 Signing String
- **Version 1 (`prev_sha256` is empty `""`):**
  ```text
  {domain}|v{version_num}|{sha256}
  ```
- **Version N (`prev_sha256` is non-empty):**
  ```text
  {domain}|v{version_num}|{sha256}|{prev_sha256}
  ```
- **Encoding & Signature:** UTF-8 bytes signed with Ed25519 (RFC 8032) using the domain's 32-byte private seed (`privkey_hex`, 64 hex chars), producing a 64-byte signature (`signature_hex`, 128 lowercase hex chars).

---

## 3. Two-Way Transclusion Syntax

Exact character-span transclusions use 0-based `[start, end)` offsets over the target version's UTF-8/character string:
```text
{{xnd://{domain}@v{version_num}:{start}-{end}}}
```
- `start` and `end` are non-negative integers with `0 <= start <= end`.
- `xnd-core span <start> <end>` slices `[start..end]` and returns `sha256` + `text`.

---

## 4. End-to-End Encrypted Spaces (`XND-E2EE-v1`)

Private `.xnd` documents use the prefix `XND-E2EE-v1:` followed by compact JSON (`separators=(",", ":")`):
```json
{
  "v": 1,
  "nonce": "<base64 12-byte AES-GCM nonce>",
  "ct": "<base64 AES-256-GCM ciphertext+tag>",
  "recipients": {
    "<recipient_ed25519_pubkey_hex>": {
      "eph": "<ephemeral X25519 pubkey 64 hex>",
      "nonce": "<base64 12-byte wrap nonce>",
      "wk": "<base64 wrapped 32-byte doc_key + 16-byte tag>"
    }
  }
}
```
Key conversion (Ed25519 → X25519) MUST match RFC 7748 / libsodium:
1. **Private key:** `h = SHA-512(ed25519_seed)[:32]`; clamp `h[0] &= 248`, `h[31] &= 127`, `h[31] |= 64`.
2. **Public key:** Birational map from Edwards `y` (little-endian, mask bit 255) to Montgomery `u = (1 + y) * (1 - y)^(-1) mod (2^255 - 19)` (32-byte little-endian).
3. **Wrap key:** `wrap_key = SHA-256(X25519(eph_sk, recip_x25519_pub))` (32 bytes), used with `AES-256-GCM` (12-byte nonce, no AAD) to encrypt the 32-byte `doc_key`.

---

## 5. Nostr Relay Discovery Wire Format

- **Kinds:** `30078` (parameterized replaceable) or `1`.
- **Tags:**
  - `["t", "xanadu-doc-v1"]`
  - `["t", "xnd-{domain}"]`
  - `["d", "{domain}"]`
- **Event Signing:** BIP-340 Schnorr over `secp256k1` (Nostr NIP-01).
- **Large Payloads:** Split into `xanadu-chunk-v1` chunk events referenced by SHA-256.

---

## 6. Conformance & Test Vectors

See:
- [schemas/xnd-bundle.schema.json](schemas/xnd-bundle.schema.json)
- [schemas/xnd-e2ee-envelope.schema.json](schemas/xnd-e2ee-envelope.schema.json)
- [test_vectors.json](test_vectors.json)
- [verify_conformance.py](verify_conformance.py)
