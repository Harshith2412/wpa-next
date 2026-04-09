# WPA-Next

**A research prototype for a hybrid post-quantum resistant Wi-Fi security protocol, implemented in Rust.**

WPA-Next explores what a next-generation replacement for WPA3 might look like once large-scale quantum computers become a realistic threat. It combines a classical elliptic-curve key exchange with a post-quantum Key Encapsulation Mechanism (KEM), and solves the practical problem of transmitting large post-quantum public keys over 802.11 management frames — which have tight size constraints.

> **Status:** Research prototype. Not for production use.

---

## The Problem WPA-Next Solves

### Why current Wi-Fi security is at risk

WPA2 and WPA3 both rely on classical cryptography — specifically Diffie-Hellman key exchange over elliptic curves (ECDH). These algorithms are secure against today's computers, but a sufficiently powerful quantum computer running Shor's algorithm could break them in polynomial time. This is sometimes called the "harvest now, decrypt later" threat: an adversary can record encrypted Wi-Fi traffic today and decrypt it once quantum hardware matures.

### Why you can't just drop in ML-KEM

NIST standardized ML-KEM (Module Lattice Key Encapsulation Mechanism) in FIPS 203 as the post-quantum replacement for classical KEMs. However, ML-KEM-768's public key is **1,184 bytes** and its ciphertext is **1,088 bytes**.

802.11 management frames — the frames used during authentication, *before* a station is associated to an access point — have a practical payload limit of roughly 300–500 bytes after accounting for:

- 802.11 MAC headers
- RSN (Robust Security Network) information elements
- Vendor-specific IEs
- Regulatory and capability fields

There is no IP layer yet at this point in the handshake, so IP fragmentation is not available. ML-KEM keys simply do not fit in a single frame.

### WPA-Next's solution

WPA-Next defines a two-stage handshake that:

1. Transmits the small (32-byte) classical X25519 public key in a single management frame.
2. Fragments the large ML-KEM ciphertext across **three Layer 2 frames** of ≤400 bytes each, with a DoS-mitigation cookie to prevent the access point from wasting memory on incomplete or forged fragment sequences.
3. Combines both shared secrets through a hybrid KDF (HKDF-SHA-384) so that breaking *either* the classical *or* the post-quantum primitive alone is not sufficient to recover the session key.

---

## Protocol Design

### Security model

The hybrid approach follows the principle: **if at least one primitive is secure, the combined output is secure.**

- If ML-KEM-768 is broken (e.g., by a quantum computer), the X25519 layer still provides 128-bit classical security.
- If X25519 is broken (e.g., by a sufficiently advanced quantum computer), the ML-KEM-768 layer still provides ~180-bit post-quantum security.
- An adversary must break *both* simultaneously to recover the session key.

### Handshake overview

```
Station                                      Access Point
─────────────────────────────────────────────────────────────────────
[STAGE 1 — DISCOVERY]

Generate ephemeral X25519 key pair
FastLinkFrame { x25519_pk, station_mac }  ──────────────────────────►
                                              Validate frame magic/version
                                              Compute HMAC cookie (stateless)
                                          ◄──  cookie challenge

[STAGE 2 — QUANTIZATION]

Receive AP's ML-KEM-768 public key (broadcast, fragmented)
Encapsulate(ap_mlkem_pk) → (ciphertext, pq_ss)
Fragment ciphertext into 3 × ≤400-byte frames

FragmentedPQFrame[0] + cookie             ──────────────────────────►
                                              Verify cookie (constant-time)
                                              Allocate reassembly state ← only now
FragmentedPQFrame[1]                      ──────────────────────────►
FragmentedPQFrame[2]                      ──────────────────────────►
                                              Reassemble ciphertext
                                              Decapsulate(mlkem_sk) → pq_ss
                                              X25519 ECDH(station_pk) → classical_ss
                                              session_key = HKDF-SHA384(classical_ss ∥ pq_ss)

X25519 ECDH(ap_x25519_pk) → classical_ss
session_key = HKDF-SHA384(classical_ss ∥ pq_ss)

[Both sides now hold identical 256-bit session keys]
```

### Key derivation (hybrid combiner)

```
IKM  = classical_shared_secret (32 bytes)
     ∥ pq_shared_secret        (32 bytes)

Salt = "WPA-Next-v1-hybrid-salt"   (static, protocol-versioned)
Info = "WPA-Next-v1-session-key"   (binds output to this purpose)

session_key = HKDF-SHA384(IKM, Salt, Info) → 32 bytes (256-bit)
```

This construction follows the concatenation-based hybrid KDF pattern from NIST SP 800-227 (draft) and draft-ietf-tls-hybrid-design.

### DoS mitigation via cookie challenge

Before the AP allocates any per-station memory for fragment reassembly, it issues a cheap HMAC challenge:

```
cookie = HMAC-SHA384(ap_secret, station_mac ∥ sequence_id ∥ "WPA-Next-cookie-v1")
```

The station must include this cookie in `FragmentedPQFrame[0]`. The AP verifies it using constant-time comparison *before* inserting any state into its reassembly map. An attacker flooding the AP with fragment frames cannot trigger memory allocation without knowing the cookie — which requires knowing the AP's secret and the specific station MAC and sequence ID.

### Layer 2 fragmentation layout

```
FragmentedPQFrame wire format (≤ 512 bytes per frame):
┌────────────────────────────────────────────────┐
│ magic       [4 bytes]  "WPAN"                  │
│ frame_type  [1 byte]   0x02                    │
│ sequence_id [4 bytes]  random per-association  │
│ frag_index  [1 byte]   0, 1, or 2              │
│ frag_total  [1 byte]   3                       │
│ payload_len [2 bytes]  actual payload length   │
│ cookie      [48 bytes] HMAC (frag 0 only)      │
│ payload     [≤400 bytes] slice of ciphertext   │
└────────────────────────────────────────────────┘

Ciphertext (1088 bytes) fragmentation:
  Fragment 0: bytes    0 – 399  (400 bytes)
  Fragment 1: bytes  400 – 799  (400 bytes)
  Fragment 2: bytes  800 – 1087 (288 bytes)
```

---

## Cryptographic Stack

| Component | Algorithm | Crate | Purpose |
|---|---|---|---|
| Post-quantum KEM | ML-KEM-768 (FIPS 203) | `libcrux-ml-kem 0.0.2` | Quantum-resistant key encapsulation |
| Classical ECDH | X25519 | `ring 0.17` | Classical Diffie-Hellman |
| Hybrid KDF | HKDF-SHA-384 | `hkdf 0.12` + `sha2 0.10` | Combines both shared secrets |
| DoS cookie | HMAC-SHA-384 | `hmac 0.12` | Stateless challenge-response |
| Constant-time ops | — | `subtle 2.6` | Prevents timing side-channels |
| Memory zeroing | — | `zeroize 1.8` | Clears secrets from memory on drop |
| Serialization | bincode | `serde 1.0` + `bincode 1.3` | Frame encoding |

### Security levels

| Layer | Security level |
|---|---|
| X25519 classical | ~128-bit (pre-quantum) |
| ML-KEM-768 post-quantum | ~180-bit (Category 3, FIPS 203) |
| Combined session key | 256-bit output |

---

## Project Structure

```
wpa-next/
├── Cargo.toml          # Dependencies and build profiles
├── README.md           # This file
├── run_tests.sh        # Test runner shell script
└── src/
    ├── main.rs         # Entry point; full handshake simulation
    ├── crypto.rs       # Cryptographic primitives (X25519, ML-KEM, HKDF, cookie)
    ├── network.rs      # Frame structs, fragmentation, AP/Station state machines
    └── tests.rs        # 45-test suite across 5 modules
```

### `crypto.rs`

Contains all cryptographic logic, isolated from networking concerns:

- **`X25519KeyPair`** — generates an ephemeral X25519 key pair; the private key is consumed on first use (single-use semantics enforced by Rust's move system).
- **`MlKemKeyPair`** — wraps a `libcrux-ml-kem` ML-KEM-768 key pair with a clean `generate()` / `decapsulate()` interface.
- **`mlkem_encapsulate()`** — encapsulates against a peer's public key bytes; returns the ciphertext and shared secret.
- **`derive_session_key()`** — HKDF-SHA-384 hybrid combiner; takes both shared secrets and produces a 256-bit session key.
- **`compute_cookie()` / `verify_cookie()`** — HMAC-SHA-384 cookie generation and constant-time verification.
- **`SessionKey`** / **`SecretBytes`** — zeroizing wrappers that clear memory on drop.

### `network.rs`

Contains frame definitions and the protocol state machines:

- **`FastLinkFrame`** — Stage 1 discovery frame; carries the station's 32-byte X25519 public key and MAC address.
- **`FragmentedPQFrame`** / **`FragmentHeader`** — Stage 2 fragmented frame; carries a slice of the ML-KEM ciphertext with sequence and fragment metadata.
- **`fragment_payload()`** — splits a byte slice into a `Vec<FragmentedPQFrame>`, embedding the cookie in fragment 0 only.
- **`reassemble_fragments()`** — reconstructs the original byte slice from a set of frames; handles out-of-order delivery; returns `None` on incomplete or inconsistent input.
- **`AccessPoint`** — stateless until a valid cookie is received; manages per-station reassembly state in a `HashMap`; completes the full handshake on receipt of the final fragment.
- **`Station`** — builds the FastLinkFrame, encapsulates against the AP's ML-KEM public key, fragments the ciphertext, and completes the handshake with X25519 ECDH.

### `tests.rs`

45 tests across 5 modules:

| Module | Count | What it covers |
|---|---|---|
| `crypto_tests` | 16 | X25519 agreement, uniqueness, single-use; ML-KEM roundtrip, randomization, CCA tamper-resistance, bad-length errors; HKDF determinism and input ordering; cookie determinism, MAC/seq-id binding, correct/wrong verification; `ct_eq` |
| `fragmentation_tests` | 13 | Fragment count for 1088/1184-byte payloads; max payload size enforcement; cookie only in fragment 0; shared sequence IDs; correct indices; `payload_len` header accuracy; in-order and out-of-order reassembly; missing fragment returns `None`; empty input; single-fragment payload; mixed sequence IDs rejected |
| `handshake_tests` | 5 | Full matching keys end-to-end; two independent handshakes produce different keys; bad magic rejected; bad version rejected; AP stateless before valid cookie |
| `security_tests` | 5 | Fragment 1 before fragment 0 rejected; all-zeros cookie rejected; wrong ML-KEM key produces mismatched session keys; cookie not transferable between stations; replay of stale fragments rejected |
| `zeroize_tests` | 3 | `SecretBytes` zeroed on demand; `SessionKey` zeroed on demand; `Debug` impl never exposes key bytes |

---

## Getting Started

### Prerequisites

- Rust 1.70 or later ([install via rustup](https://rustup.rs))
- macOS, Linux, or Windows

### Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### Clone and build

```bash
git clone <repo-url>
cd wpa-next
cargo build
```

### Run the handshake demo

```bash
cargo run
```

Expected output:

```
╔═══════════════════════════════════════════════════════════════╗
║          WPA-Next Hybrid Post-Quantum Handshake Demo          ║
║   ML-KEM-768 (FIPS 203) + X25519 + HKDF-SHA384 Combiner      ║
╚═══════════════════════════════════════════════════════════════╝

[Init] Sequence ID for this association: 0x8A1CAF7D
...
✅ Session keys MATCH — handshake successful!

   Session key (hex): 4f6a27a6ffd03b99d76338c1ef5ceca5...
```

### Run the tests

```bash
# All 45 tests
cargo test

# With full println! output
cargo test -- --nocapture

# Single suite
cargo test crypto_tests
cargo test fragmentation_tests
cargo test handshake_tests
cargo test security_tests
cargo test zeroize_tests

# Single test by name
cargo test test_full_handshake_produces_matching_keys -- --nocapture

# Using the shell script runner
chmod +x run_tests.sh
./run_tests.sh                            # All suites
./run_tests.sh --suite security_tests     # One suite
./run_tests.sh --verbose                  # With output
./run_tests.sh --release                  # Release mode (faster)
./run_tests.sh --list                     # List all test names
```

### Build in release mode

```bash
cargo build --release
./target/release/wpa-next
```

Release builds enable LTO and single codegen unit, which significantly speeds up the ML-KEM operations.

---

## Safety Properties

### Memory safety

All secrets — shared secrets, session keys, intermediate KDF material — are wrapped in types that implement `zeroize::ZeroizeOnDrop`. When these values go out of scope or are explicitly dropped, the underlying bytes are overwritten with zeros before the memory is freed. This prevents secrets from persisting in heap or stack memory after the handshake completes.

```rust
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKey(pub [u8; SESSION_KEY_LEN]);

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(pub Vec<u8>);
```

### Timing safety

All comparisons that involve secret data use constant-time operations from the `subtle` crate. This prevents timing side-channel attacks where an attacker could infer secret values by measuring how long comparisons take.

```rust
// Cookie verification — never short-circuits
expected.ct_eq(candidate).into()

// Session key comparison in tests
ap_key.0.ct_eq(&station_key.0).into()
```

### Single-use key pairs

The `X25519KeyPair` private key is stored as `Option<EphemeralPrivateKey>` and consumed (moved out) on the first call to `diffie_hellman()`. Attempting to use it a second time returns `CryptoError::AlreadyUsed`. This is enforced by Rust's ownership system at compile time for the move, and at runtime via the `Option` check.

### AP statelessness before cookie validation

The access point's `station_state: HashMap` is never written to until `verify_cookie()` returns true for an incoming fragment 0. This means:

- An attacker sending fragment 1 or 2 frames with no prior fragment 0 receives `NetworkError::UnknownStation` with zero AP state allocated.
- An attacker sending fragment 0 with a forged or all-zero cookie receives `NetworkError::InvalidCookie` with zero AP state allocated.
- Only a station that received a legitimate cookie from the AP can trigger memory allocation.

---

## Design Decisions and Trade-offs

**Why ML-KEM-768 and not ML-KEM-512 or ML-KEM-1024?**
ML-KEM-768 targets NIST security category 3 (~180-bit post-quantum security), matching the security level of X25519 in the classical setting. Using 512 would be weaker than X25519; using 1024 would require 4 fragments instead of 3 with no material benefit given the hybrid design.

**Why HKDF-SHA-384 and not HKDF-SHA-256?**
SHA-384 provides a 192-bit security level, consistent with the 180–192-bit security target of the combined system. Using SHA-256 would create a mismatch where the KDF is weaker than the post-quantum primitive.

**Why fragment the ciphertext rather than the public key?**
In the implemented design, the AP broadcasts its ML-KEM public key (which would also need fragmentation in a real deployment). The station then encapsulates and fragments the *ciphertext* to send back. In either direction, the fragmentation logic is identical — the frame format supports any payload.

**Why is the cookie 48 bytes (HMAC-SHA-384 full output)?**
Truncating the HMAC would reduce security. At 48 bytes, an attacker has a 1-in-2^384 chance of guessing a valid cookie, making brute-force completely infeasible even with quantum hardware.

---

## References

- [FIPS 203](https://csrc.nist.gov/pubs/fips/203/final) — ML-KEM Standard (NIST, 2024)
- [RFC 7748](https://www.rfc-editor.org/rfc/rfc7748) — Elliptic Curves for Security (X25519)
- [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869) — HMAC-based Key Derivation Function (HKDF)
- [draft-ietf-tls-hybrid-design](https://datatracker.ietf.org/doc/draft-ietf-tls-hybrid-design/) — Hybrid key exchange in TLS 1.3
- [NIST SP 800-227 (draft)](https://csrc.nist.gov/publications/detail/sp/800-227/draft) — Recommendations for Key-Encapsulation Mechanisms
- [IEEE 802.11-2020](https://standards.ieee.org/ieee/802.11/7028/) — Wi-Fi standard (management frame format)
- [libcrux-ml-kem](https://github.com/cryspen/libcrux) — Formally verified ML-KEM implementation