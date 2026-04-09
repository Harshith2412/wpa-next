//! # wpa-next
//!
//! A hybrid post-quantum resistant Wi-Fi security protocol prototype.
//!
//! `wpa-next` implements a two-stage handshake that combines **X25519 ECDH**
//! (classical) with **ML-KEM-768** (FIPS 203, post-quantum) and merges both
//! shared secrets through **HKDF-SHA-384**. It also solves the practical
//! problem of transmitting large post-quantum keys over 802.11 management
//! frames via a custom **Layer 2 fragmentation** protocol with a
//! **HMAC-based DoS-mitigation cookie**.
//!
//! ## Security model
//!
//! The hybrid design means an adversary must break **both** primitives to
//! recover the session key:
//!
//! - X25519 provides ~128-bit classical security (hard today)
//! - ML-KEM-768 provides ~180-bit post-quantum security (hard for quantum computers)
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use wpa_next::network::{AccessPoint, Station};
//!
//! // Create AP and Station with their MAC addresses
//! let mut ap  = AccessPoint::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).unwrap();
//! let station = Station::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]).unwrap();
//!
//! // Stage 1 — Station sends its X25519 public key
//! let fast_link = station.build_fast_link_frame().unwrap();
//! let cookie    = ap.process_fast_link_frame(&fast_link, 0xDEADBEEF).unwrap();
//!
//! // Stage 2 — Station encapsulates against AP's ML-KEM key and fragments
//! let ap_mlkem_pk       = ap.mlkem_public_key_bytes();
//! let ap_x25519_pk      = ap.x25519_public_key_bytes().unwrap();
//! let station_x25519_pk = station.x25519_public_key_bytes().unwrap();
//!
//! let (pq_frames, station_pq_ss) = station
//!     .build_pq_fragments(&ap_mlkem_pk, 0xDEADBEEF, &cookie)
//!     .unwrap();
//!
//! // AP processes fragments one at a time
//! let mut ap_session_key = None;
//! for frame in &pq_frames {
//!     ap_session_key = ap
//!         .process_fragment(frame, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66], &station_x25519_pk)
//!         .unwrap();
//! }
//!
//! // Station completes with X25519 ECDH
//! let station_key = station.complete_handshake(&ap_x25519_pk, station_pq_ss).unwrap();
//! let ap_key      = ap_session_key.unwrap();
//!
//! // Both sides now hold the same 256-bit session key
//! assert!(ap_key.ct_eq(&station_key));
//! ```
//!
//! ## Modules
//!
//! - [`crypto`] — cryptographic primitives: X25519, ML-KEM-768, HKDF combiner, cookie
//! - [`network`] — frame structures, Layer 2 fragmentation, AP and Station state machines
//!
//! ## Feature flags
//!
//! This crate has no optional features. All functionality is always available.
//!
//! ## ⚠ Research prototype
//!
//! This crate is a **research prototype** — it has not been independently
//! audited for production use in actual wireless deployments.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(clippy::all)]

/// Cryptographic primitives: X25519 ECDH, ML-KEM-768 (FIPS 203), HKDF-SHA384 hybrid combiner, and HMAC cookie.
pub mod crypto;
/// Frame structures, Layer 2 fragmentation, and the AP / Station protocol state machines.
pub mod network;

// Re-export the most commonly used types at the crate root for convenience.
pub use crypto::{
    CryptoError, MlKemKeyPair, SecretBytes, SessionKey, X25519KeyPair,
    HMAC_LEN, MLKEM_CT_LEN, MLKEM_PK_LEN, SESSION_KEY_LEN, X25519_PK_LEN,
};
pub use network::{
    AccessPoint, FastLinkFrame, FragmentHeader, FragmentedPQFrame, NetworkError, Station,
    FRAG_PAYLOAD_MAX, MLKEM_PK_FRAG_COUNT,
};

#[cfg(test)]
mod tests;