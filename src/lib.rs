//! # wpa-next
//!
//! A hybrid post-quantum resistant Wi-Fi security protocol prototype.
//!
//! Combines X25519 ECDH (classical) with ML-KEM-768 (FIPS 203, post-quantum)
//! and merges both shared secrets through HKDF-SHA-384.
//!
//! ## Quick start
//!
//! ```rust,no_run
//! use wpa_next::network::{AccessPoint, Station};
//!
//! let mut ap  = AccessPoint::new([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]).unwrap();
//! let station = Station::new([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]).unwrap();
//!
//! let fast_link = station.build_fast_link_frame().unwrap();
//! let cookie    = ap.process_fast_link_frame(&fast_link, 0xDEADBEEF).unwrap();
//!
//! let ap_mlkem_pk       = ap.mlkem_public_key_bytes();
//! let ap_x25519_pk      = ap.x25519_public_key_bytes().unwrap();
//! let station_x25519_pk = station.x25519_public_key_bytes().unwrap();
//!
//! let (pq_frames, station_pq_ss) = station
//!     .build_pq_fragments(&ap_mlkem_pk, 0xDEADBEEF, &cookie)
//!     .unwrap();
//!
//! let mut ap_session_key = None;
//! for frame in &pq_frames {
//!     ap_session_key = ap
//!         .process_fragment(frame, &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66], &station_x25519_pk)
//!         .unwrap();
//! }
//!
//! let station_key = station.complete_handshake(&ap_x25519_pk, station_pq_ss).unwrap();
//! let ap_key      = ap_session_key.unwrap();
//! assert!(ap_key.ct_eq(&station_key));
//! ```

#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod crypto;
pub mod network;

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