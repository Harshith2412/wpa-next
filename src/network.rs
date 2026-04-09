// =============================================================================
// network.rs — WPA-Next Frame Structures, Fragmentation & Protocol State Machine
// =============================================================================
//
// WHY FRAGMENTATION IS NECESSARY
// --------------------------------
// 802.11 management frames (Probe Requests, Authentication frames, Association
// Requests) are constrained by the MPDU size limit. In practice the usable
// body of a management frame is ~2304 bytes, but vendor interoperability issues
// and regulatory body information elements leave far less room — commonly only
// 300–500 bytes of usable payload in an authentication exchange.
//
// ML-KEM-768 public keys are 1184 bytes and ciphertexts are 1088 bytes.
// Neither fits in a single standard management frame alongside 802.11 headers,
// RSN information elements, and other mandatory fields.
//
// WPA-Next SOLUTION: Layer 2 Fragmentation
// ------------------------------------------
// Instead of relying on IP-layer fragmentation (which doesn't exist pre-
// association), WPA-Next defines its own application-layer fragmentation
// protocol that operates entirely within the 802.11 management frame body.
// Each fragment carries:
//   • A 4-byte Sequence_ID  — ties all fragments of one logical message together
//   • A 1-byte Frag_Index   — 0-based fragment number (0, 1, 2)
//   • A 1-byte Frag_Total   — total number of fragments in this message
//   • A 2-byte Payload_Len  — length of this fragment's payload slice
//   • A 48-byte Cookie      — DoS-mitigation HMAC (only in Frag_Index == 0)
//   • Up to 400 bytes of payload
//
// This keeps every fragment well under 512 bytes — safe for any 802.11
// management frame implementation. Three fragments reassemble the 1184-byte
// ML-KEM-768 public key on the receiver.
//
// Fragmentation also lets the AP remain STATELESS until a valid cookie is
// presented in the first fragment, preventing state-exhaustion DoS attacks.
// =============================================================================

use crate::crypto::{
    compute_cookie, derive_session_key, mlkem_encapsulate, verify_cookie, CryptoError, MlKemKeyPair,
    SecretBytes, SessionKey, X25519KeyPair, HMAC_LEN, MLKEM_CT_LEN, X25519_PK_LEN,
};
use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Frame Constants ───────────────────────────────────────────────────────────

/// Maximum payload bytes per fragment.
/// Chosen so that full wire frame (header + cookie + payload) stays < 512 bytes.
///
/// Fragmentation math:
///   MLKEM_PK_LEN (1184) / 3 = ~395 bytes → round down to 400 for alignment.
///   Fragment 0: 400 bytes  (bytes   0 – 399)
///   Fragment 1: 400 bytes  (bytes 400 – 799)
///   Fragment 2: 384 bytes  (bytes 800 – 1183)
pub const FRAG_PAYLOAD_MAX: usize = 400;

/// Number of fragments needed to carry one ML-KEM-768 public key.
pub const MLKEM_PK_FRAG_COUNT: u8 = 3;

// ── Stage 1: FastLinkFrame (Discovery) ───────────────────────────────────────
//
// Sent by a Station during the initial probe/discovery phase.
// Carries only the 32-byte X25519 public key — fits easily in a single frame.
// This is the "classical" arm of the hybrid handshake.

/// WPA-Next Stage 1 — Discovery frame.
/// Transmitted by the Station; received by the Access Point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FastLinkFrame {
    /// Protocol magic bytes: b"WPAN" — validates frame type on receipt.
    pub magic: [u8; 4],

    /// Protocol version (currently 1).
    pub version: u8,

    /// Frame type discriminant: 0x01 = FastLinkFrame.
    pub frame_type: u8,

    /// Station's ephemeral X25519 public key (32 bytes).
    /// Safe to transmit in plaintext — this is a Diffie-Hellman public value.
    pub x25519_public_key: [u8; X25519_PK_LEN],

    /// Station's MAC address (used as cookie input to bind the handshake).
    pub station_mac: [u8; 6],
}

impl FastLinkFrame {
    /// Protocol magic bytes identifying a WPA-Next frame.
    pub const MAGIC: [u8; 4] = *b"WPAN";
    /// Frame type discriminant for [`FastLinkFrame`] (Stage 1 Discovery).
    pub const FRAME_TYPE: u8 = 0x01;

    /// Create a new [`FastLinkFrame`] with the given X25519 public key and station MAC.
    pub fn new(x25519_pk: [u8; X25519_PK_LEN], station_mac: [u8; 6]) -> Self {
        FastLinkFrame {
            magic: Self::MAGIC,
            version: 1,
            frame_type: Self::FRAME_TYPE,
            x25519_public_key: x25519_pk,
            station_mac,
        }
    }

    /// Returns `true` if the magic, version, and frame_type fields are valid.
    pub fn is_valid(&self) -> bool {
        self.magic == Self::MAGIC && self.version == 1 && self.frame_type == Self::FRAME_TYPE
    }
}

// ── Stage 2: FragmentedPQFrame (Quantization Phase) ──────────────────────────
//
// Carries the ML-KEM-768 public key (1184 bytes) split into 3 fragments.
// Each fragment is a self-contained wire frame with its own header.
// Fragments are sent sequentially; the receiver reassembles before processing.

/// Header present on EVERY fragment of a fragmented PQ payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentHeader {
    /// Protocol magic (same as FastLinkFrame for quick demux).
    pub magic: [u8; 4],

    /// Frame type: 0x02 = FragmentedPQFrame.
    pub frame_type: u8,

    /// Ties all fragments of the same logical message together.
    /// Generated fresh for each new ML-KEM public key transmission.
    pub sequence_id: u32,

    /// Zero-based fragment index (0, 1, or 2 for a 3-fragment message).
    pub frag_index: u8,

    /// Total number of fragments in this message (3 for ML-KEM-768 PK).
    pub frag_total: u8,

    /// Length of the payload slice carried by this specific fragment.
    pub payload_len: u16,
}

/// A single fragment of a fragmented PQ payload — this is what goes over the air.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FragmentedPQFrame {
    /// Frame header carrying sequence ID, fragment index, and length metadata.
    pub header: FragmentHeader,

    /// DoS-mitigation cookie: only populated on frag_index == 0.
    /// HMAC-SHA384(ap_secret, station_mac || sequence_id) — 48 bytes.
    /// Subsequent fragments carry all zeros here (cookie already validated).
    /// Stored as Vec<u8> (always HMAC_LEN bytes) — serde supports Vec but not [u8; 48].
    pub cookie: Vec<u8>,

    /// The actual payload slice (≤ FRAG_PAYLOAD_MAX bytes).
    pub payload: Vec<u8>,
}

impl FragmentedPQFrame {
    /// Frame type discriminant for [`FragmentedPQFrame`] (Stage 2 Quantization).
    pub const FRAME_TYPE: u8 = 0x02;
}

/// Fragment a large byte blob (e.g., ML-KEM public key) into wire frames.
///
/// The `cookie` parameter must be pre-computed by the AP and is embedded only
/// in fragment 0. This lets the Station prove it has the cookie before the AP
/// allocates reassembly state for fragments 1 and 2.
pub fn fragment_payload(
    payload: &[u8],
    sequence_id: u32,
    cookie: &[u8; HMAC_LEN],
) -> Vec<FragmentedPQFrame> {
    let chunks: Vec<&[u8]> = payload.chunks(FRAG_PAYLOAD_MAX).collect();
    let frag_total = chunks.len() as u8;
    let mut frames = Vec::with_capacity(chunks.len());

    for (idx, chunk) in chunks.iter().enumerate() {
        let frag_index = idx as u8;
        // Cookie only in first fragment — AP validates before allocating state.
        let frame_cookie = if frag_index == 0 { cookie.to_vec() } else { vec![0u8; HMAC_LEN] };

        frames.push(FragmentedPQFrame {
            header: FragmentHeader {
                magic: FastLinkFrame::MAGIC,
                frame_type: FragmentedPQFrame::FRAME_TYPE,
                sequence_id,
                frag_index,
                frag_total,
                payload_len: chunk.len() as u16,
            },
            cookie: frame_cookie,
            payload: chunk.to_vec(),
        });
    }
    frames
}

/// Reassemble fragments into the original payload.
/// Returns `None` if fragments are incomplete, out-of-order, or inconsistent.
pub fn reassemble_fragments(frames: &[FragmentedPQFrame]) -> Option<Vec<u8>> {
    if frames.is_empty() {
        return None;
    }
    let frag_total = frames[0].header.frag_total as usize;
    if frames.len() != frag_total {
        return None; // Not all fragments received yet.
    }

    // Sort by frag_index to handle out-of-order delivery.
    let mut sorted = frames.to_vec();
    sorted.sort_by_key(|f| f.header.frag_index);

    // Validate contiguity and shared sequence_id.
    let seq_id = sorted[0].header.sequence_id;
    for (expected_idx, frame) in sorted.iter().enumerate() {
        if frame.header.frag_index as usize != expected_idx {
            return None; // Gap or duplicate.
        }
        if frame.header.sequence_id != seq_id {
            return None; // Mixed sequence IDs — discard.
        }
    }

    let mut reassembled = Vec::new();
    for frame in &sorted {
        reassembled.extend_from_slice(&frame.payload[..frame.header.payload_len as usize]);
    }
    Some(reassembled)
}

// ── Access Point State Machine ────────────────────────────────────────────────
//
// The AP starts STATELESS. It only allocates per-station state after receiving
// a fragment-0 frame with a valid DoS cookie. This prevents state-exhaustion
// attacks where an adversary floods the AP with fragment-1/2 frames to fill
// reassembly buffers.

/// Per-station reassembly state held by the AP.
#[derive(Debug)]
struct StationHandshakeState {
    /// Station's X25519 public key from the FastLinkFrame.
    x25519_pk: [u8; X25519_PK_LEN],
    /// Partially reassembled ML-KEM ciphertext fragments.
    fragments: Vec<FragmentedPQFrame>,
    /// How many fragments we expect for this sequence.
    frag_total: u8,
}

/// Access Point — starts stateless, accepts connections.
pub struct AccessPoint {
    /// MAC address of this AP (informational; used in cookie binding).
    #[allow(dead_code)]
    pub mac: [u8; 6],

    /// AP's ML-KEM-768 key pair. The public key is distributed to stations.
    mlkem_kp: MlKemKeyPair,

    /// AP's ephemeral X25519 key pair. Regenerated per station in a real impl.
    x25519_kp: Option<X25519KeyPair>,

    /// AP's secret used for DoS-mitigation cookie generation.
    /// Rotated periodically; never leaves the AP.
    cookie_secret: [u8; 32],

    /// Per-station reassembly state. Only populated after valid cookie is seen.
    /// Key = station MAC address as a u64 (6 bytes, zero-padded).
    station_state: HashMap<u64, StationHandshakeState>,
}

impl AccessPoint {
    /// Create a new AccessPoint with fresh cryptographic material.
    pub fn new(mac: [u8; 6]) -> Result<Self, NetworkError> {
        let mut secret = [0u8; 32];
        rand_core::OsRng.fill_bytes(&mut secret);

        Ok(AccessPoint {
            mac,
            mlkem_kp: MlKemKeyPair::generate().map_err(NetworkError::Crypto)?,
            x25519_kp: Some(X25519KeyPair::generate().map_err(NetworkError::Crypto)?),
            cookie_secret: secret,
            station_state: HashMap::new(),
        })
    }

    /// Returns the AP's ML-KEM-768 public key bytes (1184 bytes).
    /// This will be fragmented by `build_pk_fragments` before transmission.
    pub fn mlkem_public_key_bytes(&self) -> Vec<u8> {
        self.mlkem_kp.public_key_bytes()
    }

    /// Returns the AP's X25519 public key bytes (32 bytes).
    pub fn x25519_public_key_bytes(&self) -> Option<[u8; X25519_PK_LEN]> {
        self.x25519_kp.as_ref().map(|kp| kp.public_key_bytes)
    }

    /// Build the cookie for a given station, to be embedded in fragment-0.
    pub fn build_cookie(&self, station_mac: &[u8; 6], sequence_id: u32) -> [u8; HMAC_LEN] {
        compute_cookie(&self.cookie_secret, station_mac, sequence_id)
    }

    /// Process a Stage-1 FastLinkFrame from a Station.
    ///
    /// STATELESS at this point — no per-station memory allocated.
    /// The AP records the station's X25519 key and issues a cookie challenge.
    /// In a real AP, the cookie would be returned in a management frame;
    /// here we return it directly so the Station can embed it in fragment-0.
    pub fn process_fast_link_frame(
        &mut self,
        frame: &FastLinkFrame,
        sequence_id: u32,
    ) -> Result<[u8; HMAC_LEN], NetworkError> {
        if !frame.is_valid() {
            return Err(NetworkError::InvalidFrame("FastLinkFrame magic/version check failed"));
        }

        println!(
            "[AP] Received FastLinkFrame from station {:02X?} — issuing cookie challenge",
            frame.station_mac
        );

        // Issue cookie challenge — cheap, stateless.
        let cookie = self.build_cookie(&frame.station_mac, sequence_id);
        Ok(cookie)
    }

    /// Process an incoming fragment. Allocates state only after valid cookie.
    ///
    /// Returns `Some(SessionKey)` when all fragments have been reassembled,
    /// the ML-KEM ciphertext has been decapsulated, and the session key derived.
    pub fn process_fragment(
        &mut self,
        frame: &FragmentedPQFrame,
        station_mac: &[u8; 6],
        station_x25519_pk: &[u8; X25519_PK_LEN],
    ) -> Result<Option<SessionKey>, NetworkError> {
        let station_id = mac_to_u64(station_mac);
        let seq_id = frame.header.sequence_id;

        if frame.header.frag_index == 0 {
            // ── Fragment 0: validate cookie BEFORE allocating state ──────────
            // This is the critical DoS-mitigation step. An attacker without the
            // cookie cannot force the AP to allocate reassembly buffers.
            let cookie_arr: &[u8; HMAC_LEN] = frame.cookie.as_slice().try_into()
                .map_err(|_| NetworkError::InvalidCookie)?;
            if !verify_cookie(&self.cookie_secret, station_mac, seq_id, cookie_arr) {
                println!("[AP] Cookie verification FAILED for station {:02X?} — dropping", station_mac);
                return Err(NetworkError::InvalidCookie);
            }
            println!("[AP] Cookie verified for station {:02X?} — allocating reassembly state", station_mac);

            // Safe to allocate state now.
            self.station_state.insert(
                station_id,
                StationHandshakeState {
                    x25519_pk: *station_x25519_pk,
                    fragments: vec![frame.clone()],
                    frag_total: frame.header.frag_total,
                },
            );
            return Ok(None); // Wait for more fragments.
        }

        // ── Fragment 1 / 2: state must already exist ─────────────────────────
        let state = self
            .station_state
            .get_mut(&station_id)
            .ok_or(NetworkError::UnknownStation)?;

        state.fragments.push(frame.clone());

        if state.fragments.len() < state.frag_total as usize {
            println!(
                "[AP] Fragment {}/{} received for station {:02X?}",
                state.fragments.len(),
                state.frag_total,
                station_mac
            );
            return Ok(None); // Still waiting.
        }

        // ── All fragments received — reassemble and complete handshake ────────
        println!("[AP] All {} fragments received — reassembling ML-KEM ciphertext", state.frag_total);

        let ciphertext = reassemble_fragments(&state.fragments)
            .ok_or(NetworkError::ReassemblyFailed)?;

        if ciphertext.len() != MLKEM_CT_LEN {
            return Err(NetworkError::InvalidFrame("Reassembled payload length mismatch"));
        }

        // ML-KEM decapsulation → PQ shared secret
        let pq_ss = self
            .mlkem_kp
            .decapsulate(&ciphertext)
            .map_err(NetworkError::Crypto)?;
        println!("[AP] ML-KEM-768 decapsulation successful");

        // X25519 ECDH → classical shared secret
        let x25519_kp = self
            .x25519_kp
            .take()
            .ok_or(NetworkError::X25519Consumed)?;
        let classical_ss = x25519_kp
            .diffie_hellman(&state.x25519_pk)
            .map_err(NetworkError::Crypto)?;
        println!("[AP] X25519 ECDH successful");

        // Hybrid combine via HKDF-SHA384
        let session_key = derive_session_key(&classical_ss, &pq_ss)
            .map_err(NetworkError::Crypto)?;
        println!("[AP] Session key derived via HKDF-SHA384 hybrid combiner");

        // Clean up station state.
        self.station_state.remove(&station_id);

        Ok(Some(session_key))
    }
}

// ── Station (Client) State Machine ───────────────────────────────────────────

/// Station (Wi-Fi client) — initiates the WPA-Next handshake.
pub struct Station {
    /// MAC address of this station.
    pub mac: [u8; 6],

    /// Station's ephemeral X25519 key pair.
    x25519_kp: Option<X25519KeyPair>,
}

impl Station {
    /// Create a new [`Station`] with a fresh ephemeral X25519 key pair.
    pub fn new(mac: [u8; 6]) -> Result<Self, NetworkError> {
        Ok(Station {
            mac,
            x25519_kp: Some(X25519KeyPair::generate().map_err(NetworkError::Crypto)?),
        })
    }

    /// Build Stage 1: FastLinkFrame containing the station's X25519 public key.
    pub fn build_fast_link_frame(&self) -> Result<FastLinkFrame, NetworkError> {
        let pk = self
            .x25519_kp
            .as_ref()
            .ok_or(NetworkError::X25519Consumed)?
            .public_key_bytes;
        Ok(FastLinkFrame::new(pk, self.mac))
    }

    /// Returns the station's X25519 public key (needed by AP for ECDH).
    pub fn x25519_public_key_bytes(&self) -> Result<[u8; X25519_PK_LEN], NetworkError> {
        self.x25519_kp
            .as_ref()
            .map(|kp| kp.public_key_bytes)
            .ok_or(NetworkError::X25519Consumed)
    }

    /// Build Stage 2: fragment the AP's ML-KEM public key, encapsulate,
    /// and produce a Vec of `FragmentedPQFrame`s ready for transmission.
    ///
    /// Returns the frames AND the PQ shared secret (kept locally, not sent).
    pub fn build_pq_fragments(
        &self,
        ap_mlkem_pk: &[u8],
        sequence_id: u32,
        cookie: &[u8; HMAC_LEN],
    ) -> Result<(Vec<FragmentedPQFrame>, SecretBytes), NetworkError> {
        // Encapsulate against AP's ML-KEM public key.
        let (ciphertext, pq_ss) =
            mlkem_encapsulate(ap_mlkem_pk).map_err(NetworkError::Crypto)?;

        println!(
            "[Station] ML-KEM-768 encapsulation successful — ciphertext {} bytes",
            ciphertext.len()
        );

        // Fragment the ciphertext (1088 bytes → 3 frames of ≤400 bytes each).
        let frames = fragment_payload(&ciphertext, sequence_id, cookie);
        println!(
            "[Station] Ciphertext split into {} fragments (max {} bytes each)",
            frames.len(),
            FRAG_PAYLOAD_MAX
        );

        Ok((frames, pq_ss))
    }

    /// Complete the Station side of the handshake:
    /// Perform X25519 ECDH with the AP's public key and derive the session key.
    pub fn complete_handshake(
        mut self,
        ap_x25519_pk: &[u8; X25519_PK_LEN],
        pq_ss: SecretBytes,
    ) -> Result<SessionKey, NetworkError> {
        let x25519_kp = self.x25519_kp.take().ok_or(NetworkError::X25519Consumed)?;
        let classical_ss = x25519_kp
            .diffie_hellman(ap_x25519_pk)
            .map_err(NetworkError::Crypto)?;
        println!("[Station] X25519 ECDH successful");

        let session_key = derive_session_key(&classical_ss, &pq_ss)
            .map_err(NetworkError::Crypto)?;
        println!("[Station] Session key derived via HKDF-SHA384 hybrid combiner");

        Ok(session_key)
    }
}

// ── Utilities ─────────────────────────────────────────────────────────────────

fn mac_to_u64(mac: &[u8; 6]) -> u64 {
    let mut buf = [0u8; 8];
    buf[2..8].copy_from_slice(mac);
    u64::from_be_bytes(buf)
}

// ── Error Types ───────────────────────────────────────────────────────────────

/// Errors that can occur during WPA-Next network / protocol operations.
#[derive(Debug, thiserror::Error)]
pub enum NetworkError {
    /// An underlying cryptographic primitive failed.
    #[error("Cryptographic operation failed: {0}")]
    Crypto(#[from] CryptoError),

    /// A received frame had an invalid magic, version, or type field.
    #[error("Invalid frame: {0}")]
    InvalidFrame(&'static str),

    /// The DoS-mitigation cookie in a fragment-0 frame did not verify.
    #[error("DoS cookie verification failed")]
    InvalidCookie,

    /// Fragment reassembly failed — fragments were incomplete, out-of-range, or had mismatched sequence IDs.
    #[error("Fragment reassembly failed — incomplete or inconsistent fragments")]
    ReassemblyFailed,

    /// A non-initial fragment arrived with no prior reassembly state (fragment 0 was never received or cookie failed).
    #[error("Unknown station — received non-initial fragment without prior state")]
    UnknownStation,

    /// The X25519 key pair was already consumed — each ephemeral key pair is single-use.
    #[error("X25519 key pair already consumed (single-use)")]
    X25519Consumed,
}