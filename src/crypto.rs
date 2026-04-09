// =============================================================================
// crypto.rs — WPA-Next Cryptographic Stack
// =============================================================================
//
// Implements a hybrid classical + post-quantum key exchange:
//
//   1. Classical Layer  : X25519 ECDH  (via `ring`)
//   2. Post-Quantum Layer: ML-KEM-768  (FIPS 203, via `libcrux-ml-kem`)
//   3. Hybrid Combiner  : HKDF-SHA-384 merging both shared secrets
//
// Security rationale
// ------------------
//   The hybrid design ensures that an adversary must break *both* X25519 (hard
//   for classical computers today) AND ML-KEM-768 (hard for quantum computers)
//   to recover the session key. Neither primitive alone is sufficient.
//
//   HKDF is used as a KDF combiner per the pattern recommended in
//   draft-ietf-tls-hybrid-design: both secrets are fed as IKM with a
//   protocol-specific info string so that cross-protocol attacks are prevented.
// =============================================================================

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::RngCore;
use ring::agreement::{self, EphemeralPrivateKey, UnparsedPublicKey, X25519};
use ring::rand::SystemRandom;
use sha2::Sha384;
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

// ── ML-KEM-768 (FIPS 203) ────────────────────────────────────────────────────
// Correct API for libcrux-ml-kem 0.0.2:
//   generate_key_pair(seed)         -> MlKem768KeyPair
//   key_pair.public_key()           -> &MlKem768PublicKey
//   key_pair.private_key()          -> &MlKem768PrivateKey  (opaque wrapper)
//   encapsulate(pk, randomness)     -> (MlKem768Ciphertext, MlKemSharedSecret)
//   decapsulate(private_key(), &ct) -> MlKemSharedSecret
use libcrux_ml_kem::mlkem768::{self, MlKem768Ciphertext, MlKem768KeyPair, MlKem768PublicKey};

// ── Constants ─────────────────────────────────────────────────────────────────

/// Length of the final WPA-Next session key (256-bit AES-GCM key)
pub const SESSION_KEY_LEN: usize = 32;

/// ML-KEM-768 public key size (bytes) — dictated by FIPS 203 parameter set
pub const MLKEM_PK_LEN: usize = 1184;

/// ML-KEM-768 ciphertext size (encapsulated key) in bytes
pub const MLKEM_CT_LEN: usize = 1088;

/// X25519 public key size (bytes)
pub const X25519_PK_LEN: usize = 32;

/// HMAC-SHA384 output length used for cookie challenges
pub const HMAC_LEN: usize = 48;

// ── Zeroizing Key Wrappers ───────────────────────────────────────────────────

/// A session key that is automatically zeroed when dropped.
/// This prevents secrets from lingering in heap / stack memory after use.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SessionKey(pub [u8; SESSION_KEY_LEN]);

impl SessionKey {
    /// Constant-time equality check — never branches on secret data.
    ///
    /// Use this instead of `==` whenever comparing session keys to prevent
    /// timing side-channel attacks.
    #[allow(dead_code)]
    pub fn ct_eq(&self, other: &SessionKey) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the raw key; show a safe placeholder in debug output.
        write!(f, "SessionKey([REDACTED])")
    }
}

/// Zeroizing wrapper for any heap-allocated secret bytes.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct SecretBytes(pub Vec<u8>);

// ── X25519 (Classical ECDH Layer) ────────────────────────────────────────────

/// Holds an ephemeral X25519 key pair for one handshake leg.
pub struct X25519KeyPair {
    /// The private key — consumed (moved) on use to enforce single-use semantics.
    private_key: Option<EphemeralPrivateKey>,
    /// 32-byte public key bytes, safe to transmit over the air.
    pub public_key_bytes: [u8; X25519_PK_LEN],
}

impl X25519KeyPair {
    /// Generate a fresh ephemeral X25519 key pair.
    pub fn generate() -> Result<Self, CryptoError> {
        let rng = SystemRandom::new();
        let private_key =
            EphemeralPrivateKey::generate(&X25519, &rng).map_err(|_| CryptoError::KeyGen)?;
        let public_key = private_key.compute_public_key().map_err(|_| CryptoError::KeyGen)?;
        let mut pk_bytes = [0u8; X25519_PK_LEN];
        pk_bytes.copy_from_slice(public_key.as_ref());
        Ok(X25519KeyPair {
            private_key: Some(private_key),
            public_key_bytes: pk_bytes,
        })
    }

    /// Consume the private key and perform ECDH with the peer's public key.
    /// Returns the 32-byte shared secret wrapped in a zeroizing container.
    pub fn diffie_hellman(
        mut self,
        peer_public_key_bytes: &[u8; X25519_PK_LEN],
    ) -> Result<SecretBytes, CryptoError> {
        let private_key = self.private_key.take().ok_or(CryptoError::AlreadyUsed)?;
        let peer_pk = UnparsedPublicKey::new(&X25519, peer_public_key_bytes.as_ref());
        let shared = agreement::agree_ephemeral(private_key, &peer_pk, |ss| {
            Ok::<SecretBytes, CryptoError>(SecretBytes(ss.to_vec()))
        })
        .map_err(|_| CryptoError::Ecdh)??;
        Ok(shared)
    }
}

// ── ML-KEM-768 (Post-Quantum Layer, FIPS 203) ────────────────────────────────

/// ML-KEM-768 key pair for the Access Point's initiating encapsulation.
pub struct MlKemKeyPair {
    inner: MlKem768KeyPair,
}

impl MlKemKeyPair {
    /// Generate an ML-KEM-768 key pair using OS entropy.
    pub fn generate() -> Result<Self, CryptoError> {
        // libcrux requires a 64-byte seed drawn from a CSPRNG.
        let mut seed = [0u8; 64];
        rand_core::OsRng.fill_bytes(&mut seed);
        let kp = mlkem768::generate_key_pair(seed);
        Ok(MlKemKeyPair { inner: kp })
    }

    /// Returns the 1184-byte public key (to be fragmented across the air).
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().as_ref().to_vec()
    }

    /// Decapsulate an incoming ciphertext, recovering the shared secret.
    /// The secret is wrapped in `SecretBytes` and zeroed on drop.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<SecretBytes, CryptoError> {
        if ciphertext.len() != MLKEM_CT_LEN {
            return Err(CryptoError::InvalidCiphertext);
        }
        let ct_arr: [u8; MLKEM_CT_LEN] = ciphertext.try_into().unwrap();
        let ct = MlKem768Ciphertext::from(ct_arr);
        let ss = mlkem768::decapsulate(self.inner.private_key(), &ct);
        Ok(SecretBytes(ss.as_ref().to_vec()))
    }
}

/// Encapsulate against a peer's ML-KEM-768 public key.
/// Returns (ciphertext to send, shared secret to keep).
pub fn mlkem_encapsulate(
    public_key_bytes: &[u8],
) -> Result<(Vec<u8>, SecretBytes), CryptoError> {
    if public_key_bytes.len() != MLKEM_PK_LEN {
        return Err(CryptoError::InvalidPublicKey);
    }
    let pk_arr: [u8; MLKEM_PK_LEN] = public_key_bytes.try_into().unwrap();
    let pk = MlKem768PublicKey::from(pk_arr);

    let mut rand_bytes = [0u8; 32];
    rand_core::OsRng.fill_bytes(&mut rand_bytes);

    let (ct, ss) = mlkem768::encapsulate(&pk, rand_bytes);
    Ok((ct.as_ref().to_vec(), SecretBytes(ss.as_ref().to_vec())))
}

// ── Hybrid Combiner: HKDF-SHA-384 ────────────────────────────────────────────
//
// Protocol: WPA-Next Hybrid Combiner v1
//
// IKM  = classical_ss || pq_ss
// Salt = "WPA-Next-v1-hybrid-salt"  (static, protocol-versioned)
// Info = "WPA-Next-v1-session-key"  (binds output to this protocol + purpose)
//
// This construction follows the concatenation-based hybrid KDF pattern
// recommended in NIST SP 800-227 (draft) and draft-ietf-tls-hybrid-design.
// Feeding both secrets as IKM means that if either is strong, the output
// is computationally indistinguishable from random.

const HYBRID_SALT: &[u8] = b"WPA-Next-v1-hybrid-salt";
const HYBRID_INFO: &[u8] = b"WPA-Next-v1-session-key";

/// Derive the final session key from the classical and PQ shared secrets.
pub fn derive_session_key(
    classical_ss: &SecretBytes,
    pq_ss: &SecretBytes,
) -> Result<SessionKey, CryptoError> {
    // Concatenate both shared secrets as IKM (order is protocol-defined,
    // must be the same on both ends).
    let mut ikm = Vec::with_capacity(classical_ss.0.len() + pq_ss.0.len());
    ikm.extend_from_slice(&classical_ss.0);
    ikm.extend_from_slice(&pq_ss.0);

    let hk = Hkdf::<Sha384>::new(Some(HYBRID_SALT), &ikm);
    let mut okm = [0u8; SESSION_KEY_LEN];
    hk.expand(HYBRID_INFO, &mut okm)
        .map_err(|_| CryptoError::Hkdf)?;

    // Zeroize the intermediate concatenated IKM immediately.
    let mut ikm_zeroize = ikm;
    ikm_zeroize.zeroize();

    Ok(SessionKey(okm))
}

// ── Cookie / DoS-Mitigation Challenge ────────────────────────────────────────
//
// Before allocating reassembly state for a fragmented PQ frame, the AP issues
// a cheap HMAC challenge. Only a responder that demonstrates knowledge of the
// cookie can trigger buffer allocation, preventing fragment-flooding DoS.

type HmacSha384 = Hmac<Sha384>;

/// Compute a DoS-mitigation cookie: HMAC-SHA384(ap_secret, peer_addr || seq_id)
pub fn compute_cookie(
    ap_secret: &[u8; 32],
    peer_addr: &[u8; 6],
    sequence_id: u32,
) -> [u8; HMAC_LEN] {
    let mut mac = <HmacSha384 as Mac>::new_from_slice(ap_secret)
        .expect("HMAC accepts any key length");
    mac.update(peer_addr);
    mac.update(&sequence_id.to_be_bytes());
    mac.update(b"WPA-Next-cookie-v1");
    let result = mac.finalize().into_bytes();
    let mut out = [0u8; HMAC_LEN];
    out.copy_from_slice(&result);
    out
}

/// Constant-time cookie verification.
pub fn verify_cookie(
    ap_secret: &[u8; 32],
    peer_addr: &[u8; 6],
    sequence_id: u32,
    candidate: &[u8; HMAC_LEN],
) -> bool {
    let expected = compute_cookie(ap_secret, peer_addr, sequence_id);
    // subtle::ConstantTimeEq: never short-circuits, thwarting timing attacks.
    expected.ct_eq(candidate).into()
}

// ── Error Types ───────────────────────────────────────────────────────────────

/// Errors that can occur during WPA-Next cryptographic operations.
#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    /// Key generation failed due to insufficient entropy or an RNG error.
    #[error("Key generation failed")]
    KeyGen,
    /// X25519 ECDH key agreement failed (invalid peer public key).
    #[error("X25519 ECDH agreement failed")]
    Ecdh,
    /// HKDF-SHA384 expansion failed (output length too large).
    #[error("HKDF expansion failed (output too long)")]
    Hkdf,
    /// The ephemeral private key was already consumed — each key pair is single-use.
    #[error("Private key already consumed (single-use ephemeral)")]
    AlreadyUsed,
    /// ML-KEM ciphertext was not exactly [`MLKEM_CT_LEN`] bytes.
    #[error("Invalid ML-KEM ciphertext length")]
    InvalidCiphertext,
    /// ML-KEM public key was not exactly [`MLKEM_PK_LEN`] bytes.
    #[error("Invalid ML-KEM public key length")]
    InvalidPublicKey,
}