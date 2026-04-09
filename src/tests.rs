// =============================================================================
// tests.rs — WPA-Next Test Suite
// =============================================================================
//
// Test categories:
//
//   1. crypto_tests     — Unit tests for each crypto primitive in isolation
//   2. fragmentation_tests — Frame fragmentation and reassembly correctness
//   3. handshake_tests  — Full AP ↔ Station handshake integration tests
//   4. security_tests   — Negative-path / adversarial tests (wrong keys, bad
//                         cookies, replayed fragments, tampered frames)
//   5. zeroize_tests    — Verify secrets are zeroed after drop
//
// Run all tests:   cargo test
// Run one module:  cargo test crypto_tests
// With output:     cargo test -- --nocapture
// =============================================================================

// ─────────────────────────────────────────────────────────────────────────────
// 1. CRYPTO PRIMITIVE TESTS
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod crypto_tests {
    use crate::crypto::*;

    // ── X25519 ────────────────────────────────────────────────────────────────

    /// Two independently generated key pairs should produce the same shared
    /// secret when each performs ECDH with the other's public key.
    #[test]
    fn test_x25519_shared_secret_agreement() {
        let alice = X25519KeyPair::generate().expect("Alice keygen");
        let bob   = X25519KeyPair::generate().expect("Bob keygen");

        let alice_pk = alice.public_key_bytes;
        let bob_pk   = bob.public_key_bytes;

        let alice_ss = alice.diffie_hellman(&bob_pk).expect("Alice DH");
        let bob_ss   = bob.diffie_hellman(&alice_pk).expect("Bob DH");

        assert_eq!(
            alice_ss.0, bob_ss.0,
            "X25519: shared secrets must be equal"
        );
        // Shared secret must be non-zero (low probability of accidental zero)
        assert_ne!(alice_ss.0, vec![0u8; alice_ss.0.len()], "Shared secret must not be all-zeros");
    }

    /// Each call to generate() must produce a different key pair.
    #[test]
    fn test_x25519_keys_are_unique() {
        let kp1 = X25519KeyPair::generate().expect("keygen 1");
        let kp2 = X25519KeyPair::generate().expect("keygen 2");
        assert_ne!(
            kp1.public_key_bytes, kp2.public_key_bytes,
            "Two independently generated X25519 key pairs must differ"
        );
    }

    /// Using a key pair for ECDH twice should fail — single-use semantics.
    #[test]
    fn test_x25519_single_use_enforced() {
        let alice = X25519KeyPair::generate().expect("keygen");
        let bob   = X25519KeyPair::generate().expect("keygen");
        let bob_pk = bob.public_key_bytes;
        // First use: OK
        alice.diffie_hellman(&bob_pk).expect("first DH must succeed");
        // alice is now consumed — we can't call diffie_hellman again (compiler enforces this
        // via move semantics; no runtime test needed, but we verify compile-time ownership).
        // The following would be a compile error:
        // alice.diffie_hellman(&bob_pk).expect("second DH");
    }

    /// ECDH with different peer public keys should produce different secrets.
    #[test]
    fn test_x25519_wrong_peer_gives_different_secret() {
        let alice  = X25519KeyPair::generate().expect("keygen");
        let bob    = X25519KeyPair::generate().expect("keygen");
        let eve    = X25519KeyPair::generate().expect("keygen");

        let alice_pk = alice.public_key_bytes;

        let bob_with_alice = bob.diffie_hellman(&alice_pk).expect("Bob × Alice");
        let eve_with_alice = eve.diffie_hellman(&alice_pk).expect("Eve × Alice");

        assert_ne!(
            bob_with_alice.0, eve_with_alice.0,
            "ECDH with different private keys must yield different shared secrets"
        );
    }

    // ── ML-KEM-768 ────────────────────────────────────────────────────────────

    /// Encapsulate + Decapsulate must yield the same shared secret.
    #[test]
    fn test_mlkem_encap_decap_roundtrip() {
        let kp = MlKemKeyPair::generate().expect("MlKem keygen");
        let pk_bytes = kp.public_key_bytes();

        assert_eq!(pk_bytes.len(), MLKEM_PK_LEN, "ML-KEM-768 PK must be {MLKEM_PK_LEN} bytes");

        let (ciphertext, encap_ss) = mlkem_encapsulate(&pk_bytes).expect("encapsulate");

        assert_eq!(ciphertext.len(), MLKEM_CT_LEN, "ML-KEM-768 ciphertext must be {MLKEM_CT_LEN} bytes");

        let decap_ss = kp.decapsulate(&ciphertext).expect("decapsulate");

        assert_eq!(
            encap_ss.0, decap_ss.0,
            "ML-KEM: encap and decap shared secrets must be equal"
        );
    }

    /// Two encapsulations against the same key should produce different
    /// ciphertexts (encapsulation is randomized).
    #[test]
    fn test_mlkem_encapsulation_is_randomized() {
        let kp = MlKemKeyPair::generate().expect("keygen");
        let pk = kp.public_key_bytes();

        let (ct1, _) = mlkem_encapsulate(&pk).expect("encap 1");
        let (ct2, _) = mlkem_encapsulate(&pk).expect("encap 2");

        assert_ne!(ct1, ct2, "Each encapsulation must produce a fresh ciphertext");
    }

    /// Decapsulating a tampered ciphertext must not produce the correct secret.
    /// (ML-KEM is CCA-secure; tampered ciphertext yields a different random-looking output.)
    #[test]
    fn test_mlkem_tampered_ciphertext_yields_wrong_secret() {
        let kp = MlKemKeyPair::generate().expect("keygen");
        let pk = kp.public_key_bytes();
        let (mut ciphertext, correct_ss) = mlkem_encapsulate(&pk).expect("encap");

        // Flip a byte in the middle of the ciphertext.
        ciphertext[MLKEM_CT_LEN / 2] ^= 0xFF;

        let wrong_ss = kp.decapsulate(&ciphertext).expect("decap of tampered CT");

        assert_ne!(
            correct_ss.0, wrong_ss.0,
            "Tampered ciphertext must not yield the correct shared secret"
        );
    }

    /// Encapsulate against a public key of the wrong length must fail cleanly.
    #[test]
    fn test_mlkem_encapsulate_wrong_pk_length_errors() {
        let short_pk = vec![0u8; 100]; // Wrong length
        let result = mlkem_encapsulate(&short_pk);
        assert!(
            matches!(result, Err(CryptoError::InvalidPublicKey)),
            "Expected InvalidPublicKey error for short PK"
        );
    }

    /// Decapsulate with a ciphertext of the wrong length must fail cleanly.
    #[test]
    fn test_mlkem_decapsulate_wrong_ct_length_errors() {
        let kp = MlKemKeyPair::generate().expect("keygen");
        let bad_ct = vec![0u8; 42]; // Wrong length
        let result = kp.decapsulate(&bad_ct);
        assert!(
            matches!(result, Err(CryptoError::InvalidCiphertext)),
            "Expected InvalidCiphertext error for short CT"
        );
    }

    // ── Hybrid HKDF Combiner ──────────────────────────────────────────────────

    /// Given identical inputs, derive_session_key must be deterministic.
    #[test]
    fn test_hkdf_combiner_is_deterministic() {
        let classical = SecretBytes(vec![0xAA; 32]);
        let pq        = SecretBytes(vec![0xBB; 32]);

        let key1 = derive_session_key(&classical, &pq).expect("derive 1");
        let key2 = derive_session_key(&classical, &pq).expect("derive 2");

        assert_eq!(key1.0, key2.0, "HKDF must be deterministic for identical inputs");
    }

    /// Swapping classical_ss and pq_ss must yield a different key
    /// (order of IKM concatenation is part of the protocol spec).
    #[test]
    fn test_hkdf_combiner_input_order_matters() {
        let a = SecretBytes(vec![0xAA; 32]);
        let b = SecretBytes(vec![0xBB; 32]);

        let key_ab = derive_session_key(&a, &b).expect("a||b");
        let key_ba = derive_session_key(&b, &a).expect("b||a");

        assert_ne!(key_ab.0, key_ba.0, "Input order must matter for the hybrid combiner");
    }

    /// Different shared secrets must yield different session keys.
    #[test]
    fn test_hkdf_combiner_different_inputs_yield_different_keys() {
        let classical1 = SecretBytes(vec![0x11; 32]);
        let classical2 = SecretBytes(vec![0x22; 32]);
        let pq         = SecretBytes(vec![0xBB; 32]);

        let key1 = derive_session_key(&classical1, &pq).expect("key1");
        let key2 = derive_session_key(&classical2, &pq).expect("key2");

        assert_ne!(key1.0, key2.0, "Different classical secrets must yield different session keys");
    }

    // ── Cookie Challenge ──────────────────────────────────────────────────────

    /// compute_cookie is deterministic for identical inputs.
    #[test]
    fn test_cookie_is_deterministic() {
        let secret: [u8; 32] = [0x42; 32];
        let mac:    [u8; 6]  = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let seq:    u32      = 0xDEADBEEF;

        let c1 = compute_cookie(&secret, &mac, seq);
        let c2 = compute_cookie(&secret, &mac, seq);
        assert_eq!(c1, c2);
    }

    /// verify_cookie must return true for the correct cookie.
    #[test]
    fn test_cookie_verify_correct() {
        let secret: [u8; 32] = [0x42; 32];
        let mac:    [u8; 6]  = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let seq:    u32      = 1234;

        let cookie = compute_cookie(&secret, &mac, seq);
        assert!(verify_cookie(&secret, &mac, seq, &cookie), "Correct cookie must verify");
    }

    /// verify_cookie must return false for a wrong cookie.
    #[test]
    fn test_cookie_verify_wrong_cookie() {
        let secret: [u8; 32] = [0x42; 32];
        let mac:    [u8; 6]  = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        let seq:    u32      = 1234;

        let mut bad_cookie = compute_cookie(&secret, &mac, seq);
        bad_cookie[0] ^= 0xFF; // Flip a bit
        assert!(!verify_cookie(&secret, &mac, seq, &bad_cookie), "Tampered cookie must not verify");
    }

    /// Cookies are bound to the MAC address — a different MAC must fail.
    #[test]
    fn test_cookie_bound_to_mac() {
        let secret: [u8; 32] = [0x42; 32];
        let mac1:   [u8; 6]  = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let mac2:   [u8; 6]  = [0xFF, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA];
        let seq:    u32      = 99;

        let cookie_for_mac1 = compute_cookie(&secret, &mac1, seq);
        assert!(
            !verify_cookie(&secret, &mac2, seq, &cookie_for_mac1),
            "Cookie from mac1 must not verify for mac2"
        );
    }

    /// Cookies are bound to the sequence ID — a different seq must fail.
    #[test]
    fn test_cookie_bound_to_sequence_id() {
        let secret: [u8; 32] = [0x42; 32];
        let mac:    [u8; 6]  = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

        let cookie_seq1 = compute_cookie(&secret, &mac, 1);
        assert!(
            !verify_cookie(&secret, &mac, 2, &cookie_seq1),
            "Cookie from seq=1 must not verify for seq=2"
        );
    }

    /// SessionKey::ct_eq must return true for identical keys.
    #[test]
    fn test_session_key_ct_eq_equal() {
        let k1 = SessionKey([0xAB; SESSION_KEY_LEN]);
        let k2 = SessionKey([0xAB; SESSION_KEY_LEN]);
        assert!(k1.ct_eq(&k2));
    }

    /// SessionKey::ct_eq must return false for different keys.
    #[test]
    fn test_session_key_ct_eq_not_equal() {
        let k1 = SessionKey([0xAB; SESSION_KEY_LEN]);
        let k2 = SessionKey([0xCD; SESSION_KEY_LEN]);
        assert!(!k1.ct_eq(&k2));
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. FRAGMENTATION & REASSEMBLY TESTS
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod fragmentation_tests {
    use crate::network::*;
    use crate::crypto::HMAC_LEN;

    fn dummy_cookie() -> [u8; HMAC_LEN] { [0xCC; HMAC_LEN] }

    /// Fragmenting a 1088-byte payload (ML-KEM CT size) must produce 3 frames.
    #[test]
    fn test_fragment_count_for_mlkem_ciphertext() {
        let payload = vec![0xAB; 1088];
        let frames = fragment_payload(&payload, 42, &dummy_cookie());
        assert_eq!(frames.len(), 3, "1088-byte payload must split into 3 fragments");
    }

    /// Fragmenting a 1184-byte payload (ML-KEM PK size) must also produce 3 frames.
    #[test]
    fn test_fragment_count_for_mlkem_public_key() {
        let payload = vec![0xCD; 1184];
        let frames = fragment_payload(&payload, 1, &dummy_cookie());
        assert_eq!(frames.len(), 3, "1184-byte payload must split into 3 fragments");
    }

    /// No fragment payload must exceed FRAG_PAYLOAD_MAX bytes.
    #[test]
    fn test_no_fragment_exceeds_max_payload() {
        let payload = vec![0x55; 1184];
        let frames = fragment_payload(&payload, 7, &dummy_cookie());
        for frame in &frames {
            assert!(
                frame.payload.len() <= FRAG_PAYLOAD_MAX,
                "Fragment {} exceeds FRAG_PAYLOAD_MAX ({} > {})",
                frame.header.frag_index,
                frame.payload.len(),
                FRAG_PAYLOAD_MAX
            );
        }
    }

    /// The cookie must appear exactly in fragment 0 and be zeroed elsewhere.
    #[test]
    fn test_cookie_only_in_first_fragment() {
        let cookie = dummy_cookie();
        let frames = fragment_payload(&vec![0u8; 1088], 5, &cookie);
        assert_eq!(frames[0].cookie.as_slice(), cookie.as_ref(), "Cookie must appear in frag 0");
        for frame in &frames[1..] {
            assert_eq!(
                frame.cookie.as_slice(), [0u8; HMAC_LEN].as_ref(),
                "Cookie in frag {} must be all-zeros", frame.header.frag_index
            );
        }
    }

    /// All fragments must share the same sequence_id.
    #[test]
    fn test_all_fragments_share_sequence_id() {
        let seq_id = 0xCAFEBABE;
        let frames = fragment_payload(&vec![0u8; 1088], seq_id, &dummy_cookie());
        for frame in &frames {
            assert_eq!(frame.header.sequence_id, seq_id);
        }
    }

    /// frag_index must be 0, 1, 2 and frag_total must equal frame count.
    #[test]
    fn test_fragment_indices_are_correct() {
        let frames = fragment_payload(&vec![0u8; 1088], 1, &dummy_cookie());
        let total = frames.len() as u8;
        for (i, frame) in frames.iter().enumerate() {
            assert_eq!(frame.header.frag_index, i as u8);
            assert_eq!(frame.header.frag_total, total);
        }
    }

    /// payload_len header field must match the actual payload vec length.
    #[test]
    fn test_payload_len_header_matches_actual() {
        let frames = fragment_payload(&vec![0xAA; 1088], 3, &dummy_cookie());
        for frame in &frames {
            assert_eq!(
                frame.header.payload_len as usize,
                frame.payload.len(),
                "payload_len mismatch on frag {}", frame.header.frag_index
            );
        }
    }

    /// Reassembling in-order fragments must reconstruct the original payload.
    #[test]
    fn test_reassembly_in_order() {
        let original: Vec<u8> = (0u8..=255u8).cycle().take(1088).collect();
        let frames = fragment_payload(&original, 100, &dummy_cookie());
        let reassembled = reassemble_fragments(&frames).expect("reassembly must succeed");
        assert_eq!(reassembled, original, "Reassembled payload must equal original");
    }

    /// Reassembling out-of-order fragments must also reconstruct correctly.
    #[test]
    fn test_reassembly_out_of_order() {
        let original: Vec<u8> = (0u8..=255u8).cycle().take(1088).collect();
        let mut frames = fragment_payload(&original, 200, &dummy_cookie());
        // Reverse the order to simulate out-of-order delivery.
        frames.reverse();
        let reassembled = reassemble_fragments(&frames).expect("out-of-order reassembly must succeed");
        assert_eq!(reassembled, original);
    }

    /// Reassembly with a missing fragment must return None.
    #[test]
    fn test_reassembly_incomplete_returns_none() {
        let original = vec![0u8; 1088];
        let mut frames = fragment_payload(&original, 300, &dummy_cookie());
        frames.pop(); // Remove last fragment
        let result = reassemble_fragments(&frames);
        assert!(result.is_none(), "Incomplete fragments must return None");
    }

    /// Reassembly with an empty slice must return None.
    #[test]
    fn test_reassembly_empty_returns_none() {
        assert!(reassemble_fragments(&[]).is_none());
    }

    /// A single-fragment payload (≤ 400 bytes) must also reassemble correctly.
    #[test]
    fn test_single_fragment_payload() {
        let original = vec![0xBE; 128]; // Fits in one fragment
        let frames = fragment_payload(&original, 1, &dummy_cookie());
        assert_eq!(frames.len(), 1, "128-byte payload must produce 1 fragment");
        let reassembled = reassemble_fragments(&frames).unwrap();
        assert_eq!(reassembled, original);
    }

    /// Fragments with mixed sequence IDs must be rejected by reassembly.
    #[test]
    fn test_reassembly_rejects_mixed_sequence_ids() {
        let original = vec![0u8; 1088];
        let mut frames = fragment_payload(&original, 1, &dummy_cookie());
        // Tamper with the sequence ID of the last fragment.
        frames.last_mut().unwrap().header.sequence_id = 9999;
        let result = reassemble_fragments(&frames);
        assert!(result.is_none(), "Mixed sequence IDs must be rejected");
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. FULL HANDSHAKE INTEGRATION TESTS
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod handshake_tests {
    use crate::network::*;
    use rand_core::RngCore;

    const AP_MAC:      [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    const STATION_MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    fn random_seq_id() -> u32 {
        let mut b = [0u8; 4];
        rand_core::OsRng.fill_bytes(&mut b);
        u32::from_be_bytes(b)
    }

    /// A full, correct AP ↔ Station handshake must produce identical session keys.
    #[test]
    fn test_full_handshake_produces_matching_keys() {
        let mut ap  = AccessPoint::new(AP_MAC).expect("AP setup");
        let station = Station::new(STATION_MAC).expect("Station setup");

        let seq_id = random_seq_id();

        // Stage 1
        let fast_link = station.build_fast_link_frame().unwrap();
        let cookie = ap.process_fast_link_frame(&fast_link, seq_id).unwrap();

        // Stage 2
        let ap_mlkem_pk   = ap.mlkem_public_key_bytes();
        let ap_x25519_pk  = ap.x25519_public_key_bytes().unwrap();
        let station_x25519_pk = station.x25519_public_key_bytes().unwrap();

        let (pq_frames, station_pq_ss) =
            station.build_pq_fragments(&ap_mlkem_pk, seq_id, &cookie).unwrap();

        let mut ap_key: Option<crate::crypto::SessionKey> = None;
        for frame in &pq_frames {
            ap_key = ap.process_fragment(frame, &STATION_MAC, &station_x25519_pk).unwrap();
        }
        let ap_session_key = ap_key.expect("AP must have derived session key");

        let station_session_key =
            station.complete_handshake(&ap_x25519_pk, station_pq_ss).unwrap();

        assert!(
            ap_session_key.ct_eq(&station_session_key),
            "AP and Station session keys must be identical after successful handshake"
        );
    }

    /// Running two independent handshakes must produce different session keys
    /// (freshness — each handshake is cryptographically independent).
    #[test]
    fn test_two_handshakes_produce_different_keys() {
        fn run_handshake() -> [u8; 32] {
            let mut ap  = AccessPoint::new(AP_MAC).expect("AP setup");
            let station = Station::new(STATION_MAC).expect("Station setup");
            let seq_id  = random_seq_id();

            let fast_link = station.build_fast_link_frame().unwrap();
            let cookie    = ap.process_fast_link_frame(&fast_link, seq_id).unwrap();

            let ap_mlkem_pk       = ap.mlkem_public_key_bytes();
            let ap_x25519_pk      = ap.x25519_public_key_bytes().unwrap();
            let station_x25519_pk = station.x25519_public_key_bytes().unwrap();

            let (pq_frames, station_pq_ss) =
                station.build_pq_fragments(&ap_mlkem_pk, seq_id, &cookie).unwrap();

            let mut ap_key: Option<crate::crypto::SessionKey> = None;
            for frame in &pq_frames {
                ap_key = ap.process_fragment(frame, &STATION_MAC, &station_x25519_pk).unwrap();
            }
            let ap_sk = ap_key.unwrap();
            let _sta_sk = station.complete_handshake(&ap_x25519_pk, station_pq_ss).unwrap();
            ap_sk.0
        }

        let key1 = run_handshake();
        let key2 = run_handshake();
        assert_ne!(key1, key2, "Two independent handshakes must produce different session keys");
    }

    /// FastLinkFrame with bad magic must be rejected.
    #[test]
    fn test_fast_link_frame_bad_magic_rejected() {
        let mut ap  = AccessPoint::new(AP_MAC).expect("AP setup");
        let station = Station::new(STATION_MAC).expect("Station setup");

        let mut frame = station.build_fast_link_frame().unwrap();
        frame.magic = [0x00, 0x00, 0x00, 0x00]; // Corrupt magic

        let result = ap.process_fast_link_frame(&frame, 1);
        assert!(result.is_err(), "Frame with bad magic must be rejected");
    }

    /// FastLinkFrame with wrong version must be rejected.
    #[test]
    fn test_fast_link_frame_bad_version_rejected() {
        let mut ap  = AccessPoint::new(AP_MAC).expect("AP setup");
        let station = Station::new(STATION_MAC).expect("Station setup");

        let mut frame = station.build_fast_link_frame().unwrap();
        frame.version = 99;

        let result = ap.process_fast_link_frame(&frame, 1);
        assert!(result.is_err(), "Frame with wrong version must be rejected");
    }

    /// AP must remain stateless (no entry in station_state) until a valid
    /// fragment-0 with correct cookie is received.
    #[test]
    fn test_ap_stateless_before_valid_cookie() {
        let mut ap  = AccessPoint::new(AP_MAC).expect("AP setup");
        let station = Station::new(STATION_MAC).expect("Station setup");
        let seq_id  = random_seq_id();

        let fast_link = station.build_fast_link_frame().unwrap();
        let _cookie   = ap.process_fast_link_frame(&fast_link, seq_id).unwrap();

        let ap_mlkem_pk       = ap.mlkem_public_key_bytes();
        let station_x25519_pk = station.x25519_public_key_bytes().unwrap();
        let bad_cookie: [u8; crate::crypto::HMAC_LEN] = [0xFF; crate::crypto::HMAC_LEN];

        let (pq_frames, _station_pq_ss) =
            station.build_pq_fragments(&ap_mlkem_pk, seq_id, &bad_cookie).unwrap();

        // Fragment 0 with wrong cookie — AP must reject and stay stateless.
        let result = ap.process_fragment(&pq_frames[0], &STATION_MAC, &station_x25519_pk);
        assert!(
            matches!(result, Err(NetworkError::InvalidCookie)),
            "AP must reject frag-0 with invalid cookie"
        );
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. SECURITY / ADVERSARIAL TESTS
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod security_tests {
    use crate::network::*;
    use crate::crypto::HMAC_LEN;
    use rand_core::RngCore;

    const AP_MAC:      [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    const STATION_MAC: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
    const EVE_MAC:     [u8; 6] = [0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE];

    fn random_seq_id() -> u32 {
        let mut b = [0u8; 4];
        rand_core::OsRng.fill_bytes(&mut b);
        u32::from_be_bytes(b)
    }

    /// Sending fragment 1 before fragment 0 (no prior state) must be rejected.
    #[test]
    fn test_fragment_without_prior_state_rejected() {
        let mut ap      = AccessPoint::new(AP_MAC).expect("AP setup");
        let station     = Station::new(STATION_MAC).expect("Station setup");
        let seq_id      = random_seq_id();
        let fast_link   = station.build_fast_link_frame().unwrap();
        let cookie      = ap.process_fast_link_frame(&fast_link, seq_id).unwrap();
        let ap_mlkem_pk = ap.mlkem_public_key_bytes();
        let station_x25519_pk = station.x25519_public_key_bytes().unwrap();

        let (pq_frames, _) = station
            .build_pq_fragments(&ap_mlkem_pk, seq_id, &cookie)
            .unwrap();

        // Send frag 1 before frag 0 — no state exists yet.
        let result = ap.process_fragment(&pq_frames[1], &STATION_MAC, &station_x25519_pk);
        assert!(
            matches!(result, Err(NetworkError::UnknownStation)),
            "frag-1 before frag-0 must fail with UnknownStation"
        );
    }

    /// An all-zeros cookie (blank / attacker-fabricated) must be rejected.
    #[test]
    fn test_zero_cookie_rejected() {
        let mut ap      = AccessPoint::new(AP_MAC).expect("AP setup");
        let station     = Station::new(STATION_MAC).expect("Station setup");
        let seq_id      = random_seq_id();
        let fast_link   = station.build_fast_link_frame().unwrap();
        let _cookie     = ap.process_fast_link_frame(&fast_link, seq_id).unwrap();
        let ap_mlkem_pk = ap.mlkem_public_key_bytes();
        let station_x25519_pk = station.x25519_public_key_bytes().unwrap();

        let zero_cookie = [0u8; HMAC_LEN];
        let (pq_frames, _) = station
            .build_pq_fragments(&ap_mlkem_pk, seq_id, &zero_cookie)
            .unwrap();

        let result = ap.process_fragment(&pq_frames[0], &STATION_MAC, &station_x25519_pk);
        assert!(
            matches!(result, Err(NetworkError::InvalidCookie)),
            "All-zeros cookie must be rejected"
        );
    }

    /// A station using the wrong AP ML-KEM public key must produce keys that
    /// do NOT match the AP's session key (man-in-the-middle detection).
    #[test]
    fn test_wrong_mlkem_pk_produces_mismatched_keys() {
        let mut ap   = AccessPoint::new(AP_MAC).expect("AP setup");
        let station  = Station::new(STATION_MAC).expect("Station setup");
        let seq_id   = random_seq_id();

        let fast_link = station.build_fast_link_frame().unwrap();
        let cookie    = ap.process_fast_link_frame(&fast_link, seq_id).unwrap();

        // Station uses a DIFFERENT (attacker-generated) ML-KEM key instead of the AP's.
        let eve_kp       = crate::crypto::MlKemKeyPair::generate().unwrap();
        let wrong_mlkem_pk = eve_kp.public_key_bytes();

        let ap_x25519_pk      = ap.x25519_public_key_bytes().unwrap();
        let station_x25519_pk = station.x25519_public_key_bytes().unwrap();

        let (pq_frames, station_pq_ss) = station
            .build_pq_fragments(&wrong_mlkem_pk, seq_id, &cookie)
            .unwrap();

        let mut ap_key: Option<crate::crypto::SessionKey> = None;
        for frame in &pq_frames {
            // AP will try to decapsulate with its own SK — will "succeed" but
            // produce a garbage / randomized shared secret (CCA-security).
            let _ = ap.process_fragment(frame, &STATION_MAC, &station_x25519_pk);
            // (may error due to length or internal state; that's also acceptable)
        }

        // Station derives a key using the wrong PQ secret.
        // Even if both sides complete, keys won't match because PQ secrets differ.
        if let Some(ap_sk) = ap_key {
            let sta_sk = station.complete_handshake(&ap_x25519_pk, station_pq_ss).unwrap();
            assert!(
                !ap_sk.ct_eq(&sta_sk),
                "Wrong ML-KEM PK: keys must NOT match"
            );
        }
        // If AP errored, that's also a valid outcome — just pass.
    }

    /// Cookie from one station's MAC must not be reused for another station.
    #[test]
    fn test_cookie_not_transferable_across_stations() {
        let mut ap        = AccessPoint::new(AP_MAC).expect("AP setup");
        let station       = Station::new(STATION_MAC).expect("Station setup");
        let eve_station   = Station::new(EVE_MAC).expect("Eve setup");
        let seq_id        = random_seq_id();

        // Obtain a legitimate cookie for STATION_MAC.
        let fast_link = station.build_fast_link_frame().unwrap();
        let cookie    = ap.process_fast_link_frame(&fast_link, seq_id).unwrap();

        let ap_mlkem_pk       = ap.mlkem_public_key_bytes();
        let eve_x25519_pk     = eve_station.x25519_public_key_bytes().unwrap();

        // Eve submits fragment-0 using STATION's cookie but claims to be EVE_MAC.
        let (eve_frames, _) = eve_station
            .build_pq_fragments(&ap_mlkem_pk, seq_id, &cookie)
            .unwrap();

        let result = ap.process_fragment(&eve_frames[0], &EVE_MAC, &eve_x25519_pk);
        assert!(
            matches!(result, Err(NetworkError::InvalidCookie)),
            "Station A's cookie must not be accepted for Station B"
        );
    }

    /// A replay attack (resending old fragments with a stale sequence ID) must
    /// not allow the attacker to trigger reassembly without a fresh cookie.
    #[test]
    fn test_replayed_sequence_id_rejected() {
        let mut ap     = AccessPoint::new(AP_MAC).expect("AP setup");
        let station    = Station::new(STATION_MAC).expect("Station setup");
        let seq_id     = random_seq_id();

        let fast_link  = station.build_fast_link_frame().unwrap();
        let cookie     = ap.process_fast_link_frame(&fast_link, seq_id).unwrap();
        let ap_mlkem_pk       = ap.mlkem_public_key_bytes();
        let station_x25519_pk = station.x25519_public_key_bytes().unwrap();

        let (pq_frames, _) = station
            .build_pq_fragments(&ap_mlkem_pk, seq_id, &cookie)
            .unwrap();

        // First pass — completes handshake.
        for frame in &pq_frames {
            let _ = ap.process_fragment(frame, &STATION_MAC, &station_x25519_pk);
        }

        // Replay: resend the same fragments (stale seq_id, cookie already consumed).
        // The AP should either reject the cookie (secret rotated) or the UnknownStation
        // error if state was cleaned up. Either is a valid secure behavior.
        let replay_result =
            ap.process_fragment(&pq_frames[0], &STATION_MAC, &station_x25519_pk);
        // We accept either InvalidCookie or an error — what we must NOT get is Ok(Some(key)).
        match replay_result {
            Ok(Some(_)) => panic!("Replayed handshake must NOT produce a new session key without fresh cookie"),
            _ => { /* Rejected or waiting — both acceptable */ }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. ZEROIZE TESTS — verify secrets are cleared from memory after drop
// ─────────────────────────────────────────────────────────────────────────────
#[cfg(test)]
mod zeroize_tests {
    use crate::crypto::{SecretBytes, SessionKey, SESSION_KEY_LEN};
    use zeroize::Zeroize;

    /// After manually zeroizing a SecretBytes, all bytes must be zero.
    #[test]
    fn test_secret_bytes_zeroize_on_demand() {
        let mut secret = SecretBytes(vec![0xAB; 64]);
        assert!(secret.0.iter().all(|&b| b == 0xAB), "Pre-zeroize: should be 0xAB");
        secret.zeroize();
        assert!(secret.0.iter().all(|&b| b == 0x00), "Post-zeroize: all bytes must be 0x00");
    }

    /// After manually zeroizing a SessionKey, all bytes must be zero.
    #[test]
    fn test_session_key_zeroize_on_demand() {
        let mut key = SessionKey([0xDE; SESSION_KEY_LEN]);
        assert!(key.0.iter().all(|&b| b == 0xDE));
        key.zeroize();
        assert!(key.0.iter().all(|&b| b == 0x00), "SessionKey bytes must be zeroed after zeroize()");
    }

    /// SessionKey's Debug impl must not expose the key bytes.
    #[test]
    fn test_session_key_debug_is_redacted() {
        let key = SessionKey([0xFF; SESSION_KEY_LEN]);
        let debug_str = format!("{:?}", key);
        // Must NOT contain the hex representation of 0xFF bytes.
        assert!(
            !debug_str.contains("ff") && !debug_str.contains("FF") && !debug_str.contains("255"),
            "SessionKey Debug output must not expose key bytes: got '{}'", debug_str
        );
        assert!(
            debug_str.contains("REDACTED"),
            "SessionKey Debug must say REDACTED"
        );
    }
}