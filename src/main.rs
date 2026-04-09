// =============================================================================
// main.rs — WPA-Next Handshake Demo (binary entry point)
// =============================================================================
// This is the thin demo binary. All protocol logic lives in the library:
//   src/lib.rs      — crate root, public API
//   src/crypto.rs   — X25519, ML-KEM-768, HKDF, cookie
//   src/network.rs  — frames, fragmentation, AP/Station state machines
// =============================================================================

// Pull in the library modules directly — main.rs is part of the same crate,
// so we use `mod` declarations, not `extern crate wpa_next`.
mod crypto;
mod network;

use network::{AccessPoint, Station, MLKEM_PK_FRAG_COUNT, FRAG_PAYLOAD_MAX};
use crypto::SESSION_KEY_LEN;
use rand_core::RngCore;
use subtle::ConstantTimeEq;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("╔═══════════════════════════════════════════════════════════════╗");
    println!("║          WPA-Next Hybrid Post-Quantum Handshake Demo          ║");
    println!("║   ML-KEM-768 (FIPS 203) + X25519 + HKDF-SHA384 Combiner      ║");
    println!("╚═══════════════════════════════════════════════════════════════╝\n");

    // ── Simulated MAC addresses ───────────────────────────────────────────────
    let ap_mac:      [u8; 6] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
    let station_mac: [u8; 6] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];

    // Random sequence ID — fresh per association attempt
    let mut seq_id_bytes = [0u8; 4];
    rand_core::OsRng.fill_bytes(&mut seq_id_bytes);
    let sequence_id = u32::from_be_bytes(seq_id_bytes);
    println!("[Init] Sequence ID for this association: {:#010X}\n", sequence_id);

    // ── Setup ─────────────────────────────────────────────────────────────────
    println!("── Access Point Setup ───────────────────────────────────────────");
    let mut ap      = AccessPoint::new(ap_mac)?;
    let ap_mlkem_pk  = ap.mlkem_public_key_bytes();
    let ap_x25519_pk = ap.x25519_public_key_bytes().expect("AP X25519 key present");
    println!("[AP] ML-KEM-768 public key generated ({} bytes)", ap_mlkem_pk.len());
    println!("[AP] X25519 public key generated ({} bytes)\n", ap_x25519_pk.len());

    println!("── Station Setup ────────────────────────────────────────────────");
    let station = Station::new(station_mac)?;
    println!("[Station] Ephemeral X25519 key pair generated\n");

    // =========================================================================
    // STAGE 1 — DISCOVERY
    // Station sends its X25519 public key in a single FastLinkFrame.
    // AP returns a stateless HMAC cookie challenge.
    // =========================================================================
    println!("════════════════════════════════════════════════════════════════");
    println!(" STAGE 1 — DISCOVERY (FastLinkFrame)");
    println!("════════════════════════════════════════════════════════════════");

    let fast_link_frame = station.build_fast_link_frame()?;
    println!(
        "[Station] FastLinkFrame built — X25519 PK: {}...",
        hex::encode(&fast_link_frame.x25519_public_key[..8])
    );

    let cookie = ap.process_fast_link_frame(&fast_link_frame, sequence_id)?;
    println!("[AP] Cookie issued: {}...\n", hex::encode(&cookie[..8]));

    println!("────────────────────────────────────────────────────────────────");
    println!(
        "[AP] Broadcasting ML-KEM-768 public key ({} bytes — needs fragmentation)",
        ap_mlkem_pk.len()
    );

    // =========================================================================
    // STAGE 2 — QUANTIZATION
    // Station encapsulates against the AP's ML-KEM-768 public key.
    // The 1088-byte ciphertext is split into 3 fragments of ≤400 bytes each.
    // The AP verifies the cookie before allocating any reassembly state.
    // =========================================================================
    println!("\n════════════════════════════════════════════════════════════════");
    println!(" STAGE 2 — QUANTIZATION (FragmentedPQFrame × {})", MLKEM_PK_FRAG_COUNT);
    println!("════════════════════════════════════════════════════════════════\n");

    let station_x25519_pk = station.x25519_public_key_bytes()?;
    let (pq_frames, station_pq_ss) =
        station.build_pq_fragments(&ap_mlkem_pk, sequence_id, &cookie)?;

    println!();
    for frame in &pq_frames {
        println!(
            "[Station] → Fragment [{}/{}]  seq={:#010X}  payload={} bytes  cookie_present={}",
            frame.header.frag_index + 1,
            frame.header.frag_total,
            frame.header.sequence_id,
            frame.header.payload_len,
            frame.header.frag_index == 0,
        );
    }
    println!();

    // Feed fragments to the AP one at a time (simulating over-the-air delivery)
    let mut ap_session_key = None;
    for frame in &pq_frames {
        ap_session_key = ap.process_fragment(frame, &station_mac, &station_x25519_pk)?;
    }
    let ap_key = ap_session_key
        .expect("[AP] Should have derived session key after the final fragment");

    // Station completes its side: X25519 ECDH + hybrid key derivation
    println!();
    let station_key = station.complete_handshake(&ap_x25519_pk, station_pq_ss)?;

    // =========================================================================
    // VERIFICATION — both sides must hold identical 256-bit session keys
    // =========================================================================
    println!("\n════════════════════════════════════════════════════════════════");
    println!(" VERIFICATION");
    println!("════════════════════════════════════════════════════════════════\n");

    // Constant-time comparison — never branch on secret data
    let keys_match: bool = ap_key.0.ct_eq(&station_key.0).into();
    if keys_match {
        println!("✅ Session keys MATCH — handshake successful!\n");
        println!("   Session key (hex): {}", hex::encode(&ap_key.0));
    } else {
        eprintln!("❌ Session keys DO NOT MATCH — protocol error!");
        std::process::exit(1);
    }

    println!("\n════════════════════════════════════════════════════════════════");
    println!(" PROTOCOL SUMMARY");
    println!("════════════════════════════════════════════════════════════════");
    println!(" Classical layer  : X25519 ECDH (ring crate)");
    println!(" PQ layer         : ML-KEM-768 FIPS 203 (libcrux-ml-kem)");
    println!(" Hybrid combiner  : HKDF-SHA384 (IKM = classical_ss ∥ pq_ss)");
    println!(" DoS mitigation   : HMAC-SHA384 cookie (verified before state alloc)");
    println!(
        " Fragmentation    : {} × ≤{} byte L2 frames per ML-KEM message",
        MLKEM_PK_FRAG_COUNT, FRAG_PAYLOAD_MAX
    );
    println!(" Memory safety    : All secrets wrapped in zeroize::ZeroizeOnDrop");
    println!(" Timing safety    : Cookie & key comparison via subtle::ConstantTimeEq");
    println!("────────────────────────────────────────────────────────────────");
    println!(" Security level   : ~128-bit classical, ~180-bit post-quantum");
    println!(" Session key size : {} bits", SESSION_KEY_LEN * 8);
    println!("════════════════════════════════════════════════════════════════\n");

    Ok(())
}