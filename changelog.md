# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2025-01-01

### Added
- Initial release
- ML-KEM-768 (FIPS 203) post-quantum key encapsulation via `libcrux-ml-kem`
- X25519 classical ECDH via `ring`
- Hybrid HKDF-SHA-384 combiner merging both shared secrets
- Layer 2 fragmentation for transmitting 1088-byte ML-KEM ciphertexts across 802.11 management frames (3 × ≤400-byte fragments)
- HMAC-SHA-384 cookie challenge for DoS-resistant stateless AP fragment handling
- `AccessPoint` and `Station` state machine structs
- `SessionKey` and `SecretBytes` zeroizing wrappers
- Constant-time comparisons throughout via `subtle`
- 45-test suite covering crypto primitives, fragmentation, full handshake, security/adversarial paths, and memory zeroing