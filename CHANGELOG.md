# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

---

## [0.2.0] — 2026-03-12

### ⚠️ Breaking Changes

This release introduces fundamental changes to the cryptographic pipeline. **Vaults created with v0.1.0 are not compatible with v0.2.0.** Files encrypted under v0.1.0 must be decrypted before upgrading.

### Changed

- **Encryption algorithm**: Migrated from **AES-128-CBC** to **AES-256-GCM** (Galois/Counter Mode).
  - Key size increased from 128 bits (16 bytes) to **256 bits (32 bytes)**.
  - Nonce/IV changed from 16 bytes (CBC) to **12 bytes** (GCM standard).
  - PKCS7 padding is no longer required — GCM operates on arbitrary-length plaintext.
  - Provides **authenticated encryption with associated data (AEAD)**, combining confidentiality and integrity in a single cryptographic operation.

- **Encrypted file format**: Updated binary layout to reflect GCM structure.
  - **Before (v0.1.0):** `[16B IV] [N bytes ciphertext + PKCS7 padding] [32B HMAC-SHA256]`
  - **After (v0.2.0):** `[12B nonce] [N bytes ciphertext] [16B GCM auth tag]`

- **Path obfuscation**: Enhanced from simple HMAC-derived hashes to a **triple-layer scheme**.
  - Obfuscation now uses: `HMAC-SHA256(aes_key, name + pepper + salt)`
  - **Pepper:** A 32-byte cryptographically random value, generated once per realm and stored encrypted at `pepper.enc`.
  - **Salt:** A 16-byte unique random value per vault and per file, stored in the encrypted database.
  - This makes obfuscated paths indistinguishable from random noise. An attacker cannot correlate paths without knowing all three components (key, pepper, and salt).

- **Key derivation output**: PBKDF2-HMAC-SHA256 now derives a single **32-byte key** (previously derived a 32-byte key split into 16B AES key + 16B HMAC key). The full key is used directly as the AES-256 encryption key since GCM's built-in authentication eliminates the need for a separate HMAC key.

- **Database encryption**: The encrypted JSON database now uses AES-256-GCM, with integrity verification built into the decryption process.

- **Database schema**: Added `vault_salt` and `file_salt` fields to support the new per-vault and per-file salt scheme for path obfuscation.

### Removed

- **Separate HMAC-SHA256 integrity verification**: The standalone HMAC computation and verification pass (encrypt-then-MAC) has been removed. AES-256-GCM provides equivalent integrity guarantees through its built-in 16-byte authentication tag, which is verified automatically during decryption. This simplifies the cryptographic pipeline while maintaining the same security guarantees.

- **PKCS7 padding**: No longer needed — AES-GCM is a stream-based mode that handles arbitrary-length plaintext without padding.

- **Dual key derivation**: The previous scheme derived two keys (AES key + HMAC key) from a single PBKDF2 pass. Since GCM does not require a separate HMAC key, the derivation now produces a single 32-byte AES-256 key.

---

## [0.1.0] — 2026-03-08

### Added

- **Initial MVP release** of ASV (Atomic Stealth Vault).
- AES-128-CBC encryption with random 16-byte IV and PKCS7 padding.
- HMAC-SHA256 integrity verification (encrypt-then-MAC) for all encrypted files.
- PBKDF2-HMAC-SHA256 key derivation with 480,000 iterations (16-byte salt → 32 bytes split into AES key + HMAC key).
- Encrypted JSON database for metadata storage (realm config, vaults, file records).
- Database snapshotting with atomic write protection to prevent corruption.
- Steganographic path obfuscation using HMAC-derived hashes for vault directories and file names.
- Three-tier file deletion system: `keep`, `simple`, and `secure` (random byte overwrite).
- Vault-based file organization within a single realm.
- Master password with strict policy enforcement via `password-strength` library.
- Session management via temporary file (`/tmp/asv_session_<uid>`).
- Rich terminal UI with colors, tables, and progress indicators.
- Full CLI interface via Click: `realm` (init, unlock, lock, status), `vault` (create, list, delete), `file` (encrypt, decrypt, list).
- Linux-specific file permissions: files `0600`, directories `0700`.
