# ASV — Specification Document

> **Version:** 0.2.0
> **Status:** Draft
> **Last Updated:** 2026-03-12
> **Python:** ≥ 3.12
> **Platform:** Linux

---

## 1. Overview

ASV is a command-line file encryption and decryption system for Linux. It prioritizes **security**, **integrity**, and **availability** of user data through industry-standard cryptographic algorithms, encrypted-at-rest metadata storage, and defense-in-depth techniques including steganographic path obfuscation.

### 1.1 Design Philosophy

- **Spec-Driven Development:** This document is the single source of truth. All implementation must conform to it, and all future changes must update it first.
- **Security by Default:** Every default choice must favor security over convenience.
- **Readability & Maintainability:** Clean layered architecture with separation of concerns.
- **Scalability:** The architecture must support future extensions without breaking existing functionality.

### 1.2 Glossary

| Term | Definition |
|------|-----------|
| **Realm** | The root-level container. A user initializes one realm per ASV installation. The realm holds the master password, configuration, and all vaults. |
| **Vault** | A named logical container within a realm. Users organize encrypted files into vaults. |
| **Encrypted File** | A file encrypted by ASV and stored inside a vault's obfuscated storage directory. |
| **Master Password** | The password used to derive the encryption key for the entire realm. |
| **Database** | The encrypted JSON metadata store that tracks realm state, vaults, and file records. |
| **Snapshot** | A backup copy of the database taken before any write operation to prevent corruption. |

---

## 2. Security Architecture

### 2.1 Encryption

| Property | Value |
|----------|-------|
| **Algorithm** | AES-256-GCM (Galois/Counter Mode) |
| **Key Size** | 256 bits (32 bytes) |
| **Nonce/IV** | Random 12 bytes per encryption operation |
| **Integrity** | Built-in GCM authentication tag (16 bytes) |

**Encrypted file format (binary):**

```
[12 bytes nonce] [N bytes ciphertext] [16 bytes GCM auth tag]
```

AES-256-GCM provides authenticated encryption with associated data (AEAD),
meaning both confidentiality and integrity are guaranteed in a single operation.
No separate HMAC or padding is required.

### 2.2 Key Derivation

| Property | Value |
|----------|-------|
| **Algorithm** | PBKDF2-HMAC-SHA256 |
| **Iterations** | 480,000 |
| **Salt** | 16 bytes, cryptographically random (`os.urandom`) |
| **Output Length** | 32 bytes → used directly as AES-256 key |

With AES-256-GCM providing built-in authentication, no separate HMAC key is
needed. The full 32-byte derived key is used as the AES-256 encryption key.

The salt is stored in plaintext alongside the encrypted data (it is not secret).

### 2.3 Password Policy

Enforced via the `password-strength` library.

| Rule | Requirement |
|------|------------|
| **Minimum Length** | 12 characters |
| **Lowercase Letters** | ≥ 2 |
| **Uppercase Letters** | ≥ 2 |
| **Digits** | ≥ 2 |
| **Special Characters** | ≥ 2 |
| **Strength Score** | ≥ 0.66 (via `PasswordStats.strength()`) |

If validation fails, a descriptive error listing all failing rules is shown to the user.

### 2.4 File & Directory Permissions

| Target | Permission | Octal |
|--------|-----------|-------|
| Files created by ASV | `rw-------` | `0o600` |
| Directories created by ASV | `rwx------` | `0o700` |

Permissions are set immediately upon creation using `os.chmod()`.

### 2.5 Steganographic Path Obfuscation

All storage paths are obfuscated to prevent casual identification using a
triple-layer scheme:

```
HMAC-SHA256(aes_key, name + pepper + salt)
```

| Component | Description |
|-----------|-------------|
| **AES key** | 32-byte key derived from the master password (used as HMAC key) |
| **Pepper** | 32-byte random value, generated once per realm (global), stored encrypted |
| **Salt** | 16-byte random value, unique per vault/file, stored in the encrypted database |

This combination makes obfuscated paths indistinguishable from random noise. An
attacker cannot determine whether two paths belong to the same system without
knowing all three components.

- **Realm directory:** `~/.local/share/asv/.r_<hex8>` (hidden with dot prefix and random hex suffix).
- **Vault directories:** Named with HMAC-derived hashes, e.g., `v_<hex16>` (HMAC + pepper + per-vault salt).
- **Encrypted files:** Stored with HMAC-derived filenames, e.g., `f_<hex16>.enc` (HMAC + pepper + per-file salt).

The mapping from human-readable names to obfuscated paths (including per-item salts) is
stored exclusively in the encrypted database. The pepper is stored encrypted at
`pepper.enc` within the realm directory.

### 2.6 Secure File Deletion

Three modes for handling the original file after encryption:

| Mode | Behavior |
|------|---------|
| `keep` | Original file is untouched. |
| `simple` | Original file is deleted via `os.remove()` (pointer removal). |
| `secure` | Original file is overwritten with random bytes matching its size, then deleted. The file is NOT effectively irrecoverable. |

---

## 3. Data Architecture

### 3.1 Encrypted Database

The database is a JSON document encrypted at rest using the realm's derived key pair.

**Plaintext JSON schema:**

```json
{
  "version": "0.2.0",
  "realm": {
    "name": "default",
    "created_at": "2026-03-12 13:05:45",
    "salt": "<base64>",
    "password_hash": "<base64 PBKDF2 verification hash>"
  },
  "vaults": {
    "<vault_name>": {
      "id": "<uuid4>",
      "created_at": "2026-03-12 13:05:45",
      "obfuscated_dir": "v_<hex16>",
      "vault_salt": "<base64>",
      "files": {
        "<original_filename>": {
          "id": "<uuid4>",
          "encrypted_name": "f_<hex16>.enc",
          "original_path": "/path/to/original",
          "original_size": 1024,
          "encrypted_at": "2026-03-12 13:05:45",
          "deletion_mode": "keep|simple|secure",
          "file_salt": "<base64>"
        }
      }
    }
  }
}
```

### 3.2 Database Snapshotting

Before every write operation:

1. Copy the current encrypted database file to `db.snapshot`.
2. Perform the write (decrypt → modify → re-encrypt → write).
3. On success, delete the snapshot.
4. On failure, restore from the snapshot.

This guarantees atomicity: the database is never in a half-written state.

### 3.3 Database File Location

```
~/.local/share/asv/.data_<hex8>/
├── db.enc            # Encrypted database (AES-256-GCM)
├── db.snapshot       # Temporary snapshot (only during writes)
├── salt              # PBKDF2 salt (plaintext, not secret)
├── pepper.enc        # Global pepper (encrypted with AES-256-GCM)
└── vaults/
    ├── v_<hex16>/    # Obfuscated vault directory (HMAC+pepper+salt)
    │   ├── f_<hex16>.enc
    │   └── f_<hex16>.enc
    └── v_<hex16>/
        └── f_<hex16>.enc
```

---

## 4. Application Architecture

### 4.1 Project Layout

```
asv/
├── main.py                    # Entry point
├── SPEC.md                    # This specification
├── pyproject.toml             # Dependencies and project metadata
├── README.md               
└── asv/                       # Main package
    ├── __init__.py
    ├── cli/                   # CLI layer (Click commands)
    │   ├── __init__.py
    │   ├── main.py            # Root Click group
    │   ├── realm_commands.py  # realm init, unlock, lock, status
    │   ├── vault_commands.py  # vault create, list, delete
    │   └── file_commands.py   # file encrypt, decrypt, list
    ├── core/                  # Business logic / domain layer
    │   ├── __init__.py
    │   ├── realm.py           # Realm lifecycle management
    │   ├── vault.py           # Vault CRUD operations
    │   └── file_ops.py        # File encrypt/decrypt orchestration
    ├── crypto/                # Cryptographic primitives
    │   ├── __init__.py
    │   ├── engine.py          # AES-256-GCM authenticated encryption
    │   ├── key_derivation.py  # PBKDF2-HMAC-SHA256
    │   └── secure_delete.py   # Secure file overwrite & delete
    ├── db/                    # Database layer
    │   ├── __init__.py
    │   ├── database.py        # Encrypted JSON database CRUD
    │   └── snapshot.py        # Snapshot management
    ├── security/              # Security utilities
    │   ├── __init__.py
    │   ├── password.py        # Password validation
    │   ├── permissions.py     # File/dir permission enforcement
    │   └── steganography.py   # Path obfuscation
    └── ui/                    # User interface utilities
        ├── __init__.py
        └── console.py         # Rich console output helpers
```

### 4.2 Layer Dependencies

```
CLI Layer → Core Layer → Crypto Layer
                       → DB Layer
                       → Security Layer
         → UI Layer
```

Each layer only depends on layers below it. The CLI layer is the only entry point.

---

## 5. CLI Interface

### 5.1 Command Tree

```
asv
├── realm
│   ├── init          # Initialize a new realm (first-time setup)
│   ├── unlock        # Unlock the realm with master password
│   ├── lock          # Lock the realm (clear session)
│   └── status        # Show realm status (locked/unlocked, vault count)
├── vault
│   ├── create        # Create a new vault
│   ├── list          # List all vaults
│   └── delete        # Delete a vault and its contents
└── file
    ├── encrypt       # Encrypt a file into a vault
    ├── decrypt       # Decrypt a file from a vault
    └── list          # List files in a vault
```

### 5.2 Command Details

#### `asv realm init`
- Prompts for master password (with confirmation).
- Validates password against policy (§2.3).
- Derives key, creates realm directory, initializes encrypted database.
- Sets permissions on all created files/directories.

#### `asv realm unlock`
- Prompts for master password.
- Derives key and attempts to decrypt database.
- On success, stores session key in memory (environment variable or temp file with 0600).
- On failure, shows error and exits.

#### `asv realm lock`
- Clears the session key.
- Confirms realm is locked.

#### `asv realm status`
- Shows: locked/unlocked, vault count, total encrypted files.

#### `asv vault create <vault name>`
- Creates obfuscated vault directory.
- Updates database with vault metadata.

#### `asv vault list`
- Requires unlocked realm.
- Lists all vaults with creation date and file count.

#### `asv vault delete <vault name>`
- Requires unlocked realm.
- Prompts for confirmation.
- Deletes all encrypted files within the vault.
- Removes vault directory and database entry.

#### `asv file encrypt <file path> --vault <vault name>`
- Requires unlocked realm.
- Prompts for original file handling: `keep`, `simple-delete`, `secure-delete`.
- Computes SHA-256 hash of original file.
- Encrypts file using AES-256-GCM.
- Stores encrypted file in vault's obfuscated directory.
- Updates database with file metadata.
- Handles original per user's choice.

#### `asv file decrypt <filename> --vault <name> --output <path>`
- Requires unlocked realm.
- GCM authentication tag is verified automatically during decryption.
- Decrypts file and writes to output path.
- Verifies SHA-256 hash of decrypted file against stored hash.
- Sets permissions on output file.

#### `asv file list --vault <name>`
- Requires unlocked realm.
- Lists all files in the vault with original name, size, and encryption date.

---

## 6. Session Management

The realm session (derived key) is stored in a temporary file:

```
/tmp/asv_session_<uid>
```

- Permissions: `0600`
- Contains: Base64-encoded derived key
- Cleared on `realm lock` or process exit

> **Future Enhancement:** Consider using `keyring` or `secretservice` for more secure session storage.

---

## 7. Error Handling

All errors are caught and displayed with user-friendly messages via Rich console:

| Error Category | Behavior |
|---------------|---------|
| Invalid password | Show which policy rules failed |
| Wrong password (unlock) | "Incorrect password. Please try again." |
| Realm not initialized | "No realm found. Run `asv realm init` first." |
| Realm locked | "Realm is locked. Run `asv realm unlock` first." |
| File not found | "File not found: <path>" |
| Vault not found | "Vault '<name>' does not exist." |
| Integrity failure | "INTEGRITY ERROR: File has been tampered with. Aborting." |
| Database corruption | Auto-restore from snapshot if available |

---

## 8. Dependencies

| Package | Purpose | Version |
|---------|---------|---------|
| `click` | CLI framework | ≥ 8.0 |
| `cryptography` | AES, HMAC, PBKDF2 | ≥ 42.0 |
| `password-strength` | Password validation | ≥ 0.0.3 |
| `rich` | Terminal UI (colors, tables, progress) | ≥ 13.0 |

---

## 9. Future Enhancements (Post-MVP)

These are **not** part of the MVP but are anticipated:

- [ ] Multiple realm support
- [ ] Vault-level passwords (separate from master)
- [ ] File versioning within vaults
- [ ] Compression before encryption (gzip)
- [ ] Key rotation
- [ ] Export/import functionality
- [x] ~~AES-256-GCM upgrade option~~ (implemented in v0.2.0)
- [ ] Configurable PBKDF2 iteration count
- [ ] REST API mode
- [ ] Systemd integration for session timeout

---

## 10. Conventions

- **Language:** All code, comments, documentation, CLI messages, and error messages are in English.
- **Code Style:** PEP 8 with type hints throughout.
- **Docstrings:** Google-style docstrings on all public functions.
- **Logging:** Python `logging` module for debug/info output (hidden from user by default).
- **Testing:** `pytest` with separate unit and integration test directories.