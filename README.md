<p align="center">
  <img src="https://img.shields.io/badge/python-%3E%3D3.12-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.12+">
  <img src="https://img.shields.io/badge/platform-Linux-FCC624?style=for-the-badge&logo=linux&logoColor=black" alt="Linux">
  <img src="https://img.shields.io/badge/encryption-AES--128--CBC-00C853?style=for-the-badge&logo=gnuprivacyguard&logoColor=white" alt="AES-128-CBC">
  <img src="https://img.shields.io/badge/version-0.1.0-FF6D00?style=for-the-badge" alt="v0.1.0">
  <img src="https://img.shields.io/badge/license-MIT-blue?style=for-the-badge" alt="MIT License">
</p>

<h1 align="center">🔐 ASV — Atomic Stealth Vault</h1>

<p align="center">
  <strong>A command-line file encryption system for Linux that prioritizes security, integrity, and stealth.</strong>
</p>

<p align="center">
  Encrypt your files with military-grade cryptography · Store them in obfuscated vault directories · Manage everything from a single CLI
</p>

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| **🔑 AES-128-CBC Encryption** | Industry-standard symmetric encryption with random IV per operation |
| **🛡️ HMAC-SHA256 Integrity** | Every encrypted file is integrity-verified before decryption |
| **🔒 PBKDF2 Key Derivation** | 480,000 iterations to defeat brute-force attacks |
| **🫥 Steganographic Paths** | Vault and file paths are obfuscated with HMAC-derived hashes |
| **📦 Encrypted Database** | All metadata is encrypted at rest — zero plaintext exposure |
| **💾 Atomic Snapshots** | Database snapshots before every write guarantee data integrity |
| **🗑️ Secure File Deletion** | Overwrite originals with random bytes before deletion |
| **🏗️ Vault Organization** | Organize encrypted files into named, logical vaults |
| **🎨 Rich Terminal UI** | Beautiful, colorful CLI output powered by Rich |

---

## 🏗️ Architecture

ASV follows a clean layered architecture with strict separation of concerns:

```
CLI Layer  →  Core Layer  →  Crypto Layer
                           →  DB Layer
                           →  Security Layer
           →  UI Layer
```

```
asv/
├── cli/        # Click commands (realm, vault, file)
├── core/       # Business logic (realm, vault, file operations)
├── crypto/     # AES-128-CBC, HMAC-SHA256, PBKDF2, secure delete
├── db/         # Encrypted JSON database & snapshot management
├── security/   # Password policy, permissions, path obfuscation
└── ui/         # Rich console output helpers
```

---

## 🚀 Getting Started

### Prerequisites

- **Python** ≥ 3.12
- **Linux** (file permissions and paths are Linux-specific)
- [**uv**](https://docs.astral.sh/uv/) (recommended package manager)

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/asv.git
cd asv

# Create virtual environment and install dependencies
uv sync

# Verify installation
uv run asv --help
```

---

## 📖 Usage

### 1. Initialize your realm

A **realm** is your root-level encrypted container. You start by creating one:

```bash
asv realm init
```

You'll be prompted to create a master password. The password must meet strict security requirements (12+ characters, mixed case, digits, and special characters).

### 2. Unlock the realm

```bash
asv realm unlock
```

### 3. Create a vault

**Vaults** are named containers to organize your encrypted files:

```bash
asv vault create personal
asv vault create work
```

### 4. Encrypt files

```bash
asv file encrypt secret-document.pdf --vault personal
```

You'll be asked how to handle the original file:
- **`keep`** — Leave the original untouched
- **`simple`** — Delete the original (pointer removal)
- **`secure`** — Overwrite with random bytes, then delete (irrecoverable)

### 5. List & decrypt files

```bash
# List files in a vault
asv file list --vault personal

# Decrypt a file
asv file decrypt secret-document.pdf --vault personal --output ./restored.pdf
```

### 6. Lock when done

```bash
asv realm lock
```

---

## 🔐 Security Design

<table>
  <tr>
    <th>Component</th>
    <th>Implementation</th>
  </tr>
  <tr>
    <td><strong>Encryption</strong></td>
    <td>AES-128-CBC with random 16-byte IV, PKCS7 padding</td>
  </tr>
  <tr>
    <td><strong>Integrity</strong></td>
    <td>HMAC-SHA256 computed over <code>IV + ciphertext</code></td>
  </tr>
  <tr>
    <td><strong>Key Derivation</strong></td>
    <td>PBKDF2-HMAC-SHA256, 480,000 iterations, 16-byte random salt</td>
  </tr>
  <tr>
    <td><strong>Permissions</strong></td>
    <td>Files: <code>0600</code> · Directories: <code>0700</code></td>
  </tr>
  <tr>
    <td><strong>Path Obfuscation</strong></td>
    <td>HMAC-derived hashes for vault dirs and filenames</td>
  </tr>
  <tr>
    <td><strong>Password Policy</strong></td>
    <td>12+ chars, 2 upper, 2 lower, 2 digits, 2 special, strength ≥ 0.66</td>
  </tr>
</table>

**Encrypted file format:**

```
[16 bytes IV] [N bytes ciphertext (PKCS7)] [32 bytes HMAC-SHA256]
```

---

## 📋 Command Reference

```
asv
├── realm
│   ├── init       Initialize a new realm (first-time setup)
│   ├── unlock     Unlock the realm with master password
│   ├── lock       Lock the realm (clear session)
│   └── status     Show realm status and statistics
├── vault
│   ├── create     Create a new vault
│   ├── list       List all vaults
│   └── delete     Delete a vault and its contents
└── file
    ├── encrypt    Encrypt a file into a vault
    ├── decrypt    Decrypt a file from a vault
    └── list       List files in a vault
```

---

## 🛠️ Dependencies

| Package | Purpose |
|---------|---------|
| [click](https://click.palletsprojects.com/) `≥ 8.0` | CLI framework |
| [cryptography](https://cryptography.io/) `≥ 42.0` | AES, HMAC, PBKDF2 |
| [password-strength](https://pypi.org/project/password-strength/) `≥ 0.0.3` | Password validation |
| [rich](https://rich.readthedocs.io/) `≥ 13.0` | Terminal UI |

---

## 🗺️ Roadmap

> These features are planned for post-MVP releases.

- [ ] Multiple realm support
- [ ] Vault-level passwords
- [ ] File versioning within vaults
- [ ] Compression before encryption (gzip)
- [ ] Key rotation
- [ ] Export/import functionality
- [ ] AES-256-GCM upgrade option
- [ ] REST API mode
- [ ] Systemd integration for session timeout

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).

---

<p align="center">
  <sub>Built with 🐍 Python · 🔐 cryptography · 🎨 Rich</sub>
</p>
