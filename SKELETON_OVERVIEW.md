# Skeleton Code Overview

## 📁 Repository Structure

The skeleton provides a well-organized structure with placeholder files containing `NotImplementedError` and TODO markers.

### ✅ What's Already Provided:

1. **Folder Structure:**
   - `app/` - Main application code
   - `scripts/` - Certificate generation scripts
   - `tests/manual/` - Manual testing notes
   - `certs/` - For certificates (gitignored)
   - `transcripts/` - For session transcripts (gitignored)

2. **Dependencies (`requirements.txt`):**
   - `cryptography` - For AES, RSA, X.509 certificates
   - `PyMySQL` - For MySQL database operations
   - `python-dotenv` - For environment variables
   - `pydantic` - For message models/validation
   - `rich` - For console formatting

3. **Skeleton Files (All need implementation):**

#### **Scripts:**
- `scripts/gen_ca.py` - Create Root CA (RSA + self-signed X.509)
- `scripts/gen_cert.py` - Issue client/server certs signed by Root CA

#### **Application Core:**
- `app/client.py` - Client workflow (plain TCP, no TLS)
- `app/server.py` - Server workflow (plain TCP, no TLS)

#### **Crypto Module (`app/crypto/`):**
- `aes.py` - AES-128(ECB) + PKCS#7 padding
- `dh.py` - Classic DH helpers + key derivation `Trunc16(SHA256(Ks))`
- `pki.py` - X.509 validation (CA signature, validity, CN)
- `sign.py` - RSA PKCS#1 v1.5 SHA-256 sign/verify

#### **Common Module (`app/common/`):**
- `protocol.py` - Pydantic message models (hello, login, msg, receipt, etc.)
- `utils.py` - Helpers (base64, now_ms, sha256_hex)

#### **Storage Module (`app/storage/`):**
- `db.py` - MySQL user store (salted SHA-256 passwords)
- `transcript.py` - Append-only transcript + transcript hash

## 🎯 Implementation Order (Recommended)

Based on the assignment requirements, implement in this order:

### Phase 1: Foundation
1. **Step 2:** `scripts/gen_ca.py` and `scripts/gen_cert.py`
2. **Step 3:** `app/crypto/pki.py` (certificate validation)
3. **Step 4:** `app/storage/db.py` (MySQL setup)

### Phase 2: Crypto Primitives
4. **Step 5:** `app/crypto/dh.py` (Diffie-Hellman)
5. **Step 6:** `app/crypto/aes.py` (AES-128 encryption)
6. **Step 7:** `app/crypto/sign.py` (RSA signing)
7. **Step 8:** `app/common/utils.py` (helper functions)
8. **Step 9:** `app/common/protocol.py` (message models)

### Phase 3: Application Logic
9. **Step 10:** `app/server.py` (server workflow)
10. **Step 11:** `app/client.py` (client workflow)
11. **Step 12:** `app/storage/transcript.py` (transcript management)

## 📝 Key Implementation Notes

### Message Types (from assignment):
- `hello` - Client certificate exchange
- `server_hello` - Server certificate exchange
- `register` - User registration (encrypted)
- `login` - User login (encrypted)
- `dh_client` - Client DH parameters
- `dh_server` - Server DH response
- `msg` - Encrypted chat message
- `receipt` - Session receipt for non-repudiation

### Key Formulas:
- Password hash: `hex(SHA256(salt || password))`
- AES key: `K = Trunc16(SHA256(big-endian(Ks)))`
- Message hash: `SHA256(seqno || timestamp || ciphertext)`
- Transcript hash: `SHA256(concatenation of all transcript lines)`

### Security Requirements:
- ✅ No TLS/SSL - all crypto at application layer
- ✅ Mutual certificate validation
- ✅ Encrypted credential transmission
- ✅ Salted password hashing
- ✅ Per-message RSA signatures
- ✅ Sequence number replay protection
- ✅ Append-only transcripts
- ✅ Signed session receipts

## 🚀 Next Steps

1. **Review this skeleton structure**
2. **Start with Step 2:** Implement PKI scripts (`gen_ca.py` and `gen_cert.py`)
3. **Follow the implementation steps** in `IMPLEMENTATION_STEPS.md`

## 📚 Resources

- Assignment spec: `assignemnt 2.txt`
- Implementation guide: `IMPLEMENTATION_STEPS.md`
- Testing notes: `tests/manual/NOTES.md`

