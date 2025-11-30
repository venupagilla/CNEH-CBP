# CNEH-CBP

A full-stack file encryption and hashing web application built with a FastAPI backend and a React + Tailwind CSS frontend. Users can upload files, preview contents, encrypt/decrypt using multiple algorithms & key derivation functions (KDFs), and download processed results. Supports hashing (SHA-256) and secure symmetric encryption algorithms.

## Features
- Multi-algorithm encryption: AES-256 (CBC), ChaCha20-Poly1305 (AEAD), Blowfish (CBC), Fernet, XOR (educational), SHA-256 hashing
- Pluggable Key Derivation Functions: PBKDF2, Argon2id, scrypt, bcrypt
- Automatic KDF detection on decryption (stored as leading metadata byte)
- File preview for PDF, DOC/DOCX, and plain text before encryption
- Download encrypted or decrypted artifacts
- CORS-enabled frontend integration (`http://localhost:3000`)
- Secure temporary storage under `backend/temp/` (ignored by git)

## Tech Stack
| Layer     | Tech |
|----------|------|
| Frontend | React, Tailwind CSS |
| Backend  | FastAPI, Uvicorn |
| Crypto   | cryptography, PyCryptodome, argon2-cffi, bcrypt |
| Parsing  | PyPDF2, python-docx |

## Project Structure
```
backend/
  main.py              # FastAPI app & encryption endpoints
  temp/                # Generated encrypted/decrypted/hash files (ignored)
frontend/
  src/                 # React source
  public/              # Static assets
cneh/                  # Local Python virtual environment (ignored)
.gitignore             # Ignore rules (venv, temp, node_modules, etc.)
README.md
```

## Backend API Summary
Base URL (dev): `http://localhost:8000`

### POST /encrypt
Form fields:
- `file`: uploaded file (multipart)
- `algorithm`: one of `AES`, `ChaCha20`, `Blowfish`, `Fernet`, `XOR`, `SHA-256`
- `password`: required for AES / ChaCha20 / Blowfish / XOR (optional for Fernet, forbidden for SHA-256)
- `kdf`: one of `pbkdf2`, `argon2`, `scrypt`, `bcrypt` (ignored for Fernet, XOR, SHA-256)

Returns JSON with: `preview` (Base64 for encrypted, hash string for SHA-256), `filename`, `algorithm`, optional `kdf`, `size`, `is_hash`.

### POST /decrypt
Form fields:
- `file`: previously encrypted artifact
- `algorithm`: algorithm originally used (auto-detects KDF internally for supported ones)
- `password`: required if original algorithm needed it

Returns JSON with plaintext preview and output filename (`decrypted_<original>`).

### POST /preview
Form fields:
- `file`: uploaded file

Returns first ~1000 chars extracted from PDF, DOCX/DOC, or raw text.

### GET /download/{filename}
Downloads an encrypted/decrypted/hash file from `backend/temp/`.

## Encryption Algorithms & Metadata Format
| Algorithm  | Mode / Notes | Metadata Layout (prefix bytes before ciphertext) |
|-----------|--------------|--------------------------------------------------|
| AES-256   | CBC + PKCS padding | `[kdf_byte][salt(16)][iv(16)][ciphertext]` |
| ChaCha20-Poly1305 | AEAD (nonce + tag) | `[kdf_byte][salt(16)][nonce(12)][tag(16)][ciphertext]` |
| Blowfish  | CBC 8-byte blocks | `[kdf_byte][salt(16)][iv(8)][ciphertext]` |
| Fernet    | Built-in token | No manual layout; uses Fernet format |
| XOR       | Simple byte-wise XOR | Raw XOR output (educational only) |
| SHA-256   | One-way hash | Plain hex digest returned (not a file encryption) |

`kdf_byte` mapping: `0=pbkdf2, 1=argon2, 2=scrypt, 3=bcrypt`.

## Local Development Setup (Windows PowerShell)
### Prerequisites
- Python 3.11+ (recommended)
- Node.js 18+ and npm

### 1. Clone (if not already)
```powershell
git clone https://github.com/venupagilla/CNEH-CBP.git
cd CNEH-CBP
```

### 2. Python Virtual Environment (existing `cneh/`)
Activate existing venv:
```powershell
.\cneh\Scripts\Activate.ps1
```
If you need to recreate:
```powershell
python -m venv cneh
.\cneh\Scripts\Activate.ps1
```

### 3. Install Backend Dependencies
(Generate if requirements.txt is added later.)
```powershell
pip install fastapi uvicorn[standard] cryptography pycryptodome argon2-cffi bcrypt PyPDF2 python-docx
```

### 4. Run Backend
```powershell
python backend\main.py
# or
uvicorn backend.main:app --reload --port 8000
```
Backend will listen on `http://localhost:8000`.

### 5. Frontend Setup
```powershell
cd frontend
npm install
npm start
```
Frontend dev server: `http://localhost:3000`.

## Example Usage (curl)
Encrypt with AES + Argon2:
```bash
curl -X POST \
  -F "file=@sample.txt" \
  -F "algorithm=AES" \
  -F "password=My$ecret123" \
  -F "kdf=argon2" \
  http://localhost:8000/encrypt
```
Download encrypted artifact:
```bash
curl -O http://localhost:8000/download/encrypted_sample.txt
```
Decrypt:
```bash
curl -X POST \
  -F "file=@encrypted_sample.txt" \
  -F "algorithm=AES" \
  -F "password=My$ecret123" \
  http://localhost:8000/decrypt
```
Hash a file:
```bash
curl -X POST -F "file=@sample.txt" -F "algorithm=SHA-256" http://localhost:8000/encrypt
```

## Frontend Integration Notes
- Adjust CORS origins in `backend/main.py` (`allow_origins=["http://localhost:3000"]`).
- Use `FormData` to send file + fields (`algorithm`, `password`, `kdf`).
- When decrypting, ensure algorithm and password match original encryption.

## Security Considerations
- Temporary files stored unencrypted in `backend/temp/`; for production move to secure storage and auto-clean.
- XOR is insecure—only for demonstration.
- Fernet internally handles key management (here a single runtime key). Persist a key securely for production.
- Increase Argon2 memory/time cost for stronger resistance in production.
- Validate file size & type to prevent resource exhaustion.

## Cleaning Temp Files
```powershell
Remove-Item -Recurse -Force backend\temp\*
```

## Git Hygiene
- `cneh/` virtual environment and `backend/temp/` are excluded via `.gitignore`.
- Avoid committing secrets; use `.env` (already ignored).

## Future Improvements
- Add JWT-based user auth
- Persist encryption keys per user
- Add audit logging for operations
- Implement rate limiting
- Provide requirements.txt & automated Dockerfile

## Contributing
1. Fork the repo
2. Create a feature branch (`git checkout -b feature/xyz`)
3. Commit changes (`git commit -m "Add xyz"`)
4. Push & open PR

## License
Specify a license (e.g., MIT) if desired.

---
Maintained by: @venupagilla
