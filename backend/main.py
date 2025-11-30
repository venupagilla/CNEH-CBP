from fastapi import FastAPI, File, UploadFile, Form, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from Crypto.Cipher import ChaCha20_Poly1305, Blowfish
from Crypto.Protocol.KDF import PBKDF2 as CryptoPBKDF2
import argon2
import bcrypt
import base64
import os
import hashlib
from io import BytesIO
import PyPDF2
from docx import Document
import struct

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

ENCRYPTION_KEY = Fernet.generate_key()
fernet = Fernet(ENCRYPTION_KEY)

class EncryptionService:
    
    # Key Derivation Functions
    @staticmethod
    def derive_key_pbkdf2(password: str, salt: bytes, key_length: int = 32) -> bytes:
        """PBKDF2 key derivation"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=key_length,
            salt=salt,
            iterations=100000,
        )
        return kdf.derive(password.encode())
    
    @staticmethod
    def derive_key_argon2(password: str, salt: bytes, key_length: int = 32) -> bytes:
        """Argon2 key derivation - most secure"""
        hasher = argon2.PasswordHasher(
            time_cost=2,
            memory_cost=65536,
            parallelism=1,
            hash_len=key_length,
            salt_len=16
        )
        raw_hash = argon2.low_level.hash_secret_raw(
            secret=password.encode(),
            salt=salt,
            time_cost=2,
            memory_cost=65536,
            parallelism=1,
            hash_len=key_length,
            type=argon2.low_level.Type.ID
        )
        return raw_hash
    
    @staticmethod
    def derive_key_scrypt(password: str, salt: bytes, key_length: int = 32) -> bytes:
        """scrypt key derivation"""
        kdf = Scrypt(
            salt=salt,
            length=key_length,
            n=2**14,
            r=8,
            p=1,
        )
        return kdf.derive(password.encode())
    
    @staticmethod
    def derive_key_bcrypt(password: str, salt: bytes, key_length: int = 32) -> bytes:
        """bcrypt-based key derivation"""
        # bcrypt needs exactly 16 bytes salt
        bcrypt_salt = b'$2b$12$' + base64.b64encode(salt[:16])[:22]
        hashed = bcrypt.hashpw(password.encode(), bcrypt_salt)
        # Extend to required length using SHA256
        return hashlib.sha256(hashed).digest()[:key_length]
    
    # AES Encryption
    @staticmethod
    def aes_encrypt(data: bytes, password: str, kdf: str = 'pbkdf2') -> bytes:
        """AES-256 encryption with selectable KDF"""
        salt = os.urandom(16)
        
        if kdf == 'argon2':
            key = EncryptionService.derive_key_argon2(password, salt, 32)
        elif kdf == 'scrypt':
            key = EncryptionService.derive_key_scrypt(password, salt, 32)
        elif kdf == 'bcrypt':
            key = EncryptionService.derive_key_bcrypt(password, salt, 32)
        else:  # pbkdf2
            key = EncryptionService.derive_key_pbkdf2(password, salt, 32)
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        
        padding_length = 16 - (len(data) % 16)
        padded_data = data + bytes([padding_length] * padding_length)
        
        encrypted = encryptor.update(padded_data) + encryptor.finalize()
        # Format: kdf_type(1 byte) + salt(16) + iv(16) + encrypted_data
        kdf_byte = {'pbkdf2': 0, 'argon2': 1, 'scrypt': 2, 'bcrypt': 3}.get(kdf, 0)
        return bytes([kdf_byte]) + salt + iv + encrypted
    
    @staticmethod
    def aes_decrypt(encrypted_data: bytes, password: str) -> bytes:
        """AES-256 decryption with automatic KDF detection"""
        kdf_byte = encrypted_data[0]
        kdf = {0: 'pbkdf2', 1: 'argon2', 2: 'scrypt', 3: 'bcrypt'}.get(kdf_byte, 'pbkdf2')
        
        salt = encrypted_data[1:17]
        iv = encrypted_data[17:33]
        ciphertext = encrypted_data[33:]
        
        if kdf == 'argon2':
            key = EncryptionService.derive_key_argon2(password, salt, 32)
        elif kdf == 'scrypt':
            key = EncryptionService.derive_key_scrypt(password, salt, 32)
        elif kdf == 'bcrypt':
            key = EncryptionService.derive_key_bcrypt(password, salt, 32)
        else:
            key = EncryptionService.derive_key_pbkdf2(password, salt, 32)
        
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_padded = decryptor.update(ciphertext) + decryptor.finalize()
        
        padding_length = decrypted_padded[-1]
        return decrypted_padded[:-padding_length]
    
    # ChaCha20-Poly1305
    @staticmethod
    def chacha20_encrypt(data: bytes, password: str, kdf: str = 'argon2') -> bytes:
        """ChaCha20-Poly1305 AEAD encryption"""
        salt = os.urandom(16)
        
        if kdf == 'argon2':
            key = EncryptionService.derive_key_argon2(password, salt, 32)
        elif kdf == 'scrypt':
            key = EncryptionService.derive_key_scrypt(password, salt, 32)
        elif kdf == 'bcrypt':
            key = EncryptionService.derive_key_bcrypt(password, salt, 32)
        else:
            key = EncryptionService.derive_key_pbkdf2(password, salt, 32)
        
        cipher = ChaCha20_Poly1305.new(key=key)
        ciphertext, tag = cipher.encrypt_and_digest(data)
        
        kdf_byte = {'pbkdf2': 0, 'argon2': 1, 'scrypt': 2, 'bcrypt': 3}.get(kdf, 1)
        return bytes([kdf_byte]) + salt + cipher.nonce + tag + ciphertext
    
    @staticmethod
    def chacha20_decrypt(encrypted_data: bytes, password: str) -> bytes:
        """ChaCha20-Poly1305 decryption"""
        kdf_byte = encrypted_data[0]
        kdf = {0: 'pbkdf2', 1: 'argon2', 2: 'scrypt', 3: 'bcrypt'}.get(kdf_byte, 'argon2')
        
        salt = encrypted_data[1:17]
        nonce = encrypted_data[17:29]  # ChaCha20 nonce is 12 bytes
        tag = encrypted_data[29:45]    # Tag is 16 bytes
        ciphertext = encrypted_data[45:]
        
        if kdf == 'argon2':
            key = EncryptionService.derive_key_argon2(password, salt, 32)
        elif kdf == 'scrypt':
            key = EncryptionService.derive_key_scrypt(password, salt, 32)
        elif kdf == 'bcrypt':
            key = EncryptionService.derive_key_bcrypt(password, salt, 32)
        else:
            key = EncryptionService.derive_key_pbkdf2(password, salt, 32)
        
        cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ciphertext, tag)
        return plaintext
    
    # Blowfish
    @staticmethod
    def blowfish_encrypt(data: bytes, password: str, kdf: str = 'pbkdf2') -> bytes:
        """Blowfish encryption"""
        salt = os.urandom(16)
        
        if kdf == 'argon2':
            key = EncryptionService.derive_key_argon2(password, salt, 32)
        elif kdf == 'scrypt':
            key = EncryptionService.derive_key_scrypt(password, salt, 32)
        elif kdf == 'bcrypt':
            key = EncryptionService.derive_key_bcrypt(password, salt, 32)
        else:
            key = EncryptionService.derive_key_pbkdf2(password, salt, 32)
        
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        
        padding_length = 8 - (len(data) % 8)  # Blowfish uses 8-byte blocks
        padded_data = data + bytes([padding_length] * padding_length)
        
        encrypted = cipher.encrypt(padded_data)
        
        kdf_byte = {'pbkdf2': 0, 'argon2': 1, 'scrypt': 2, 'bcrypt': 3}.get(kdf, 0)
        return bytes([kdf_byte]) + salt + cipher.iv + encrypted
    
    @staticmethod
    def blowfish_decrypt(encrypted_data: bytes, password: str) -> bytes:
        """Blowfish decryption"""
        kdf_byte = encrypted_data[0]
        kdf = {0: 'pbkdf2', 1: 'argon2', 2: 'scrypt', 3: 'bcrypt'}.get(kdf_byte, 'pbkdf2')
        
        salt = encrypted_data[1:17]
        iv = encrypted_data[17:25]  # Blowfish IV is 8 bytes
        ciphertext = encrypted_data[25:]
        
        if kdf == 'argon2':
            key = EncryptionService.derive_key_argon2(password, salt, 32)
        elif kdf == 'scrypt':
            key = EncryptionService.derive_key_scrypt(password, salt, 32)
        elif kdf == 'bcrypt':
            key = EncryptionService.derive_key_bcrypt(password, salt, 32)
        else:
            key = EncryptionService.derive_key_pbkdf2(password, salt, 32)
        
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted_padded = cipher.decrypt(ciphertext)
        
        padding_length = decrypted_padded[-1]
        return decrypted_padded[:-padding_length]
    
    @staticmethod
    def fernet_encrypt(data: bytes) -> bytes:
        """Fernet encryption"""
        return fernet.encrypt(data)
    
    @staticmethod
    def fernet_decrypt(encrypted_data: bytes) -> bytes:
        """Fernet decryption"""
        return fernet.decrypt(encrypted_data)
    
    @staticmethod
    def xor_encrypt(data: bytes, key: str) -> bytes:
        """Simple XOR encryption"""
        key_bytes = key.encode()
        return bytes([data[i] ^ key_bytes[i % len(key_bytes)] for i in range(len(data))])
    
    @staticmethod
    def sha256_hash(data: bytes) -> str:
        """SHA-256 hashing"""
        sha256 = hashlib.sha256()
        sha256.update(data)
        return sha256.hexdigest()

def extract_text_from_file(file: UploadFile, content: bytes) -> str:
    """Extract text content from different file formats"""
    filename = file.filename.lower()
    
    if filename.endswith('.pdf'):
        pdf_reader = PyPDF2.PdfReader(BytesIO(content))
        text = ""
        for page in pdf_reader.pages:
            text += page.extract_text()
        return text
    elif filename.endswith(('.docx', '.doc')):
        doc = Document(BytesIO(content))
        return "\n".join([para.text for para in doc.paragraphs])
    else:
        return content.decode('utf-8', errors='ignore')

@app.post("/encrypt")
async def encrypt_file(
    file: UploadFile = File(...),
    algorithm: str = Form(...),
    password: str = Form(None),
    kdf: str = Form("argon2")
):
    """Encrypt uploaded file or generate hash"""
    try:
        content = await file.read()
        
        # Validate password for algorithms that need it
        password_required = ["AES", "ChaCha20", "Blowfish", "XOR"]
        if algorithm in password_required and not password:
            raise HTTPException(
                status_code=400, 
                detail=f"{algorithm} requires a password"
            )
        
        # SHA-256 hashing
        if algorithm == "SHA-256":
            hash_value = EncryptionService.sha256_hash(content)
            
            hash_filename = f"hash_{file.filename}.txt"
            file_path = f"temp/{hash_filename}"
            os.makedirs("temp", exist_ok=True)
            
            with open(file_path, "w") as f:
                f.write(f"SHA-256 Hash of {file.filename}:\n{hash_value}\n")
                f.write(f"\nOriginal file size: {len(content)} bytes")
            
            return JSONResponse({
                "success": True,
                "preview": hash_value,
                "filename": hash_filename,
                "original_name": file.filename,
                "algorithm": algorithm,
                "is_hash": True,
                "size": len(hash_value)
            })
        
        # Handle encryption algorithms
        if algorithm == "AES":
            encrypted_data = EncryptionService.aes_encrypt(content, password, kdf)
        elif algorithm == "ChaCha20":
            encrypted_data = EncryptionService.chacha20_encrypt(content, password, kdf)
        elif algorithm == "Blowfish":
            encrypted_data = EncryptionService.blowfish_encrypt(content, password, kdf)
        elif algorithm == "Fernet":
            encrypted_data = EncryptionService.fernet_encrypt(content)
        elif algorithm == "XOR":
            encrypted_data = EncryptionService.xor_encrypt(content, password)
        else:
            raise HTTPException(status_code=400, detail="Invalid algorithm")
        
        encrypted_preview = base64.b64encode(encrypted_data[:500]).decode('utf-8')
        
        encrypted_filename = f"encrypted_{file.filename}"
        file_path = f"temp/{encrypted_filename}"
        os.makedirs("temp", exist_ok=True)
        
        with open(file_path, "wb") as f:
            f.write(encrypted_data)
        
        return JSONResponse({
            "success": True,
            "preview": encrypted_preview,
            "filename": encrypted_filename,
            "original_name": file.filename,
            "algorithm": algorithm,
            "kdf": kdf if algorithm != "Fernet" and algorithm != "XOR" else None,
            "is_hash": False,
            "size": len(encrypted_data)
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/decrypt")
async def decrypt_file(
    file: UploadFile = File(...),
    algorithm: str = Form(...),
    password: str = Form(None)
):
    """Decrypt uploaded encrypted file"""
    try:
        if algorithm == "SHA-256":
            raise HTTPException(
                status_code=400, 
                detail="SHA-256 is a one-way hash function and cannot be decrypted"
            )
        
        password_required = ["AES", "ChaCha20", "Blowfish", "XOR"]
        if algorithm in password_required and not password:
            raise HTTPException(
                status_code=400, 
                detail=f"{algorithm} requires the encryption password"
            )
        
        encrypted_content = await file.read()
        
        if algorithm == "AES":
            decrypted_data = EncryptionService.aes_decrypt(encrypted_content, password)
        elif algorithm == "ChaCha20":
            decrypted_data = EncryptionService.chacha20_decrypt(encrypted_content, password)
        elif algorithm == "Blowfish":
            decrypted_data = EncryptionService.blowfish_decrypt(encrypted_content, password)
        elif algorithm == "Fernet":
            decrypted_data = EncryptionService.fernet_decrypt(encrypted_content)
        elif algorithm == "XOR":
            decrypted_data = EncryptionService.xor_encrypt(encrypted_content, password)
        else:
            raise HTTPException(status_code=400, detail="Invalid algorithm")
        
        preview = decrypted_data[:500].decode('utf-8', errors='ignore')
        
        decrypted_filename = f"decrypted_{file.filename}"
        file_path = f"temp/{decrypted_filename}"
        
        with open(file_path, "wb") as f:
            f.write(decrypted_data)
        
        return JSONResponse({
            "success": True,
            "preview": preview,
            "filename": decrypted_filename,
            "size": len(decrypted_data)
        })
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

@app.get("/download/{filename}")
async def download_file(filename: str):
    """Download encrypted/decrypted file"""
    file_path = f"temp/{filename}"
    if not os.path.exists(file_path):
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        file_path,
        media_type='application/octet-stream',
        filename=filename
    )

@app.post("/preview")
async def preview_file(file: UploadFile = File(...)):
    """Preview file content before encryption"""
    try:
        content = await file.read()
        text = extract_text_from_file(file, content)
        
        return JSONResponse({
            "success": True,
            "preview": text[:1000],
            "filename": file.filename,
            "size": len(content)
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
