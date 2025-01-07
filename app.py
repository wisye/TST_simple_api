from fastapi import FastAPI, Depends, HTTPException, status, Security, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, APIKeyHeader
from pydantic import BaseModel
from passlib.context import CryptContext
import secrets
import oqs
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import logging
import sqlite3
from datetime import datetime, timedelta
import uuid
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

app = FastAPI()
app.mount("/static", StaticFiles(directory="static"), name="static")
logging.basicConfig(level=logging.INFO)

class KeyRequest(BaseModel):
        sensitivity : str
        
class EncryptRequest(BaseModel):
        text: str
        sensitivity: str = "medium"
        
class EncryptResponse(BaseModel):
        key_id: str
        cipher_text: str
        iv: str
        
class DecryptRequest(BaseModel):
        key_id: str
        cipher_text: str
        iv: str
        
class APIKeyResponse(BaseModel):
        api_key: str
        service_name: str
        expires_at: datetime

class APIKeyRequest(BaseModel):
        service_name: str
        expires_in_days: int = 30

API_KEY_NAME = "furina-encryption-service"
API_KEY_HEADER = APIKeyHeader(name=API_KEY_NAME, auto_error=False)

VALID_API_KEYS = {
	"furina-is-key": "key"
}

def init_db():
        conn = sqlite3.connect("key_vault.db")
        cursor = conn.cursor()
        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS api_keys (
                               api_key TEXT PRIMARY KEY,
                               service_name TEXT NOT NULL,
                               created_At TIMESTAMP,
                               expires_at TIMESTAMP
                       )
                       """)
        conn.commit()
        conn.close()

async def validate_service(api_key: str = Security(API_KEY_HEADER)):
        if not api_key:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
        conn = sqlite3.connect("key_vault.db")
        cursor = conn.cursor()
        cursor.execute("""
                       SELECT service_name, expires_at
                       FROM api_keys
                       WHERE api_key = ?
                       """, (api_key,)
                       )
        result = cursor.fetchone()
        conn.close()
        
        if not result:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN)
        
        service_name, expires_at = result
        if datetime.fromisoformat(expires_at) < datetime.utcnow():
                raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="API key expired"
                )
        return service_name

@app.post("/api/keys", response_model=APIKeyResponse)
async def create_api_key(request: APIKeyRequest):
        api_key = f"furina_{uuid.uuid4().hex}"
        created_at = datetime.utcnow()
        expires_at = created_at + timedelta(days=request.expires_in_days)
        
        conn = sqlite3.connect("key_vault.db")
        cursor = conn.cursor()
        cursor.execute("""
                       INSERT INTO api_keys (api_key, service_name, created_at, expires_at)
                       VALUES (?, ?, ?, ?)
                       """,
                       (api_key, request.service_name, created_at, expires_at)
                       )
        conn.commit()
        conn.close()
        
        return {
                "api_key": api_key,
                "service_name": request.service_name,
                "expires_at": expires_at
        }

@app.delete("api/keys/{api_key}")
async def revoke_api_key(api_key: str):
        conn = sqlite3.connect("key_vault.db")
        cursor = conn.cursor()
        cursor.execute("DELETE FROM api_keys WHERE api_key = ?", (api_key,))
        conn.commit()
        conn.close()
        return {"status": "revoked"}
        
def get_key(key_id: str):
        conn = sqlite3.connect("key_vault.db")
        cursor = conn.cursor()
        cursor.execute("SELECT key_data FROM keys WHERE key_id = ?", (key_id,))
        result = cursor.fetchone()
        conn.close()
        if not result:
                raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
        return eval(result[0])
        
def encrypt_data(shared_secret : bytes, plain_text : str):
        key = shared_secret[:32]
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        encryptor = cipher.encryptor()
        cipher_text = encryptor.update(plain_text.encode()) + encryptor.finalize()
        return {
		"iv" : base64.b64encode(iv).decode(),
		"cipher_text" : base64.b64encode(cipher_text).decode()
	}
        
def select_complexity(sensitivity : str):
        if sensitivity == "high":
                return "ML-KEM-1024"
        elif sensitivity == "medium":
                return "Kyber768"
        return "ML-KEM-512"

def key_management(sensitivity : str):
        algorithm = select_complexity(sensitivity)
        kem = oqs.KeyEncapsulation(algorithm)
        public_key = kem.generate_keypair()
        ciphertext, shared_secret = kem.encap_secret(public_key)
        kem.free()
        return {
                "algorithm": algorithm,
                "shared_secret": base64.b64encode(shared_secret).decode(),
        }
        
@app.middleware("http")
async def log_request(request : Request, call_next):
        response = await call_next(request)
        logging.info(f"{request.method} {request.url} - {response.status_code}")
        return response

def store_key(service: str, key_data: dict) -> str:
        key_id = secrets.token_urlsafe(16)
        conn = sqlite3.connect("key_vault.db")
        cursor = conn.cursor()
        cursor.execute("""
                       CREATE TABLE IF NOT EXISTS keys 
                       (key_id TEXT PRIMARY KEY, service TEXT, key_data TEXT)
                       """
        )
        cursor.execute("INSERT INTO keys (key_id, service, key_data) VALUES (?, ?, ?)", 
                       (key_id, service, str(key_data)))
        conn.commit()
        conn.close()
        return key_id

@app.post("/api/encrypt", response_model=EncryptResponse)
async def encrypt_text(request: EncryptRequest, service: str = Depends(validate_service)):
        key_data = key_management(request.sensitivity)
        key_id = store_key(service, key_data)
        
        shared_secret = base64.b64decode(key_data["shared_secret"])
        encrypted = encrypt_data(shared_secret, request.text)
        
        return {
                "key_id": key_id,
                "cipher_text": encrypted["cipher_text"],
                "iv": encrypted["iv"]
        }
        
@app.post("/api/decrypt")
async def decrypt_text(request: DecryptRequest, service: str = Depends(validate_service)):
        key_data = get_key(request.key_id)
        shared_secret = base64.b64decode(key_data["shared_secret"])
        
        key = shared_secret[:32]
        iv = base64.b64decode(request.iv)
        cipher_text = base64.b64decode(request.cipher_text)
        
        cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
        decryptor = cipher.decryptor()
        plain_text = decryptor.update(cipher_text) + decryptor.finalize()

        return {"text": plain_text.decode()}

@app.on_event("startup")
async def startup_event():
        init_db()
        
@app.get("/")
async def read_root():
        return FileResponse("static/index.html")