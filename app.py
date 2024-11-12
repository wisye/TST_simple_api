from fastapi import FastAPI
import secrets

app = FastAPI()

@app.get("/api/key")
def get_key():
    key = secrets.token_hex(16)
    return {"key": key}