from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from passlib.context import CryptContext
import secrets

app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"])

def hash_password(password: str):
        return password
        # return pwd_context.hash(password)

class User(BaseModel):
        username: str
        full_name: str
        
class UserInDB(User):
        hashed_password: str
        disabled: bool
        
db = {
	"furina": {
		"username": "furina",
		"full_name": "Furina De Fontaine",
		"hashed_password": "ilovefurinasomuchfrfr",
		"disabled": False,
	}
}
        
def get_user(db, username: str):
        if username in db:
                user_dict = db[username]
                return UserInDB(**user_dict)

def decode_token(token):
        user = get_user(db, token)
        return user
        
async def get_current_user(token: str = Depends(oauth2_scheme)):
        user = decode_token(token)
        if not user:
                raise HTTPException(
			status_code=status.HTTP_418_IM_A_TEAPOT,
			detail="Invalid authentication",
			headers={"WWW-Authenticate": "Bearer"},
		)
        return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
	if current_user.disabled:
		raise HTTPException(status_code=400, detail="Inactive user")
	return current_user

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
	user_dict = db.get(form_data.username)
	if not user_dict:
		raise HTTPException(status_code=400, detail="Incorrect username or password")
	user = UserInDB(**user_dict)
	hashed_password = hash_password(form_data.password)
	if not hashed_password == user.hashed_password:
		raise HTTPException(status_code=400, detail="Incorrect username or password")
	return {"access_token": user.username, "token_type": "bearer"}

@app.get("/api/key")
def get_key(current_user: User = Depends(get_current_active_user)):
	key = secrets.token_hex(16)
	return {"key": key}
