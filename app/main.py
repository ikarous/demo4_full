from fastapi import FastAPI, HTTPException, Depends, Request, Response, Cookie
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from datetime import datetime, timedelta
import jwt
import memcache
from passlib.context import CryptContext
from preload_users import fake_users_db

# --- FastAPI Setup ---
app = FastAPI()

# --- CORS: Required for cookies to be sent cross-origin ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],  # must match frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- JWT and Security Settings ---
SECRET_KEY = "your-secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# --- Memcached ---
mc = memcache.Client(['memcached:11211'], debug=0)

# --- Preload users ---
for username, user in fake_users_db.items():
    mc.set(f"user:{username}", user)

# --- Models ---
class LoginRequest(BaseModel):
    username: str
    password: str

# --- Helpers ---
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def get_user(username: str) -> dict | None:
    return mc.get(f"user:{username}")

# --- Dependencies ---
async def get_current_user(access_token: str = Cookie(None)):
    if not access_token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Invalid token payload")
        user = get_user(username)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# --- Routes ---

@app.post("/token")
async def login(form: LoginRequest, response: Response):
    user = get_user(form.username)
    if not user or not verify_password(form.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token({"sub": user["username"]})

    # Set JWT in secure cookie
    resp = JSONResponse(content={"message": "Login successful"})
    resp.set_cookie(
        key="access_token",
        value=access_token,
        httponly=True,
        secure=False,  # set to True with HTTPS
        samesite="Lax",  # set to "None" with secure=True for cross-site
        max_age=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )
    return resp

@app.post("/logout")
def logout():
    resp = JSONResponse(content={"message": "Logged out"})
    resp.delete_cookie("access_token")
    return resp

@app.get("/protected")
async def protected_route(current_user: dict = Depends(get_current_user)):
    return {
        "message": f"Hello, {current_user['full_name']}! This is a protected endpoint."
    }

@app.get("/protected2")
async def protected_admin_route(current_user: dict = Depends(get_current_user)):
    if not current_user.get("admin"):
        raise HTTPException(status_code=403, detail="Admin access required")
    return {
        "message": f"Welcome Admin {current_user['full_name']}! You have access to this route."
    }

# Dev-only server run
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

