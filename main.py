import os
from datetime import timedelta
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

from database import create_document
from schemas import BlogReport

# ===== Security settings =====
SECRET_KEY = os.getenv("SECRET_KEY", "dev-secret-key-change-me")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60 * 12  # 12 hours

# Single admin user from env vars (simple demo)
ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = os.getenv("ADMIN_PASSWORD_HASH")  # if not set, we'll hash ADMIN_PASSWORD
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "admin123")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

if not ADMIN_PASSWORD_HASH:
    # Hash once at startup for the provided ADMIN_PASSWORD
    try:
        ADMIN_PASSWORD_HASH = pwd_context.hash(ADMIN_PASSWORD[:72])
    except Exception:
        # Fallback in unlikely event of backend issues
        ADMIN_PASSWORD_HASH = pwd_context.hash("admin123")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str

class LoginRequest(BaseModel):
    username: str
    password: str

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ===== Auth helpers =====

def verify_password(plain_password, hashed_password):
    try:
        return pwd_context.verify(plain_password, hashed_password)
    except Exception:
        return False

def authenticate_admin(username: str, password: str) -> Optional[User]:
    if username == ADMIN_USERNAME and verify_password(password, ADMIN_PASSWORD_HASH):
        return User(username=username)
    return None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    # Not a real exp claim; just encoding ttl info for this demo
    to_encode.update({"exp_seconds": expire.total_seconds()})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    if token_data.username != ADMIN_USERNAME:
        raise credentials_exception
    return User(username=token_data.username)

# ===== Routes =====

@app.get("/")
def read_root():
    return {"message": "Hello from FastAPI Backend!"}

@app.post("/auth/login", response_model=Token)
async def login(payload: LoginRequest):
    user = authenticate_admin(payload.username, payload.password)
    if not user:
        raise HTTPException(status_code=400, detail="Incorrect username or password")
    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/reports")
async def create_report(
    title: str = Form(...),
    category: str = Form(...),
    excerpt: Optional[str] = Form(None),
    content: str = Form(...),
    image: Optional[UploadFile] = File(None),
    current_user: User = Depends(get_current_user),
):
    """
    Create a blog report. Auth required. Accepts multipart form with optional image file.
    For demo, images are written to /tmp; we return a pseudo URL.
    """
    image_url = None
    if image is not None:
        content_bytes = await image.read()
        tmp_dir = "/tmp/uploads"
        os.makedirs(tmp_dir, exist_ok=True)
        safe_name = image.filename.replace("/", "_").replace("\\", "_")
        file_path = os.path.join(tmp_dir, safe_name)
        with open(file_path, "wb") as f:
            f.write(content_bytes)
        image_url = f"/uploads/{safe_name}"

    doc = BlogReport(
        title=title,
        category=category if category in ["Kebabs", "Burgers", "Restaurants"] else "Restaurants",
        excerpt=excerpt,
        content=content,
        image_url=image_url,
        author="admin",
        status="published"
    )
    inserted_id = create_document("blogreport", doc)
    return {"id": inserted_id, "image_url": image_url}

@app.get("/api/hello")
def hello():
    return {"message": "Hello from the backend API!"}

@app.get("/test")
def test_database():
    """Test endpoint to check if database is available and accessible"""
    response = {
        "backend": "✅ Running",
        "database": "❌ Not Available",
        "database_url": None,
        "database_name": None,
        "connection_status": "Not Connected",
        "collections": []
    }
    
    try:
        # Try to import database module
        from database import db
        
        if db is not None:
            response["database"] = "✅ Available"
            response["database_url"] = "✅ Configured"
            response["database_name"] = db.name if hasattr(db, 'name') else "✅ Connected"
            response["connection_status"] = "Connected"
            
            # Try to list collections to verify connectivity
            try:
                collections = db.list_collection_names()
                response["collections"] = collections[:10]  # Show first 10 collections
                response["database"] = "✅ Connected & Working"
            except Exception as e:
                response["database"] = f"⚠️  Connected but Error: {str(e)[:50]}"
        else:
            response["database"] = "⚠️  Available but not initialized"
            
    except ImportError:
        response["database"] = "❌ Database module not found (run enable-database first)"
    except Exception as e:
        response["database"] = f"❌ Error: {str(e)[:50]}"
    
    # Check environment variables
    import os
    response["database_url"] = "✅ Set" if os.getenv("DATABASE_URL") else "❌ Not Set"
    response["database_name"] = "✅ Set" if os.getenv("DATABASE_NAME") else "❌ Not Set"
    
    return response

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
