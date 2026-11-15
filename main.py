import os
import json
import uuid
from datetime import datetime, timedelta
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Text, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker, Session
from passlib.context import CryptContext
from jose import jwt
import redis
import boto3

# Environment Config (PostgreSQL, Redis, S3/R2 Object Storage)
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./canvas_pro.db") # Replace with postgresql://user:pass@localhost/canvasdb
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
SECRET_KEY = os.getenv("SECRET_KEY", "CANVAS_PRO_SUPER_SECRET_2026")
S3_BUCKET = os.getenv("S3_BUCKET", "canvas-pro-assets")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

try:
    redis_client = redis.from_url(REDIS_URL, decode_responses=True)
    redis_client.ping()
except Exception:
    redis_client = None

# Database Models
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True, nullable=False)
    full_name = Column(String, nullable=False)
    hashed_password = Column(String, nullable=False)
    avatar_url = Column(String, default="")
    created_at = Column(DateTime, default=datetime.utcnow)

class CloudProject(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    user_email = Column(String, index=True)
    title = Column(String, nullable=False)
    canvas_json = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow)

Base.metadata.create_all(bind=engine)

app = FastAPI(title="CANVAS Studio Pro API")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

class RegisterIn(BaseModel):
    email: EmailStr
    password: str
    full_name: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class ResetIn(BaseModel):
    email: EmailStr
    new_password: str

class ProjectIn(BaseModel):
    user_email: str
    title: str
    canvas_json: str

def create_token(email: str):
    payload = {"sub": email, "exp": datetime.utcnow() + timedelta(days=7)}
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

@app.post("/auth/register")
def register(data: RegisterIn, db: Session = Depends(get_db)):
    if db.query(User).filter(User.email == data.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    user = User(
        email=data.email,
        full_name=data.full_name,
        hashed_password=pwd_context.hash(data.password)
    )
    db.add(user)
    db.commit()
    return {"message": "User registered successfully"}

@app.post("/auth/login")
def login(data: LoginIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not pwd_context.verify(data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user.email)
    return {
        "access_token": token,
        "user": {"email": user.email, "full_name": user.full_name, "avatar_url": user.avatar_url}
    }

@app.post("/auth/reset-password")
def reset_password(data: ResetIn, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    user.hashed_password = pwd_context.hash(data.new_password)
    db.commit()
    return {"message": "Password updated"}

@app.post("/projects/save")
def save_project(data: ProjectIn, db: Session = Depends(get_db)):
    proj = CloudProject(user_email=data.user_email, title=data.title, canvas_json=data.canvas_json)
    db.add(proj)
    db.commit()
    if redis_client:
        redis_client.delete(f"projects:{data.user_email}")
    return {"id": proj.id, "status": "saved"}

@app.get("/projects/{user_email}")
def list_projects(user_email: str, db: Session = Depends(get_db)):
    if redis_client:
        cached = redis_client.get(f"projects:{user_email}")
        if cached:
            return json.loads(cached)
    items = db.query(CloudProject).filter(CloudProject.user_email == user_email).all()
    result = [{"id": p.id, "title": p.title, "canvas_json": p.canvas_json} for p in items]
    if redis_client:
        redis_client.setex(f"projects:{user_email}", 300, json.dumps(result))
    return result

@app.post("/assets/upload")
async def upload_asset(file: UploadFile = File(...)):
    os.makedirs("uploads", exist_ok=True)
    ext = file.filename.split(".")[-1]
    key = f"{uuid.uuid4()}.{ext}"
    file_path = f"uploads/{key}"
    content = await file.read()
    with open(file_path, "wb") as f:
        f.write(content)
    # Optional S3 / Cloudflare R2 Upload
    if os.getenv("AWS_ACCESS_KEY_ID"):
        s3 = boto3.client("s3", endpoint_url=os.getenv("S3_ENDPOINT"))
        s3.put_object(Bucket=S3_BUCKET, Key=key, Body=content, ContentType=file.content_type)
    return {"url": f"/uploads/{key}", "filename": key}
