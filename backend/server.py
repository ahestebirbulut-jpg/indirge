from dotenv import load_dotenv
load_dotenv()

import os
import re
import jwt
import bcrypt
from datetime import datetime, timezone, timedelta
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Request, APIRouter
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

# ─── ENV ─────────────────────────────────────
MONGO_URL = os.environ["MONGO_URL"]
DB_NAME = os.environ["DB_NAME"]
JWT_SECRET = os.environ["JWT_SECRET"]
ADMIN_USERNAME = os.environ["ADMIN_USERNAME"]
ADMIN_PASSWORD = os.environ["ADMIN_PASSWORD"]
ADMIN_VERIFICATION_CODE = os.environ["ADMIN_VERIFICATION_CODE"]
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 24 * 7  # 7 days for admin convenience

# ─── DB ──────────────────────────────────────
client = AsyncIOMotorClient(MONGO_URL)
db = client[DB_NAME]

# ─── APP ─────────────────────────────────────
app = FastAPI(title="Indirge Kuantum Blog API")
api = APIRouter(prefix="/api")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── HELPERS ─────────────────────────────────
def hash_password(pw: str) -> str:
    return bcrypt.hashpw(pw.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

def verify_password(pw: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(pw.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False

def create_token(username: str) -> str:
    payload = {
        "sub": username,
        "role": "admin",
        "exp": datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

def slugify(text: str) -> str:
    text = text.lower().strip()
    # Turkish letter mapping
    tr_map = str.maketrans("çğıöşüâîû", "cgiosuaiu")
    text = text.translate(tr_map)
    text = re.sub(r"[^a-z0-9\s-]", "", text)
    text = re.sub(r"[\s_-]+", "-", text)
    text = text.strip("-")
    return text or "post"

async def require_admin(request: Request) -> dict:
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Yetkilendirme gerekli")
    token = auth[7:]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token süresi doldu")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Geçersiz token")
    if payload.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin yetkisi gerekli")
    return payload

# ─── MODELS ──────────────────────────────────
class LoginIn(BaseModel):
    username: str
    password: str
    verification_code: str

class PostIn(BaseModel):
    title: str
    slug: Optional[str] = None
    excerpt: Optional[str] = ""
    category: Optional[str] = "GENEL"
    content: Optional[str] = ""

class CommentIn(BaseModel):
    author: str = Field(..., min_length=1, max_length=60)
    body: str = Field(..., min_length=1, max_length=2000)

# ─── AUTH ────────────────────────────────────
@api.post("/auth/login")
async def login(payload: LoginIn):
    # Step1: verify admin user exists
    admin = await db.admin.find_one({"username": payload.username})
    if not admin or not verify_password(payload.password, admin["password_hash"]):
        raise HTTPException(status_code=401, detail="Kullanıcı adı veya şifre hatalı")
    # Step2: verify code
    if payload.verification_code != ADMIN_VERIFICATION_CODE:
        raise HTTPException(status_code=401, detail="Doğrulama kodu hatalı")
    token = create_token(payload.username)
    return {"access_token": token, "token_type": "bearer", "username": payload.username}

@api.get("/auth/me")
async def me(user=Depends(require_admin)):
    return {"username": user["sub"], "role": user["role"]}

# ─── POSTS ───────────────────────────────────
def serialize_post(p: dict) -> dict:
    return {
        "id": str(p["_id"]),
        "title": p["title"],
        "slug": p["slug"],
        "excerpt": p.get("excerpt", ""),
        "category": p.get("category", "GENEL"),
        "content": p.get("content", ""),
        "created_at": p["created_at"].isoformat() if isinstance(p.get("created_at"), datetime) else p.get("created_at"),
        "updated_at": p["updated_at"].isoformat() if isinstance(p.get("updated_at"), datetime) else p.get("updated_at"),
    }

@api.get("/posts")
async def list_posts():
    cursor = db.posts.find().sort("created_at", -1)
    out = []
    async for p in cursor:
        out.append(serialize_post(p))
    return out

@api.get("/posts/{slug}")
async def get_post(slug: str):
    p = await db.posts.find_one({"slug": slug})
    if not p:
        raise HTTPException(status_code=404, detail="Yazı bulunamadı")
    return serialize_post(p)

@api.post("/posts")
async def create_post(payload: PostIn, user=Depends(require_admin)):
    slug = payload.slug.strip() if payload.slug else slugify(payload.title)
    slug = slugify(slug)
    # ensure unique
    base = slug
    n = 2
    while await db.posts.find_one({"slug": slug}):
        slug = f"{base}-{n}"
        n += 1
    now = datetime.now(timezone.utc)
    doc = {
        "title": payload.title,
        "slug": slug,
        "excerpt": payload.excerpt or "",
        "category": payload.category or "GENEL",
        "content": payload.content or "",
        "created_at": now,
        "updated_at": now,
    }
    res = await db.posts.insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_post(doc)

@api.put("/posts/{slug}")
async def update_post(slug: str, payload: PostIn, user=Depends(require_admin)):
    existing = await db.posts.find_one({"slug": slug})
    if not existing:
        raise HTTPException(status_code=404, detail="Yazı bulunamadı")
    new_slug = existing["slug"]
    if payload.slug and slugify(payload.slug) != existing["slug"]:
        candidate = slugify(payload.slug)
        if await db.posts.find_one({"slug": candidate}):
            raise HTTPException(status_code=400, detail="Bu slug zaten kullanılıyor")
        new_slug = candidate
    update = {
        "title": payload.title,
        "slug": new_slug,
        "excerpt": payload.excerpt or "",
        "category": payload.category or existing.get("category", "GENEL"),
        "content": payload.content or "",
        "updated_at": datetime.now(timezone.utc),
    }
    await db.posts.update_one({"_id": existing["_id"]}, {"$set": update})
    p = await db.posts.find_one({"_id": existing["_id"]})
    return serialize_post(p)

@api.delete("/posts/{slug}")
async def delete_post(slug: str, user=Depends(require_admin)):
    res = await db.posts.delete_one({"slug": slug})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Yazı bulunamadı")
    await db.comments.delete_many({"post_slug": slug})
    return {"ok": True}

# ─── COMMENTS ────────────────────────────────
def serialize_comment(c: dict) -> dict:
    return {
        "id": str(c["_id"]),
        "post_slug": c["post_slug"],
        "author": c["author"],
        "body": c["body"],
        "created_at": c["created_at"].isoformat() if isinstance(c.get("created_at"), datetime) else c.get("created_at"),
    }

@api.get("/posts/{slug}/comments")
async def list_comments(slug: str):
    cursor = db.comments.find({"post_slug": slug}).sort("created_at", -1)
    out = []
    async for c in cursor:
        out.append(serialize_comment(c))
    return out

@api.post("/posts/{slug}/comments")
async def create_comment(slug: str, payload: CommentIn):
    p = await db.posts.find_one({"slug": slug})
    if not p:
        raise HTTPException(status_code=404, detail="Yazı bulunamadı")
    doc = {
        "post_slug": slug,
        "author": payload.author.strip()[:60],
        "body": payload.body.strip()[:2000],
        "created_at": datetime.now(timezone.utc),
    }
    res = await db.comments.insert_one(doc)
    doc["_id"] = res.inserted_id
    return serialize_comment(doc)

@api.delete("/comments/{cid}")
async def delete_comment(cid: str, user=Depends(require_admin)):
    try:
        oid = ObjectId(cid)
    except Exception:
        raise HTTPException(status_code=400, detail="Geçersiz ID")
    res = await db.comments.delete_one({"_id": oid})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Yorum bulunamadı")
    return {"ok": True}

# ─── HEALTH ──────────────────────────────────
@api.get("/")
async def root():
    return {"status": "ok", "service": "indirge-blog-api"}

# ─── STARTUP ─────────────────────────────────
@app.on_event("startup")
async def startup():
    # indexes
    await db.posts.create_index("slug", unique=True)
    await db.posts.create_index("created_at")
    await db.comments.create_index("post_slug")
    await db.admin.create_index("username", unique=True)
    # seed admin (idempotent)
    existing = await db.admin.find_one({"username": ADMIN_USERNAME})
    if not existing:
        await db.admin.insert_one({
            "username": ADMIN_USERNAME,
            "password_hash": hash_password(ADMIN_PASSWORD),
            "created_at": datetime.now(timezone.utc),
        })
    elif not verify_password(ADMIN_PASSWORD, existing["password_hash"]):
        await db.admin.update_one(
            {"username": ADMIN_USERNAME},
            {"$set": {"password_hash": hash_password(ADMIN_PASSWORD)}},
        )

app.include_router(api)
