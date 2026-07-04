import asyncio
import json
import os
import hashlib
import secrets
import time
import aiofiles
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo
from urllib.parse import quote
from collections import deque, defaultdict
from pathlib import Path

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect, Depends
from fastapi.responses import Response, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ARG-Gateway")

IRAN_TZ = ZoneInfo("Asia/Tehran")

app = FastAPI(title="ARG Gateway", docs_url=None, redoc_url=None)

CONFIG = {
    "port": int(os.environ.get("PORT", 8000)),
    "secret": os.environ.get("SECRET_KEY", secrets.token_urlsafe(32)),
    "host": os.environ.get("RAILWAY_PUBLIC_DOMAIN", "localhost"),
}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Persistence ───────────────────────────────────────────────────────────────
DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
DATA_FILE = DATA_DIR / "arg_state.json"
SAVE_LOCK = asyncio.Lock()

async def load_state():
    global LINKS, AUTH, SUBS, SUB_ADMINS
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        if DATA_FILE.exists():
            async with aiofiles.open(DATA_FILE, "r", encoding="utf-8") as f:
                raw = await f.read()
            data = json.loads(raw)
            LINKS.update(data.get("links", {}))
            SUBS.update(data.get("subs", {}))
            SUB_ADMINS.update(data.get("sub_admins", {}))
            if "password_hash" in data:
                AUTH["password_hash"] = data["password_hash"]
            logger.info(f"State loaded: {len(LINKS)} links, {len(SUBS)} subs, {len(SUB_ADMINS)} sub-admins")
    except Exception as e:
        logger.warning(f"Could not load state: {e}")

async def save_state():
    async with SAVE_LOCK:
        try:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            data = {
                "links": dict(LINKS),
                "subs": dict(SUBS),
                "sub_admins": dict(SUB_ADMINS),
                "password_hash": AUTH["password_hash"],
                "saved_at": datetime.now().isoformat(),
            }
            tmp = DATA_FILE.with_suffix(".tmp")
            async with aiofiles.open(tmp, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, ensure_ascii=False, indent=2))
            tmp.replace(DATA_FILE)
        except Exception as e:
            logger.warning(f"Could not save state: {e}")

# ── In-memory state ───────────────────────────────────────────────────────────
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
activity_logs: deque = deque(maxlen=200)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()
SUBS: dict = {}
SUBS_LOCK = asyncio.Lock()
SUB_ADMINS: dict = {}
SUB_ADMINS_LOCK = asyncio.Lock()

PROTOCOLS = ("vless-ws", "xhttp-packet-up", "xhttp-stream-up", "xhttp-stream-one")
DEFAULT_PROTOCOL = "vless-ws"

def log_activity(kind: str, message: str, level: str = "info"):
    activity_logs.append({
        "kind": kind,
        "level": level,
        "message": message,
        "time": datetime.now().isoformat(),
    })

# ── Auth ──────────────────────────────────────────────────────────────────────
SESSION_COOKIE = "arg_session"
SESSION_TTL = 60 * 60 * 24 * 7

def hash_password(pw: str) -> str:
    return hashlib.sha256(f"{pw}{CONFIG['secret']}".encode()).hexdigest()

AUTH = {"password_hash": hash_password(os.environ.get("ADMIN_PASSWORD", "123456"))}
SESSIONS: dict = {}
SESSIONS_LOCK = asyncio.Lock()

async def create_session(user_type="admin", username=None) -> str:
    token = secrets.token_urlsafe(32)
    async with SESSIONS_LOCK:
        SESSIONS[token] = {
            "exp": time.time() + SESSION_TTL,
            "user_type": user_type,
            "username": username
        }
    return token

async def is_valid_session(token: str | None) -> dict | None:
    if not token:
        return None
    async with SESSIONS_LOCK:
        session = SESSIONS.get(token)
        if session is None:
            return None
        if session.get("exp", 0) < time.time():
            SESSIONS.pop(token, None)
            return None
        return session

async def destroy_session(token: str | None):
    if not token:
        return
    async with SESSIONS_LOCK:
        SESSIONS.pop(token, None)

async def require_auth(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    session = await is_valid_session(token)
    if not session:
        raise HTTPException(status_code=401, detail="unauthorized")
    
    user_type = session.get("user_type", "admin")
    username = session.get("username")
    
    if user_type == "sub_admin" and username:
        async with SUB_ADMINS_LOCK:
            admin = SUB_ADMINS.get(username)
            if not admin:
                raise HTTPException(status_code=403, detail="حساب کاربری پیدا نشد")
            if not admin.get("active", True):
                raise HTTPException(status_code=403, detail="حساب کاربری غیرفعال است")
            remaining = admin.get("quota_bytes", 0) - admin.get("used_bytes", 0)
            if remaining <= 0:
                raise HTTPException(status_code=403, detail="سهمیه شما به پایان رسیده است")
    
    return {"token": token, "session": session}

# ── Startup / Shutdown ────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(
        limits=limits, timeout=timeout, follow_redirects=True,
    )
    await load_state()
    log_activity("system", "سرور راه‌اندازی شد", "ok")
    logger.info(f"ARG Gateway v9.2 started on port {CONFIG['port']}")

@app.on_event("shutdown")
async def shutdown():
    await save_state()
    if http_client:
        await http_client.aclose()

# ── Helpers ───────────────────────────────────────────────────────────────────
def get_host() -> str:
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN", CONFIG["host"])

def generate_uuid() -> str:
    h = secrets.token_hex(16)
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"
    
def now_ir() -> datetime:
    return datetime.now(IRAN_TZ)

def generate_vless_link(uuid: str, host: str, remark: str = "ARG", protocol: str = DEFAULT_PROTOCOL) -> str:
    if protocol == "vless-ws":
        path = f"/ws/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": "chrome",
            "alpn": "http/1.1",
        }
    else:
        mode = protocol.replace("xhttp-", "")
        path = f"/xhttp-siz10/{mode}/{uuid}"
        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": "chrome",
            "alpn": "h2,http/1.1",
        }
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:443?{query}#{quote(remark)}"

def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB": return int(value * 1024 ** 3)
    if unit == "MB": return int(value * 1024 ** 2)
    if unit == "KB": return int(value * 1024)
    return int(value)

def is_link_expired(link: dict) -> bool:
    exp = link.get("expires_at")
    if not exp:
        return False
    try:
        return datetime.now() > datetime.fromisoformat(exp)
    except Exception:
        return False

def is_link_allowed(link: dict | None) -> bool:
    if link is None:
        return False
    if not link.get("active", True):
        return False
    if is_link_expired(link):
        return False
    lb = link.get("limit_bytes", 0)
    if lb > 0 and link.get("used_bytes", 0) >= lb:
        return False
    return True

def fmt_bytes(b: int) -> str:
    if b < 1024: return f"{b} B"
    if b < 1024**2: return f"{b/1024:.1f} KB"
    if b < 1024**3: return f"{b/1024**2:.2f} MB"
    return f"{b/1024**3:.2f} GB"

def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip.strip()
    return request.client.host if request.client else "نامشخص"

# ── Sub-Admin Functions ──────────────────────────────────────────────────────
async def get_sub_admin(username: str) -> dict | None:
    async with SUB_ADMINS_LOCK:
        return SUB_ADMINS.get(username)

async def use_sub_admin_quota(username: str, bytes_used: int) -> bool:
    async with SUB_ADMINS_LOCK:
        if username not in SUB_ADMINS:
            return False
        admin = SUB_ADMINS[username]
        quota = admin.get("quota_bytes", 0)
        used = admin.get("used_bytes", 0)
        if not admin.get("active", True):
            return False
        if quota > 0 and (used + bytes_used) > quota:
            return False
        admin["used_bytes"] = used + bytes_used
        asyncio.create_task(save_state())
        return True

# ── Default link ──────────────────────────────────────────────────────────────
_default_link_created = False

async def ensure_default_link():
    global _default_link_created
    if _default_link_created:
        return
    async with LINKS_LOCK:
        if not any(l.get("is_default") for l in LINKS.values()):
            uid = hashlib.sha256(f"default{CONFIG['secret']}".encode()).hexdigest()
            uid = f"{uid[:8]}-{uid[8:12]}-{uid[12:16]}-{uid[16:20]}-{uid[20:32]}"
            if uid not in LINKS:
                LINKS[uid] = {
                    "label": "لینک پیش‌فرض",
                    "limit_bytes": 0,
                    "used_bytes": 0,
                    "created_at": datetime.now().isoformat(),
                    "active": True,
                    "expires_at": None,
                    "note": "",
                    "is_default": True,
                    "sub_id": None,
                    "protocol": DEFAULT_PROTOCOL,
                    "created_by": None,
                }
                asyncio.create_task(save_state())
        _default_link_created = True

# ── Basic endpoints ───────────────────────────────────────────────────────────
@app.get("/")
async def root():
    return {"service": "ARG Gateway", "version": "9.2", "status": "active"}

@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}

# ── Subscription ──────────────────────────────────────────────────────────────
@app.get("/sub/{uuid}")
async def subscription_single(uuid: str):
    import base64
    async with LINKS_LOCK:
        link = LINKS.get(uuid)
    if not link or not is_link_allowed(link):
        raise HTTPException(status_code=404, detail="not found or inactive")
    host = get_host()
    proto = link.get("protocol", DEFAULT_PROTOCOL)
    vless = generate_vless_link(uuid, host, remark=f"ARG-{link['label']}", protocol=proto)
    content = base64.b64encode(vless.encode()).decode()
    return Response(content=content, media_type="text/plain",
                    headers={"profile-title": quote(link["label"])})

@app.get("/sub-all")
async def subscription_all(_=Depends(require_auth)):
    import base64
    host = get_host()
    async with LINKS_LOCK:
        lines = [
            generate_vless_link(uid, host, remark=f"ARG-{d['label']}", protocol=d.get("protocol", DEFAULT_PROTOCOL))
            for uid, d in LINKS.items()
            if is_link_allowed(d)
        ]
    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(content=content, media_type="text/plain")

# ── Sub Groups ─────────────────────────────────────────────────────────────────
@app.post("/api/subs")
async def create_sub(request: Request, auth=Depends(require_auth)):
    # ✅ فقط ادمین اصلی
    if auth["session"].get("user_type") == "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    
    body = await request.json()
    name = (body.get("name") or "گروه جدید").strip()[:60]
    desc = (body.get("desc") or "").strip()[:200]
    password = (body.get("password") or "").strip()
    sub_id = generate_uuid()
    uuid_key = secrets.token_urlsafe(16)
    async with SUBS_LOCK:
        SUBS[sub_id] = {
            "name": name,
            "desc": desc,
            "password_hash": hash_password(password) if password else None,
            "uuid_key": uuid_key,
            "created_at": datetime.now().isoformat(),
            "link_ids": [],
        }
    asyncio.create_task(save_state())
    log_activity("sub", f"گروه «{name}» ساخته شد", "ok")
    host = get_host()
    return {
        "sub_id": sub_id,
        **SUBS[sub_id],
        "public_url": f"https://{host}/p/{uuid_key}",
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
    }

@app.get("/api/subs")
async def list_subs(auth=Depends(require_auth)):
    # ✅ فقط ادمین اصلی
    if auth["session"].get("user_type") == "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    
    host = get_host()
    async with SUBS_LOCK:
        snap_subs = dict(SUBS)
    async with LINKS_LOCK:
        snap_links = dict(LINKS)
    result = []
    for sid, s in snap_subs.items():
        link_ids = s.get("link_ids", [])
        active_count = sum(1 for lid in link_ids if is_link_allowed(snap_links.get(lid)))
        total_used = sum(snap_links[lid].get("used_bytes", 0) for lid in link_ids if lid in snap_links)
        result.append({
            "sub_id": sid,
            **s,
            "password_hash": None,
            "has_password": s.get("password_hash") is not None,
            "links_count": len(link_ids),
            "active_count": active_count,
            "total_used_bytes": total_used,
            "total_used_fmt": fmt_bytes(total_used),
            "public_url": f"https://{host}/p/{s['uuid_key']}",
            "sub_url": f"https://{host}/sub-group/{s['uuid_key']}",
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"subs": result}

@app.patch("/api/subs/{sub_id}")
async def update_sub(sub_id: str, request: Request, auth=Depends(require_auth)):
    # ✅ فقط ادمین اصلی
    if auth["session"].get("user_type") == "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    
    body = await request.json()
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        if "name" in body:
            s["name"] = str(body["name"])[:60]
        if "desc" in body:
            s["desc"] = str(body["desc"])[:200]
        if "password" in body:
            pw = str(body["password"]).strip()
            s["password_hash"] = hash_password(pw) if pw else None
        if "link_ids" in body:
            s["link_ids"] = list(body["link_ids"])
    asyncio.create_task(save_state())
    return {"ok": True}

@app.delete("/api/subs/{sub_id}")
async def delete_sub(sub_id: str, auth=Depends(require_auth)):
    # ✅ فقط ادمین اصلی
    if auth["session"].get("user_type") == "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        name = SUBS[sub_id].get("name", sub_id)
        del SUBS[sub_id]
    async with LINKS_LOCK:
        for link in LINKS.values():
            if link.get("sub_id") == sub_id:
                link["sub_id"] = None
    asyncio.create_task(save_state())
    log_activity("sub", f"گروه «{name}» حذف شد", "warn")
    return {"ok": True, "deleted": sub_id}

@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(sub_id: str, request: Request, auth=Depends(require_auth)):
    # ✅ فقط ادمین اصلی
    if auth["session"].get("user_type") == "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    
    body = await request.json()
    link_id = str(body.get("link_id", ""))
    action = str(body.get("action", "add"))
    async with SUBS_LOCK:
        if sub_id not in SUBS:
            raise HTTPException(status_code=404, detail="sub not found")
        s = SUBS[sub_id]
        ids = s.setdefault("link_ids", [])
        if action == "add":
            if link_id not in ids:
                ids.append(link_id)
        else:
            if link_id in ids:
                ids.remove(link_id)
    async with LINKS_LOCK:
        if link_id in LINKS:
            LINKS[link_id]["sub_id"] = sub_id if action == "add" else None
    asyncio.create_task(save_state())
    return {"ok": True}

# ── Public sub-group subscription ────────────────────────────────────────────
@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(uuid_key: str, request: Request):
    import base64
    async with SUBS_LOCK:
        sub = next((s for s in SUBS.values() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        raise HTTPException(status_code=404, detail="not found")

    if sub.get("password_hash"):
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            raise HTTPException(status_code=403, detail="wrong password")

    host = get_host()
    link_ids = sub.get("link_ids", [])
    async with LINKS_LOCK:
        lines = []
        for lid in link_ids:
            link = LINKS.get(lid)
            if link and is_link_allowed(link):
                lines.append(generate_vless_link(lid, host, remark=f"ARG-{link['label']}", protocol=link.get("protocol", DEFAULT_PROTOCOL)))

    content = base64.b64encode("\n".join(lines).encode()).decode()
    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "profile-title": quote(sub["name"]),
            "profile-update-interval": "12",
        }
    )

# ── Auth endpoints ────────────────────────────────────────────────────────────
@app.post("/api/login")
async def api_login(request: Request):
    body = await request.json()
    ip = client_ip(request)
    if hash_password(str(body.get("password", ""))) != AUTH["password_hash"]:
        log_activity("auth", f"تلاش ورود ناموفق از {ip}", "err")
        raise HTTPException(status_code=401, detail="رمز عبور اشتباه است")
    token = await create_session()
    log_activity("auth", f"ورود موفق به پنل از {ip}", "ok")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.post("/api/logout")
async def api_logout(request: Request):
    await destroy_session(request.cookies.get(SESSION_COOKIE))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(SESSION_COOKIE, path="/")
    return resp

@app.get("/api/me")
async def api_me(request: Request):
    session = await is_valid_session(request.cookies.get(SESSION_COOKIE))
    return {"authenticated": session is not None}

@app.post("/api/change-password")
async def api_change_password(request: Request, auth=Depends(require_auth)):
    # ✅ فقط ادمین اصلی
    if auth["session"].get("user_type") == "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    
    body = await request.json()
    if hash_password(str(body.get("current_password", ""))) != AUTH["password_hash"]:
        raise HTTPException(status_code=400, detail="رمز فعلی اشتباه است")
    new = str(body.get("new_password", ""))
    if len(new) < 4:
        raise HTTPException(status_code=400, detail="رمز جدید باید حداقل ۴ کاراکتر باشد")
    AUTH["password_hash"] = hash_password(new)
    async with SESSIONS_LOCK:
        for token, session in list(SESSIONS.items()):
            if session.get("user_type") == "admin":
                SESSIONS.pop(token, None)
    token = await create_session()
    await save_state()
    log_activity("auth", "رمز عبور پنل تغییر کرد", "ok")
    resp = JSONResponse({"ok": True})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

# ── Sub-Admin Login ──────────────────────────────────────────────────────────
@app.get("/admin_gigi", response_class=HTMLResponse)
async def sub_admin_login_page(request: Request):
    from pages import SUB_ADMIN_LOGIN_HTML
    return HTMLResponse(content=SUB_ADMIN_LOGIN_HTML)

@app.post("/api/sub-admin/login")
async def sub_admin_login(request: Request):
    body = await request.json()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", "")).strip()
    ip = client_ip(request)
    
    async with SUB_ADMINS_LOCK:
        admin = SUB_ADMINS.get(username)
        if not admin:
            log_activity("sub_admin_auth", f"تلاش ورود ناموفق (کاربر不存在) از {ip}", "err")
            raise HTTPException(status_code=401, detail="نام کاربری یا رمز عبور اشتباه است")
        if not admin.get("active", True):
            raise HTTPException(status_code=403, detail="حساب کاربری غیرفعال است")
        if hash_password(password) != admin.get("password_hash"):
            log_activity("sub_admin_auth", f"تلاش ورود ناموفق (رمز اشتباه) از {ip}", "err")
            raise HTTPException(status_code=401, detail="نام کاربری یا رمز عبور اشتباه است")
        remaining = admin.get("quota_bytes", 0) - admin.get("used_bytes", 0)
        if remaining <= 0:
            log_activity("sub_admin_auth", f"تلاش ورود با سهمیه تمام شده از {ip}", "warn")
            raise HTTPException(status_code=403, detail="سهمیه شما به پایان رسیده است")
    
    token = await create_session(user_type="sub_admin", username=username)
    log_activity("sub_admin_auth", f"ورود موفق ادمین فرعی «{username}» از {ip}", "ok")
    resp = JSONResponse({"ok": True, "user_type": "sub_admin", "username": username})
    resp.set_cookie(SESSION_COOKIE, token, max_age=SESSION_TTL, httponly=True, samesite="lax", path="/")
    return resp

@app.get("/api/sub-admin/status")
async def sub_admin_status(auth=Depends(require_auth)):
    # ✅ فقط ادمین فرعی
    session = auth["session"]
    if session.get("user_type") != "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی فقط برای ادمین‌های فرعی")
    username = session.get("username")
    
    async with SUB_ADMINS_LOCK:
        admin = SUB_ADMINS.get(username)
        if not admin:
            raise HTTPException(status_code=404, detail="ادمین پیدا نشد")
        quota = admin.get("quota_bytes", 0)
        used = admin.get("used_bytes", 0)
        remaining = quota - used
        return {
            "username": username,
            "quota_bytes": quota,
            "quota_fmt": fmt_bytes(quota),
            "used_bytes": used,
            "used_fmt": fmt_bytes(used),
            "remaining_bytes": remaining if remaining > 0 else 0,
            "remaining_fmt": fmt_bytes(remaining) if remaining > 0 else "۰",
            "used_percent": round((used / quota) * 100) if quota > 0 else 0,
            "is_exhausted": remaining <= 0,
            "active": admin.get("active", True),
        }

# ── Sub-Admin Management (فقط ادمین اصلی) ──────────────────────────────────
@app.post("/api/sub-admins")
async def create_sub_admin(request: Request, auth=Depends(require_auth)):
    # ✅ فقط ادمین اصلی
    if auth["session"].get("user_type") == "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    
    body = await request.json()
    username = str(body.get("username", "")).strip()
    password = str(body.get("password", "")).strip()
    quota_gb = float(body.get("quota_gb", 2))
    
    if not username or len(username) < 3:
        raise HTTPException(status_code=400, detail="نام کاربری حداقل ۳ کاراکتر")
    if not password or len(password) < 4:
        raise HTTPException(status_code=400, detail="رمز عبور حداقل ۴ کاراکتر")
    if quota_gb < 0.1:
        raise HTTPException(status_code=400, detail="سهمیه باید حداقل ۰.۱ گیگ باشد")
    
    async with SUB_ADMINS_LOCK:
        if username in SUB_ADMINS:
            raise HTTPException(status_code=400, detail="این نام کاربری قبلاً ثبت شده")
        SUB_ADMINS[username] = {
            "password_hash": hash_password(password),
            "quota_bytes": int(quota_gb * 1024 ** 3),
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
        }
    
    asyncio.create_task(save_state())
    log_activity("sub_admin", f"ادمین فرعی «{username}» با سهمیه {quota_gb}GB ساخته شد", "ok")
    return {"ok": True, "username": username, "quota_gb": quota_gb}

@app.get("/api/sub-admins")
async def list_sub_admins(auth=Depends(require_auth)):
    # ✅ فقط ادمین اصلی
    if auth["session"].get("user_type") == "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    
    async with SUB_ADMINS_LOCK:
        result = []
        for username, data in SUB_ADMINS.items():
            quota = data.get("quota_bytes", 0)
            used = data.get("used_bytes", 0)
            result.append({
                "username": username,
                "quota_gb": round(quota / 1024**3, 2),
                "used_gb": round(used / 1024**3, 2),
                "remaining_gb": round((quota - used) / 1024**3, 2),
                "used_percent": round((used / quota) * 100) if quota > 0 else 0,
                "created_at": data.get("created_at"),
                "active": data.get("active", True),
            })
        return {"sub_admins": result}

@app.delete("/api/sub-admins/{username}")
async def delete_sub_admin(username: str, auth=Depends(require_auth)):
    # ✅ فقط ادمین اصلی
    if auth["session"].get("user_type") == "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    
    async with SUB_ADMINS_LOCK:
        if username not in SUB_ADMINS:
            raise HTTPException(status_code=404, detail="ادمین پیدا نشد")
        del SUB_ADMINS[username]
    asyncio.create_task(save_state())
    log_activity("sub_admin", f"ادمین فرعی «{username}» حذف شد", "warn")
    return {"ok": True}

# ── Stats ─────────────────────────────────────────────────────────────────────
@app.get("/stats")
async def get_stats(auth=Depends(require_auth)):
    # ✅ فقط ادمین اصلی
    if auth["session"].get("user_type") == "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    
    async with LINKS_LOCK:
        snap = dict(LINKS)
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 ** 2), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": datetime.now().isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(snap),
        "active_links": sum(1 for l in snap.values() if is_link_allowed(l)),
        "expired_links": sum(1 for l in snap.values() if is_link_expired(l)),
        "subs_count": len(SUBS),
    }

# ── Activity Logs ─────────────────────────────────────────────────────────────
@app.get("/api/activity")
async def get_activity(auth=Depends(require_auth)):
    # ✅ فقط ادمین اصلی - ادمین فرعی دسترسی نداره
    if auth["session"].get("user_type") == "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    return {"logs": list(activity_logs)[-150:]}

# ── Live connections ──────────────────────────────────────────────────────────
@app.get("/api/connections")
async def get_connections(auth=Depends(require_auth)):
    # ✅ فقط ادمین اصلی
    if auth["session"].get("user_type") == "sub_admin":
        raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
    
    async with LINKS_LOCK:
        snap = dict(LINKS)

    grouped: dict[str, dict] = {}
    for conn_id, c in connections.items():
        ip = c.get("ip", "نامشخص")
        link = snap.get(c.get("uuid"))
        label = link.get("label") if link else "نامشخص"
        g = grouped.get(ip)
        if g is None:
            g = {
                "ip": ip,
                "sessions": 0,
                "bytes": 0,
                "labels": set(),
                "transports": set(),
                "first_connected_at": c.get("connected_at"),
                "last_connected_at": c.get("connected_at"),
            }
            grouped[ip] = g
        g["sessions"] += 1
        g["bytes"] += c.get("bytes", 0)
        g["labels"].add(label)
        g["transports"].add(c.get("transport", "vless-ws"))
        ca = c.get("connected_at")
        if ca:
            if not g["first_connected_at"] or ca < g["first_connected_at"]:
                g["first_connected_at"] = ca
            if not g["last_connected_at"] or ca > g["last_connected_at"]:
                g["last_connected_at"] = ca

    result = []
    for ip, g in grouped.items():
        result.append({
            "ip": ip,
            "sessions": g["sessions"],
            "labels": sorted(g["labels"]),
            "label": " · ".join(sorted(g["labels"])) if g["labels"] else "نامشخص",
            "transports": sorted(g["transports"]),
            "bytes": g["bytes"],
            "bytes_fmt": fmt_bytes(g["bytes"]),
            "connected_at": g["first_connected_at"],
            "last_connected_at": g["last_connected_at"],
        })
    result.sort(key=lambda x: x.get("last_connected_at") or "", reverse=True)

    return {
        "connections": result,
        "count": len(result),
        "raw_count": len(connections),
    }

# ── Link Management ───────────────────────────────────────────────────────────
@app.post("/api/links")
async def create_link(request: Request, auth=Depends(require_auth)):
    # ✅ هم ادمین اصلی و هم ادمین فرعی
    body = await request.json()
    label = (body.get("label") or "لینک جدید").strip()[:60]
    lv = float(body.get("limit_value") or 0)
    lu = body.get("limit_unit") or "GB"
    limit_bytes = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
    exp_days = int(body.get("expires_days") or 0)
    expires_at = (datetime.now() + timedelta(days=exp_days)).isoformat() if exp_days > 0 else None
    note = (body.get("note") or "").strip()[:200]
    sub_id = body.get("sub_id") or None
    protocol = body.get("protocol") or DEFAULT_PROTOCOL
    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    created_by = None
    session = auth["session"]
    if session.get("user_type") == "sub_admin":
        username = session.get("username")
        created_by = username
        async with SUB_ADMINS_LOCK:
            admin = SUB_ADMINS.get(username)
            if admin:
                remaining = admin.get("quota_bytes", 0) - admin.get("used_bytes", 0)
                if remaining <= 0:
                    raise HTTPException(status_code=403, detail="سهمیه شما به پایان رسیده است")

    uid = generate_uuid()
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
            "expires_at": expires_at,
            "note": note,
            "is_default": False,
            "sub_id": sub_id,
            "protocol": protocol,
            "created_by": created_by,
        }

    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{label}» ساخته شد", "ok")
    host = get_host()
    return {
        "uuid": uid,
        **LINKS[uid],
        "expired": False,
        "vless_link": generate_vless_link(uid, host, remark=f"ARG-{label}", protocol=protocol),
        "sub_url": f"https://{host}/sub/{uid}",
    }

@app.get("/api/links")
async def list_links(auth=Depends(require_auth)):
    # ✅ ادمین اصلی همه رو میبینه، ادمین فرعی فقط کانفیگ‌های خودش
    host = get_host()
    async with LINKS_LOCK:
        snap = dict(LINKS)
    
    if auth["session"].get("user_type") == "sub_admin":
        username = auth["session"].get("username")
        snap = {uid: d for uid, d in snap.items() if d.get("created_by") == username}
    
    result = []
    for uid, d in snap.items():
        proto = d.get("protocol", DEFAULT_PROTOCOL)
        result.append({
            "uuid": uid,
            **d,
            "protocol": proto,
            "expired": is_link_expired(d),
            "vless_link": generate_vless_link(uid, host, remark=f"ARG-{d['label']}", protocol=proto),
            "sub_url": f"https://{host}/sub/{uid}",
        })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}

@app.patch("/api/links/{uid}")
async def update_link(uid: str, request: Request, auth=Depends(require_auth)):
    # ✅ ادمین اصلی همه رو ویرایش کنه، ادمین فرعی فقط کانفیگ‌های خودش
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        link = LINKS[uid]
        
        if auth["session"].get("user_type") == "sub_admin":
            if link.get("created_by") != auth["session"].get("username"):
                raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
        
        old_sub = link.get("sub_id")
        label = link.get("label")
        if "active" in body:
            link["active"] = bool(body["active"])
            log_activity("link", f"کانفیگ «{label}» {'فعال' if link['active'] else 'غیرفعال'} شد", "ok" if link["active"] else "warn")
        if "label" in body:
            link["label"] = str(body["label"])[:60]
        if "note" in body:
            link["note"] = str(body["note"])[:200]
        if "reset_usage" in body and body["reset_usage"]:
            link["used_bytes"] = 0
            log_activity("link", f"مصرف کانفیگ «{label}» ریست شد", "info")
        if "limit_value" in body:
            lv = float(body.get("limit_value") or 0)
            lu = body.get("limit_unit") or "GB"
            link["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, lu)
        if "expires_days" in body:
            ed = int(body["expires_days"] or 0)
            link["expires_at"] = (datetime.now() + timedelta(days=ed)).isoformat() if ed > 0 else None
        if any(k in body for k in ("label", "note", "limit_value", "expires_days")):
            log_activity("link", f"کانفیگ «{link['label']}» ویرایش شد", "info")
        new_sub = body.get("sub_id", "UNCHANGED")
        if new_sub != "UNCHANGED":
            link["sub_id"] = new_sub or None

    if new_sub != "UNCHANGED":
        async with SUBS_LOCK:
            if old_sub and old_sub in SUBS:
                ids = SUBS[old_sub].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
            if new_sub and new_sub in SUBS:
                ids = SUBS[new_sub].setdefault("link_ids", [])
                if uid not in ids:
                    ids.append(uid)

    asyncio.create_task(save_state())
    return {"ok": True}

@app.delete("/api/links/{uid}")
async def delete_link(uid: str, auth=Depends(require_auth)):
    # ✅ ادمین اصلی همه رو حذف کنه، ادمین فرعی فقط کانفیگ‌های خودش
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        
        if auth["session"].get("user_type") == "sub_admin":
            if LINKS[uid].get("created_by") != auth["session"].get("username"):
                raise HTTPException(status_code=403, detail="دسترسی غیرمجاز")
        
        label = LINKS[uid].get("label", uid)
        sub_id = LINKS[uid].get("sub_id")
        del LINKS[uid]
    if sub_id:
        async with SUBS_LOCK:
            if sub_id in SUBS:
                ids = SUBS[sub_id].get("link_ids", [])
                if uid in ids:
                    ids.remove(uid)
    asyncio.create_task(save_state())
    log_activity("link", f"کانفیگ «{label}» حذف شد", "err")
    return {"ok": True, "deleted": uid}

# ══════════════════════════════════════════════════════════════════════════════
# VLESS Relay
# ══════════════════════════════════════════════════════════════════════════════

from relay_vless import (
    RELAY_BUF,
    parse_vless_header,
    check_and_use,
    relay_ws_to_tcp,
    relay_tcp_to_ws,
    websocket_tunnel,
)

app.add_api_websocket_route("/ws/{uuid}", websocket_tunnel)

# ══════════════════════════════════════════════════════════════════════════════
# XHTTP
# ══════════════════════════════════════════════════════════════════════════════
from xhttp_siz10 import router as xhttp_router
app.include_router(xhttp_router)

# ── HTTP Proxy ────────────────────────────────────────────────────────────────
_HOP = {"connection","keep-alive","proxy-authenticate","proxy-authorization",
        "te","trailers","transfer-encoding","upgrade","content-encoding","content-length"}

@app.api_route("/proxy/{target_url:path}", methods=["GET","POST","PUT","DELETE","PATCH","HEAD","OPTIONS"])
async def http_proxy(target_url: str, request: Request):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url
    try:
        body = await request.body()
        headers = {k: v for k, v in request.headers.items() if k.lower() not in _HOP and k.lower() != "host"}
        resp = await http_client.request(method=request.method, url=target_url, headers=headers, content=body)
        stats["total_bytes"] += len(resp.content)
        stats["total_requests"] += 1
        hourly_traffic[now_ir().strftime("%H:00")] += len(resp.content)
        return Response(content=resp.content, status_code=resp.status_code,
                        headers={k: v for k, v in resp.headers.items() if k.lower() not in _HOP})
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")

# ── Public sub page ───────────────────────────────────────────────────────────
@app.get("/p/{uuid_key}", response_class=HTMLResponse)
async def public_sub_page(uuid_key: str, request: Request):
    from pages import get_public_page_html
    async with SUBS_LOCK:
        sub = next(({"sub_id": sid, **s} for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub:
        return HTMLResponse("<h2 style='font-family:sans-serif;padding:40px'>گروه پیدا نشد</h2>", status_code=404)
    return HTMLResponse(content=get_public_page_html(uuid_key))

@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(uuid_key: str, request: Request):
    async with SUBS_LOCK:
        sub_entry = next(((sid, s) for sid, s in SUBS.items() if s.get("uuid_key") == uuid_key), None)
    if not sub_entry:
        raise HTTPException(status_code=404, detail="not found")
    sub_id, sub = sub_entry

    has_pw = sub.get("password_hash") is not None
    if has_pw:
        pw = request.query_params.get("pw", "")
        if hash_password(pw) != sub["password_hash"]:
            return JSONResponse({"locked": True, "name": sub["name"]})

    host = get_host()
    link_ids = sub.get("link_ids", [])
    async with LINKS_LOCK:
        snap = dict(LINKS)

    links_out = []
    active_conns = 0
    for lid in link_ids:
        link = snap.get(lid)
        if not link:
            continue
        allowed = is_link_allowed(link)
        conn_count = sum(1 for c in connections.values() if c.get("uuid") == lid)
        active_conns += conn_count
        proto = link.get("protocol", DEFAULT_PROTOCOL)
        links_out.append({
            "uuid": lid,
            "label": link["label"],
            "active": allowed,
            "protocol": proto,
            "used_bytes": link.get("used_bytes", 0),
            "used_fmt": fmt_bytes(link.get("used_bytes", 0)),
            "limit_bytes": link.get("limit_bytes", 0),
            "limit_fmt": "∞" if link.get("limit_bytes", 0) == 0 else fmt_bytes(link["limit_bytes"]),
            "expires_at": link.get("expires_at"),
            "vless_link": generate_vless_link(lid, host, remark=f"ARG-{link['label']}", protocol=proto),
            "sub_url": f"https://{host}/sub/{lid}",
            "connections": conn_count,
        })

    total_used = sum(l["used_bytes"] for l in links_out)
    return {
        "locked": False,
        "name": sub["name"],
        "desc": sub.get("desc", ""),
        "sub_url": f"https://{host}/sub-group/{uuid_key}",
        "active_connections": active_conns,
        "total_used_fmt": fmt_bytes(total_used),
        "links": links_out,
    }

# ── HTML Pages ────────────────────────────────────────────────────────────────
from pages import LOGIN_HTML, DASHBOARD_HTML

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    if await is_valid_session(request.cookies.get(SESSION_COOKIE)):
        return RedirectResponse(url="/dashboard")
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    session = await is_valid_session(request.cookies.get(SESSION_COOKIE))
    if not session:
        return RedirectResponse(url="/login")
    await ensure_default_link()
    return HTMLResponse(content=DASHBOARD_HTML)

@app.get("/test-ws", response_class=HTMLResponse)
async def test_ws_redirect():
    return HTMLResponse(content="<script>location.href='/dashboard'</script>")

if __name__ == "__main__":
    uvicorn.run("main:app", host="0.0.0.0", port=CONFIG["port"], log_level="info", workers=1)
