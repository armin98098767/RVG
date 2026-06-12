import asyncio
import json
import os
import hashlib
import secrets
import time
from datetime import datetime
from urllib.parse import quote
from collections import deque, defaultdict

from fastapi import FastAPI, Request, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import Response, PlainTextResponse, HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import httpx
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("RVG-Gateway")

app = FastAPI(title="RVG Gateway – codebox", docs_url=None, redoc_url=None)

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

# ───────── State (in-memory) ─────────
connections: dict = {}
stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}
error_logs: deque = deque(maxlen=50)
hourly_traffic: dict = defaultdict(int)
http_client: httpx.AsyncClient | None = None

# لینک‌های ساخته‌شده توسط کاربران: uuid -> {label, limit_bytes(0=unlimited), used_bytes, created_at, active}
LINKS: dict = {}
LINKS_LOCK = asyncio.Lock()


# ───────── Startup / Shutdown ─────────
@app.on_event("startup")
async def startup():
    global http_client
    limits = httpx.Limits(max_connections=500, max_keepalive_connections=100)
    timeout = httpx.Timeout(30.0, connect=10.0)
    http_client = httpx.AsyncClient(limits=limits, timeout=timeout, follow_redirects=True)
    logger.info(f"🚀 RVG Gateway started on port {CONFIG['port']}")


@app.on_event("shutdown")
async def shutdown():
    if http_client:
        await http_client.aclose()


# ───────── Helpers ─────────
def get_host() -> str:
    return os.environ.get("RAILWAY_PUBLIC_DOMAIN", CONFIG["host"])


def generate_uuid(seed: str | None = None) -> str:
    if seed is None:
        return str(secrets.token_hex(16))[:8] + "-" + secrets.token_hex(2) + "-" + \
               secrets.token_hex(2) + "-" + secrets.token_hex(2) + "-" + secrets.token_hex(6)
    h = hashlib.sha256(f"{seed}{CONFIG['secret']}".encode()).hexdigest()
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


def generate_vless_link(uuid: str, host: str, remark: str = "RVG-Railway") -> str:
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
    query = "&".join(f"{k}={quote(str(v))}" for k, v in params.items())
    return f"vless://{uuid}@{host}:443?{query}#{quote(remark)}"


def uptime() -> str:
    secs = int(time.time() - stats["start_time"])
    h, m, s = secs // 3600, (secs % 3600) // 60, secs % 60
    return f"{h:02d}:{m:02d}:{s:02d}"


def parse_size_to_bytes(value: float, unit: str) -> int:
    unit = unit.upper()
    if unit == "GB":
        return int(value * 1024 * 1024 * 1024)
    if unit == "MB":
        return int(value * 1024 * 1024)
    if unit == "KB":
        return int(value * 1024)
    return int(value)


# ───────── Default link (auto-created on first request) ─────────
async def ensure_default_link():
    async with LINKS_LOCK:
        if not LINKS:
            uid = generate_uuid("default")
            LINKS[uid] = {
                "label": "لینک پیش‌فرض",
                "limit_bytes": 0,  # unlimited
                "used_bytes": 0,
                "created_at": datetime.now().isoformat(),
                "active": True,
            }


# ───────── Basic endpoints ─────────
@app.get("/")
async def root():
    return {
        "service": "RVG Gateway – codebox",
        "version": "6.0",
        "status": "active",
        "channel": "https://t.me/CodeBoxo",
        "host": get_host(),
    }


@app.get("/health")
async def health():
    return {"status": "ok", "connections": len(connections), "uptime": uptime()}


@app.get("/stats")
async def get_stats():
    now = datetime.now()
    return {
        "active_connections": len(connections),
        "total_traffic_mb": round(stats["total_bytes"] / (1024 * 1024), 2),
        "total_requests": stats["total_requests"],
        "total_errors": stats["total_errors"],
        "uptime": uptime(),
        "timestamp": now.isoformat(),
        "hourly": dict(hourly_traffic),
        "recent_errors": list(error_logs)[-10:],
        "links_count": len(LINKS),
    }


# ───────── Link Management API ─────────
@app.post("/api/links")
async def create_link(request: Request):
    body = await request.json()
    label = (body.get("label") or "لینک جدید").strip()[:60]
    limit_value = float(body.get("limit_value") or 0)
    limit_unit = body.get("limit_unit") or "GB"

    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)

    uid = generate_uuid()  # کاملا رندوم
    async with LINKS_LOCK:
        LINKS[uid] = {
            "label": label,
            "limit_bytes": limit_bytes,
            "used_bytes": 0,
            "created_at": datetime.now().isoformat(),
            "active": True,
        }

    host = get_host()
    return {
        "uuid": uid,
        "label": label,
        "limit_bytes": limit_bytes,
        "used_bytes": 0,
        "active": True,
        "created_at": LINKS[uid]["created_at"],
        "vless_link": generate_vless_link(uid, host, remark=f"RVG-{label}"),
    }


@app.get("/api/links")
async def list_links():
    host = get_host()
    result = []
    async with LINKS_LOCK:
        for uid, data in LINKS.items():
            result.append({
                "uuid": uid,
                "label": data["label"],
                "limit_bytes": data["limit_bytes"],
                "used_bytes": data["used_bytes"],
                "active": data["active"],
                "created_at": data["created_at"],
                "vless_link": generate_vless_link(uid, host, remark=f"RVG-{data['label']}"),
            })
    result.sort(key=lambda x: x["created_at"], reverse=True)
    return {"links": result}


@app.patch("/api/links/{uid}")
async def toggle_link(uid: str, request: Request):
    body = await request.json()
    async with LINKS_LOCK:
        if uid not in LINKS:
            raise HTTPException(status_code=404, detail="link not found")
        if "active" in body:
            LINKS[uid]["active"] = bool(body["active"])
        if "limit_value" in body:
            limit_value = float(body.get("limit_value") or 0)
            limit_unit = body.get("limit_unit") or "GB"
            LINKS[uid]["limit_bytes"] = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
        if "reset_usage" in body and body["reset_usage"]:
            LINKS[uid]["used_bytes"] = 0
        if "label" in body:
            LINKS[uid]["label"] = str(body["label"])[:60]
    return {"ok": True}


@app.delete("/api/links/{uid}")
async def delete_link(uid: str):
    async with LINKS_LOCK:
        LINKS.pop(uid, None)
    return {"ok": True}


# ───────── VLESS Protocol Relay ─────────
RELAY_BUF = 64 * 1024


async def parse_vless_header(first_chunk: bytes):
    if len(first_chunk) < 24:
        raise ValueError("chunk too small for VLESS header")

    pos = 0
    version = first_chunk[pos]; pos += 1          # noqa: E702
    req_uuid = first_chunk[pos:pos + 16]; pos += 16  # noqa: E702

    addon_len = first_chunk[pos]; pos += 1
    pos += addon_len

    command = first_chunk[pos]; pos += 1  # noqa: E702
    port = int.from_bytes(first_chunk[pos:pos + 2], "big"); pos += 2

    addr_type = first_chunk[pos]; pos += 1

    if addr_type == 1:
        addr_bytes = first_chunk[pos:pos + 4]; pos += 4
        address = ".".join(str(b) for b in addr_bytes)
    elif addr_type == 2:
        domain_len = first_chunk[pos]; pos += 1
        address = first_chunk[pos:pos + domain_len].decode("utf-8", errors="ignore")
        pos += domain_len
    elif addr_type == 3:
        addr_bytes = first_chunk[pos:pos + 16]; pos += 16
        address = ":".join(f"{addr_bytes[i]:02x}{addr_bytes[i+1]:02x}" for i in range(0, 16, 2))
    else:
        raise ValueError(f"unknown address type: {addr_type}")

    payload = first_chunk[pos:]
    return req_uuid, command, address, port, payload


def format_link_uuid(raw16: bytes) -> str:
    h = raw16.hex()
    return f"{h[0:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}"


async def check_quota(uid: str, extra_bytes: int) -> bool:
    """True اگر اجازه عبور دارد (سهمیه تمام نشده)."""
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if link is None:
            return True  # لینک ناشناس → اجازه (بک‌ورد کامپتیبیلیتی)
        if not link["active"]:
            return False
        if link["limit_bytes"] == 0:
            return True
        return (link["used_bytes"] + extra_bytes) <= link["limit_bytes"]


async def add_usage(uid: str, n: int):
    async with LINKS_LOCK:
        if uid in LINKS:
            LINKS[uid]["used_bytes"] += n


async def ws_to_tcp(websocket: WebSocket, writer: asyncio.StreamWriter, conn_id: str, link_uid: str):
    try:
        while True:
            msg = await websocket.receive()
            if msg["type"] == "websocket.disconnect":
                break
            data = msg.get("bytes")
            if data is None and msg.get("text") is not None:
                data = msg["text"].encode()
            if not data:
                continue

            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break

            stats["total_bytes"] += size
            stats["total_requests"] += 1
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)

            writer.write(data)
            await writer.drain()
    except WebSocketDisconnect:
        pass
    finally:
        try:
            writer.write_eof()
        except Exception:
            pass


async def tcp_to_ws(websocket: WebSocket, reader: asyncio.StreamReader, conn_id: str, link_uid: str):
    first = True
    try:
        while True:
            data = await reader.read(RELAY_BUF)
            if not data:
                break

            size = len(data)
            if not await check_quota(link_uid, size):
                await websocket.close(code=1008, reason="quota exceeded")
                break

            stats["total_bytes"] += size
            connections[conn_id]["bytes"] += size
            hourly_traffic[datetime.now().strftime("%H:00")] += size
            await add_usage(link_uid, size)

            if first:
                await websocket.send_bytes(b"\x00\x00" + data)
                first = False
            else:
                await websocket.send_bytes(data)
    except Exception:
        pass


@app.websocket("/ws/{uuid}")
async def websocket_tunnel(websocket: WebSocket, uuid: str):
    await ensure_default_link()
    await websocket.accept()
    conn_id = secrets.token_urlsafe(8)
    connections[conn_id] = {
        "uuid": uuid,
        "connected_at": datetime.now().isoformat(),
        "bytes": 0,
    }
    logger.info(f"✅ WS connected [{conn_id}] uuid={uuid}  active={len(connections)}")

    writer = None
    try:
        # بررسی سهمیه پیش از شروع
        if not await check_quota(uuid, 0):
            await websocket.close(code=1008, reason="quota exceeded or link disabled")
            return

        first_msg = await asyncio.wait_for(websocket.receive(), timeout=15.0)
        if first_msg["type"] == "websocket.disconnect":
            return

        first_chunk = first_msg.get("bytes")
        if first_chunk is None and first_msg.get("text") is not None:
            first_chunk = first_msg["text"].encode()
        if not first_chunk:
            return

        req_uuid_raw, command, address, port, initial_payload = await parse_vless_header(first_chunk)

        size = len(first_chunk)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
        connections[conn_id]["bytes"] += size
        hourly_traffic[datetime.now().strftime("%H:00")] += size
        await add_usage(uuid, size)

        logger.info(f"➡️  [{conn_id}] CONNECT {address}:{port} (cmd={command}) link={uuid[:8]}")

        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(address, port), timeout=10.0
        )

        if initial_payload:
            writer.write(initial_payload)
            await writer.drain()

        task_up = asyncio.create_task(ws_to_tcp(websocket, writer, conn_id, uuid))
        task_down = asyncio.create_task(tcp_to_ws(websocket, reader, conn_id, uuid))

        done, pending = await asyncio.wait(
            {task_up, task_down}, return_when=asyncio.FIRST_COMPLETED
        )
        for t in pending:
            t.cancel()

    except WebSocketDisconnect:
        pass
    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "time": datetime.now().isoformat()})
        logger.error(f"WS error [{conn_id}]: {exc}")
    finally:
        if writer:
            try:
                writer.close()
            except Exception:
                pass
        connections.pop(conn_id, None)
        logger.info(f"🔌 WS closed [{conn_id}]  active={len(connections)}")


# ───────── HTTP Proxy ─────────
_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
    "content-encoding", "content-length",
}


@app.api_route("/proxy/{target_url:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def http_proxy(target_url: str, request: Request):
    if not target_url.startswith("http"):
        target_url = "https://" + target_url

    try:
        body = await request.body()
        headers = {
            k: v for k, v in request.headers.items()
            if k.lower() not in _HOP_HEADERS and k.lower() != "host"
        }

        resp = await http_client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )

        size = len(resp.content)
        stats["total_bytes"] += size
        stats["total_requests"] += 1
        hourly_traffic[datetime.now().strftime("%H:00")] += size

        resp_headers = {
            k: v for k, v in resp.headers.items()
            if k.lower() not in _HOP_HEADERS
        }
        return Response(content=resp.content, status_code=resp.status_code, headers=resp_headers)

    except Exception as exc:
        stats["total_errors"] += 1
        error_logs.append({"error": str(exc), "url": target_url, "time": datetime.now().isoformat()})
        raise HTTPException(status_code=502, detail=f"Proxy error: {exc}")


# ───────── Dashboard (SPA) ─────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>RVG Gateway · codebox</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@tabler/icons-webfont@3.19.0/dist/tabler-icons.min.css">
<script src="https://cdnjs.cloudflare.com/ajax/libs/Chart.js/4.4.1/chart.umd.js"></script>
<style>
*{margin:0;padding:0;box-sizing:border-box}
:root{
  --blue-50:#E6F1FB;--blue-100:#B5D4F4;--blue-200:#85B7EB;
  --blue-300:#5BA3E8;--blue-400:#378ADD;--blue-500:#2570C2;
  --blue-600:#185FA5;--blue-700:#11518F;--blue-800:#0C447C;--blue-900:#042C53;
  --green-bg:#EAF3DE;--green-text:#3B6D11;--green-dot:#6CA52E;
  --red-bg:#FCEBEB;--red-text:#A32D2D;--red-dot:#E24B4A;
  --amber-bg:#FAEEDA;--amber-text:#854F0B;--amber-dot:#D99A2B;
  --border:#CFE3F7;--bg:#EEF5FE;--white:#fff;
  --text-1:#042C53;--text-2:#378ADD;--text-3:#85B7EB;
  --shadow:0 1px 2px rgba(4,44,83,0.04), 0 1px 12px rgba(4,44,83,0.03);
}
html,body{height:100%}
body{font-family:'Vazirmatn',sans-serif;background:var(--bg);color:var(--text-1);min-height:100vh;display:flex;font-size:14px}
::-webkit-scrollbar{width:6px;height:6px}
::-webkit-scrollbar-thumb{background:var(--blue-100);border-radius:3px}
a{color:inherit}

/* SIDEBAR */
.sidebar{width:236px;min-height:100vh;background:linear-gradient(180deg,var(--blue-900) 0%,#031f3c 100%);display:flex;flex-direction:column;flex-shrink:0;position:fixed;right:0;top:0;bottom:0;z-index:100}
.logo{display:flex;align-items:center;gap:11px;padding:22px 18px 20px;border-bottom:1px solid rgba(255,255,255,0.06)}
.logo img{width:42px;height:42px;border-radius:11px;object-fit:cover;border:1px solid rgba(255,255,255,0.1)}
.logo-name{color:#fff;font-size:15px;font-weight:700;letter-spacing:.01em}
.logo-sub{color:var(--blue-300);font-size:11px;margin-top:2px}
.nav-scroll{flex:1;overflow-y:auto;padding-bottom:10px}
.nav-group-label{color:var(--blue-400);font-size:10px;letter-spacing:.1em;padding:18px 20px 6px;text-transform:uppercase;font-weight:600}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 20px;color:var(--blue-200);font-size:13px;cursor:pointer;border-right:3px solid transparent;transition:.15s;user-select:none;position:relative}
.nav-item i{font-size:18px;width:20px;text-align:center}
.nav-item:hover{background:rgba(255,255,255,0.04);color:#fff}
.nav-item.active{background:linear-gradient(90deg,rgba(55,138,221,0.18),rgba(55,138,221,0.02));color:#fff;border-right-color:var(--blue-400)}
.nav-item .nav-badge{margin-right:auto;background:rgba(55,138,221,0.18);color:var(--blue-200);font-size:10px;padding:2px 7px;border-radius:20px;font-weight:600}
.sidebar-footer{padding:16px 18px;border-top:1px solid rgba(255,255,255,0.06)}
.sidebar-footer-label{color:var(--blue-300);font-size:11px;margin-bottom:9px;display:flex;align-items:center;gap:6px}
.tg-btn{display:flex;align-items:center;justify-content:center;gap:8px;background:linear-gradient(135deg,#0098e6,#0077bb);color:#fff;border-radius:10px;padding:11px;font-size:13px;font-weight:500;font-family:inherit;border:none;cursor:pointer;width:100%;text-decoration:none;transition:.15s;box-shadow:0 4px 14px rgba(0,136,204,0.25)}
.tg-btn:hover{filter:brightness(1.08)}
.tg-btn i{font-size:18px}

/* MAIN */
.main{margin-right:236px;flex:1;padding:26px 28px 50px;max-width:calc(100% - 236px)}
.page{display:none}
.page.active{display:block;animation:fadeIn .25s ease}
@keyframes fadeIn{from{opacity:0;transform:translateY(6px)}to{opacity:1;transform:none}}

.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:26px;flex-wrap:wrap;gap:12px}
.topbar-title{font-size:20px;font-weight:700;color:var(--blue-900);display:flex;align-items:center;gap:9px}
.topbar-title i{color:var(--blue-400);font-size:22px}
.topbar-sub{font-size:12px;color:var(--blue-400);margin-top:4px}
.topbar-right{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.badge{font-size:11px;padding:5px 12px;border-radius:20px;font-weight:600;display:inline-flex;align-items:center;gap:6px}
.badge-green{background:var(--green-bg);color:var(--green-text)}
.badge-blue{background:var(--blue-50);color:var(--blue-600)}
.badge-amber{background:var(--amber-bg);color:var(--amber-text)}
.badge-red{background:var(--red-bg);color:var(--red-text)}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block}
.dot-green{background:var(--green-dot)}
.dot-red{background:var(--red-dot)}
.dot-amber{background:var(--amber-dot)}
.pulse{animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}

/* METRICS */
.metrics{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:22px}
.metric{background:var(--white);border-radius:14px;border:1px solid var(--border);padding:18px 18px;box-shadow:var(--shadow);transition:.15s}
.metric:hover{transform:translateY(-2px);box-shadow:0 4px 18px rgba(4,44,83,0.07)}
.metric-label{font-size:11px;color:var(--blue-400);margin-bottom:9px;display:flex;align-items:center;gap:6px;font-weight:600}
.metric-label i{font-size:16px}
.metric-val{font-size:28px;font-weight:700;color:var(--blue-900);line-height:1}
.metric-unit{font-size:13px;font-weight:500;color:var(--blue-400);margin-right:3px}
.metric-sub{font-size:11px;color:var(--blue-600);margin-top:6px;display:flex;align-items:center;gap:4px}
.metric-error .metric-label{color:var(--red-text)}
.metric-error .metric-val{color:var(--red-dot)}
.metric-error .metric-sub{color:var(--red-text)}

/* VLESS BOX */
.vless-box{background:linear-gradient(135deg,var(--blue-900) 0%,#06335e 100%);border-radius:16px;padding:22px 24px;margin-bottom:22px;box-shadow:0 8px 30px rgba(4,44,83,0.18)}
.vless-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:13px;flex-wrap:wrap;gap:10px}
.vless-title{color:var(--blue-200);font-size:12px;display:flex;align-items:center;gap:7px;font-weight:600}
.vless-title i{font-size:17px}
.vless-link-wrap{background:rgba(255,255,255,0.04);border:1px solid rgba(55,138,221,0.22);border-radius:10px;padding:14px 16px}
.vless-link{color:var(--blue-100);font-size:11.5px;font-family:ui-monospace,monospace;word-break:break-all;line-height:1.7;letter-spacing:.01em}
.vless-actions{display:flex;gap:9px;margin-top:14px;flex-wrap:wrap}
.btn{font-family:inherit;font-size:12.5px;font-weight:500;border-radius:9px;padding:9px 15px;cursor:pointer;display:inline-flex;align-items:center;gap:6px;border:none;transition:.15s;white-space:nowrap}
.btn-primary{background:var(--blue-600);color:#fff;box-shadow:0 2px 8px rgba(24,95,165,0.25)}
.btn-primary:hover{background:var(--blue-700)}
.btn-outline{background:transparent;border:1px solid rgba(55,138,221,0.35);color:var(--blue-200)}
.btn-outline:hover{background:rgba(55,138,221,0.1)}
.btn-light-outline{background:var(--white);border:1px solid var(--border);color:var(--blue-700)}
.btn-light-outline:hover{background:var(--blue-50)}
.btn-danger{background:var(--red-bg);color:var(--red-text);border:1px solid #f0a5a580}
.btn-danger:hover{background:#f7c1c1}
.btn-sm{padding:6px 11px;font-size:11.5px;border-radius:7px}
.btn i{font-size:14px}
.btn:disabled{opacity:.5;cursor:not-allowed}

/* GRID */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:22px}
.grid3{display:grid;grid-template-columns:2fr 1fr;gap:14px;margin-bottom:22px}
.card{background:var(--white);border-radius:14px;border:1px solid var(--border);padding:20px 22px;box-shadow:var(--shadow)}
.card-title{font-size:13.5px;font-weight:700;color:var(--blue-800);margin-bottom:16px;display:flex;align-items:center;gap:8px}
.card-title i{font-size:18px;color:var(--blue-400)}
.card-title .ml-auto{margin-right:auto}

/* STATUS TABLE */
.status-row{display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--blue-50);font-size:12.5px}
.status-row:last-child{border-bottom:none}
.status-key{color:var(--blue-800);display:flex;align-items:center;gap:7px}
.status-key i{font-size:15px;color:var(--blue-400)}
.status-val{color:var(--blue-600);font-weight:600}
.speed-bar{height:6px;border-radius:4px;background:var(--blue-50);margin-top:6px;overflow:hidden}
.speed-fill{height:100%;border-radius:4px;background:linear-gradient(90deg,var(--blue-300),var(--blue-500));transition:width 1s}

/* ERRORS */
.err-row{padding:10px 0;border-bottom:1px solid var(--blue-50);font-size:11.5px}
.err-row:last-child{border-bottom:none}
.err-time{color:var(--blue-400);font-size:10px;margin-bottom:3px;display:flex;align-items:center;gap:5px}
.err-msg{color:var(--red-text);font-family:ui-monospace,monospace;background:var(--red-bg);padding:7px 10px;border-radius:7px;word-break:break-all}

/* CHARTS */
.chart-wrap{position:relative;height:220px;width:100%}
.chart-wrap-sm{position:relative;height:180px;width:100%}

/* FOOTER */
.dash-footer{border-top:1px solid var(--border);margin-top:14px;padding-top:16px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px}
.footer-text{font-size:11px;color:var(--blue-400)}
.footer-link{font-size:12.5px;color:var(--blue-600);text-decoration:none;display:flex;align-items:center;gap:6px;font-weight:500}
.footer-link:hover{color:var(--blue-800)}

/* TOAST */
.toast{position:fixed;bottom:28px;left:50%;transform:translateX(-50%) translateY(40px);background:var(--blue-900);color:#fff;border-radius:10px;padding:11px 22px;font-size:13px;opacity:0;transition:all .3s;z-index:999;pointer-events:none;display:flex;align-items:center;gap:8px;box-shadow:0 6px 24px rgba(0,0,0,.2)}
.toast.show{opacity:1;transform:translateX(-50%) translateY(0)}
.toast.err{background:var(--red-text)}

/* FORM ELEMENTS */
.form-row{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.form-group{display:flex;flex-direction:column;gap:6px}
.form-label{font-size:11.5px;color:var(--blue-700);font-weight:600}
.form-input,.form-select{padding:10px 13px;border-radius:9px;border:1px solid var(--border);font-family:inherit;font-size:12.5px;outline:none;color:var(--text-1);background:var(--bg);min-width:120px;transition:.15s}
.form-input:focus,.form-select:focus{border-color:var(--blue-400);background:#fff}

/* LINKS TABLE */
.links-table{width:100%;border-collapse:collapse}
.links-table th{text-align:right;font-size:11px;color:var(--blue-400);font-weight:600;padding:10px 8px;border-bottom:2px solid var(--blue-50);white-space:nowrap}
.links-table td{padding:13px 8px;border-bottom:1px solid var(--blue-50);font-size:12.5px;vertical-align:middle}
.links-table tr:last-child td{border-bottom:none}
.links-table tr:hover td{background:var(--blue-50)}
.link-uuid{font-family:ui-monospace,monospace;font-size:10.5px;color:var(--blue-600);background:var(--blue-50);padding:3px 8px;border-radius:6px;display:inline-block}
.usage-bar-wrap{width:140px}
.usage-bar{height:7px;border-radius:4px;background:var(--blue-50);overflow:hidden;margin-bottom:4px}
.usage-bar-fill{height:100%;border-radius:4px;transition:width .3s}
.usage-text{font-size:10.5px;color:var(--blue-400)}
.empty-state{text-align:center;padding:50px 20px;color:var(--blue-400)}
.empty-state i{font-size:42px;color:var(--blue-200);margin-bottom:12px;display:block}

/* TOGGLE */
.toggle{width:38px;height:21px;border-radius:20px;background:var(--blue-100);position:relative;cursor:pointer;transition:.2s;flex-shrink:0;border:none}
.toggle::after{content:'';position:absolute;width:15px;height:15px;border-radius:50%;background:#fff;top:3px;right:3px;transition:.2s;box-shadow:0 1px 3px rgba(0,0,0,.2)}
.toggle.on{background:var(--green-dot)}
.toggle.on::after{right:20px}

/* INFO CALLOUT */
.callout{background:var(--blue-50);border:1px solid var(--blue-100);border-radius:11px;padding:14px 16px;font-size:12px;color:var(--blue-700);display:flex;gap:10px;align-items:flex-start;line-height:1.8}
.callout i{font-size:18px;color:var(--blue-400);margin-top:1px}
.callout.amber{background:var(--amber-bg);border-color:#f0d9ab;color:var(--amber-text)}
.callout.amber i{color:var(--amber-dot)}

/* IDEA CARDS */
.idea-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}
.idea-card{background:var(--white);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:var(--shadow)}
.idea-icon{width:38px;height:38px;border-radius:10px;background:var(--blue-50);display:flex;align-items:center;justify-content:center;color:var(--blue-500);font-size:19px;margin-bottom:11px}
.idea-title{font-size:13px;font-weight:700;color:var(--blue-900);margin-bottom:6px}
.idea-desc{font-size:11.5px;color:var(--blue-600);line-height:1.8}
.idea-badge{display:inline-block;margin-top:10px;font-size:10px;background:var(--blue-50);color:var(--blue-500);padding:3px 9px;border-radius:20px;font-weight:600}

@media(max-width:1000px){
  .sidebar{display:none}.main{margin-right:0;max-width:100%}
  .metrics{grid-template-columns:1fr 1fr}
  .grid2,.grid3{grid-template-columns:1fr}
  .idea-grid{grid-template-columns:1fr}
}
</style>
</head>
<body>

<div class="toast" id="toast"></div>

<!-- SIDEBAR -->
<aside class="sidebar">
  <div class="logo">
    <img src="https://yt3.googleusercontent.com/vA6bYj1V386YmibpWRNFJtsRRqwfY_U9wnb7gmW90eRVXyNB7gAfjj1XPs5UX0cdKdQprrI=s160-c-k-c0x00ffffff-no-rj" alt="codebox">
    <div>
      <div class="logo-name">codebox</div>
      <div class="logo-sub">RVG Gateway · v6.0</div>
    </div>
  </div>

  <div class="nav-scroll">
    <div class="nav-group-label">پنل</div>
    <div class="nav-item active" data-page="overview"><i class="ti ti-layout-dashboard"></i> داشبورد کلی</div>
    <div class="nav-item" data-page="links"><i class="ti ti-link-plus"></i> مدیریت لینک‌ها <span class="nav-badge" id="links-count-badge">0</span></div>
    <div class="nav-item" data-page="traffic"><i class="ti ti-chart-area"></i> آمار ترافیک</div>
    <div class="nav-item" data-page="connections"><i class="ti ti-plug-connected"></i> اتصالات فعال <span class="nav-badge" id="conns-count-badge">0</span></div>

    <div class="nav-group-label">سیستم</div>
    <div class="nav-item" data-page="security"><i class="ti ti-shield-lock"></i> امنیت</div>
    <div class="nav-item" data-page="errors"><i class="ti ti-alert-triangle"></i> خطاها</div>
    <div class="nav-item" data-page="ideas"><i class="ti ti-bulb"></i> ایده‌ها و قابلیت‌ها</div>
    <div class="nav-item" data-page="testws"><i class="ti ti-wifi"></i> تست WebSocket</div>
    <div class="nav-item" data-page="settings"><i class="ti ti-settings"></i> تنظیمات</div>
  </div>

  <div class="sidebar-footer">
    <div class="sidebar-footer-label"><i class="ti ti-brand-telegram"></i> کانال تلگرام codebox</div>
    <a class="tg-btn" href="https://t.me/CodeBoxo" target="_blank" rel="noopener">
      <i class="ti ti-brand-telegram"></i> @CodeBoxo
    </a>
  </div>
</aside>

<!-- MAIN -->
<main class="main">

  <!-- ═══════ OVERVIEW PAGE ═══════ -->
  <section class="page active" id="page-overview">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-layout-dashboard"></i> داشبورد کلی</div>
        <div class="topbar-sub" id="last-update">در حال بارگذاری...</div>
      </div>
      <div class="topbar-right">
        <span class="badge badge-green"><span class="dot dot-green pulse"></span> سرور فعال</span>
        <span class="badge badge-blue" id="uptime-badge">Railway · --</span>
        <button class="btn btn-primary" onclick="refreshAll()"><i class="ti ti-refresh"></i> رفرش</button>
      </div>
    </div>

    <div class="metrics">
      <div class="metric">
        <div class="metric-label"><i class="ti ti-plug-connected"></i> اتصالات فعال</div>
        <div class="metric-val" id="m-conns">—</div>
        <div class="metric-sub" id="m-conns-sub">اتصال WebSocket باز</div>
      </div>
      <div class="metric">
        <div class="metric-label"><i class="ti ti-transfer"></i> کل ترافیک</div>
        <div class="metric-val" id="m-traffic">—<span class="metric-unit">MB</span></div>
        <div class="metric-sub">از ابتدای راه‌اندازی</div>
      </div>
      <div class="metric">
        <div class="metric-label"><i class="ti ti-send"></i> کل درخواست‌ها</div>
        <div class="metric-val" id="m-reqs">—</div>
        <div class="metric-sub">از ابتدای سرویس</div>
      </div>
      <div class="metric metric-error">
        <div class="metric-label"><i class="ti ti-alert-circle"></i> خطاها</div>
        <div class="metric-val" id="m-errors">—</div>
        <div class="metric-sub">ثبت شده</div>
      </div>
    </div>

    <div class="vless-box">
      <div class="vless-header">
        <div class="vless-title"><i class="ti ti-link"></i> لینک پیش‌فرض (بدون محدودیت)</div>
        <span class="badge" style="background:rgba(55,138,221,0.15);color:var(--blue-200)">TLS 443 · WS</span>
      </div>
      <div class="vless-link-wrap">
        <div class="vless-link" id="vless-link-overview">در حال دریافت...</div>
      </div>
      <div class="vless-actions">
        <button class="btn btn-primary" onclick="copyText('vless-link-overview')"><i class="ti ti-copy"></i> کپی لینک</button>
        <button class="btn btn-outline" onclick="qrFor('vless-link-overview')"><i class="ti ti-qrcode"></i> QR کد</button>
        <button class="btn btn-outline" onclick="switchPage('links')"><i class="ti ti-link-plus"></i> ساخت لینک با محدودیت ترافیک</button>
        <a class="btn btn-outline" href="https://t.me/CodeBoxo" target="_blank" rel="noopener" style="text-decoration:none">
          <i class="ti ti-brand-telegram"></i> codebox
        </a>
      </div>
    </div>

    <div class="grid3">
      <div class="card">
        <div class="card-title"><i class="ti ti-chart-area"></i> ترافیک ساعتی (MB)</div>
        <div class="chart-wrap"><canvas id="trafficChart" role="img" aria-label="نمودار ترافیک ساعتی"></canvas></div>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-chart-donut"></i> توزیع درخواست‌ها</div>
        <div class="chart-wrap-sm"><canvas id="donutChart" role="img" aria-label="توزیع نوع ترافیک"></canvas></div>
      </div>
    </div>

    <div class="grid2">
      <div class="card">
        <div class="card-title"><i class="ti ti-activity"></i> وضعیت سرویس‌ها</div>
        <div class="status-row"><span class="status-key"><i class="ti ti-circle-check"></i> VLESS / WebSocket Tunnel</span><span class="status-val" style="color:var(--green-text)">● فعال</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-circle-check"></i> HTTP Proxy</span><span class="status-val" style="color:var(--green-text)">● فعال</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-server"></i> Async Connection Pool</span><span class="status-val" style="color:var(--green-text)">● فعال</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-clock"></i> آپتایم</span><span class="status-val" id="uptime-inline">—</span></div>
        <div class="status-row" style="flex-direction:column;align-items:flex-start;gap:6px">
          <div style="width:100%;display:flex;justify-content:space-between"><span class="status-key"><i class="ti ti-gauge"></i> پهنای باند (نسبی)</span><span class="status-val" id="bw-pct">—%</span></div>
          <div class="speed-bar" style="width:100%"><div class="speed-fill" id="bw-bar" style="width:0%"></div></div>
        </div>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-link-plus"></i> خلاصه لینک‌ها <span class="ml-auto badge badge-blue" id="links-summary-badge">۰ لینک</span></div>
        <div id="links-summary-list" style="font-size:12px;color:var(--blue-400)">در حال بارگذاری...</div>
      </div>
    </div>

    <div class="dash-footer">
      <span class="footer-text">codebox RVG Gateway v6.0 · Railway · 2025</span>
      <a class="footer-link" href="https://t.me/CodeBoxo" target="_blank" rel="noopener">
        <i class="ti ti-brand-telegram" style="font-size:16px"></i> t.me/CodeBoxo
      </a>
    </div>
  </section>

  <!-- ═══════ LINKS MANAGEMENT PAGE ═══════ -->
  <section class="page" id="page-links">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-link-plus"></i> مدیریت لینک‌ها</div>
        <div class="topbar-sub">ساخت لینک رندوم با محدودیت ترافیک اختصاصی (MB / GB)</div>
      </div>
      <div class="topbar-right">
        <span class="badge badge-blue" id="links-page-count">۰ لینک ساخته شده</span>
      </div>
    </div>

    <div class="card" style="margin-bottom:18px">
      <div class="card-title"><i class="ti ti-plus"></i> ساخت لینک جدید</div>
      <div class="form-row">
        <div class="form-group" style="flex:1;min-width:180px">
          <label class="form-label">عنوان / یادداشت لینک</label>
          <input class="form-input" id="new-link-label" placeholder="مثلاً: برای علی" style="width:100%">
        </div>
        <div class="form-group">
          <label class="form-label">مقدار سهمیه ترافیک</label>
          <input class="form-input" id="new-link-value" type="number" min="0" step="0.1" placeholder="0 = بی‌نهایت" style="width:130px">
        </div>
        <div class="form-group">
          <label class="form-label">واحد</label>
          <select class="form-select" id="new-link-unit">
            <option value="GB">گیگابایت (GB)</option>
            <option value="MB" selected>مگابایت (MB)</option>
          </select>
        </div>
        <button class="btn btn-primary" onclick="createLink()"><i class="ti ti-link-plus"></i> ساخت لینک رندوم</button>
      </div>
      <div class="callout" style="margin-top:14px">
        <i class="ti ti-info-circle"></i>
        <span>هر لینک یک UUID کاملاً رندوم و یکتا دارد. اگر مقدار سهمیه را ۰ یا خالی بگذارید، لینک بدون محدودیت ترافیک خواهد بود. به محض رسیدن مصرف به سقف تعیین‌شده، اتصال آن لینک به‌صورت خودکار قطع و مسدود می‌شود.</span>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><i class="ti ti-list"></i> لینک‌های ساخته‌شده</div>
      <div style="overflow-x:auto">
      <table class="links-table">
        <thead>
          <tr>
            <th>عنوان</th>
            <th>UUID</th>
            <th>مصرف / سهمیه</th>
            <th>وضعیت</th>
            <th>عملیات</th>
          </tr>
        </thead>
        <tbody id="links-tbody"></tbody>
      </table>
      </div>
      <div class="empty-state" id="links-empty" style="display:none">
        <i class="ti ti-link-off"></i>
        هنوز هیچ لینکی ساخته نشده. از فرم بالا یک لینک جدید بسازید.
      </div>
    </div>
  </section>

  <!-- ═══════ TRAFFIC PAGE ═══════ -->
  <section class="page" id="page-traffic">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-chart-area"></i> آمار ترافیک</div>
        <div class="topbar-sub">نمایش لحظه‌ای ترافیک عبوری از Gateway</div>
      </div>
      <div class="topbar-right">
        <button class="btn btn-primary" onclick="refreshAll()"><i class="ti ti-refresh"></i> رفرش</button>
      </div>
    </div>

    <div class="metrics" style="grid-template-columns:repeat(3,1fr)">
      <div class="metric">
        <div class="metric-label"><i class="ti ti-database"></i> کل ترافیک</div>
        <div class="metric-val" id="t-traffic">—<span class="metric-unit">MB</span></div>
        <div class="metric-sub">جمع آپلود + دانلود</div>
      </div>
      <div class="metric">
        <div class="metric-label"><i class="ti ti-arrow-up"></i> میانگین در ساعت</div>
        <div class="metric-val" id="t-avg">—<span class="metric-unit">MB</span></div>
        <div class="metric-sub">بر اساس داده‌های امروز</div>
      </div>
      <div class="metric">
        <div class="metric-label"><i class="ti ti-chart-bar"></i> پیک ساعتی</div>
        <div class="metric-val" id="t-peak">—<span class="metric-unit">MB</span></div>
        <div class="metric-sub">بالاترین مصرف ساعتی</div>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><i class="ti ti-chart-area"></i> نمودار کامل ترافیک ساعتی</div>
      <div class="chart-wrap" style="height:320px"><canvas id="trafficChartBig"></canvas></div>
    </div>
  </section>

  <!-- ═══════ CONNECTIONS PAGE ═══════ -->
  <section class="page" id="page-connections">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-plug-connected"></i> اتصالات فعال</div>
        <div class="topbar-sub">لیست اتصالات WebSocket باز در همین لحظه</div>
      </div>
      <div class="topbar-right">
        <span class="badge badge-green" id="conns-live-badge"><span class="dot dot-green pulse"></span> ۰ اتصال زنده</span>
        <button class="btn btn-primary" onclick="refreshAll()"><i class="ti ti-refresh"></i> رفرش</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><i class="ti ti-list"></i> جزئیات اتصالات</div>
      <div style="overflow-x:auto">
      <table class="links-table">
        <thead><tr><th>شناسه اتصال</th><th>UUID لینک</th><th>زمان اتصال</th><th>حجم انتقال</th></tr></thead>
        <tbody id="conns-tbody"></tbody>
      </table>
      </div>
      <div class="empty-state" id="conns-empty" style="display:none">
        <i class="ti ti-plug-off"></i>
        در حال حاضر هیچ اتصال فعالی وجود ندارد.
      </div>
    </div>
  </section>

  <!-- ═══════ SECURITY PAGE ═══════ -->
  <section class="page" id="page-security">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-shield-lock"></i> امنیت</div>
        <div class="topbar-sub">وضعیت امنیتی Gateway</div>
      </div>
    </div>

    <div class="grid2">
      <div class="card">
        <div class="card-title"><i class="ti ti-lock"></i> رمزنگاری و انتقال</div>
        <div class="status-row"><span class="status-key"><i class="ti ti-certificate"></i> TLS / HTTPS</span><span class="status-val" style="color:var(--green-text)">● فعال (پورت 443)</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-fingerprint"></i> Fingerprint Spoofing</span><span class="status-val" style="color:var(--green-text)">Chrome</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-network"></i> نوع پروتکل</span><span class="status-val">VLESS over WebSocket</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-key"></i> کلید سرویس</span><span class="status-val">رمزنگاری شده (SHA-256)</span></div>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-shield-check"></i> کنترل دسترسی</div>
        <div class="status-row"><span class="status-key"><i class="ti ti-toggle-right"></i> فعال/غیرفعال‌سازی هر لینک</span><span class="status-val" style="color:var(--green-text)">پشتیبانی می‌شود</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-gauge"></i> محدودیت سهمیه ترافیک</span><span class="status-val" style="color:var(--green-text)">پشتیبانی می‌شود</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-ban"></i> قطع خودکار پس از اتمام سهمیه</span><span class="status-val" style="color:var(--green-text)">فعال</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-eye-off"></i> عدم ذخیره محتوای ترافیک</span><span class="status-val" style="color:var(--green-text)">فعال</span></div>
      </div>
    </div>

    <div class="callout amber">
      <i class="ti ti-alert-triangle"></i>
      <span>توجه: تمام لینک‌های ساخته‌شده و آمار مصرف به‌صورت <b>درون‌حافظه (in-memory)</b> ذخیره می‌شوند و با ری‌استارت شدن سرویس روی Railway، پاک خواهند شد. برای ذخیره دائمی، نیاز به اتصال یک دیتابیس (مثل Redis یا PostgreSQL) است.</span>
    </div>
  </section>

  <!-- ═══════ ERRORS PAGE ═══════ -->
  <section class="page" id="page-errors">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-alert-triangle"></i> خطاها</div>
        <div class="topbar-sub">آخرین خطاهای ثبت‌شده توسط سرویس</div>
      </div>
      <div class="topbar-right">
        <span class="badge badge-red" id="errors-count-badge">۰ خطا</span>
        <button class="btn btn-primary" onclick="refreshAll()"><i class="ti ti-refresh"></i> رفرش</button>
      </div>
    </div>

    <div class="card">
      <div class="card-title"><i class="ti ti-bug"></i> لاگ خطاهای اخیر</div>
      <div id="errors-list-full" style="font-size:12px;color:var(--blue-400)">در حال بارگذاری...</div>
    </div>
  </section>

  <!-- ═══════ IDEAS PAGE ═══════ -->
  <section class="page" id="page-ideas">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-bulb"></i> ایده‌ها و قابلیت‌های پیشنهادی</div>
        <div class="topbar-sub">پیشنهاد برای توسعه‌های بعدی RVG Gateway</div>
      </div>
    </div>

    <div class="idea-grid">
      <div class="idea-card">
        <div class="idea-icon"><i class="ti ti-database"></i></div>
        <div class="idea-title">ذخیره‌سازی دائمی با Redis</div>
        <div class="idea-desc">اتصال لینک‌ها و آمار مصرف به Redis یا SQLite تا با ری‌استارت سرویس، اطلاعات حفظ شوند.</div>
        <span class="idea-badge">پیشنهادی</span>
      </div>
      <div class="idea-card">
        <div class="idea-icon"><i class="ti ti-calendar-time"></i></div>
        <div class="idea-title">انقضای زمانی لینک</div>
        <div class="idea-desc">علاوه بر سهمیه حجمی، امکان تعیین تاریخ انقضا برای هر لینک (مثلاً ۳۰ روزه).</div>
        <span class="idea-badge">پیشنهادی</span>
      </div>
      <div class="idea-card">
        <div class="idea-icon"><i class="ti ti-brand-telegram"></i></div>
        <div class="idea-title">اعلان تلگرامی مصرف</div>
        <div class="idea-desc">ارسال پیام به کانال/بات تلگرام هنگام رسیدن مصرف هر لینک به ۸۰٪ و ۱۰۰٪ سهمیه.</div>
        <span class="idea-badge">پیشنهادی</span>
      </div>
      <div class="idea-card">
        <div class="idea-icon"><i class="ti ti-users"></i></div>
        <div class="idea-title">پروفایل کاربران چندگانه</div>
        <div class="idea-desc">گروه‌بندی لینک‌ها زیر نام کاربران مختلف برای مدیریت تیمی و گزارش‌گیری جدا.</div>
        <span class="idea-badge">پیشنهادی</span>
      </div>
      <div class="idea-card">
        <div class="idea-icon"><i class="ti ti-route"></i></div>
        <div class="idea-title">چند مسیر خروجی (Multi-Outbound)</div>
        <div class="idea-desc">اضافه‌کردن چند سرور خروجی و انتخاب هوشمند بر اساس کمترین تأخیر برای هر کاربر.</div>
        <span class="idea-badge">پیشنهادی</span>
      </div>
      <div class="idea-card">
        <div class="idea-icon"><i class="ti ti-qrcode"></i></div>
        <div class="idea-title">QR Code اختصاصی هر لینک</div>
        <div class="idea-desc">نمایش QR هر لینک به‌صورت کارت قابل دانلود برای اشتراک‌گذاری سریع با کاربر نهایی.</div>
        <span class="idea-badge">آماده در نسخه فعلی</span>
      </div>
      <div class="idea-card">
        <div class="idea-icon"><i class="ti ti-chart-pie-2"></i></div>
        <div class="idea-title">گزارش مصرف روزانه/ماهانه</div>
        <div class="idea-desc">نمودار تجمعی مصرف هر لینک به تفکیک روز و ماه برای آنالیز دقیق‌تر.</div>
        <span class="idea-badge">پیشنهادی</span>
      </div>
      <div class="idea-card">
        <div class="idea-icon"><i class="ti ti-lock-access"></i></div>
        <div class="idea-title">رمز ورود به داشبورد</div>
        <div class="idea-desc">افزودن یک صفحه لاگین ساده با پسورد برای جلوگیری از دسترسی عمومی به پنل مدیریت.</div>
        <span class="idea-badge">پیشنهادی</span>
      </div>
      <div class="idea-card">
        <div class="idea-icon"><i class="ti ti-server-2"></i></div>
        <div class="idea-title">Load Balancing چند سرور</div>
        <div class="idea-desc">امکان معرفی چند نمونه Railway و توزیع اتصالات بین آن‌ها برای افزایش ظرفیت.</div>
        <span class="idea-badge">پیشنهادی</span>
      </div>
    </div>
  </section>

  <!-- ═══════ TEST WS PAGE ═══════ -->
  <section class="page" id="page-testws">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-wifi"></i> تست WebSocket</div>
        <div class="topbar-sub">بررسی سریع اتصال WebSocket به Gateway</div>
      </div>
    </div>

    <div class="card" style="max-width:680px">
      <div class="form-row" style="margin-bottom:14px">
        <div class="form-group" style="flex:1">
          <label class="form-label">UUID (خالی = تصادفی)</label>
          <input class="form-input" id="ws-uuid" placeholder="UUID لینک" style="width:100%">
        </div>
        <button class="btn btn-primary" onclick="wsConnect()"><i class="ti ti-plug-connected"></i> اتصال</button>
        <button class="btn btn-danger" onclick="wsDisconnect()"><i class="ti ti-plug-x"></i> قطع</button>
      </div>
      <div class="form-row" style="margin-bottom:14px">
        <input class="form-input" id="ws-msg" placeholder="پیام تست..." style="flex:1">
        <button class="btn btn-outline" onclick="wsSend()"><i class="ti ti-send"></i> ارسال</button>
      </div>
      <div style="background:var(--blue-900);border-radius:11px;padding:16px;height:260px;overflow-y:auto;font-family:ui-monospace,monospace;font-size:11.5px;line-height:1.9" id="ws-log">
        <p style="color:var(--blue-200)">منتظر اتصال...</p>
      </div>
    </div>
  </section>

  <!-- ═══════ SETTINGS PAGE ═══════ -->
  <section class="page" id="page-settings">
    <div class="topbar">
      <div>
        <div class="topbar-title"><i class="ti ti-settings"></i> تنظیمات</div>
        <div class="topbar-sub">اطلاعات کلی سرویس RVG Gateway</div>
      </div>
    </div>

    <div class="grid2">
      <div class="card">
        <div class="card-title"><i class="ti ti-server"></i> اطلاعات سرور</div>
        <div class="status-row"><span class="status-key"><i class="ti ti-world"></i> دامنه</span><span class="status-val" id="set-host">—</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-route"></i> پورت اتصال</span><span class="status-val">443 (TLS)</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-versions"></i> نسخه</span><span class="status-val">RVG Gateway v6.0</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-brand-fastapi"></i> فریم‌ورک</span><span class="status-val">FastAPI + Uvicorn</span></div>
        <div class="status-row"><span class="status-key"><i class="ti ti-cloud"></i> پلتفرم</span><span class="status-val">Railway</span></div>
      </div>
      <div class="card">
        <div class="card-title"><i class="ti ti-brand-telegram"></i> ارتباط با ما</div>
        <div style="font-size:12.5px;color:var(--blue-700);line-height:1.9;margin-bottom:14px">
          برای دریافت آخرین آپدیت‌ها، آموزش‌ها و پشتیبانی پروژه‌های شبکه و برنامه‌نویسی، به کانال تلگرام <b>codebox</b> بپیوندید.
        </div>
        <a class="tg-btn" href="https://t.me/CodeBoxo" target="_blank" rel="noopener" style="max-width:240px">
          <i class="ti ti-brand-telegram"></i> پیوستن به @CodeBoxo
        </a>
      </div>
    </div>
  </section>

</main>

<script>
let trafficChart, donutChart, trafficChartBig;
let prevTraffic = 0;
let vlessLinkText = '';
let ws;

function toast(msg, isErr){
  const t=document.getElementById('toast');
  t.textContent=msg;
  t.className='toast show'+(isErr?' err':'');
  setTimeout(()=>t.classList.remove('show'),2200);
}

function fmt(n){ return n>=1000?`${(n/1000).toFixed(1)}k`:n; }
function fmtBytes(b){
  if(b===0) return '0 B';
  if(b<1024) return b+' B';
  if(b<1024*1024) return (b/1024).toFixed(1)+' KB';
  if(b<1024*1024*1024) return (b/(1024*1024)).toFixed(2)+' MB';
  return (b/(1024*1024*1024)).toFixed(2)+' GB';
}

/* ───────── Navigation ───────── */
function switchPage(name){
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.toggle('active', n.dataset.page===name));
  document.querySelectorAll('.page').forEach(p=>p.classList.toggle('active', p.id==='page-'+name));
  if(name==='links') loadLinks();
  if(name==='connections') loadConnections();
  if(name==='errors') loadErrorsFull();
}
document.querySelectorAll('.nav-item').forEach(item=>{
  item.addEventListener('click', ()=>switchPage(item.dataset.page));
});

/* ───────── Stats / Charts ───────── */
async function fetchStats(){
  try{
    const r=await fetch('/stats');
    const d=await r.json();

    document.getElementById('m-conns').textContent=d.active_connections;
    document.getElementById('conns-count-badge').textContent=d.active_connections;
    document.getElementById('m-traffic').innerHTML=`${d.total_traffic_mb.toFixed(1)}<span class="metric-unit">MB</span>`;
    document.getElementById('m-reqs').textContent=fmt(d.total_requests);
    document.getElementById('m-errors').textContent=d.total_errors;
    document.getElementById('errors-count-badge').textContent=`${d.total_errors} خطا`;
    document.getElementById('uptime-inline').textContent=d.uptime||'—';
    document.getElementById('uptime-badge').textContent=`Railway · ${d.uptime||'—'}`;
    document.getElementById('last-update').textContent=`آخرین بروزرسانی: ${new Date().toLocaleTimeString('fa-IR')}`;
    document.getElementById('conns-live-badge').innerHTML=`<span class="dot dot-green pulse"></span> ${d.active_connections} اتصال زنده`;

    // traffic page
    document.getElementById('t-traffic').innerHTML=`${d.total_traffic_mb.toFixed(1)}<span class="metric-unit">MB</span>`;

    const delta=d.total_traffic_mb-prevTraffic;
    const pct=Math.min(100,Math.round((delta/50)*100));
    document.getElementById('bw-pct').textContent=`${pct}%`;
    document.getElementById('bw-bar').style.width=pct+'%';
    prevTraffic=d.total_traffic_mb;

    if(d.hourly){
      const labels=Object.keys(d.hourly).sort();
      const vals=labels.map(k=>+(d.hourly[k]/(1024*1024)).toFixed(2));
      [trafficChart, trafficChartBig].forEach(ch=>{
        if(!ch) return;
        ch.data.labels=labels;
        ch.data.datasets[0].data=vals;
        ch.update();
      });
      if(vals.length){
        const avg=vals.reduce((a,b)=>a+b,0)/vals.length;
        const peak=Math.max(...vals);
        document.getElementById('t-avg').innerHTML=`${avg.toFixed(2)}<span class="metric-unit">MB</span>`;
        document.getElementById('t-peak').innerHTML=`${peak.toFixed(2)}<span class="metric-unit">MB</span>`;
      }
    }

    renderErrors(d.recent_errors||[]);
  }catch(e){ console.error(e); }
}

function renderErrors(errors){
  const el=document.getElementById('errors-list');
  const elFull=document.getElementById('errors-list-full');
  if(errors.length){
    const html5=errors.slice(-5).reverse().map(e=>`
      <div class="err-row">
        <div class="err-time"><i class="ti ti-clock" style="font-size:11px"></i> ${new Date(e.time).toLocaleString('fa-IR')}</div>
        <div class="err-msg">${escapeHtml(e.error)}</div>
      </div>`).join('');
    const htmlAll=errors.slice().reverse().map(e=>`
      <div class="err-row">
        <div class="err-time"><i class="ti ti-clock" style="font-size:11px"></i> ${new Date(e.time).toLocaleString('fa-IR')}</div>
        <div class="err-msg">${escapeHtml(e.error)}${e.url?' — '+escapeHtml(e.url):''}</div>
      </div>`).join('');
    if(el) el.innerHTML=html5;
    if(elFull) elFull.innerHTML=htmlAll;
  } else {
    const okHtml='<div style="color:var(--green-text);padding:12px 0;display:flex;align-items:center;gap:6px"><i class="ti ti-circle-check"></i> هیچ خطایی ثبت نشده</div>';
    if(el) el.innerHTML=okHtml;
    if(elFull) elFull.innerHTML=okHtml;
  }
}

function escapeHtml(s){
  return String(s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}

/* ───────── Links Management ───────── */
async function loadLinks(){
  try{
    const r=await fetch('/api/links');
    const d=await r.json();
    const tbody=document.getElementById('links-tbody');
    const empty=document.getElementById('links-empty');
    const links=d.links||[];

    document.getElementById('links-count-badge').textContent=links.length;
    document.getElementById('links-page-count').textContent=`${toFa(links.length)} لینک ساخته شده`;
    document.getElementById('links-summary-badge').textContent=`${toFa(links.length)} لینک`;

    if(!links.length){
      tbody.innerHTML='';
      empty.style.display='block';
    } else {
      empty.style.display='none';
      tbody.innerHTML=links.map(l=>{
        const limitTxt = l.limit_bytes===0 ? 'بی‌نهایت' : fmtBytes(l.limit_bytes);
        const pct = l.limit_bytes===0 ? 0 : Math.min(100, (l.used_bytes/l.limit_bytes)*100);
        const barColor = pct>90 ? 'var(--red-dot)' : pct>70 ? 'var(--amber-dot)' : 'var(--blue-400)';
        return `
        <tr>
          <td><b>${escapeHtml(l.label)}</b><div style="font-size:10px;color:var(--blue-400);margin-top:2px">${new Date(l.created_at).toLocaleString('fa-IR')}</div></td>
          <td><span class="link-uuid">${l.uuid}</span></td>
          <td>
            <div class="usage-bar-wrap">
              <div class="usage-bar"><div class="usage-bar-fill" style="width:${pct}%;background:${barColor}"></div></div>
              <div class="usage-text">${fmtBytes(l.used_bytes)} / ${limitTxt}</div>
            </div>
          </td>
          <td>
            <button class="toggle ${l.active?'on':''}" onclick="toggleLink('${l.uuid}', ${!l.active})" title="فعال/غیرفعال"></button>
          </td>
          <td style="white-space:nowrap">
            <button class="btn btn-sm btn-light-outline" onclick="copyVless('${l.vless_link.replace(/'/g,"\\'")}')"><i class="ti ti-copy"></i> کپی</button>
            <button class="btn btn-sm btn-light-outline" onclick="qrForText('${l.vless_link.replace(/'/g,"\\'")}')"><i class="ti ti-qrcode"></i></button>
            <button class="btn btn-sm btn-light-outline" onclick="resetUsage('${l.uuid}')"><i class="ti ti-rotate"></i></button>
            <button class="btn btn-sm btn-danger" onclick="deleteLink('${l.uuid}')"><i class="ti ti-trash"></i></button>
          </td>
        </tr>`;
      }).join('');
    }

    // overview summary
    const sumEl=document.getElementById('links-summary-list');
    if(!links.length){
      sumEl.innerHTML='هنوز لینکی ساخته نشده.';
    } else {
      sumEl.innerHTML=links.slice(0,5).map(l=>{
        const limitTxt = l.limit_bytes===0 ? 'بی‌نهایت' : fmtBytes(l.limit_bytes);
        return `<div class="status-row">
          <span class="status-key"><i class="ti ${l.active?'ti-circle-check':'ti-circle-x'}" style="color:${l.active?'var(--green-dot)':'var(--red-dot)'}"></i> ${escapeHtml(l.label)}</span>
          <span class="status-val">${fmtBytes(l.used_bytes)} / ${limitTxt}</span>
        </div>`;
      }).join('');
    }
  }catch(e){ console.error(e); }
}

function toFa(n){ return n.toString().replace(/\d/g, d=>'۰۱۲۳۴۵۶۷۸۹'[d]); }

async function createLink(){
  const label=document.getElementById('new-link-label').value.trim() || 'لینک جدید';
  const value=document.getElementById('new-link-value').value;
  const unit=document.getElementById('new-link-unit').value;
  try{
    const r=await fetch('/api/links',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({label, limit_value:value||0, limit_unit:unit})
    });
    if(!r.ok) throw new Error('failed');
    document.getElementById('new-link-label').value='';
    document.getElementById('new-link-value').value='';
    toast('✓ لینک جدید ساخته شد');
    loadLinks();
  }catch(e){ toast('✗ خطا در ساخت لینک', true); }
}

async function toggleLink(uuid, newState){
  try{
    await fetch(`/api/links/${uuid}`,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({active:newState})
    });
    toast(newState?'✓ لینک فعال شد':'✓ لینک غیرفعال شد');
    loadLinks();
  }catch(e){ toast('✗ خطا', true); }
}

async function resetUsage(uuid){
  try{
    await fetch(`/api/links/${uuid}`,{
      method:'PATCH',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({reset_usage:true})
    });
    toast('✓ مصرف ریست شد');
    loadLinks();
  }catch(e){ toast('✗ خطا', true); }
}

async function deleteLink(uuid){
  if(!confirm('آیا از حذف این لینک مطمئن هستید؟')) return;
  try{
    await fetch(`/api/links/${uuid}`,{method:'DELETE'});
    toast('✓ لینک حذف شد');
    loadLinks();
  }catch(e){ toast('✗ خطا', true); }
}

function copyVless(text){
  navigator.clipboard.writeText(text).then(()=>toast('✓ لینک کپی شد'));
}
function qrForText(text){
  window.open(`https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(text)}`,'_blank');
}

/* ───────── Connections Page ───────── */
async function loadConnections(){
  // یک endpoint سبک برای جزئیات اتصالات وجود ندارد روی /stats، پس از همان داده‌های موجود استفاده می‌کنیم
  try{
    const r=await fetch('/stats');
    const d=await r.json();
    const tbody=document.getElementById('conns-tbody');
    const empty=document.getElementById('conns-empty');
    if(d.active_connections===0){
      tbody.innerHTML='';
      empty.style.display='block';
    } else {
      empty.style.display='none';
      // نمایش placeholder چون جزئیات per-connection روی /stats نیست
      tbody.innerHTML=`<tr><td colspan="4" style="text-align:center;color:var(--blue-400);padding:20px">
        ${d.active_connections} اتصال فعال در حال انتقال داده — برای جزئیات کامل هر اتصال، endpoint <code>/api/connections</code> را اضافه کنید.
      </td></tr>`;
    }
  }catch(e){ console.error(e); }
}

async function loadErrorsFull(){
  try{
    const r=await fetch('/stats');
    const d=await r.json();
    renderErrors(d.recent_errors||[]);
  }catch(e){}
}

/* ───────── VLESS overview link ───────── */
async function fetchOverviewVless(){
  try{
    const r=await fetch('/api/links');
    const d=await r.json();
    const links=d.links||[];
    const def = links.find(l=>l.limit_bytes===0) || links[0];
    if(def){
      vlessLinkText=def.vless_link;
      document.getElementById('vless-link-overview').textContent=vlessLinkText;
    } else {
      document.getElementById('vless-link-overview').textContent='در حال ساخت لینک پیش‌فرض... یک‌بار رفرش کنید.';
    }
  }catch(e){ console.error(e); }
}

function copyText(elId){
  const text=document.getElementById(elId).textContent;
  if(!text||text.includes('بارگ')){ toast('لینک هنوز آماده نیست', true); return; }
  navigator.clipboard.writeText(text).then(()=>toast('✓ لینک کپی شد'));
}
function qrFor(elId){
  const text=document.getElementById(elId).textContent;
  if(!text||text.includes('بارگ')){ toast('لینک هنوز آماده نیست', true); return; }
  window.open(`https://api.qrserver.com/v1/create-qr-code/?size=250x250&data=${encodeURIComponent(text)}`,'_blank');
}

function refreshAll(){
  fetchStats();
  fetchOverviewVless();
  loadLinks();
  toast('در حال رفرش...');
}

/* ───────── WebSocket Test ───────── */
function wsLog(cls,msg){
  const log=document.getElementById('ws-log');
  const p=document.createElement('p');
  const colors={ok:'#97C459',err:'#F09595',info:'#85B7EB',sent:'#FAC775'};
  p.style.color=colors[cls]||'#fff';
  p.textContent=`[${new Date().toLocaleTimeString('fa-IR')}] ${msg}`;
  log.appendChild(p); log.scrollTop=log.scrollHeight;
}
function wsConnect(){
  let uuid=document.getElementById('ws-uuid').value.trim()||crypto.randomUUID();
  const url=`${location.protocol==='https:'?'wss':'ws'}://${location.host}/ws/${uuid}`;
  wsLog('info',`در حال اتصال: ${url}`);
  ws=new WebSocket(url);
  ws.onopen=()=>wsLog('ok','✓ اتصال برقرار شد');
  ws.onerror=()=>wsLog('err','✗ خطا در اتصال');
  ws.onmessage=m=>wsLog('info','دریافت داده ('+(m.data.size||m.data.length)+' بایت)');
  ws.onclose=(e)=>wsLog('err',`اتصال قطع شد (code: ${e.code})`);
}
function wsSend(){
  const m=document.getElementById('ws-msg').value;
  if(!m){wsLog('err','پیام خالی است');return}
  if(!ws||ws.readyState!==1){wsLog('err','ابتدا متصل شوید');return}
  ws.send(m); wsLog('sent','ارسال: '+m);
  document.getElementById('ws-msg').value='';
}
function wsDisconnect(){ if(ws) ws.close(); }

/* ───────── Charts init ───────── */
function initCharts(){
  const baseOpts={
    responsive:true,maintainAspectRatio:false,
    plugins:{legend:{display:false},tooltip:{callbacks:{label:v=>`${v.parsed.y.toFixed(2)} MB`}}},
    scales:{
      x:{grid:{color:'rgba(55,138,221,0.07)'},ticks:{color:'#378ADD',font:{size:10}}},
      y:{grid:{color:'rgba(55,138,221,0.07)'},ticks:{color:'#378ADD',font:{size:10},callback:v=>`${v}MB`}}
    }
  };
  const lineData={
    label:'MB',data:[],
    borderColor:'#378ADD',
    backgroundColor:'rgba(55,138,221,0.08)',
    fill:true,tension:0.45,
    pointRadius:4,pointHoverRadius:6,
    pointBackgroundColor:'#185FA5',
    pointBorderColor:'#fff',pointBorderWidth:2,
    borderWidth:2.5
  };

  trafficChart=new Chart(document.getElementById('trafficChart'),{
    type:'line', data:{labels:[],datasets:[{...lineData}]}, options:baseOpts
  });
  trafficChartBig=new Chart(document.getElementById('trafficChartBig'),{
    type:'line', data:{labels:[],datasets:[{...lineData}]}, options:baseOpts
  });

  donutChart=new Chart(document.getElementById('donutChart'),{
    type:'doughnut',
    data:{
      labels:['VLESS / WS','HTTP Proxy','سایر'],
      datasets:[{
        data:[70,25,5],
        backgroundColor:['#185FA5','#378ADD','#85B7EB'],
        borderColor:'#fff',borderWidth:2,
        hoverOffset:6
      }]
    },
    options:{
      responsive:true,maintainAspectRatio:false,cutout:'68%',
      plugins:{legend:{position:'bottom',labels:{color:'#0C447C',font:{size:11},padding:10,usePointStyle:true,pointStyleWidth:10}}}
    }
  });
}

document.addEventListener('DOMContentLoaded',()=>{
  initCharts();
  document.getElementById('set-host').textContent=location.host;
  fetchStats();
  fetchOverviewVless();
  loadLinks();
  setInterval(fetchStats,4000);
  setInterval(()=>{ if(document.getElementById('page-links').classList.contains('active')) loadLinks(); }, 5000);
});
</script>
</body>
</html>"""


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    await ensure_default_link()
    return HTMLResponse(content=DASHBOARD_HTML)


@app.get("/test-ws", response_class=HTMLResponse)
async def test_ws_redirect():
    return HTMLResponse(content="<script>location.href='/dashboard';</script>")


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=CONFIG["port"],
        log_level="info",
        workers=1,
    )
