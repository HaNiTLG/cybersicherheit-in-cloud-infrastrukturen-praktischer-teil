import os, time, secrets, hashlib, hmac, datetime, logging
from typing import Optional, Dict

from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, constr
import pymysql

log = logging.getLogger("snakecloud")
logging.basicConfig(level=logging.INFO)

DB_HOST = os.getenv("DB_HOST", "macloud-backend1.hanitlg.de")
DB_PORT = int(os.getenv("DB_PORT", "3306"))
DB_NAME = os.getenv("DB_NAME", "snakecloud")
DB_USER = os.getenv("DB_USER", "snakeapp")
DB_PASS = os.getenv("DB_PASSWORD") or (
    open("/run/secrets/db_app").read().strip()
    if os.path.exists("/run/secrets/db_app") else ""
)

DB_SSLMODE = (os.getenv("DB_SSLMODE", "require") or "require").lower()
DB_SSL_CA = os.getenv("DB_SSL_CA", "/run/secrets/db_ssl_ca")

COOKIE_NAME = "session"
SESSION_DAYS = 7

COMMON_CONN_ARGS = dict(
    host=DB_HOST,
    port=DB_PORT,
    user=DB_USER,
    password=DB_PASS,
    database=DB_NAME,
    autocommit=True,
    cursorclass=pymysql.cursors.DictCursor,
    charset="utf8mb4",
    connect_timeout=3,
    read_timeout=5,
    write_timeout=5,
)

def _build_ssl_arg():
    need_ssl = DB_SSLMODE in ("require", "verify-ca", "verify_full", "on", "true", "1")
    if need_ssl and os.path.exists(DB_SSL_CA):
        return {"ca": DB_SSL_CA}
    if need_ssl:
        log.error("DB_SSLMODE=%s aber CA fehlt: %s", DB_SSLMODE, DB_SSL_CA)
    return None

def get_conn(retries:int=2, backoff:float=0.3):
    last_err = None
    ssl_arg = _build_ssl_arg()
    for attempt in range(retries+1):
        try:
            if ssl_arg:
                return pymysql.connect(**COMMON_CONN_ARGS, ssl=ssl_arg)
            return pymysql.connect(**COMMON_CONN_ARGS)
        except Exception as e:
            last_err = e
            if attempt < retries:
                time.sleep(backoff*(attempt+1))
    log.error("DB connect failed to %s:%s: %r", DB_HOST, DB_PORT, last_err)
    raise HTTPException(status_code=503, detail="db_unavailable")

def hash_pw(password: str, salt: Optional[bytes] = None) -> Dict[str, bytes]:
    if salt is None:
        salt = secrets.token_bytes(16)
    pw_hash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000, dklen=64)
    return {"salt": salt, "hash": pw_hash}

def verify_pw(password: str, salt: bytes, pw_hash: bytes) -> bool:
    calc = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000, dklen=64)
    return hmac.compare_digest(calc, pw_hash)

class RegisterIn(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=50)
    email: EmailStr
    password: constr(min_length=6, max_length=200)

class LoginIn(BaseModel):
    username: constr(strip_whitespace=True, min_length=3, max_length=50)
    password: constr(min_length=6, max_length=200)

class ScoreIn(BaseModel):
    score: int

class ChangePwIn(BaseModel):
    old_password: constr(min_length=6, max_length=200)
    new_password: constr(min_length=6, max_length=200)

app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/api/health")
def health():
    return {"ok": True}

def create_session(cur, user_id: int) -> str:
    token = secrets.token_hex(32)
    exp = (datetime.datetime.utcnow() + datetime.timedelta(days=SESSION_DAYS)).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute(
        "INSERT INTO sessions (token, user_id, expires_at) VALUES (%s,%s,%s)",
        (token, user_id, exp),
    )
    return token

def get_user_from_request(req: Request):
    tok = req.cookies.get(COOKIE_NAME)
    if not tok:
        return None
    with get_conn() as con, con.cursor() as cur:
        cur.execute(
            "SELECT u.id,u.username,u.email,u.highscore FROM sessions s "
            "JOIN users u ON u.id=s.user_id "
            "WHERE s.token=%s AND s.expires_at>UTC_TIMESTAMP()",
            (tok,),
        )
        return cur.fetchone()

def require_user(req: Request):
    user = get_user_from_request(req)
    if not user:
        raise HTTPException(status_code=401, detail="unauthorized")
    return user

@app.post("/api/register")
def register(data: RegisterIn):
    try:
        with get_conn() as con, con.cursor() as cur:
            hp = hash_pw(data.password)
            cur.execute(
                "INSERT INTO users (username,email,password_hash,salt) VALUES (%s,%s,%s,%s)",
                (data.username, data.email, hp["hash"], hp["salt"]),
            )
        return {"ok": True}
    except pymysql.err.IntegrityError:
        raise HTTPException(status_code=400, detail="username_or_email_exists")
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="server_error")

@app.post("/api/login")
def login(data: LoginIn, res: Response):
    try:
        with get_conn() as con, con.cursor() as cur:
            cur.execute("SELECT id,username,email,password_hash,salt,highscore FROM users WHERE username=%s", (data.username,))
            u = cur.fetchone()
            if not u or not verify_pw(data.password, u["salt"], u["password_hash"]):
                raise HTTPException(status_code=401, detail="invalid_credentials")
            cur.execute("DELETE FROM sessions WHERE user_id=%s OR expires_at<=UTC_TIMESTAMP()", (u["id"],))
            tok = create_session(cur, u["id"])
        res.set_cookie(
            COOKIE_NAME, tok,
            httponly=True, max_age=SESSION_DAYS*24*3600, samesite="lax", path="/"
        )
        return {"username": u["username"], "highscore": u["highscore"]}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="server_error")

@app.post("/api/logout")
def logout(req: Request, res: Response):
    tok = req.cookies.get(COOKIE_NAME)
    if tok:
        with get_conn() as con, con.cursor() as cur:
            cur.execute("DELETE FROM sessions WHERE token=%s", (tok,))
    res.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}

@app.get("/api/me")
def me(req: Request):
    u = require_user(req)
    return {"username": u["username"], "highscore": u["highscore"]}

@app.post("/api/score")
def score(req: Request, data: ScoreIn):
    u = require_user(req)
    if data.score < 0:
        raise HTTPException(status_code=400, detail="bad_score")
    with get_conn() as con, con.cursor() as cur:
        cur.execute("SELECT highscore FROM users WHERE id=%s", (u["id"],))
        row = cur.fetchone()
        hi = row["highscore"] if row else 0
        if data.score > hi:
            cur.execute("UPDATE users SET highscore=%s WHERE id=%s", (data.score, u["id"]))
            hi = data.score
    return {"highscore": hi}

@app.get("/api/leaderboard")
def leaderboard():
    with get_conn() as con, con.cursor() as cur:
        cur.execute("SELECT username, highscore FROM users ORDER BY highscore DESC, id ASC LIMIT 5")
        return cur.fetchall()

@app.post("/api/change_password")
def change_password(req: Request, data: ChangePwIn):
    u = require_user(req)
    try:
        with get_conn() as con, con.cursor() as cur:
            cur.execute("SELECT password_hash, salt FROM users WHERE id=%s", (u["id"],))
            row = cur.fetchone()
            if not row or not verify_pw(data.old_password, row["salt"], row["password_hash"]):
                raise HTTPException(status_code=400, detail="wrong_old_password")
            hp = hash_pw(data.new_password)
            cur.execute("UPDATE users SET password_hash=%s, salt=%s WHERE id=%s",
                        (hp["hash"], hp["salt"], u["id"]))
            cur.execute("DELETE FROM sessions WHERE user_id=%s", (u["id"],))
        return {"ok": True}
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500, detail="server_error")

@app.on_event("startup")
def check_schema():
    try:
        with get_conn() as con, con.cursor() as cur:
            cur.execute("SELECT 1 FROM users LIMIT 1")
            cur.execute("SELECT 1 FROM sessions LIMIT 1")
        log.info("INFO:snakecloud:Schema OK")
    except HTTPException as e:
        log.error("DB check failed on startup (HTTP %s)", e.status_code)
    except Exception as e:
        log.error("DB check failed on startup: %r", e)