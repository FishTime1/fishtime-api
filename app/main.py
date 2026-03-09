import datetime as dt
import secrets
from fastapi import FastAPI, Depends, HTTPException, Header, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session
from sqlalchemy import select, func

from .db import Base, engine, get_db
from .models import User, Subscription, ActivationCode, Device
from .security import hash_password, verify_password, create_token, decode_token
from .settings import settings

Base.metadata.create_all(bind=engine)

app = FastAPI(title="FishTime API", version="1.1")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://www.fishtime.online",
        "https://fishtime.online",
        "http://www.fishtime.online",
        "http://fishtime.online",
        "https://fishtime-api.onrender.com",
        "https://api.fishtime.online",
        "https://FishTime1.github.io",
        "https://fishTime1.github.io",
        "http://localhost:5500",
        "http://127.0.0.1:5500",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

auth_scheme = HTTPBearer(auto_error=False)

def utcnow():
    return dt.datetime.now(dt.timezone.utc)

def require_admin(x_admin_key: str | None):
    if not x_admin_key or x_admin_key != settings.ADMIN_KEY:
        raise HTTPException(status_code=401, detail="admin_unauthorized")

def get_current_user(
    creds: HTTPAuthorizationCredentials = Depends(auth_scheme),
    db: Session = Depends(get_db),
):
    if not creds:
        raise HTTPException(status_code=401, detail="missing_token")
    try:
        payload = decode_token(creds.credentials)
        user_id = int(payload["sub"])
    except Exception:
        raise HTTPException(status_code=401, detail="invalid_token")

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=401, detail="user_not_found")
    return user

def enforce_device_limit(db: Session, user: User, device_id: str):
    existing = db.execute(
        select(Device).where(Device.user_id == user.id, Device.device_id == device_id)
    ).scalar_one_or_none()
    if existing:
        existing.last_seen = utcnow()
        return

    count = db.execute(
        select(func.count(Device.id)).where(Device.user_id == user.id)
    ).scalar_one()

    if count >= settings.DEVICE_LIMIT:
        raise HTTPException(status_code=403, detail="device_limit_reached")

    db.add(Device(user_id=user.id, device_id=device_id))

def get_subscription(db: Session, user: User) -> Subscription:
    sub = db.get(Subscription, user.id)
    if not sub:
        sub = Subscription(user_id=user.id, expires_at=utcnow())
        db.add(sub)
        db.flush()
    return sub

def remaining_info(expires_at: dt.datetime):
    now = utcnow()
    remaining = int((expires_at - now).total_seconds())
    return {
        "server_time": now.isoformat(),
        "expires_at": expires_at.isoformat(),
        "remaining_seconds": remaining,
        "ok": remaining > 0,
    }

def admin_get_user_by_email(db: Session, email: str):
    email = email.lower().strip()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="user_not_found")
    return user

class RegisterReq(BaseModel):
    email: EmailStr
    password: str
    device_id: str

class LoginReq(BaseModel):
    email: EmailStr
    password: str
    device_id: str

class RedeemReq(BaseModel):
    code: str

class AdminCodeReq(BaseModel):
    plan: str

class ChangePasswordReq(BaseModel):
    current_password: str
    new_password: str

class AdminAddTimeReq(BaseModel):
    email: EmailStr
    days: int = 0
    hours: int = 0
    minutes: int = 0

class AdminDeleteUserReq(BaseModel):
    email: EmailStr

class AdminResetDevicesReq(BaseModel):
    email: EmailStr

class AdminResetPasswordReq(BaseModel):
    email: EmailStr
    new_password: str

PLAN_SECONDS = {
    "trial_2h": 2 * 3600,
    "day_1": 1 * 86400,
    "day_7": 7 * 86400,
    "day_15": 15 * 86400,
    "day_30": 30 * 86400,
}

def gen_code():
    part = lambda n: secrets.token_hex(n)[:n*2].upper()
    return f"FT-{part(2)}-{part(2)}-{part(2)}"

@app.get("/v1/health")
def health():
    return {"ok": True}

@app.post("/v1/register")
def register(req: RegisterReq, db: Session = Depends(get_db)):
    email = req.email.lower().strip()
    if len(req.password) < 6:
        raise HTTPException(status_code=400, detail="password_too_short")

    exists = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if exists:
        raise HTTPException(status_code=409, detail="email_in_use")

    user = User(email=email, password_hash=hash_password(req.password))
    db.add(user)
    db.flush()

    enforce_device_limit(db, user, req.device_id)
    sub = get_subscription(db, user)

    db.commit()

    token = create_token(user.id, user.email)
    info = remaining_info(sub.expires_at)
    return {"registered": True, "token": token, **info}

@app.post("/v1/login")
def login(req: LoginReq, db: Session = Depends(get_db)):
    email = req.email.lower().strip()
    user = db.execute(select(User).where(User.email == email)).scalar_one_or_none()
    if not user or not verify_password(req.password, user.password_hash):
        raise HTTPException(status_code=401, detail="invalid_credentials")

    enforce_device_limit(db, user, req.device_id)
    sub = get_subscription(db, user)

    db.commit()

    token = create_token(user.id, user.email)
    info = remaining_info(sub.expires_at)
    return {"token": token, **info}

@app.post("/v1/redeem")
def redeem(req: RedeemReq, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    code_str = req.code.strip().upper()

    code = db.execute(select(ActivationCode).where(ActivationCode.code == code_str)).scalar_one_or_none()
    if not code:
        raise HTTPException(status_code=404, detail="code_not_found")
    if code.is_used:
        raise HTTPException(status_code=409, detail="code_already_used")

    sub = get_subscription(db, user)
    now = utcnow()
    base = sub.expires_at if sub.expires_at > now else now
    sub.expires_at = base + dt.timedelta(seconds=code.duration_seconds)

    code.is_used = True
    code.used_by_user_id = user.id
    code.used_at = now

    db.commit()
    return remaining_info(sub.expires_at)

@app.get("/v1/check")
def check(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sub = get_subscription(db, user)
    db.commit()
    return remaining_info(sub.expires_at)

@app.get("/v1/me")
def me(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sub = get_subscription(db, user)
    db.commit()

    info = remaining_info(sub.expires_at)
    device_count = db.execute(
        select(func.count(Device.id)).where(Device.user_id == user.id)
    ).scalar_one()

    return {
        "email": user.email,
        "device_count": device_count,
        "device_limit": settings.DEVICE_LIMIT,
        **info,
    }

@app.post("/v1/change-password")
def change_password(
    req: ChangePasswordReq,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if not verify_password(req.current_password, user.password_hash):
        raise HTTPException(status_code=401, detail="wrong_current_password")

    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="password_too_short")

    user.password_hash = hash_password(req.new_password)
    db.commit()
    return {"ok": True, "message": "password_changed"}

# ---------------------------
# ADMIN: DASHBOARD / USERS
# ---------------------------

@app.get("/v1/admin/stats")
def admin_stats(
    x_admin_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key)

    total_users = db.execute(select(func.count(User.id))).scalar_one()
    total_codes = db.execute(select(func.count(ActivationCode.code))).scalar_one()
    used_codes = db.execute(
        select(func.count(ActivationCode.code)).where(ActivationCode.is_used == True)
    ).scalar_one()

    now = utcnow()

    subs = db.execute(select(Subscription)).scalars().all()
    active_users = 0
    expired_users = 0

    for sub in subs:
        if sub.expires_at and sub.expires_at > now:
            active_users += 1
        else:
            expired_users += 1

    return {
        "total_users": total_users,
        "active_users": active_users,
        "expired_users": expired_users,
        "total_codes": total_codes,
        "used_codes": used_codes,
    }

@app.get("/v1/admin/users")
def admin_list_users(
    x_admin_key: str | None = Header(default=None),
    q: str = Query(default=""),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key)

    stmt = select(User).order_by(User.id.desc())
    if q.strip():
        stmt = select(User).where(User.email.ilike(f"%{q.strip().lower()}%")).order_by(User.id.desc())

    users = db.execute(stmt).scalars().all()
    results = []

    for user in users:
        sub = get_subscription(db, user)
        info = remaining_info(sub.expires_at)

        device_count = db.execute(
            select(func.count(Device.id)).where(Device.user_id == user.id)
        ).scalar_one()

        results.append({
            "id": user.id,
            "email": user.email,
            "device_count": device_count,
            "device_limit": settings.DEVICE_LIMIT,
            **info,
        })

    db.commit()
    return results

@app.post("/v1/admin/users/add-time")
def admin_add_time(
    req: AdminAddTimeReq,
    x_admin_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key)

    if req.days == 0 and req.hours == 0 and req.minutes == 0:
        raise HTTPException(status_code=400, detail="time_required")

    user = admin_get_user_by_email(db, req.email)
    sub = get_subscription(db, user)

    now = utcnow()
    base = sub.expires_at if sub.expires_at > now else now
    sub.expires_at = base + dt.timedelta(days=req.days, hours=req.hours, minutes=req.minutes)

    db.commit()
    return {
        "ok": True,
        "email": user.email,
        **remaining_info(sub.expires_at)
    }

@app.post("/v1/admin/users/reset-devices")
def admin_reset_devices(
    req: AdminResetDevicesReq,
    x_admin_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key)

    user = admin_get_user_by_email(db, req.email)

    devices = db.execute(
        select(Device).where(Device.user_id == user.id)
    ).scalars().all()

    removed = 0
    for d in devices:
        db.delete(d)
        removed += 1

    db.commit()
    return {
        "ok": True,
        "email": user.email,
        "removed_devices": removed,
    }

@app.post("/v1/admin/users/reset-password")
def admin_reset_password(
    req: AdminResetPasswordReq,
    x_admin_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key)

    if len(req.new_password) < 6:
        raise HTTPException(status_code=400, detail="password_too_short")

    user = admin_get_user_by_email(db, req.email)
    user.password_hash = hash_password(req.new_password)
    db.commit()

    return {
        "ok": True,
        "email": user.email,
        "message": "password_reset"
    }

@app.post("/v1/admin/users/delete")
def admin_delete_user(
    req: AdminDeleteUserReq,
    x_admin_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key)

    user = admin_get_user_by_email(db, req.email)

    devices = db.execute(
        select(Device).where(Device.user_id == user.id)
    ).scalars().all()
    for d in devices:
        db.delete(d)

    sub = db.get(Subscription, user.id)
    if sub:
        db.delete(sub)

    # Kullanılmış kodları bozmadan kullanıcı referansını temizleyelim
    used_codes = db.execute(
        select(ActivationCode).where(ActivationCode.used_by_user_id == user.id)
    ).scalars().all()

    for code in used_codes:
        try:
            code.used_by_user_id = None
        except Exception:
            pass

    db.delete(user)
    db.commit()

    return {
        "ok": True,
        "email": req.email.lower().strip(),
        "message": "user_deleted"
    }

# ---------------------------
# ADMIN: CODES
# ---------------------------

@app.post("/v1/admin/codes")
def admin_create_code(
    req: AdminCodeReq,
    x_admin_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key)

    if req.plan not in PLAN_SECONDS:
        raise HTTPException(status_code=400, detail="invalid_plan")

    duration = PLAN_SECONDS[req.plan]

    for _ in range(10):
        c = gen_code()
        exists = db.execute(select(ActivationCode).where(ActivationCode.code == c)).scalar_one_or_none()
        if not exists:
            code = ActivationCode(code=c, duration_seconds=duration, is_used=False)
            db.add(code)
            db.commit()
            return {"code": c, "duration_seconds": duration, "plan": req.plan}

    raise HTTPException(status_code=500, detail="code_generation_failed")

@app.get("/v1/admin/codes")
def admin_list_codes(
    x_admin_key: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key)

    codes = db.execute(
        select(ActivationCode).order_by(ActivationCode.code.desc())
    ).scalars().all()

    results = []
    for c in codes:
        results.append({
            "code": c.code,
            "duration_seconds": c.duration_seconds,
            "is_used": c.is_used,
            "used_by_user_id": c.used_by_user_id,
            "used_at": c.used_at.isoformat() if c.used_at else None,
        })

    return results
