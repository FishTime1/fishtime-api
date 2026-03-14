import datetime as dt
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, EmailStr
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from .db import Base, engine, get_db
from .models import ActivationCode, Device, Subscription, SupportMessage, User
from .security import create_admin_token, create_token, decode_token, hash_password, verify_password
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
ADMIN_KEY_FALLBACK = "4e1ace7667"


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


class SupportMessageReq(BaseModel):
    message: str


class AdminUserActionReq(BaseModel):
    email: EmailStr


class AdminAddTimeReq(BaseModel):
    email: EmailStr
    days: int = 0
    hours: int = 0
    minutes: int = 0


class AdminResetPasswordReq(BaseModel):
    email: EmailStr
    new_password: str


class AdminWebLoginReq(BaseModel):
    username: str
    password: str


PLAN_SECONDS = {
    "trial_2h": 2 * 3600,
    "day_1": 1 * 86400,
    "day_7": 7 * 86400,
    "day_15": 15 * 86400,
    "day_30": 30 * 86400,
}


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def require_admin(x_admin_key: str | None, x_admin_token: str | None = None):
    valid_keys = {ADMIN_KEY_FALLBACK}
    if settings.ADMIN_KEY:
        valid_keys.add(settings.ADMIN_KEY)

    if x_admin_key and x_admin_key in valid_keys:
        return {"mode": "key"}

    if x_admin_token:
        try:
            payload = decode_token(x_admin_token)
        except Exception:
            raise HTTPException(status_code=401, detail="admin_unauthorized")

        if payload.get("role") == "admin" and payload.get("username") == settings.ADMIN_WEB_USERNAME:
            return payload

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


def gen_code():
    part = lambda n: secrets.token_hex(n)[: n * 2].upper()
    return f"FT-{part(2)}-{part(2)}-{part(2)}"


def get_user_by_email(db: Session, email: str) -> User:
    normalized = email.lower().strip()
    user = db.execute(select(User).where(User.email == normalized)).scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="user_not_found")
    return user


def serialize_code(code: ActivationCode):
    return {
        "id": code.id,
        "code": code.code,
        "duration_seconds": code.duration_seconds,
        "is_used": code.is_used,
        "used_by_user_id": code.used_by_user_id,
        "used_at": code.used_at.isoformat() if code.used_at else None,
        "created_at": code.created_at.isoformat() if code.created_at else None,
    }


def serialize_support_message(message: SupportMessage):
    return {
        "id": message.id,
        "user_id": message.user_id,
        "sender_role": message.sender_role,
        "body": message.body,
        "is_read_by_user": message.is_read_by_user,
        "is_read_by_admin": message.is_read_by_admin,
        "created_at": message.created_at.isoformat() if message.created_at else None,
    }


def serialize_device(device: Device):
    return {
        "id": device.id,
        "device_id": device.device_id,
        "first_seen": device.first_seen.isoformat() if device.first_seen else None,
        "last_seen": device.last_seen.isoformat() if device.last_seen else None,
    }


def build_user_summary(db: Session, user: User):
    sub = db.get(Subscription, user.id)
    expires_at = sub.expires_at if sub else utcnow()
    devices = db.execute(
        select(Device)
        .where(Device.user_id == user.id)
        .order_by(Device.last_seen.desc(), Device.id.desc())
    ).scalars().all()
    last_seen = devices[0].last_seen if devices else None
    return {
        "id": user.id,
        "email": user.email,
        "created_at": user.created_at.isoformat() if user.created_at else None,
        "device_count": len(devices),
        "device_limit": settings.DEVICE_LIMIT,
        "devices": [serialize_device(device) for device in devices],
        "last_device_seen_at": last_seen.isoformat() if last_seen else None,
        **remaining_info(expires_at),
    }


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
    return build_user_summary(db, user) | {"expires_at": sub.expires_at.isoformat()}


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


@app.get("/v1/messages")
def get_my_messages(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    messages = db.execute(
        select(SupportMessage)
        .where(SupportMessage.user_id == user.id)
        .order_by(SupportMessage.created_at.asc(), SupportMessage.id.asc())
    ).scalars().all()

    changed = False
    for message in messages:
        if message.sender_role == "admin" and not message.is_read_by_user:
            message.is_read_by_user = True
            changed = True

    if changed:
        db.commit()

    return {
        "messages": [serialize_support_message(message) for message in messages],
        "user": {"id": user.id, "email": user.email},
    }


@app.post("/v1/messages")
def send_my_message(
    req: SupportMessageReq,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    body = req.message.strip()
    if not body:
        raise HTTPException(status_code=400, detail="message_required")

    message = SupportMessage(
        user_id=user.id,
        sender_role="user",
        body=body,
        is_read_by_user=True,
        is_read_by_admin=False,
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return {"ok": True, "message": serialize_support_message(message)}


@app.delete("/v1/admin/messages/item/{message_id}")
def admin_delete_message(
    message_id: int,
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    message = db.get(SupportMessage, message_id)
    if not message:
        raise HTTPException(status_code=404, detail="message_not_found")

    db.delete(message)
    db.commit()
    return {"ok": True, "message_id": message_id}


@app.delete("/v1/admin/messages/thread/{user_id}")
def admin_delete_message_thread(
    user_id: int,
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user_not_found")

    messages = db.execute(
        select(SupportMessage).where(SupportMessage.user_id == user_id)
    ).scalars().all()
    removed_count = len(messages)
    for message in messages:
        db.delete(message)
    db.commit()
    return {"ok": True, "user_id": user_id, "removed_count": removed_count}


@app.post("/v1/admin/web-login")
def admin_web_login(req: AdminWebLoginReq):
    username = req.username.strip()
    password = req.password

    if username != settings.ADMIN_WEB_USERNAME or password != settings.ADMIN_WEB_PASSWORD:
        raise HTTPException(status_code=401, detail="invalid_admin_credentials")

    return {
        "ok": True,
        "username": settings.ADMIN_WEB_USERNAME,
        "token": create_admin_token(settings.ADMIN_WEB_USERNAME),
    }


@app.get("/v1/admin/stats")
def admin_stats(
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    now = utcnow()
    total_users = db.execute(select(func.count(User.id))).scalar_one()
    active_users = db.execute(
        select(func.count(Subscription.user_id)).where(Subscription.expires_at > now)
    ).scalar_one()
    total_codes = db.execute(select(func.count(ActivationCode.id))).scalar_one()
    used_codes = db.execute(
        select(func.count(ActivationCode.id)).where(ActivationCode.is_used.is_(True))
    ).scalar_one()
    unread_support = db.execute(
        select(func.count(SupportMessage.id)).where(
            SupportMessage.sender_role == "user",
            SupportMessage.is_read_by_admin.is_(False),
        )
    ).scalar_one()

    return {
        "total_users": total_users,
        "active_users": active_users,
        "expired_users": max(total_users - active_users, 0),
        "total_codes": total_codes,
        "used_codes": used_codes,
        "unread_support_messages": unread_support,
    }


@app.get("/v1/admin/users")
def admin_users(
    q: str = Query(default=""),
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    stmt = select(User).order_by(User.created_at.desc())
    if q.strip():
        pattern = f"%{q.strip().lower()}%"
        stmt = stmt.where(func.lower(User.email).like(pattern))

    users = db.execute(stmt).scalars().all()
    return [build_user_summary(db, user) for user in users]


@app.post("/v1/admin/users/add-time")
def admin_add_time(
    req: AdminAddTimeReq,
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    total_seconds = (req.days * 86400) + (req.hours * 3600) + (req.minutes * 60)
    if total_seconds <= 0:
        raise HTTPException(status_code=400, detail="invalid_duration")

    user = get_user_by_email(db, str(req.email))
    sub = get_subscription(db, user)
    now = utcnow()
    base = sub.expires_at if sub.expires_at > now else now
    sub.expires_at = base + dt.timedelta(seconds=total_seconds)

    db.commit()
    return {"email": user.email, **remaining_info(sub.expires_at)}


@app.post("/v1/admin/users/reset-devices")
def admin_reset_devices(
    req: AdminUserActionReq,
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    user = get_user_by_email(db, str(req.email))
    devices = db.execute(select(Device).where(Device.user_id == user.id)).scalars().all()
    removed_devices = len(devices)
    for device in devices:
        db.delete(device)
    db.commit()
    return {"ok": True, "email": user.email, "removed_devices": removed_devices}


@app.post("/v1/admin/users/reset-password")
def admin_reset_password(
    req: AdminResetPasswordReq,
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    if len(req.new_password.strip()) < 6:
        raise HTTPException(status_code=400, detail="password_too_short")

    user = get_user_by_email(db, str(req.email))
    user.password_hash = hash_password(req.new_password.strip())
    db.commit()
    return {"ok": True, "email": user.email}


@app.post("/v1/admin/users/delete")
def admin_delete_user(
    req: AdminUserActionReq,
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    user = get_user_by_email(db, str(req.email))
    used_codes = db.execute(
        select(ActivationCode).where(ActivationCode.used_by_user_id == user.id)
    ).scalars().all()
    for code in used_codes:
        code.used_by_user_id = None

    email = user.email
    db.delete(user)
    db.commit()
    return {"ok": True, "email": email}


@app.get("/v1/admin/codes")
def admin_list_codes(
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    codes = db.execute(
        select(ActivationCode).order_by(ActivationCode.created_at.desc(), ActivationCode.id.desc())
    ).scalars().all()
    return [serialize_code(code) for code in codes]


@app.post("/v1/admin/codes")
def admin_create_code(
    req: AdminCodeReq,
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    if req.plan not in PLAN_SECONDS:
        raise HTTPException(status_code=400, detail="invalid_plan")

    duration = PLAN_SECONDS[req.plan]

    for _ in range(10):
        code_value = gen_code()
        exists = db.execute(
            select(ActivationCode).where(ActivationCode.code == code_value)
        ).scalar_one_or_none()
        if not exists:
            code = ActivationCode(code=code_value, duration_seconds=duration, is_used=False)
            db.add(code)
            db.commit()
            db.refresh(code)
            return {
                "code": code.code,
                "duration_seconds": duration,
                "plan": req.plan,
                "created_at": code.created_at.isoformat() if code.created_at else None,
            }

    raise HTTPException(status_code=500, detail="code_generation_failed")


@app.delete("/v1/admin/codes/{code_id}")
def admin_delete_code(
    code_id: int,
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    code = db.get(ActivationCode, code_id)
    if not code:
        raise HTTPException(status_code=404, detail="code_not_found")

    code_value = code.code
    db.delete(code)
    db.commit()
    return {"ok": True, "id": code_id, "code": code_value}


@app.get("/v1/admin/messages")
def admin_list_messages(
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    users = db.execute(select(User).order_by(User.created_at.desc())).scalars().all()
    conversations = []
    for user in users:
        messages = db.execute(
            select(SupportMessage)
            .where(SupportMessage.user_id == user.id)
            .order_by(SupportMessage.created_at.desc(), SupportMessage.id.desc())
        ).scalars().all()
        if not messages:
            continue

        latest = messages[0]
        unread_count = sum(
            1
            for message in messages
            if message.sender_role == "user" and not message.is_read_by_admin
        )
        conversations.append(
            {
                "user_id": user.id,
                "email": user.email,
                "last_message": latest.body,
                "last_message_at": latest.created_at.isoformat() if latest.created_at else None,
                "last_sender_role": latest.sender_role,
                "unread_count": unread_count,
            }
        )

    conversations.sort(key=lambda item: item.get("last_message_at") or "", reverse=True)
    return conversations


@app.get("/v1/admin/messages/{user_id}")
def admin_get_message_thread(
    user_id: int,
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user_not_found")

    messages = db.execute(
        select(SupportMessage)
        .where(SupportMessage.user_id == user.id)
        .order_by(SupportMessage.created_at.asc(), SupportMessage.id.asc())
    ).scalars().all()

    changed = False
    for message in messages:
        if message.sender_role == "user" and not message.is_read_by_admin:
            message.is_read_by_admin = True
            changed = True

    if changed:
        db.commit()

    return {
        "user": {"id": user.id, "email": user.email},
        "messages": [serialize_support_message(message) for message in messages],
    }


@app.post("/v1/admin/messages/{user_id}")
def admin_send_message(
    user_id: int,
    req: SupportMessageReq,
    x_admin_key: str | None = Header(default=None),
    x_admin_token: str | None = Header(default=None),
    db: Session = Depends(get_db),
):
    require_admin(x_admin_key, x_admin_token)

    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=404, detail="user_not_found")

    body = req.message.strip()
    if not body:
        raise HTTPException(status_code=400, detail="message_required")

    message = SupportMessage(
        user_id=user.id,
        sender_role="admin",
        body=body,
        is_read_by_user=False,
        is_read_by_admin=True,
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return {"ok": True, "message": serialize_support_message(message)}