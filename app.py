from __future__ import annotations

import hashlib
import base64
import hmac
import json
import math
import os
import secrets
import smtplib
import sqlite3
import threading
import time
import traceback
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, quote, urlparse
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "data"
STATIC_DIR = APP_DIR / "static"
DB_PATH = DATA_DIR / "app.db"
APP_VERSION = "1.6.1"
AUTH_CONFIG_PATH = Path(os.getenv("AUTH_CONFIG_PATH") or (DATA_DIR / "auth.json"))
AUTH_COOKIE_NAME = "upstream_watch_session"
DEFAULT_SESSION_DAYS = 30
MAX_LOGIN_FAILURES = 5
LOGIN_FAILURE_WINDOW_SECONDS = 10 * 60
DEFAULT_INTERVAL_MINUTES = 3
MIN_INTERVAL_MINUTES = 1
HTTP_TIMEOUT_SECONDS = 15
SCAN_INTERVAL_SECONDS = 10
SERVER_HOST = os.getenv("HOST", "127.0.0.1")
SERVER_PORT = int(os.getenv("PORT", "8000"))
APP_TIMEZONE_NAME = os.getenv("APP_TIMEZONE") or os.getenv("TZ") or "Asia/Shanghai"
try:
    APP_TIMEZONE = ZoneInfo(APP_TIMEZONE_NAME)
except ZoneInfoNotFoundError:
    APP_TIMEZONE_NAME = "Asia/Shanghai"
    APP_TIMEZONE = timezone(timedelta(hours=8), APP_TIMEZONE_NAME)

DB_LOCK = threading.RLock()
AUTH_LOCK = threading.RLock()
AUTH_FAILURES: Dict[str, List[float]] = {}
STOP_EVENT = threading.Event()
SITE_DETECTION_LOCKS_LOCK = threading.Lock()
SITE_DETECTION_LOCKS: Dict[int, threading.Lock] = {}


def app_now() -> datetime:
    return datetime.now(APP_TIMEZONE)


def utc_now_iso() -> str:
    return app_now().isoformat(timespec="seconds")


def parse_iso_dt(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def normalize_base_url(value: str) -> str:
    value = (value or "").strip().rstrip("/")
    if not value:
        return value
    return value


def normalize_qq_group_id(value: Any) -> str:
    text = str(value or "").strip()
    return text if text.isdigit() and 5 <= len(text) <= 20 else ""


def normalize_qq_api_url(value: Any) -> str:
    text = str(value or "").strip().rstrip("/")
    if not text:
        return ""
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("QQ 通知接口地址必须是有效的 HTTP 或 HTTPS URL")
    return text


def ensure_dirs() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    STATIC_DIR.mkdir(parents=True, exist_ok=True)


def write_auth_config(config: Dict[str, Any]) -> None:
    AUTH_CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    temp_path = AUTH_CONFIG_PATH.with_suffix(AUTH_CONFIG_PATH.suffix + ".tmp")
    temp_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    temp_path.replace(AUTH_CONFIG_PATH)
    try:
        os.chmod(AUTH_CONFIG_PATH, 0o600)
    except OSError:
        pass


def ensure_auth_config() -> Dict[str, Any]:
    created = False
    with AUTH_LOCK:
        if AUTH_CONFIG_PATH.exists():
            try:
                config = json.loads(AUTH_CONFIG_PATH.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"登录配置读取失败：{exc}") from exc
        else:
            config = {
                "username": "admin",
                "password": secrets.token_urlsafe(18),
                "session_days": DEFAULT_SESSION_DAYS,
                "session_secret": secrets.token_urlsafe(32),
            }
            created = True

        changed = False
        if not str(config.get("session_secret") or "").strip():
            config["session_secret"] = secrets.token_urlsafe(32)
            changed = True
        if "session_days" not in config:
            config["session_days"] = DEFAULT_SESSION_DAYS
            changed = True
        if created or changed:
            write_auth_config(config)

    username = str(config.get("username") or "").strip()
    password = str(config.get("password") or "")
    try:
        session_days = int(config.get("session_days") or DEFAULT_SESSION_DAYS)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("登录配置 session_days 必须是整数") from exc
    if not username or not password:
        raise RuntimeError("登录配置 username/password 不能为空")
    if session_days < 1 or session_days > 365:
        raise RuntimeError("登录配置 session_days 必须在 1 到 365 之间")
    config["username"] = username
    config["password"] = password
    config["session_days"] = session_days
    if created:
        print(f"Generated login config: {AUTH_CONFIG_PATH}")
        print(f"Initial login username: {username}")
        print("Initial login password is stored in the config file.")
    return config


def load_auth_config() -> Dict[str, Any]:
    return ensure_auth_config()


def auth_credential_version(config: Dict[str, Any]) -> str:
    text = f"{config['username']}\n{config['password']}"
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:24]


def urlsafe_b64encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def urlsafe_b64decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def create_session_token(config: Dict[str, Any]) -> Tuple[str, int]:
    expires_at = int(time.time()) + int(config["session_days"]) * 86400
    payload = {
        "username": config["username"],
        "expires_at": expires_at,
        "version": auth_credential_version(config),
    }
    encoded_payload = urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signature = hmac.new(
        str(config["session_secret"]).encode("utf-8"),
        encoded_payload.encode("ascii"),
        hashlib.sha256,
    ).digest()
    return f"{encoded_payload}.{urlsafe_b64encode(signature)}", expires_at


def validate_session_token(token: str, config: Optional[Dict[str, Any]] = None) -> Optional[Dict[str, Any]]:
    try:
        config = config or load_auth_config()
        payload_part, signature_part = str(token or "").split(".", 1)
        expected_signature = hmac.new(
            str(config["session_secret"]).encode("utf-8"),
            payload_part.encode("ascii"),
            hashlib.sha256,
        ).digest()
        supplied_signature = urlsafe_b64decode(signature_part)
        if not hmac.compare_digest(expected_signature, supplied_signature):
            return None
        payload = json.loads(urlsafe_b64decode(payload_part).decode("utf-8"))
        if int(payload.get("expires_at") or 0) <= int(time.time()):
            return None
        if payload.get("username") != config["username"]:
            return None
        if payload.get("version") != auth_credential_version(config):
            return None
        return payload
    except Exception:
        return None


def session_from_cookie_header(cookie_header: str) -> Optional[Dict[str, Any]]:
    if not cookie_header:
        return None
    try:
        cookie = SimpleCookie()
        cookie.load(cookie_header)
        morsel = cookie.get(AUTH_COOKIE_NAME)
        return validate_session_token(morsel.value if morsel else "")
    except Exception:
        return None


def request_client_ip(handler: BaseHTTPRequestHandler) -> str:
    forwarded = str(handler.headers.get("X-Forwarded-For") or "").split(",", 1)[0].strip()
    return forwarded or str(handler.client_address[0])


def login_rate_limited(client_ip: str) -> bool:
    cutoff = time.monotonic() - LOGIN_FAILURE_WINDOW_SECONDS
    with AUTH_LOCK:
        attempts = [value for value in AUTH_FAILURES.get(client_ip, []) if value >= cutoff]
        AUTH_FAILURES[client_ip] = attempts
        return len(attempts) >= MAX_LOGIN_FAILURES


def record_login_failure(client_ip: str) -> None:
    with AUTH_LOCK:
        AUTH_FAILURES.setdefault(client_ip, []).append(time.monotonic())


def clear_login_failures(client_ip: str) -> None:
    with AUTH_LOCK:
        AUTH_FAILURES.pop(client_ip, None)


def session_cookie_header(handler: BaseHTTPRequestHandler, token: str, max_age: int) -> str:
    cookie = f"{AUTH_COOKIE_NAME}={token}; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Strict"
    forwarded_proto = str(handler.headers.get("X-Forwarded-Proto") or "").split(",", 1)[0].strip().lower()
    if forwarded_proto == "https":
        cookie += "; Secure"
    return cookie


def connect_db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    return conn


def init_db() -> None:
    with DB_LOCK, connect_db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS sites (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                base_url TEXT NOT NULL UNIQUE,
                platform TEXT NOT NULL DEFAULT 'newapi',
                enabled INTEGER NOT NULL DEFAULT 1,
                interval_minutes INTEGER NOT NULL DEFAULT 3,
                focus_keywords TEXT,
                notify_groups_json TEXT,
                login_enabled INTEGER NOT NULL DEFAULT 0,
                auth_mode TEXT NOT NULL DEFAULT 'password',
                login_username TEXT,
                login_password TEXT,
                access_token TEXT,
                access_user_id TEXT,
                refresh_token TEXT,
                token_expires_at TEXT,
                auth_alert_active INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'unknown',
                last_error TEXT,
                last_check_at TEXT,
                next_check_at TEXT,
                consecutive_failures INTEGER NOT NULL DEFAULT 0,
                current_groups_json TEXT,
                current_login_groups_json TEXT,
                login_last_error TEXT,
                login_last_check_at TEXT,
                balance_alert_enabled INTEGER NOT NULL DEFAULT 0,
                balance_alert_threshold REAL NOT NULL DEFAULT 10,
                current_balance REAL,
                balance_currency TEXT NOT NULL DEFAULT 'USD',
                balance_last_error TEXT,
                balance_last_check_at TEXT,
                balance_alert_active INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT '/api/user/groups',
                groups_json TEXT,
                raw_json TEXT,
                hash TEXT,
                error_message TEXT,
                checked_at TEXT NOT NULL,
                FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS changes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id INTEGER NOT NULL,
                change_type TEXT NOT NULL,
                group_name TEXT,
                old_value TEXT,
                new_value TEXT,
                change_percent REAL,
                message TEXT NOT NULL,
                created_at TEXT NOT NULL,
                acknowledged INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS balance_snapshots (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                site_id INTEGER NOT NULL,
                status TEXT NOT NULL,
                balance REAL,
                currency TEXT NOT NULL DEFAULT 'USD',
                raw_json TEXT,
                error_message TEXT,
                checked_at TEXT NOT NULL,
                FOREIGN KEY(site_id) REFERENCES sites(id) ON DELETE CASCADE
            );

            CREATE TABLE IF NOT EXISTS notification_settings (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                wecom_enabled INTEGER NOT NULL DEFAULT 0,
                wecom_webhook TEXT,
                wecom_last_error TEXT,
                wecom_last_sent_at TEXT,
                feishu_enabled INTEGER NOT NULL DEFAULT 0,
                feishu_webhook TEXT,
                feishu_secret TEXT,
                feishu_last_error TEXT,
                feishu_last_sent_at TEXT,
                qq_enabled INTEGER NOT NULL DEFAULT 0,
                qq_api_url TEXT,
                qq_api_token TEXT,
                qq_group_id TEXT,
                qq_last_error TEXT,
                qq_last_sent_at TEXT,
                email_enabled INTEGER NOT NULL DEFAULT 0,
                smtp_host TEXT,
                smtp_port INTEGER NOT NULL DEFAULT 465,
                smtp_username TEXT,
                smtp_password TEXT,
                smtp_use_ssl INTEGER NOT NULL DEFAULT 1,
                smtp_from TEXT,
                smtp_to TEXT,
                email_last_error TEXT,
                email_last_sent_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS notification_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                channel TEXT NOT NULL,
                status TEXT NOT NULL,
                target TEXT,
                message TEXT,
                error_message TEXT,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_sites_enabled_next_check ON sites(enabled, next_check_at);
            CREATE INDEX IF NOT EXISTS idx_snapshots_site_checked ON snapshots(site_id, checked_at DESC);
            CREATE INDEX IF NOT EXISTS idx_changes_site_created ON changes(site_id, created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_balance_snapshots_site_checked ON balance_snapshots(site_id, checked_at DESC);
            CREATE INDEX IF NOT EXISTS idx_notification_logs_created ON notification_logs(created_at DESC);
            """
        )
        columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(sites)").fetchall()
        }
        if "focus_keywords" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN focus_keywords TEXT")
        if "notify_groups_json" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN notify_groups_json TEXT")
        if "login_enabled" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN login_enabled INTEGER NOT NULL DEFAULT 0")
        if "auth_mode" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN auth_mode TEXT NOT NULL DEFAULT 'password'")
        if "login_username" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN login_username TEXT")
        if "login_password" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN login_password TEXT")
        if "access_token" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN access_token TEXT")
        if "access_user_id" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN access_user_id TEXT")
        if "refresh_token" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN refresh_token TEXT")
        if "token_expires_at" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN token_expires_at TEXT")
        if "auth_alert_active" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN auth_alert_active INTEGER NOT NULL DEFAULT 0")
        if "current_login_groups_json" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN current_login_groups_json TEXT")
        if "login_last_error" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN login_last_error TEXT")
        if "login_last_check_at" not in columns:
            conn.execute("ALTER TABLE sites ADD COLUMN login_last_check_at TEXT")
        site_columns = {
            "balance_alert_enabled": "INTEGER NOT NULL DEFAULT 0",
            "balance_alert_threshold": "REAL NOT NULL DEFAULT 10",
            "current_balance": "REAL",
            "balance_currency": "TEXT NOT NULL DEFAULT 'USD'",
            "balance_last_error": "TEXT",
            "balance_last_check_at": "TEXT",
            "balance_alert_active": "INTEGER NOT NULL DEFAULT 0",
        }
        for column_name, column_type in site_columns.items():
            if column_name not in columns:
                conn.execute(f"ALTER TABLE sites ADD COLUMN {column_name} {column_type}")
        setting_columns = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(notification_settings)").fetchall()
        }
        notification_columns = {
            "email_enabled": "INTEGER NOT NULL DEFAULT 0",
            "wecom_enabled": "INTEGER NOT NULL DEFAULT 0",
            "wecom_webhook": "TEXT",
            "wecom_last_error": "TEXT",
            "wecom_last_sent_at": "TEXT",
            "feishu_enabled": "INTEGER NOT NULL DEFAULT 0",
            "feishu_webhook": "TEXT",
            "feishu_secret": "TEXT",
            "feishu_last_error": "TEXT",
            "feishu_last_sent_at": "TEXT",
            "qq_enabled": "INTEGER NOT NULL DEFAULT 0",
            "qq_api_url": "TEXT",
            "qq_api_token": "TEXT",
            "qq_group_id": "TEXT",
            "qq_last_error": "TEXT",
            "qq_last_sent_at": "TEXT",
            "smtp_host": "TEXT",
            "smtp_port": "INTEGER NOT NULL DEFAULT 465",
            "smtp_username": "TEXT",
            "smtp_password": "TEXT",
            "smtp_use_ssl": "INTEGER NOT NULL DEFAULT 1",
            "smtp_from": "TEXT",
            "smtp_to": "TEXT",
            "email_last_error": "TEXT",
            "email_last_sent_at": "TEXT",
        }
        for column_name, column_type in notification_columns.items():
            if column_name not in setting_columns:
                conn.execute(f"ALTER TABLE notification_settings ADD COLUMN {column_name} {column_type}")
        setting = conn.execute("SELECT id FROM notification_settings WHERE id = 1").fetchone()
        if not setting:
            now = utc_now_iso()
            conn.execute(
                """
                INSERT INTO notification_settings
                (id, wecom_enabled, wecom_webhook, wecom_last_error, wecom_last_sent_at, feishu_enabled, feishu_webhook, feishu_secret, feishu_last_error, feishu_last_sent_at, qq_enabled, qq_api_url, qq_api_token, qq_group_id, qq_last_error, qq_last_sent_at, email_enabled, smtp_host, smtp_port, smtp_username, smtp_password, smtp_use_ssl, smtp_from, smtp_to, email_last_error, email_last_sent_at, created_at, updated_at)
                VALUES (1, 0, '', NULL, NULL, 0, '', '', NULL, NULL, 0, '', '', '', NULL, NULL, 0, '', 465, '', '', 1, '', '', NULL, NULL, ?, ?)
                """,
                (now, now),
            )


def dict_from_row(row: sqlite3.Row) -> Dict[str, Any]:
    return dict(row)


def db_query_all(sql: str, params: Iterable[Any] = ()) -> List[Dict[str, Any]]:
    with DB_LOCK, connect_db() as conn:
        rows = conn.execute(sql, tuple(params)).fetchall()
        return [dict_from_row(row) for row in rows]


def db_query_one(sql: str, params: Iterable[Any] = ()) -> Optional[Dict[str, Any]]:
    with DB_LOCK, connect_db() as conn:
        row = conn.execute(sql, tuple(params)).fetchone()
        return dict_from_row(row) if row else None


def db_execute(sql: str, params: Iterable[Any] = ()) -> int:
    with DB_LOCK, connect_db() as conn:
        cur = conn.execute(sql, tuple(params))
        conn.commit()
        return cur.lastrowid


def db_execute_many(sql: str, params_list: Iterable[Iterable[Any]]) -> None:
    with DB_LOCK, connect_db() as conn:
        conn.executemany(sql, params_list)
        conn.commit()


def json_request(
    url: str,
    payload: Dict[str, Any],
    headers: Optional[Dict[str, str]] = None,
    method: str = "POST",
) -> Tuple[int, Dict[str, Any], str]:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request_headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "Upstream-Ratio-Watch/1.0",
    }
    if headers:
        request_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        try:
            payload_obj = json.loads(raw) if raw else {}
        except Exception:
            payload_obj = {"raw": raw}
        if not isinstance(payload_obj, dict):
            payload_obj = {"raw": raw}
        return resp.status, payload_obj, raw


def parse_groups_payload(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    data = payload.get("data") or {}
    if not isinstance(data, dict):
        return {}

    normalized: Dict[str, Dict[str, Any]] = {}
    for name in sorted(data.keys()):
        info = data.get(name) or {}
        if not isinstance(info, dict):
            info = {}

        ratio = info.get("ratio")
        if isinstance(ratio, (int, float)):
            ratio_value: Any = float(ratio)
            ratio_type = "number"
        elif isinstance(ratio, str):
            stripped = ratio.strip()
            try:
                ratio_value = float(stripped)
                ratio_type = "number"
            except ValueError:
                ratio_value = stripped
                ratio_type = "text"
        else:
            ratio_value = ratio
            ratio_type = "text"

        normalized[name] = {
            "ratio": ratio_value,
            "ratio_type": ratio_type,
            "desc": info.get("desc", ""),
        }
    return normalized


def parse_sub2api_groups(groups_payload: Any, rates_payload: Any = None) -> Dict[str, Dict[str, Any]]:
    if isinstance(groups_payload, dict) and "data" in groups_payload:
        groups_payload = groups_payload.get("data")
    if isinstance(rates_payload, dict) and "data" in rates_payload:
        rates_payload = rates_payload.get("data")
    if not isinstance(groups_payload, list):
        return {}
    rates: Dict[str, Any] = {}
    if isinstance(rates_payload, dict):
        rates = {str(key): value for key, value in rates_payload.items()}

    normalized: Dict[str, Dict[str, Any]] = {}
    for item in groups_payload:
        if not isinstance(item, dict):
            continue
        group_id = item.get("id")
        name = str(item.get("name") or group_id or "").strip()
        if not name:
            continue
        base_ratio = item.get("rate_multiplier")
        effective_ratio = rates.get(str(group_id), base_ratio)
        try:
            ratio_value: Any = float(effective_ratio)
            ratio_type = "number"
        except (TypeError, ValueError):
            ratio_value = effective_ratio
            ratio_type = "text"
        normalized[name] = {
            "ratio": ratio_value,
            "ratio_type": ratio_type,
            "desc": item.get("description") or "",
            "id": group_id,
            "platform": item.get("platform") or "",
            "base_ratio": base_ratio,
            "user_ratio": rates.get(str(group_id)),
            "status": item.get("status") or "",
            "is_exclusive": bool(item.get("is_exclusive")),
            "subscription_type": item.get("subscription_type") or "",
            "rpm_limit": item.get("rpm_limit"),
        }
    return normalized


def stable_hash(obj: Any) -> str:
    text = json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def next_check_iso(interval_minutes: int) -> str:
    return (app_now() + timedelta(minutes=max(MIN_INTERVAL_MINUTES, interval_minutes))).isoformat(timespec="seconds")


def fetch_newapi_groups(base_url: str) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    url = f"{normalize_base_url(base_url)}/api/user/groups"
    req = urllib.request.Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "Upstream-Ratio-Watch/1.0",
        },
        method="GET",
    )
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            payload = json.loads(body)
            if not isinstance(payload, dict) or not payload.get("success"):
                return False, payload if isinstance(payload, dict) else {"raw": body}, "success=false"
            return True, payload, None
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:
            raw = ""
        return False, {"status": exc.code, "raw": raw}, f"HTTP {exc.code}"
    except Exception as exc:
        return False, {"error": str(exc)}, str(exc)


def request_json(url: str, headers: Optional[Dict[str, str]] = None, payload: Optional[Dict[str, Any]] = None, method: str = "GET") -> Tuple[bool, Any, Optional[str]]:
    data = None
    request_headers = {
        "Accept": "application/json",
        "User-Agent": "Upstream-Ratio-Watch/1.0",
    }
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        request_headers["Content-Type"] = "application/json"
    if headers:
        request_headers.update(headers)
    req = urllib.request.Request(url, data=data, headers=request_headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            parsed = json.loads(body) if body else {}
            return True, parsed, None
    except urllib.error.HTTPError as exc:
        try:
            raw = exc.read().decode("utf-8", errors="replace")
        except Exception:
            raw = ""
        return False, {"status": exc.code, "raw": raw}, f"HTTP {exc.code}"
    except Exception as exc:
        return False, {"error": str(exc)}, str(exc)


def is_sub2api_auth_error(payload: Any, error: Optional[str] = None) -> bool:
    auth_markers = (
        "unauthorized", "forbidden", "token", "jwt", "auth",
        "未授权", "无权限", "令牌", "登录", "凭证", "认证", "过期", "失效",
    )
    if isinstance(payload, dict):
        if isinstance(payload.get("groups"), dict) and is_sub2api_auth_error(payload["groups"], error):
            return True
        if isinstance(payload.get("refresh"), dict) and is_sub2api_auth_error(payload["refresh"], error):
            return True
        status = payload.get("status")
        raw = str(payload.get("raw") or "")
        message = str(payload.get("message") or payload.get("error") or "")
        code = str(payload.get("code") or "")
        if str(status) in {"401", "403"} or code in {"401", "403"}:
            return True
        text = f"{raw} {message} {code} {error or ''}".lower()
        return any(word in text for word in auth_markers)
    error_text = str(error or "").lower()
    return error_text.startswith(("http 401", "http 403")) or any(word in error_text for word in auth_markers)


def parse_token_expiry(value: Any) -> Optional[datetime]:
    text = str(value or "").strip()
    if not text:
        return None
    try:
        timestamp = float(text)
        if timestamp > 10_000_000_000:
            timestamp /= 1000
        return datetime.fromtimestamp(timestamp, timezone.utc)
    except (TypeError, ValueError, OSError, OverflowError):
        pass
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        return parsed.replace(tzinfo=APP_TIMEZONE) if parsed.tzinfo is None else parsed
    except ValueError:
        return None


def sub2api_token_refresh_due(token_expires_at: Any, leeway_seconds: int = 300) -> bool:
    expires_at = parse_token_expiry(token_expires_at)
    return bool(expires_at and expires_at <= app_now() + timedelta(seconds=leeway_seconds))


def refreshed_token_expiry(data: Dict[str, Any]) -> Optional[str]:
    expires_in = data.get("expires_in")
    try:
        if expires_in is not None:
            return (app_now() + timedelta(seconds=int(expires_in))).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError):
        pass
    explicit = data.get("token_expires_at") or data.get("expires_at")
    parsed = parse_token_expiry(explicit)
    return parsed.astimezone(APP_TIMEZONE).isoformat(timespec="seconds") if parsed else None


def refreshed_auth_payload(data: Dict[str, Any], fallback_refresh_token: str) -> Dict[str, Any]:
    return {
        "access_token": str(data.get("access_token") or "").strip(),
        "refresh_token": str(data.get("refresh_token") or fallback_refresh_token).strip(),
        "expires_in": data.get("expires_in"),
        "token_expires_at": refreshed_token_expiry(data),
    }


def unwrap_sub2api_response(payload: Any) -> Tuple[bool, Any, Optional[str]]:
    if not isinstance(payload, dict):
        return False, payload, "响应不是 JSON 对象"
    if "code" in payload and payload.get("code") != 0:
        return False, payload, str(payload.get("message") or "code != 0")
    return True, payload.get("data"), None


def sub2api_login(base_url: str, username: str, password: str) -> Tuple[bool, str, Dict[str, Any], Optional[str]]:
    email = (username or "").strip()
    password = password or ""
    if not email or not password:
        return False, "", {}, "sub2api 需要填写普通用户邮箱和密码"
    ok, payload, error = request_json(
        f"{normalize_base_url(base_url)}/api/v1/auth/login",
        payload={"email": email, "password": password},
        method="POST",
    )
    if not ok:
        return False, "", payload if isinstance(payload, dict) else {"raw": payload}, error
    success, data, message = unwrap_sub2api_response(payload)
    if not success or not isinstance(data, dict):
        return False, "", payload if isinstance(payload, dict) else {"raw": payload}, message or "登录失败"
    token = str(data.get("access_token") or "").strip()
    if not token:
        return False, "", payload if isinstance(payload, dict) else {"raw": payload}, "登录成功但没有返回 access_token"
    return True, token, payload if isinstance(payload, dict) else {"raw": payload}, None


def sub2api_refresh_token(base_url: str, refresh_token: str) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    token = (refresh_token or "").strip()
    if not token:
        return False, {}, "refresh_token 为空"
    ok, payload, error = request_json(
        f"{normalize_base_url(base_url)}/api/v1/auth/refresh",
        payload={"refresh_token": token},
        method="POST",
    )
    if not ok:
        return False, payload if isinstance(payload, dict) else {"raw": payload}, error
    success, data, message = unwrap_sub2api_response(payload)
    if not success or not isinstance(data, dict):
        return False, payload if isinstance(payload, dict) else {"raw": payload}, message or "刷新登录态失败"
    return True, data, None


def sub2api_token_headers(access_token: str) -> Dict[str, str]:
    token = (access_token or "").strip()
    if token.lower().startswith("bearer "):
        return {"Authorization": token}
    return {"Authorization": f"Bearer {token}"}


def normalized_balance(amount: Any, source: str, **extra: Any) -> Optional[Dict[str, Any]]:
    try:
        value = float(amount)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(value):
        return None
    result = {"amount": round(value, 6), "currency": "USD", "source": source}
    result.update({key: value for key, value in extra.items() if value is not None})
    return result


def find_quota_per_unit(payload: Any) -> Optional[float]:
    if not isinstance(payload, dict):
        return None
    for key in ("quota_per_unit", "QuotaPerUnit"):
        if key in payload:
            try:
                value = float(payload[key])
                if value > 0 and math.isfinite(value):
                    return value
            except (TypeError, ValueError):
                pass
    for key in ("data", "config", "status"):
        nested = find_quota_per_unit(payload.get(key))
        if nested:
            return nested
    return None


def fetch_newapi_balance(base_url: str, access_token: str, user_id: str = "") -> Tuple[bool, Dict[str, Any], Optional[str]]:
    token = (access_token or "").strip()
    if not token:
        return False, {}, "余额采集需要系统访问令牌"
    headers = {
        "Authorization": token.removeprefix("Bearer ").removeprefix("bearer ").strip(),
    }
    if str(user_id or "").strip():
        headers["New-Api-User"] = str(user_id).strip()
    ok, payload, error = request_json(
        f"{normalize_base_url(base_url)}/api/user/self",
        headers=headers,
    )
    if not ok or not isinstance(payload, dict):
        return False, payload if isinstance(payload, dict) else {"raw": payload}, error or "余额请求失败"
    if payload.get("success") is False:
        return False, payload, str(payload.get("message") or "余额响应 success=false")
    user_data = payload.get("data")
    if not isinstance(user_data, dict):
        return False, payload, "余额响应缺少 data"
    raw_quota = user_data.get("quota")
    try:
        quota_value = float(raw_quota)
    except (TypeError, ValueError):
        return False, payload, "余额响应缺少有效 quota"

    quota_per_unit = 500000.0
    status_ok, status_payload, _ = request_json(f"{normalize_base_url(base_url)}/api/status")
    detected_unit = find_quota_per_unit(status_payload) if status_ok else None
    if detected_unit:
        quota_per_unit = detected_unit
    balance = normalized_balance(
        quota_value / quota_per_unit,
        "/api/user/self",
        raw_quota=raw_quota,
        quota_per_unit=quota_per_unit,
        used_quota=user_data.get("used_quota"),
    )
    if not balance:
        return False, payload, "余额换算失败"
    return True, balance, None


def fetch_sub2api_groups_by_token(base_url: str, access_token: str) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    token = (access_token or "").strip()
    if not token:
        return False, {}, "auth_token 为空"
    headers = sub2api_token_headers(token)
    groups_ok, groups_payload, groups_error = request_json(
        f"{normalize_base_url(base_url)}/api/v1/groups/available",
        headers=headers,
    )
    if not groups_ok:
        return False, {"groups": groups_payload}, groups_error or "用户可用分组请求失败"
    groups_success, groups_data, groups_message = unwrap_sub2api_response(groups_payload)
    if not groups_success:
        return False, {"groups": groups_payload}, groups_message or "用户可用分组响应失败"

    rates_ok, rates_payload, rates_error = request_json(
        f"{normalize_base_url(base_url)}/api/v1/groups/rates",
        headers=headers,
    )
    rates_data: Any = {}
    if rates_ok:
        rates_success, parsed_rates, _ = unwrap_sub2api_response(rates_payload)
        if rates_success and isinstance(parsed_rates, dict):
            rates_data = parsed_rates

    profile_ok, profile_payload, profile_error = request_json(
        f"{normalize_base_url(base_url)}/api/v1/user/profile",
        headers=headers,
    )
    balance: Optional[Dict[str, Any]] = None
    balance_error: Optional[str] = None
    if profile_ok:
        profile_success, profile_data, profile_message = unwrap_sub2api_response(profile_payload)
        if profile_success and isinstance(profile_data, dict):
            balance = normalized_balance(
                profile_data.get("balance"),
                "/api/v1/user/profile",
                frozen_amount=profile_data.get("frozen_balance"),
            )
            if not balance:
                balance_error = "用户资料响应缺少有效 balance"
        else:
            balance_error = profile_message or "用户资料响应失败"
    else:
        balance_error = profile_error or "用户资料请求失败"

    return True, {
        "success": True,
        "data": groups_data,
        "user_rates": rates_data,
        "rates_error": None if rates_ok else rates_error,
        "balance": balance,
        "balance_error": balance_error,
    }, None


def fetch_sub2api_user_groups(
    base_url: str,
    username: str = "",
    password: str = "",
    auth_mode: str = "password",
    access_token: str = "",
    refresh_token: str = "",
    token_expires_at: Any = None,
) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    mode = (auth_mode or "password").strip().lower()
    if mode == "token":
        refresh_attempted = False
        refresh_failure: Optional[str] = None
        refresh_payload: Dict[str, Any] = {}
        if refresh_token and sub2api_token_refresh_due(token_expires_at):
            refresh_attempted = True
            refresh_ok, refreshed, refresh_error = sub2api_refresh_token(base_url, refresh_token)
            refresh_payload = refreshed
            if refresh_ok:
                new_access_token = str(refreshed.get("access_token") or "").strip()
                if new_access_token:
                    ok, payload, error_message = fetch_sub2api_groups_by_token(base_url, new_access_token)
                    if isinstance(payload, dict):
                        payload["refreshed_auth"] = refreshed_auth_payload(refreshed, refresh_token)
                    return ok, payload, error_message
                refresh_failure = "刷新成功但没有返回 access_token"
            else:
                refresh_failure = refresh_error or "登录态主动刷新失败"

        ok, payload, error_message = fetch_sub2api_groups_by_token(base_url, access_token)
        if ok or not refresh_token or not is_sub2api_auth_error(payload, error_message):
            return ok, payload, error_message
        if refresh_attempted:
            return False, {"groups": payload, "refresh": refresh_payload}, refresh_failure or error_message or "登录态刷新失败"
        refresh_ok, refreshed, refresh_error = sub2api_refresh_token(base_url, refresh_token)
        if not refresh_ok:
            return False, {"groups": payload, "refresh": refreshed}, refresh_error or error_message or "登录态刷新失败"
        new_access_token = str(refreshed.get("access_token") or "").strip()
        if not new_access_token:
            return False, {"refresh": refreshed}, "刷新成功但没有返回 access_token"
        ok, payload, error_message = fetch_sub2api_groups_by_token(base_url, new_access_token)
        if isinstance(payload, dict):
            payload["refreshed_auth"] = refreshed_auth_payload(refreshed, refresh_token)
        return ok, payload, error_message

    login_ok, token, login_payload, login_error = sub2api_login(base_url, username, password)
    if not login_ok:
        return False, {"login": login_payload}, login_error or "登录失败"
    return fetch_sub2api_groups_by_token(base_url, token)


def fetch_newapi_groups_with_access_token(base_url: str, access_token: str, user_id: str = "") -> Tuple[bool, Dict[str, Any], Optional[str]]:
    token = (access_token or "").strip()
    if not token:
        return False, {}, "访问令牌为空"

    headers = {
        "Accept": "application/json",
        "User-Agent": "Upstream-Ratio-Watch/1.0",
        "Authorization": token.removeprefix("Bearer ").removeprefix("bearer ").strip(),
    }
    if str(user_id or "").strip():
        headers["New-Api-User"] = str(user_id).strip()
    errors: List[str] = []
    for path in ("/api/user/self/groups", "/api/user/groups"):
        url = f"{normalize_base_url(base_url)}{path}"
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as resp:
                body = resp.read().decode("utf-8", errors="replace")
                payload = json.loads(body)
                if isinstance(payload, dict) and payload.get("success"):
                    return True, payload, None
                message = payload.get("message") if isinstance(payload, dict) else None
                errors.append(f"{path}: {message or 'success=false'}")
        except urllib.error.HTTPError as exc:
            errors.append(f"{path}: HTTP {exc.code}")
        except Exception as exc:
            errors.append(f"{path}: {exc}")

    return False, {"errors": errors}, "访问令牌分组采集失败：" + "；".join(errors)


def probe_newapi_groups(base_url: str) -> Dict[str, Any]:
    ok, payload, error_message = fetch_newapi_groups(base_url)
    if not ok:
        return {
            "success": False,
            "message": error_message or "request failed",
            "groups_count": 0,
            "groups": {},
            "raw": payload,
        }

    groups = parse_groups_payload(payload)
    return {
        "success": True,
        "message": "ok",
        "groups_count": len(groups),
        "groups": groups,
    }


def probe_sub2api_groups(
    base_url: str,
    username: str = "",
    password: str = "",
    auth_mode: str = "password",
    access_token: str = "",
    refresh_token: str = "",
    token_expires_at: Any = None,
) -> Dict[str, Any]:
    ok, payload, error_message = fetch_sub2api_user_groups(
        base_url,
        username=username,
        password=password,
        auth_mode=auth_mode,
        access_token=access_token,
        refresh_token=refresh_token,
        token_expires_at=token_expires_at,
    )
    if not ok:
        result = {
            "success": False,
            "message": error_message or "request failed",
            "groups_count": 0,
            "groups": {},
            "raw": payload,
        }
        if isinstance(payload.get("refreshed_auth"), dict):
            result["refreshed_auth"] = payload["refreshed_auth"]
        return result
    groups = parse_sub2api_groups(payload.get("data"), payload.get("user_rates"))
    result = {
        "success": True,
        "message": "ok",
        "groups_count": len(groups),
        "groups": groups,
    }
    if isinstance(payload.get("refreshed_auth"), dict):
        result["refreshed_auth"] = payload["refreshed_auth"]
    return result


def get_last_success_snapshot(site_id: int) -> Optional[Dict[str, Any]]:
    return db_query_one(
        """
        SELECT * FROM snapshots
        WHERE site_id = ? AND status = 'success'
        ORDER BY id DESC
        LIMIT 1
        """,
        (site_id,),
    )


def unique_group_ids(groups: Dict[str, Dict[str, Any]]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    duplicates = set()
    for name, item in groups.items():
        group_id = item.get("id") if isinstance(item, dict) else None
        if group_id is None or not str(group_id).strip():
            continue
        key = str(group_id)
        if key in result:
            duplicates.add(key)
        else:
            result[key] = name
    for key in duplicates:
        result.pop(key, None)
    return result


def append_group_item_changes(
    changes: List[Dict[str, Any]],
    old_name: str,
    new_name: str,
    old_item: Dict[str, Any],
    new_item: Dict[str, Any],
) -> None:
    name_changed = old_name != new_name
    name_metadata = {
        "old_group_name": old_name,
        "new_group_name": new_name,
    } if name_changed else {}
    old_ratio = old_item.get("ratio")
    new_ratio = new_item.get("ratio")

    if old_ratio != new_ratio:
        change_percent = None
        if isinstance(old_ratio, (int, float)) and isinstance(new_ratio, (int, float)) and old_ratio != 0:
            change_percent = round((float(new_ratio) - float(old_ratio)) / float(old_ratio) * 100, 2)
        changes.append({
            "change_type": "ratio_changed",
            "group_name": new_name,
            "old_value": old_item,
            "new_value": new_item,
            "change_percent": change_percent,
            "message": f"{new_name} 倍率 {old_ratio} -> {new_ratio}",
            **name_metadata,
        })
    elif name_changed:
        changes.append({
            "change_type": "group_renamed",
            "group_name": new_name,
            "old_value": old_name,
            "new_value": new_name,
            "change_percent": None,
            "message": f"分组更名 {old_name} -> {new_name}",
            **name_metadata,
        })

    if old_item.get("desc") != new_item.get("desc"):
        changes.append({
            "change_type": "desc_changed",
            "group_name": new_name,
            "old_value": old_item.get("desc"),
            "new_value": new_item.get("desc"),
            "change_percent": None,
            "message": f"{new_name} 描述变化",
            **name_metadata,
        })
    for field, label in (
        ("status", "状态"),
        ("is_exclusive", "专属分组"),
        ("subscription_type", "订阅类型"),
        ("rpm_limit", "RPM 限制"),
        ("platform", "平台"),
    ):
        if field in old_item or field in new_item:
            if old_item.get(field) != new_item.get(field):
                changes.append({
                    "change_type": f"{field}_changed",
                    "group_name": new_name,
                    "old_value": old_item.get(field),
                    "new_value": new_item.get(field),
                    "change_percent": None,
                    "message": f"{new_name} {label}变化：{old_item.get(field)} -> {new_item.get(field)}",
                    **name_metadata,
                })


def diff_groups(old_groups: Dict[str, Dict[str, Any]], new_groups: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    changes: List[Dict[str, Any]] = []
    old_unmatched = set(old_groups.keys())
    new_unmatched = set(new_groups.keys())
    matched: List[Tuple[str, str]] = []

    old_ids = unique_group_ids(old_groups)
    new_ids = unique_group_ids(new_groups)
    for group_id in sorted(set(old_ids) & set(new_ids)):
        old_name = old_ids[group_id]
        new_name = new_ids[group_id]
        matched.append((old_name, new_name))
        old_unmatched.discard(old_name)
        new_unmatched.discard(new_name)

    for name in sorted(old_unmatched & new_unmatched):
        matched.append((name, name))
        old_unmatched.discard(name)
        new_unmatched.discard(name)

    for name in sorted(new_unmatched):
        changes.append({
            "change_type": "group_added",
            "group_name": name,
            "old_value": None,
            "new_value": new_groups[name],
            "change_percent": None,
            "message": f"新增分组 {name}",
        })

    for name in sorted(old_unmatched):
        changes.append({
            "change_type": "group_removed",
            "group_name": name,
            "old_value": old_groups[name],
            "new_value": None,
            "change_percent": None,
            "message": f"删除分组 {name}",
        })

    for old_name, new_name in sorted(matched, key=lambda pair: pair[1]):
        append_group_item_changes(
            changes,
            old_name,
            new_name,
            old_groups[old_name],
            new_groups[new_name],
        )

    return changes


def get_notification_settings() -> Dict[str, Any]:
    row = db_query_one("SELECT * FROM notification_settings WHERE id = 1")
    if row:
        return row
    now = utc_now_iso()
    db_execute(
        """
        INSERT OR IGNORE INTO notification_settings
        (id, email_enabled, smtp_host, smtp_port, smtp_username, smtp_password, smtp_use_ssl, smtp_from, smtp_to, created_at, updated_at)
        VALUES (1, 0, '', 465, '', '', 1, '', '', ?, ?)
        """,
        (now, now),
    )
    return db_query_one("SELECT * FROM notification_settings WHERE id = 1") or {}


def notification_settings_payload() -> Dict[str, Any]:
    settings = get_notification_settings()
    return {
        "wecom_enabled": bool(settings.get("wecom_enabled")),
        "wecom_webhook": settings.get("wecom_webhook") or "",
        "wecom_has_webhook": bool(settings.get("wecom_webhook")),
        "wecom_last_error": settings.get("wecom_last_error"),
        "wecom_last_sent_at": settings.get("wecom_last_sent_at"),
        "feishu_enabled": bool(settings.get("feishu_enabled")),
        "feishu_webhook": settings.get("feishu_webhook") or "",
        "feishu_has_webhook": bool(settings.get("feishu_webhook")),
        "feishu_has_secret": bool(settings.get("feishu_secret")),
        "feishu_last_error": settings.get("feishu_last_error"),
        "feishu_last_sent_at": settings.get("feishu_last_sent_at"),
        "qq_enabled": bool(settings.get("qq_enabled")),
        "qq_api_url": settings.get("qq_api_url") or "",
        "qq_has_api_token": bool(settings.get("qq_api_token")),
        "qq_group_id": settings.get("qq_group_id") or "",
        "qq_last_error": settings.get("qq_last_error"),
        "qq_last_sent_at": settings.get("qq_last_sent_at"),
        "email_enabled": bool(settings.get("email_enabled")),
        "smtp_host": settings.get("smtp_host") or "",
        "smtp_port": int(settings.get("smtp_port") or 465),
        "smtp_username": settings.get("smtp_username") or "",
        "has_smtp_password": bool(settings.get("smtp_password")),
        "smtp_use_ssl": bool(settings.get("smtp_use_ssl")),
        "smtp_from": settings.get("smtp_from") or "",
        "smtp_to": settings.get("smtp_to") or "",
        "email_last_error": settings.get("email_last_error"),
        "email_last_sent_at": settings.get("email_last_sent_at"),
        "updated_at": settings.get("updated_at"),
    }


def notification_bearer_token_matches(authorization: Any) -> bool:
    settings = get_notification_settings()
    expected = str(settings.get("qq_api_token") or "").strip()
    header = str(authorization or "").strip()
    supplied = header[7:].strip() if header.startswith("Bearer ") else ""
    return bool(expected and supplied and hmac.compare_digest(expected, supplied))


def bot_balance_payload() -> List[Dict[str, Any]]:
    return db_query_all(
        """
        SELECT name, current_balance, balance_currency, balance_last_error,
               balance_last_check_at, enabled, status
        FROM sites
        ORDER BY id ASC
        """
    )


def site_detection_lock(site_id: int) -> threading.Lock:
    with SITE_DETECTION_LOCKS_LOCK:
        return SITE_DETECTION_LOCKS.setdefault(site_id, threading.Lock())


def ratio_groups_for_site(site: Dict[str, Any], result: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    groups = result.get("groups") if isinstance(result.get("groups"), dict) else {}
    login_groups = result.get("login_groups") if isinstance(result.get("login_groups"), dict) else {}
    if site.get("login_enabled") and login_groups:
        return login_groups
    return groups


def bot_live_ratio_payload() -> List[Dict[str, Any]]:
    sites = db_query_all("SELECT * FROM sites WHERE enabled = 1 ORDER BY id ASC")
    if not sites:
        return []

    def inspect_site(site: Dict[str, Any]) -> Dict[str, Any]:
        try:
            result = detect_site(int(site["id"]))
            refreshed_site = db_query_one("SELECT * FROM sites WHERE id = ?", (site["id"],)) or site
            groups = ratio_groups_for_site(refreshed_site, result)
            selected = notification_groups_for_site(refreshed_site)
            names = selected if selected else sorted(groups.keys())
            selected_groups = []
            for name in names:
                item = groups.get(name)
                selected_groups.append({
                    "name": name,
                    "ratio": item.get("ratio") if isinstance(item, dict) else None,
                    "available": isinstance(item, dict),
                })
            return {
                "id": site["id"],
                "name": site["name"],
                "success": bool(result.get("success")) and bool(groups),
                "error": None if result.get("success") else str(result.get("message") or "检测失败"),
                "groups": selected_groups,
            }
        except Exception as exc:
            return {
                "id": site["id"],
                "name": site["name"],
                "success": False,
                "error": str(exc),
                "groups": [],
            }

    results: Dict[int, Dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=min(4, len(sites))) as executor:
        futures = {executor.submit(inspect_site, site): int(site["id"]) for site in sites}
        for future in as_completed(futures):
            results[futures[future]] = future.result()
    return [results[int(site["id"])] for site in sites]


def update_notification_settings(body: Dict[str, Any]) -> None:
    settings = get_notification_settings()
    wecom_enabled = bool(body.get("wecom_enabled", False))
    wecom_webhook = str(body.get("wecom_webhook") or "").strip()
    feishu_enabled = bool(body.get("feishu_enabled", False))
    feishu_webhook = str(body.get("feishu_webhook") or "").strip()
    feishu_secret = str(body.get("feishu_secret") or "").strip()
    qq_enabled = bool(body.get("qq_enabled", False))
    qq_api_url = normalize_qq_api_url(body.get("qq_api_url"))
    qq_api_token = str(body.get("qq_api_token") or "").strip()
    qq_group_id_raw = str(body.get("qq_group_id") or "").strip()
    qq_group_id = normalize_qq_group_id(qq_group_id_raw)
    email_enabled = bool(body.get("email_enabled", False))
    smtp_host = str(body.get("smtp_host") or "").strip()
    smtp_port = int(body.get("smtp_port") or 465)
    smtp_username = str(body.get("smtp_username") or "").strip()
    smtp_password = str(body.get("smtp_password") or "")
    smtp_use_ssl = bool(body.get("smtp_use_ssl", True))
    smtp_from = str(body.get("smtp_from") or "").strip()
    smtp_to = str(body.get("smtp_to") or "").strip()

    if email_enabled:
        if not smtp_host or not smtp_port or not smtp_username or not (smtp_password or settings.get("smtp_password")) or not smtp_to:
            raise ValueError("启用邮箱推送时需要填写 SMTP 服务器、端口、账号、密码和收件人")
        if not smtp_from:
            smtp_from = smtp_username
    if wecom_enabled and not (wecom_webhook or settings.get("wecom_webhook")):
        raise ValueError("启用企业微信推送时需要填写 Webhook 地址")
    if feishu_enabled and not (feishu_webhook or settings.get("feishu_webhook")):
        raise ValueError("启用飞书推送时需要填写 Webhook 地址")
    if qq_enabled:
        if not (qq_api_url or settings.get("qq_api_url")):
            raise ValueError("启用 QQ 推送时需要填写机器人通知接口地址")
        if not (qq_api_token or settings.get("qq_api_token")):
            raise ValueError("启用 QQ 推送时需要填写通知接口 Token")
        if not qq_group_id:
            raise ValueError("启用 QQ 推送时需要填写有效的 QQ 群号")
    elif qq_group_id_raw and not qq_group_id:
        raise ValueError("QQ 群号格式无效")

    fields = [
        "wecom_enabled = ?",
        "feishu_enabled = ?",
        "qq_enabled = ?",
        "email_enabled = ?",
        "wecom_webhook = ?",
        "feishu_webhook = ?",
        "qq_api_url = ?",
        "qq_group_id = ?",
        "smtp_host = ?",
        "smtp_port = ?",
        "smtp_username = ?",
        "smtp_use_ssl = ?",
        "smtp_from = ?",
        "smtp_to = ?",
        "updated_at = ?",
    ]
    params: List[Any] = [
        1 if wecom_enabled else 0,
        1 if feishu_enabled else 0,
        1 if qq_enabled else 0,
        1 if email_enabled else 0,
        wecom_webhook if wecom_webhook else (settings.get("wecom_webhook") or ""),
        feishu_webhook if feishu_webhook else (settings.get("feishu_webhook") or ""),
        qq_api_url if qq_api_url else (settings.get("qq_api_url") or ""),
        qq_group_id,
        smtp_host,
        smtp_port,
        smtp_username,
        1 if smtp_use_ssl else 0,
        smtp_from,
        smtp_to,
        utc_now_iso(),
    ]
    if smtp_password:
        fields.append("smtp_password = ?")
        params.append(smtp_password)
    if feishu_secret:
        fields.append("feishu_secret = ?")
        params.append(feishu_secret)
    if qq_api_token:
        fields.append("qq_api_token = ?")
        params.append(qq_api_token)
    params.append(1)
    db_execute(f"UPDATE notification_settings SET {', '.join(fields)} WHERE id = ?", params)


def log_notification(channel: str, status: str, target: str, message: str, error_message: Optional[str] = None) -> None:
    db_execute(
        """
        INSERT INTO notification_logs (channel, status, target, message, error_message, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (channel, status, target, message, error_message, utc_now_iso()),
    )


def qq_notification_error(payload: Any, fallback: str) -> str:
    if isinstance(payload, dict):
        if payload.get("message"):
            return str(payload["message"])
        raw = str(payload.get("raw") or "").strip()
        if raw:
            try:
                parsed = json.loads(raw)
                if isinstance(parsed, dict) and parsed.get("message"):
                    return str(parsed["message"])
            except (TypeError, ValueError):
                pass
    return fallback


def send_qq_message(subject: str, message: str) -> Tuple[bool, Optional[str]]:
    settings = get_notification_settings()
    if not settings.get("qq_enabled"):
        return True, "QQ 推送未启用，未发送消息"

    api_url = str(settings.get("qq_api_url") or "").strip()
    api_token = str(settings.get("qq_api_token") or "").strip()
    group_id = normalize_qq_group_id(settings.get("qq_group_id"))
    if not api_url or not api_token or not group_id:
        return False, "QQ 推送配置不完整"

    ok, response_payload, error = request_json(
        api_url,
        headers={"Authorization": f"Bearer {api_token}"},
        payload={"group_id": group_id, "subject": subject, "message": message},
        method="POST",
    )
    if not ok or not isinstance(response_payload, dict) or not response_payload.get("success"):
        error_text = qq_notification_error(response_payload, error or "QQ 推送失败")
        db_execute(
            "UPDATE notification_settings SET qq_last_error = ?, updated_at = ? WHERE id = 1",
            (error_text, utc_now_iso()),
        )
        log_notification("qq", "failed", group_id, message, error_text)
        return False, error_text

    sent_at = utc_now_iso()
    db_execute(
        """
        UPDATE notification_settings
        SET qq_last_error = NULL, qq_last_sent_at = ?, updated_at = ?
        WHERE id = 1
        """,
        (sent_at, sent_at),
    )
    log_notification("qq", "success", group_id, message, None)
    return True, None


def send_email_message(subject: str, message: str) -> Tuple[bool, Optional[str]]:
    settings = get_notification_settings()
    if not settings.get("email_enabled"):
        return True, "邮箱推送未启用，未发送测试邮件"

    smtp_host = str(settings.get("smtp_host") or "").strip()
    smtp_port = int(settings.get("smtp_port") or 465)
    smtp_username = str(settings.get("smtp_username") or "").strip()
    smtp_password = str(settings.get("smtp_password") or "")
    smtp_from = str(settings.get("smtp_from") or smtp_username).strip()
    smtp_to = str(settings.get("smtp_to") or "").strip()
    smtp_use_ssl = bool(settings.get("smtp_use_ssl"))
    if not smtp_host or not smtp_port or not smtp_username or not smtp_password or not smtp_to:
        return False, "邮箱 SMTP 配置不完整"

    recipients = [item.strip() for item in smtp_to.replace("，", ",").split(",") if item.strip()]
    email = EmailMessage()
    email["Subject"] = subject
    email["From"] = smtp_from
    email["To"] = ", ".join(recipients)
    email.set_content(message)

    try:
        if smtp_use_ssl:
            with smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=HTTP_TIMEOUT_SECONDS) as smtp:
                smtp.login(smtp_username, smtp_password)
                smtp.send_message(email)
        else:
            with smtplib.SMTP(smtp_host, smtp_port, timeout=HTTP_TIMEOUT_SECONDS) as smtp:
                smtp.starttls()
                smtp.login(smtp_username, smtp_password)
                smtp.send_message(email)
    except Exception as exc:
        error = f"邮箱推送失败：{exc}"
        db_execute(
            "UPDATE notification_settings SET email_last_error = ?, updated_at = ? WHERE id = 1",
            (error, utc_now_iso()),
        )
        log_notification("email", "failed", smtp_to, message, error)
        return False, error

    sent_at = utc_now_iso()
    db_execute(
        """
        UPDATE notification_settings
        SET email_last_error = NULL, email_last_sent_at = ?, updated_at = ?
        WHERE id = 1
        """,
        (sent_at, sent_at),
    )
    log_notification("email", "success", smtp_to, message, None)
    return True, None


def send_wecom_message(subject: str, message: str) -> Tuple[bool, Optional[str]]:
    settings = get_notification_settings()
    if not settings.get("wecom_enabled"):
        return True, "企业微信推送未启用，未发送消息"

    webhook = str(settings.get("wecom_webhook") or "").strip()
    if not webhook:
        return False, "企业微信 Webhook 未配置"

    content = f"**{subject}**\n\n{message}"
    ok, payload, error = request_json(
        webhook,
        payload={
            "msgtype": "markdown",
            "markdown": {
                "content": content,
            },
        },
        method="POST",
    )
    if not ok:
        error_text = error or "企业微信推送失败"
        db_execute(
            "UPDATE notification_settings SET wecom_last_error = ?, updated_at = ? WHERE id = 1",
            (error_text, utc_now_iso()),
        )
        log_notification("wecom", "failed", webhook, message, error_text)
        return False, error_text

    if isinstance(payload, dict) and payload.get("errcode") not in (None, 0):
        error_text = f"企业微信推送失败：{payload.get('errmsg') or payload.get('errcode')}"
        db_execute(
            "UPDATE notification_settings SET wecom_last_error = ?, updated_at = ? WHERE id = 1",
            (error_text, utc_now_iso()),
        )
        log_notification("wecom", "failed", webhook, message, error_text)
        return False, error_text

    sent_at = utc_now_iso()
    db_execute(
        """
        UPDATE notification_settings
        SET wecom_last_error = NULL, wecom_last_sent_at = ?, updated_at = ?
        WHERE id = 1
        """,
        (sent_at, sent_at),
    )
    log_notification("wecom", "success", webhook, message, None)
    return True, None


def send_feishu_message(subject: str, message: str) -> Tuple[bool, Optional[str]]:
    settings = get_notification_settings()
    if not settings.get("feishu_enabled"):
        return True, "飞书推送未启用，未发送消息"

    webhook = str(settings.get("feishu_webhook") or "").strip()
    if not webhook:
        return False, "飞书 Webhook 未配置"
    payload: Dict[str, Any] = {
        "msg_type": "text",
        "content": {"text": f"{subject}\n\n{message}"},
    }
    secret = str(settings.get("feishu_secret") or "").strip()
    if secret:
        timestamp = str(int(time.time()))
        string_to_sign = f"{timestamp}\n{secret}".encode("utf-8")
        signature = hmac.new(string_to_sign, digestmod=hashlib.sha256).digest()
        payload["timestamp"] = timestamp
        payload["sign"] = base64.b64encode(signature).decode("ascii")

    ok, response_payload, error = request_json(webhook, payload=payload, method="POST")
    error_text: Optional[str] = None
    if not ok:
        error_text = error or "飞书推送失败"
    elif isinstance(response_payload, dict):
        code = response_payload.get("code", response_payload.get("StatusCode"))
        if code not in (None, 0, "0"):
            error_text = f"飞书推送失败：{response_payload.get('msg') or response_payload.get('StatusMessage') or code}"

    if error_text:
        db_execute(
            "UPDATE notification_settings SET feishu_last_error = ?, updated_at = ? WHERE id = 1",
            (error_text, utc_now_iso()),
        )
        log_notification("feishu", "failed", webhook, message, error_text)
        return False, error_text

    sent_at = utc_now_iso()
    db_execute(
        "UPDATE notification_settings SET feishu_last_error = NULL, feishu_last_sent_at = ?, updated_at = ? WHERE id = 1",
        (sent_at, sent_at),
    )
    log_notification("feishu", "success", webhook, message, None)
    return True, None


def format_change_value(raw: Any) -> str:
    if raw is None:
        return "-"
    if isinstance(raw, dict) and "ratio" in raw:
        ratio = raw.get("ratio")
        try:
            text = f"{float(ratio):.8f}".rstrip("0").rstrip(".")
            return f"{text or '0'}x"
        except Exception:
            return str(ratio)
    return str(raw)


def ratio_number(raw: Any) -> Optional[float]:
    if isinstance(raw, dict):
        raw = raw.get("ratio")
    try:
        return float(raw)
    except (TypeError, ValueError):
        return None


def ratio_direction(change: Dict[str, Any]) -> str:
    old_ratio = ratio_number(change.get("old_value"))
    new_ratio = ratio_number(change.get("new_value"))
    if old_ratio is None or new_ratio is None:
        return "changed"
    if new_ratio > old_ratio:
        return "up"
    if new_ratio < old_ratio:
        return "down"
    return "changed"


def percent_text(change: Dict[str, Any]) -> str:
    percent = change.get("change_percent")
    if isinstance(percent, (int, float)):
        return f"{abs(percent):.2f}".rstrip("0").rstrip(".") + "%"
    return ""


def fmt_local_time_for_message(value: str) -> str:
    dt = parse_iso_dt(value)
    if not dt:
        return value
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    local_dt = dt.astimezone(APP_TIMEZONE)
    tz_name = local_dt.tzname() or ""
    suffix = f" {tz_name}" if tz_name else ""
    return local_dt.strftime("%Y-%m-%d %H:%M:%S") + suffix


def platform_label(site: Dict[str, Any]) -> str:
    return "sub2api" if (site.get("platform") or "newapi") == "sub2api" else "NewAPI"


def format_change_subject(site: Dict[str, Any], changes: List[Dict[str, Any]]) -> str:
    site_name = site["name"]
    platform = platform_label(site)
    ratio_changes = [item for item in changes if item.get("change_type") == "ratio_changed"]
    if len(ratio_changes) == 1:
        change = ratio_changes[0]
        label = "倍率上涨" if ratio_direction(change) == "up" else "倍率下降" if ratio_direction(change) == "down" else "倍率变动"
        return f"【{platform} {label}】{site_name} / {change.get('group_name') or '-'}：{format_change_value(change.get('old_value'))} -> {format_change_value(change.get('new_value'))}"
    if len(ratio_changes) > 1:
        return f"【{platform} 倍率变动】{site_name}：{len(ratio_changes)} 个分组有变化"

    added = [item for item in changes if item.get("change_type") == "group_added"]
    removed = [item for item in changes if item.get("change_type") == "group_removed"]
    renamed = [item for item in changes if item.get("change_type") == "group_renamed"]
    if len(added) == 1 and not removed:
        change = added[0]
        return f"【{platform} 新增分组】{site_name} / {change.get('group_name') or '-'}：{format_change_value(change.get('new_value'))}"
    if len(removed) == 1 and not added:
        change = removed[0]
        return f"【{platform} 删除分组】{site_name} / {change.get('group_name') or '-'}"
    if len(renamed) == 1 and not added and not removed:
        change = renamed[0]
        return f"【{platform} 分组更名】{site_name}：{change.get('old_value')} -> {change.get('new_value')}"
    return f"【{platform} 分组变化】{site_name}：{len(changes)} 条变化"


def format_change_notification(site: Dict[str, Any], changes: List[Dict[str, Any]], checked_at: str) -> str:
    up_changes = [item for item in changes if item.get("change_type") == "ratio_changed" and ratio_direction(item) == "up"]
    down_changes = [item for item in changes if item.get("change_type") == "ratio_changed" and ratio_direction(item) == "down"]
    changed_ratio = [item for item in changes if item.get("change_type") == "ratio_changed" and ratio_direction(item) == "changed"]
    added = [item for item in changes if item.get("change_type") == "group_added"]
    removed = [item for item in changes if item.get("change_type") == "group_removed"]
    renamed = [item for item in changes if item.get("change_type") == "group_renamed"]
    desc_changed = [item for item in changes if item.get("change_type") == "desc_changed"]
    other_changed = [
        item for item in changes
        if item.get("change_type") not in {"ratio_changed", "group_added", "group_removed", "group_renamed", "desc_changed"}
    ]

    lines = [
        "上游倍率监控提醒",
        f"站点：{site['name']}",
        f"平台：{platform_label(site)}",
        f"时间：{fmt_local_time_for_message(checked_at)}",
        f"本次共 {len(changes)} 条变化",
    ]

    def append_ratio_block(title: str, items: List[Dict[str, Any]], suffix: str) -> None:
        if not items:
            return
        lines.extend(["", title])
        for change in items[:6]:
            percent = percent_text(change)
            extra = f"，{suffix} {percent}" if percent else f"，{suffix}"
            lines.append(
                f"- {change.get('group_name') or '-'}：{format_change_value(change.get('old_value'))} -> {format_change_value(change.get('new_value'))}{extra}"
            )

    append_ratio_block("涨价了，钱包先别眨眼：", up_changes, "上涨")
    append_ratio_block("降价了，这波可以多看两眼：", down_changes, "下降")

    if changed_ratio:
        lines.extend(["", "倍率变了，但方向不太好判断："])
        for change in changed_ratio[:6]:
            lines.append(f"- {change.get('group_name') or '-'}：{format_change_value(change.get('old_value'))} -> {format_change_value(change.get('new_value'))}")

    if added:
        lines.extend(["", "新分组上线："])
        for change in added[:6]:
            lines.append(f"- {change.get('group_name') or '-'}：{format_change_value(change.get('new_value'))}")

    if removed:
        lines.extend(["", "分组下线了："])
        for change in removed[:6]:
            lines.append(f"- {change.get('group_name') or '-'}：原倍率 {format_change_value(change.get('old_value'))}")

    if renamed:
        lines.extend(["", "分组更名："])
        for change in renamed[:6]:
            lines.append(f"- {change.get('old_value')} -> {change.get('new_value')}")

    if desc_changed:
        lines.extend(["", "描述有变化："])
        for change in desc_changed[:6]:
            lines.append(f"- {change.get('group_name') or '-'}")

    if other_changed:
        lines.extend(["", "其他配置变化："])
        for change in other_changed[:8]:
            lines.append(
                f"- {change.get('group_name') or '-'}：{format_change_value(change.get('old_value'))} -> {format_change_value(change.get('new_value'))}"
            )

    if len(changes) > 8:
        lines.append("")
        lines.append(f"其余 {len(changes) - 8} 条变化请在面板查看")
    return "\n".join(lines)


def normalize_notify_groups(raw: Any) -> List[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            raw = parsed if isinstance(parsed, list) else []
        except (TypeError, ValueError):
            raw = []
    if not isinstance(raw, (list, tuple, set)):
        return []
    groups: List[str] = []
    seen = set()
    for item in raw:
        name = str(item or "").strip()
        if name and name not in seen:
            seen.add(name)
            groups.append(name)
    return groups


def notification_groups_for_site(site: Dict[str, Any]) -> List[str]:
    return normalize_notify_groups(site.get("notify_groups_json"))


def filter_notification_changes(site: Dict[str, Any], changes: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    selected_groups = notification_groups_for_site(site)
    if not selected_groups:
        return changes
    selected = set(selected_groups)
    filtered = []
    for change in changes:
        change_names = {
            str(change.get("group_name") or ""),
            str(change.get("old_group_name") or ""),
            str(change.get("new_group_name") or ""),
        }
        if selected & change_names:
            filtered.append(change)
    return filtered


def remap_notification_group_names(site: Dict[str, Any], changes: List[Dict[str, Any]]) -> Dict[str, Any]:
    selected_groups = notification_groups_for_site(site)
    if not selected_groups:
        return site
    rename_map = {
        str(change.get("old_group_name")): str(change.get("new_group_name"))
        for change in changes
        if change.get("old_group_name") and change.get("new_group_name")
        and change.get("old_group_name") != change.get("new_group_name")
    }
    if not rename_map:
        return site

    updated_groups: List[str] = []
    seen = set()
    for name in selected_groups:
        updated_name = rename_map.get(name, name)
        if updated_name not in seen:
            seen.add(updated_name)
            updated_groups.append(updated_name)
    if updated_groups == selected_groups:
        return site

    encoded = json.dumps(updated_groups, ensure_ascii=False)
    db_execute(
        "UPDATE sites SET notify_groups_json = ?, updated_at = ? WHERE id = ?",
        (encoded, utc_now_iso(), site["id"]),
    )
    updated_site = dict(site)
    updated_site["notify_groups_json"] = encoded
    return updated_site


def notify_changes(site: Dict[str, Any], changes: List[Dict[str, Any]], checked_at: str) -> None:
    if not changes:
        return
    subject = format_change_subject(site, changes)
    message = format_change_notification(site, changes, checked_at)
    send_email_message(subject, message)
    send_wecom_message(subject, message)
    send_feishu_message(subject, message)
    send_qq_message(subject, message)


def sub2api_auth_state_failed(site: Dict[str, Any], payload: Dict[str, Any], error_message: Optional[str]) -> bool:
    if (site.get("platform") or "newapi") != "sub2api" or (site.get("auth_mode") or "password") != "token":
        return False
    if not is_sub2api_auth_error(payload, error_message):
        return False
    return not site.get("refresh_token") or "refresh" in payload or "refreshed_auth" in payload


def notify_sub2api_auth_failure(site: Dict[str, Any], error_message: Optional[str], checked_at: str) -> Tuple[bool, Optional[str]]:
    subject = f"【{site['name']}】登录状态失效"
    message = "\n".join([
        subject,
        f"站点：{site['name']}",
        f"地址：{site['base_url']}",
        "状态：AT 已失效，自动刷新未能恢复监控",
        f"错误：{error_message or '登录态刷新失败'}",
        f"时间：{fmt_local_time_for_message(checked_at)}",
        "请重新登录 sub2api，并更新 AT、RT 和 token_expires_at。",
    ])
    return send_qq_message(subject, message)


def format_balance_amount(amount: float, currency: str = "USD") -> str:
    symbol = "$" if currency == "USD" else f"{currency} "
    return f"{symbol}{amount:.2f}"


def record_balance_event(site: Dict[str, Any], event_type: str, amount: float, threshold: float, checked_at: str) -> None:
    recovered = event_type == "balance_recovered"
    message = (
        f"余额已恢复至 {format_balance_amount(amount)}，高于预警阈值 {format_balance_amount(threshold)}"
        if recovered
        else f"余额仅剩 {format_balance_amount(amount)}，已低于预警阈值 {format_balance_amount(threshold)}"
    )
    db_execute(
        """
        INSERT INTO changes
        (site_id, change_type, group_name, old_value, new_value, change_percent, message, created_at, acknowledged)
        VALUES (?, ?, NULL, ?, ?, NULL, ?, ?, 0)
        """,
        (site["id"], event_type, json.dumps(threshold), json.dumps(amount), message, checked_at),
    )
    label = "余额恢复" if recovered else "低余额预警"
    subject = f"【{platform_label(site)} {label}】{site['name']}：{format_balance_amount(amount)}"
    body = "\n".join([
        "上游余额监控提醒",
        f"站点：{site['name']}",
        f"平台：{platform_label(site)}",
        f"当前余额：{format_balance_amount(amount)}",
        f"预警阈值：{format_balance_amount(threshold)}",
        f"状态：{'余额已恢复' if recovered else '余额不足，请及时充值'}",
        f"时间：{fmt_local_time_for_message(checked_at)}",
    ])
    send_email_message(subject, body)
    send_wecom_message(subject, body)
    send_feishu_message(subject, body)
    send_qq_message(subject, body)


def collect_site_groups(site: Dict[str, Any]) -> Tuple[bool, Dict[str, Dict[str, Any]], Dict[str, Any], str, Optional[str]]:
    platform = site.get("platform") or "newapi"
    if platform == "sub2api":
        ok, payload, error_message = fetch_sub2api_user_groups(
            site["base_url"],
            username=site.get("login_username") or "",
            password=site.get("login_password") or "",
            auth_mode=site.get("auth_mode") or "password",
            access_token=site.get("access_token") or "",
            refresh_token=site.get("refresh_token") or "",
            token_expires_at=site.get("token_expires_at"),
        )
        groups = parse_sub2api_groups(payload.get("data"), payload.get("user_rates")) if ok else {}
        return ok, groups, payload, "/api/v1/groups/available", error_message

    ok, payload, error_message = fetch_newapi_groups(site["base_url"])
    groups = parse_groups_payload(payload) if ok else {}
    return ok, groups, payload, "/api/user/groups", error_message


def detect_site(site_id: int) -> Dict[str, Any]:
    with site_detection_lock(site_id):
        return _detect_site(site_id)


def _detect_site(site_id: int) -> Dict[str, Any]:
    site = db_query_one("SELECT * FROM sites WHERE id = ?", (site_id,))
    if not site:
        return {"success": False, "message": "site not found"}

    checked_at = utc_now_iso()
    ok, new_groups, payload, source, error_message = collect_site_groups(site)
    latest_success = get_last_success_snapshot(site_id)
    refreshed_auth = payload.get("refreshed_auth") if isinstance(payload, dict) else None
    refreshed_access_token = ""
    refreshed_refresh_token = ""
    refreshed_expires_at = None
    if isinstance(refreshed_auth, dict):
        refreshed_access_token = str(refreshed_auth.get("access_token") or "").strip()
        refreshed_refresh_token = str(refreshed_auth.get("refresh_token") or "").strip()
        refreshed_expires_at = str(refreshed_auth.get("token_expires_at") or "").strip() or refreshed_token_expiry(refreshed_auth)

    if not ok:
        db_execute(
            """
            INSERT INTO snapshots (site_id, status, source, raw_json, error_message, checked_at, hash)
            VALUES (?, 'failed', ?, ?, ?, ?, NULL)
            """,
            (site_id, source, json.dumps(payload, ensure_ascii=False), error_message, checked_at),
        )

        consecutive_failures = int(site["consecutive_failures"] or 0) + 1
        status = "failed" if consecutive_failures >= 3 else "warning"
        next_check_at = next_check_iso(int(site["interval_minutes"] or DEFAULT_INTERVAL_MINUTES))
        auth_alert_active = bool(site.get("auth_alert_active"))
        if sub2api_auth_state_failed(site, payload, error_message) and not auth_alert_active:
            notification_ok, _ = notify_sub2api_auth_failure(site, error_message, checked_at)
            if notification_ok:
                auth_alert_active = True
        db_execute(
            """
            UPDATE sites
            SET status = ?, last_error = ?, last_check_at = ?, next_check_at = ?, consecutive_failures = ?,
                access_token = COALESCE(NULLIF(?, ''), access_token),
                refresh_token = COALESCE(NULLIF(?, ''), refresh_token),
                token_expires_at = COALESCE(?, token_expires_at),
                auth_alert_active = ?,
                updated_at = ?
            WHERE id = ?
            """,
            (
                status, error_message, checked_at, next_check_at, consecutive_failures,
                refreshed_access_token, refreshed_refresh_token, refreshed_expires_at,
                1 if auth_alert_active else 0, checked_at, site_id,
            ),
        )
        return {"success": False, "message": error_message, "status": status}

    groups_json = json.dumps(new_groups, ensure_ascii=False, sort_keys=True)
    hash_value = stable_hash(new_groups)
    login_groups: Dict[str, Dict[str, Any]] = {}
    login_groups_json: Optional[str] = None
    login_error: Optional[str] = None
    if refreshed_auth and isinstance(payload, dict):
        payload = dict(payload)
        payload.pop("refreshed_auth", None)

    db_execute(
        """
        INSERT INTO snapshots (site_id, status, source, groups_json, raw_json, hash, error_message, checked_at)
        VALUES (?, 'success', ?, ?, ?, ?, NULL, ?)
        """,
        (site_id, source, groups_json, json.dumps(payload, ensure_ascii=False), hash_value, checked_at),
    )

    changes: List[Dict[str, Any]] = []
    if latest_success and latest_success.get("groups_json"):
        try:
            old_groups = json.loads(latest_success["groups_json"])
            if isinstance(old_groups, dict):
                changes = diff_groups(old_groups, new_groups)
        except Exception:
            changes = []

    if (site.get("platform") or "newapi") == "newapi" and site.get("login_enabled") and site.get("access_token") and site.get("access_user_id"):
        login_ok, login_payload, login_error_message = fetch_newapi_groups_with_access_token(
            site["base_url"],
            site["access_token"],
            site.get("access_user_id") or "",
        )
        if login_ok:
            login_groups = parse_groups_payload(login_payload)
            login_groups_json = json.dumps(login_groups, ensure_ascii=False, sort_keys=True)
            old_login_groups = {}
            if site.get("current_login_groups_json"):
                try:
                    parsed_old_login = json.loads(site["current_login_groups_json"])
                    if isinstance(parsed_old_login, dict):
                        old_login_groups = parsed_old_login
                except Exception:
                    old_login_groups = {}
            login_changes = diff_groups(old_login_groups, login_groups) if old_login_groups else []
            for change in login_changes:
                change["message"] = f"认证增强 {change['message']}"
            changes.extend(login_changes)
        else:
            login_error = login_error_message or "认证增强采集失败"

    for change in changes:
        severity = "info"
        if change["change_type"] in {"group_removed"}:
            severity = "critical"
        elif change["change_type"] == "ratio_changed":
            percent = change.get("change_percent")
            if isinstance(percent, (int, float)) and percent > 0:
                severity = "warning"

        db_execute(
            """
            INSERT INTO changes
            (site_id, change_type, group_name, old_value, new_value, change_percent, message, created_at, acknowledged)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                site_id,
                change["change_type"],
                change.get("group_name"),
                json.dumps(change.get("old_value"), ensure_ascii=False) if change.get("old_value") is not None else None,
                json.dumps(change.get("new_value"), ensure_ascii=False) if change.get("new_value") is not None else None,
                change.get("change_percent"),
                change["message"],
                checked_at,
            ),
        )
        change["severity"] = severity

    notification_site = remap_notification_group_names(site, changes)
    notify_changes(notification_site, filter_notification_changes(notification_site, changes), checked_at)

    balance_attempted = False
    balance_info: Optional[Dict[str, Any]] = None
    balance_error: Optional[str] = None
    if (site.get("platform") or "newapi") == "sub2api":
        balance_attempted = True
        if isinstance(payload, dict) and isinstance(payload.get("balance"), dict):
            balance_info = payload.get("balance")
        else:
            balance_error = str(payload.get("balance_error") or "sub2api 未返回余额") if isinstance(payload, dict) else "sub2api 未返回余额"
    elif site.get("login_enabled") and site.get("access_token"):
        balance_attempted = True
        balance_ok, fetched_balance, balance_error = fetch_newapi_balance(
            site["base_url"], site.get("access_token") or "", site.get("access_user_id") or ""
        )
        if balance_ok:
            balance_info = fetched_balance

    if balance_attempted:
        db_execute(
            """
            INSERT INTO balance_snapshots (site_id, status, balance, currency, raw_json, error_message, checked_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                site_id,
                "success" if balance_info else "failed",
                balance_info.get("amount") if balance_info else None,
                balance_info.get("currency", "USD") if balance_info else "USD",
                json.dumps(balance_info, ensure_ascii=False) if balance_info else None,
                balance_error,
                checked_at,
            ),
        )

    alert_active = bool(site.get("balance_alert_active"))
    if not site.get("balance_alert_enabled"):
        alert_active = False
    if balance_info and site.get("balance_alert_enabled"):
        amount = float(balance_info["amount"])
        threshold = float(site.get("balance_alert_threshold") or 0)
        if amount <= threshold and not alert_active:
            alert_active = True
            record_balance_event(site, "balance_low", amount, threshold, checked_at)
        elif amount > threshold and alert_active:
            alert_active = False
            record_balance_event(site, "balance_recovered", amount, threshold, checked_at)

    next_check_at = next_check_iso(int(site["interval_minutes"] or DEFAULT_INTERVAL_MINUTES))
    effective_status = "warning" if login_error or alert_active or (site.get("balance_alert_enabled") and balance_error) else "ok"
    db_execute(
        """
        UPDATE sites
        SET status = ?,
            last_error = NULL,
            last_check_at = ?,
            next_check_at = ?,
            consecutive_failures = 0,
            current_groups_json = ?,
            current_login_groups_json = COALESCE(?, current_login_groups_json),
            login_last_error = ?,
            login_last_check_at = ?,
            access_token = COALESCE(NULLIF(?, ''), access_token),
            refresh_token = COALESCE(NULLIF(?, ''), refresh_token),
            token_expires_at = COALESCE(?, token_expires_at),
            auth_alert_active = 0,
            current_balance = COALESCE(?, current_balance),
            balance_currency = COALESCE(?, balance_currency),
            balance_last_error = CASE WHEN ? = 1 THEN ? ELSE balance_last_error END,
            balance_last_check_at = CASE WHEN ? = 1 THEN ? ELSE balance_last_check_at END,
            balance_alert_active = ?,
            updated_at = ?
        WHERE id = ?
        """,
        (
            effective_status,
            checked_at,
            next_check_at,
            groups_json,
            login_groups_json,
            login_error,
            checked_at if site.get("login_enabled") else None,
            refreshed_access_token,
            refreshed_refresh_token,
            refreshed_expires_at,
            balance_info.get("amount") if balance_info else None,
            balance_info.get("currency") if balance_info else None,
            1 if balance_attempted else 0,
            balance_error,
            1 if balance_attempted else 0,
            checked_at if balance_attempted else None,
            1 if alert_active else 0,
            checked_at,
            site_id,
        ),
    )

    return {
        "success": not bool(login_error),
        "message": login_error or "ok",
        "checked_at": checked_at,
        "groups": new_groups,
        "login_groups": login_groups,
        "changes": changes,
        "balance": balance_info,
        "balance_error": balance_error,
    }


def schedule_worker() -> None:
    while not STOP_EVENT.is_set():
        try:
            now = app_now()
            due_sites = db_query_all(
                """
                SELECT * FROM sites
                WHERE enabled = 1
                  AND (next_check_at IS NULL OR next_check_at <= ?)
                ORDER BY
                  CASE WHEN next_check_at IS NULL THEN 0 ELSE 1 END,
                  next_check_at ASC,
                  id ASC
                """,
                (now.isoformat(timespec="seconds"),),
            )
            for site in due_sites:
                if STOP_EVENT.is_set():
                    break
                try:
                    detect_site(int(site["id"]))
                except Exception:
                    checked_at = utc_now_iso()
                    err = traceback.format_exc(limit=2)
                    consecutive_failures = int(site["consecutive_failures"] or 0) + 1
                    next_check_at = next_check_iso(int(site["interval_minutes"] or DEFAULT_INTERVAL_MINUTES))
                    db_execute(
                        """
                        UPDATE sites
                        SET status = ?,
                            last_error = ?,
                            last_check_at = ?,
                            next_check_at = ?,
                            consecutive_failures = ?,
                            updated_at = ?
                        WHERE id = ?
                        """,
                        (
                            "failed" if consecutive_failures >= 3 else "warning",
                            err,
                            checked_at,
                            next_check_at,
                            consecutive_failures,
                            checked_at,
                            site["id"],
                        ),
                    )
        except Exception:
            pass
        STOP_EVENT.wait(SCAN_INTERVAL_SECONDS)


def json_response(
    handler: BaseHTTPRequestHandler,
    payload: Any,
    status: int = 200,
    headers: Optional[Dict[str, str]] = None,
) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.send_header("Cache-Control", "no-store")
    for name, value in (headers or {}).items():
        handler.send_header(name, value)
    handler.end_headers()
    handler.wfile.write(body)


def redirect_response(handler: BaseHTTPRequestHandler, location: str, status: int = 302) -> None:
    handler.send_response(status)
    handler.send_header("Location", location)
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("Content-Length", "0")
    handler.end_headers()


def read_json_body(handler: BaseHTTPRequestHandler) -> Any:
    length = int(handler.headers.get("Content-Length", "0") or "0")
    raw = handler.rfile.read(length).decode("utf-8") if length > 0 else "{}"
    return json.loads(raw or "{}")


def site_summary(site: Dict[str, Any]) -> Dict[str, Any]:
    groups = {}
    login_groups = {}
    if site.get("current_groups_json"):
        try:
            groups = json.loads(site["current_groups_json"]) or {}
        except Exception:
            groups = {}
    if site.get("current_login_groups_json"):
        try:
            login_groups = json.loads(site["current_login_groups_json"]) or {}
        except Exception:
            login_groups = {}
    notify_groups = notification_groups_for_site(site)
    latest_snapshot = db_query_one(
        "SELECT checked_at, status, error_message FROM snapshots WHERE site_id = ? ORDER BY id DESC LIMIT 1",
        (site["id"],),
    )
    latest_change = db_query_one(
        "SELECT * FROM changes WHERE site_id = ? ORDER BY id DESC LIMIT 1",
        (site["id"],),
    )
    return {
        "id": site["id"],
        "name": site["name"],
        "base_url": site["base_url"],
        "platform": site["platform"],
        "platform_label": "sub2api" if site["platform"] == "sub2api" else "NewAPI",
        "enabled": bool(site["enabled"]),
        "interval_minutes": site["interval_minutes"],
        "notify_all_groups": not bool(notify_groups),
        "notify_groups": notify_groups,
        "login_enabled": bool(site.get("login_enabled")),
        "auth_mode": site.get("auth_mode") or "password",
        "login_username": site.get("login_username") or "",
        "has_login_password": bool(site.get("login_password")),
        "has_access_token": bool(site.get("access_token")),
        "has_refresh_token": bool(site.get("refresh_token")),
        "token_expires_at": site.get("token_expires_at") or "",
        "auth_alert_active": bool(site.get("auth_alert_active")),
        "access_user_id": site.get("access_user_id") or "",
        "login_last_error": site.get("login_last_error"),
        "login_last_check_at": site.get("login_last_check_at"),
        "balance_alert_enabled": bool(site.get("balance_alert_enabled")),
        "balance_alert_threshold": float(site.get("balance_alert_threshold") or 0),
        "current_balance": site.get("current_balance"),
        "balance_currency": site.get("balance_currency") or "USD",
        "balance_last_error": site.get("balance_last_error"),
        "balance_last_check_at": site.get("balance_last_check_at"),
        "balance_alert_active": bool(site.get("balance_alert_active")),
        "status": site["status"],
        "last_error": site["last_error"],
        "last_check_at": site["last_check_at"],
        "next_check_at": site["next_check_at"],
        "consecutive_failures": site["consecutive_failures"],
        "current_groups": groups,
        "current_groups_count": len(groups) if isinstance(groups, dict) else 0,
        "current_login_groups": login_groups,
        "current_login_groups_count": len(login_groups) if isinstance(login_groups, dict) else 0,
        "latest_snapshot": latest_snapshot,
        "latest_change": latest_change,
    }


def overview_payload() -> Dict[str, Any]:
    sites = db_query_all("SELECT * FROM sites ORDER BY id DESC")
    changes = db_query_all("SELECT * FROM changes ORDER BY id DESC LIMIT 8")
    totals = {
        "sites_total": len(sites),
        "sites_enabled": sum(1 for s in sites if s["enabled"]),
        "sites_ok": sum(1 for s in sites if s["status"] == "ok"),
        "sites_failed": sum(1 for s in sites if s["status"] in {"failed", "warning"}),
        "changes_today": db_query_one(
            "SELECT COUNT(*) AS count FROM changes WHERE created_at >= ?",
            (app_now().replace(hour=0, minute=0, second=0, microsecond=0).isoformat(timespec="seconds"),),
        ) or {"count": 0},
    }
    return {
        "version": APP_VERSION,
        "stats": {
            "sites_total": totals["sites_total"],
            "sites_enabled": totals["sites_enabled"],
            "sites_ok": totals["sites_ok"],
            "sites_failed": totals["sites_failed"],
            "changes_today": totals["changes_today"]["count"],
        },
        "sites": [site_summary(site) for site in sites],
        "changes": changes,
    }


def list_sites_payload() -> List[Dict[str, Any]]:
    sites = db_query_all("SELECT * FROM sites ORDER BY id DESC")
    return [site_summary(site) for site in sites]


def list_snapshots(site_id: int) -> List[Dict[str, Any]]:
    return db_query_all(
        """
        SELECT * FROM snapshots
        WHERE site_id = ?
        ORDER BY id DESC
        LIMIT 100
        """,
        (site_id,),
    )


def list_changes(limit: int = 100) -> List[Dict[str, Any]]:
    return db_query_all(
        "SELECT * FROM changes ORDER BY id DESC LIMIT ?",
        (limit,),
    )


def list_site_changes(site_id: int, limit: int = 100) -> List[Dict[str, Any]]:
    return db_query_all(
        """
        SELECT * FROM changes
        WHERE site_id = ?
        ORDER BY id DESC
        LIMIT ?
        """,
        (site_id, limit),
    )


class Handler(BaseHTTPRequestHandler):
    server_version = "NewAPIPriceWatch/0.1"

    def log_message(self, fmt: str, *args: Any) -> None:
        return

    def _auth_session(self) -> Optional[Dict[str, Any]]:
        return session_from_cookie_header(str(self.headers.get("Cookie") or ""))

    def _require_auth(self, api_request: bool = True) -> Optional[Dict[str, Any]]:
        session = self._auth_session()
        if session:
            return session
        if api_request:
            json_response(self, {"success": False, "message": "登录已过期，请重新登录"}, 401)
        else:
            next_path = quote(self.path or "/", safe="")
            redirect_response(self, f"/login?next={next_path}")
        return None

    def _serve_file(self, path: Path, content_type: str) -> None:
        if not path.exists():
            self.send_error(HTTPStatus.NOT_FOUND)
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        if path == "/api/auth/status":
            session = self._auth_session()
            return json_response(self, {
                "authenticated": bool(session),
                "username": session.get("username") if session else None,
                "expires_at": session.get("expires_at") if session else None,
            })
        if path == "/api/version":
            return json_response(self, {"name": "Upstream Ratio Watch", "version": APP_VERSION})
        if path == "/api/bot/balances":
            if not notification_bearer_token_matches(self.headers.get("Authorization")):
                return json_response(self, {"success": False, "message": "机器人接口鉴权失败"}, 401)
            return json_response(self, {"success": True, "data": bot_balance_payload()})
        if path in {"/login", "/login.html"}:
            if self._auth_session():
                return redirect_response(self, "/")
            return self._serve_file(STATIC_DIR / "login.html", "text/html; charset=utf-8")
        if path == "/login.js":
            return self._serve_file(STATIC_DIR / "login.js", "application/javascript; charset=utf-8")
        if path == "/styles.css":
            return self._serve_file(STATIC_DIR / "styles.css", "text/css; charset=utf-8")

        if not self._require_auth(api_request=path.startswith("/api/")):
            return

        if path == "/":
            return self._serve_file(STATIC_DIR / "index.html", "text/html; charset=utf-8")
        if path == "/app.js":
            return self._serve_file(STATIC_DIR / "app.js", "application/javascript; charset=utf-8")
        if path == "/api/overview":
            return json_response(self, overview_payload())
        if path == "/api/sites":
            return json_response(self, {"data": list_sites_payload()})
        if path == "/api/changes":
            params = parse_qs(parsed.query)
            limit = int(params.get("limit", ["100"])[0] or 100)
            return json_response(self, {"data": list_changes(limit)})
        if path == "/api/notifications/settings":
            return json_response(self, {"data": notification_settings_payload()})
        if path == "/api/notifications/logs":
            return json_response(self, {"data": db_query_all("SELECT * FROM notification_logs ORDER BY id DESC LIMIT 30")})
        if path.startswith("/api/sites/") and path.endswith("/snapshots"):
            try:
                site_id = int(path.split("/")[3])
            except Exception:
                return self.send_error(HTTPStatus.BAD_REQUEST, "invalid site id")
            return json_response(self, {"data": list_snapshots(site_id)})
        if path.startswith("/api/sites/") and path.endswith("/changes"):
            try:
                site_id = int(path.split("/")[3])
            except Exception:
                return self.send_error(HTTPStatus.BAD_REQUEST, "invalid site id")
            params = parse_qs(parsed.query)
            limit = int(params.get("limit", ["100"])[0] or 100)
            return json_response(self, {"data": list_site_changes(site_id, limit)})

        self.send_error(HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path

        try:
            if path == "/api/auth/login":
                client_ip = request_client_ip(self)
                if login_rate_limited(client_ip):
                    return json_response(self, {"success": False, "message": "登录失败次数过多，请稍后再试"}, 429)
                body = read_json_body(self)
                username = str(body.get("username") or "")
                password = str(body.get("password") or "")
                config = load_auth_config()
                valid_username = hmac.compare_digest(username.encode("utf-8"), str(config["username"]).encode("utf-8"))
                valid_password = hmac.compare_digest(password.encode("utf-8"), str(config["password"]).encode("utf-8"))
                if not valid_username or not valid_password:
                    record_login_failure(client_ip)
                    return json_response(self, {"success": False, "message": "用户名或密码错误"}, 401)
                clear_login_failures(client_ip)
                token, expires_at = create_session_token(config)
                max_age = int(config["session_days"]) * 86400
                return json_response(
                    self,
                    {"success": True, "username": config["username"], "expires_at": expires_at},
                    headers={"Set-Cookie": session_cookie_header(self, token, max_age)},
                )

            if path == "/api/auth/logout":
                return json_response(
                    self,
                    {"success": True},
                    headers={"Set-Cookie": session_cookie_header(self, "", 0)},
                )

            if path == "/api/bot/ratios":
                if not notification_bearer_token_matches(self.headers.get("Authorization")):
                    return json_response(self, {"success": False, "message": "机器人接口鉴权失败"}, 401)
                return json_response(self, {"success": True, "data": bot_live_ratio_payload()})

            if not self._require_auth(api_request=True):
                return

            if path == "/api/check-connection":
                body = read_json_body(self)
                base_url = normalize_base_url(str(body.get("base_url") or ""))
                platform = str(body.get("platform") or "newapi").strip().lower()
                if not base_url:
                    return json_response(self, {"success": False, "message": "base_url required"}, 400)
                if platform == "sub2api":
                    result = probe_sub2api_groups(
                        base_url,
                        username=str(body.get("login_username") or "").strip(),
                        password=str(body.get("login_password") or ""),
                        auth_mode=str(body.get("auth_mode") or "password").strip().lower(),
                        access_token=str(body.get("access_token") or "").strip(),
                        refresh_token=str(body.get("refresh_token") or "").strip(),
                        token_expires_at=body.get("token_expires_at"),
                    )
                else:
                    result = probe_newapi_groups(base_url)
                return json_response(self, result)

            if path == "/api/check-login":
                body = read_json_body(self)
                base_url = normalize_base_url(str(body.get("base_url") or ""))
                access_token = str(body.get("access_token") or "").strip()
                access_user_id = str(body.get("access_user_id") or "").strip()
                if not base_url or not access_token or not access_user_id:
                    return json_response(self, {"success": False, "message": "Base URL、系统访问令牌、NewAPI 用户 ID 都需要填写"}, 400)
                groups_ok, groups_payload, groups_error = fetch_newapi_groups_with_access_token(base_url, access_token, access_user_id)
                groups = parse_groups_payload(groups_payload) if groups_ok else {}
                return json_response(self, {
                    "success": groups_ok,
                    "message": groups_error or "访问令牌验证成功",
                    "groups_count": len(groups),
                    "groups": groups,
                })

            if path == "/api/sites":
                body = read_json_body(self)
                name = str(body.get("name") or "").strip()
                base_url = normalize_base_url(str(body.get("base_url") or ""))
                platform = str(body.get("platform") or "newapi").strip().lower()
                enabled = bool(body.get("enabled", True))
                interval = int(body.get("interval_minutes") or DEFAULT_INTERVAL_MINUTES)
                interval = max(MIN_INTERVAL_MINUTES, interval)
                login_enabled = bool(body.get("login_enabled", False))
                login_username = str(body.get("login_username") or "").strip()
                login_password = str(body.get("login_password") or "")
                access_token = str(body.get("access_token") or "").strip()
                access_user_id = str(body.get("access_user_id") or "").strip()
                refresh_token = str(body.get("refresh_token") or "").strip()
                token_expires_at = str(body.get("token_expires_at") or "").strip()
                auth_mode = str(body.get("auth_mode") or "password").strip().lower()
                balance_alert_enabled = bool(body.get("balance_alert_enabled", False))
                balance_alert_threshold = float(body.get("balance_alert_threshold") or 0)
                notify_all_groups = bool(body.get("notify_all_groups", True))
                notify_groups = normalize_notify_groups(body.get("notify_groups"))
                if platform not in {"newapi", "sub2api"}:
                    return json_response(self, {"success": False, "message": "platform invalid"}, 400)
                if auth_mode not in {"password", "token"}:
                    return json_response(self, {"success": False, "message": "auth_mode invalid"}, 400)
                if not name or not base_url:
                    return json_response(self, {"success": False, "message": "name/base_url required"}, 400)
                if platform == "newapi" and login_enabled and (not access_token or not access_user_id):
                    return json_response(self, {"success": False, "message": "使用系统访问令牌时需要填写 NewAPI 用户 ID"}, 400)
                if platform == "sub2api" and auth_mode == "password" and (not login_username or not login_password):
                    return json_response(self, {"success": False, "message": "sub2api 需要填写普通用户邮箱和密码"}, 400)
                if platform == "sub2api" and auth_mode == "token" and not access_token:
                    return json_response(self, {"success": False, "message": "导入登录态时需要填写 auth_token"}, 400)
                if balance_alert_enabled and balance_alert_threshold < 0:
                    return json_response(self, {"success": False, "message": "余额预警阈值不能小于 0"}, 400)
                if platform == "newapi" and balance_alert_enabled and not login_enabled:
                    return json_response(self, {"success": False, "message": "NewAPI 余额监控需要开启认证增强监控"}, 400)
                if not notify_all_groups and not notify_groups:
                    return json_response(self, {"success": False, "message": "指定分组通知模式至少需要选择一个分组"}, 400)
                now = utc_now_iso()
                site_id = db_execute(
                    """
                    INSERT INTO sites
                    (name, base_url, platform, enabled, interval_minutes, notify_groups_json, login_enabled, auth_mode, login_username, login_password, access_token, access_user_id, refresh_token, token_expires_at, balance_alert_enabled, balance_alert_threshold, status, last_error, last_check_at, next_check_at, consecutive_failures, current_groups_json, created_at, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'unknown', NULL, NULL, ?, 0, NULL, ?, ?)
                    """,
                    (
                        name,
                        base_url,
                        platform,
                        1 if enabled else 0,
                        interval,
                        None if notify_all_groups else json.dumps(notify_groups, ensure_ascii=False),
                        1 if (login_enabled or platform == "sub2api") else 0,
                        auth_mode if platform == "sub2api" else "password",
                        login_username if platform == "sub2api" and auth_mode == "password" else "",
                        login_password if platform == "sub2api" and auth_mode == "password" else "",
                        access_token if ((platform == "newapi" and login_enabled) or (platform == "sub2api" and auth_mode == "token")) else "",
                        access_user_id if platform == "newapi" and login_enabled else "",
                        refresh_token if platform == "sub2api" and auth_mode == "token" else "",
                        token_expires_at if platform == "sub2api" and auth_mode == "token" else "",
                        1 if balance_alert_enabled else 0,
                        balance_alert_threshold,
                        next_check_iso(interval),
                        now,
                        now,
                    ),
                )
                return json_response(self, {"success": True, "id": site_id})

            if path.startswith("/api/sites/") and path.endswith("/check"):
                try:
                    site_id = int(path.split("/")[3])
                except Exception:
                    return json_response(self, {"success": False, "message": "invalid site id"}, 400)
                result = detect_site(site_id)
                return json_response(self, result)

            if path == "/api/notifications/test-email":
                body = read_json_body(self)
                if body:
                    update_notification_settings(body)
                message = "这是一封上游分组倍率监控测试邮件。"
                ok, error_message = send_email_message("上游倍率监控邮箱测试", message)
                return json_response(self, {"success": ok, "message": error_message or "测试邮件已发送"})

            if path == "/api/notifications/test-wecom":
                body = read_json_body(self)
                if body:
                    update_notification_settings(body)
                message = "这是一条上游分组倍率监控测试消息。"
                ok, error_message = send_wecom_message("上游倍率监控企业微信测试", message)
                return json_response(self, {"success": ok, "message": error_message or "测试消息已发送"})

            if path == "/api/notifications/test-feishu":
                body = read_json_body(self)
                if body:
                    update_notification_settings(body)
                message = "这是一条上游倍率与余额监控测试消息。"
                ok, error_message = send_feishu_message("上游监控飞书测试", message)
                return json_response(self, {"success": ok, "message": error_message or "测试消息已发送"})

            if path == "/api/notifications/test-qq":
                body = read_json_body(self)
                if body:
                    update_notification_settings(body)
                message = "这是一条上游倍率与余额监控测试消息。"
                ok, error_message = send_qq_message("上游监控 QQ 测试", message)
                return json_response(self, {"success": ok, "message": error_message or "测试消息已发送到 QQ 群"})

            self.send_error(HTTPStatus.NOT_FOUND)
        except Exception as exc:
            return json_response(self, {"success": False, "message": str(exc)}, 500)

    def do_PUT(self) -> None:
        path = urlparse(self.path).path
        if not self._require_auth(api_request=True):
            return
        if path.startswith("/api/sites/"):
            try:
                site_id = int(path.split("/")[3])
            except Exception:
                return json_response(self, {"success": False, "message": "invalid site id"}, 400)
            body = read_json_body(self)
            site = db_query_one("SELECT * FROM sites WHERE id = ?", (site_id,))
            if not site:
                return json_response(self, {"success": False, "message": "site not found"}, 404)
            fields = []
            params = []

            if "name" in body:
                fields.append("name = ?")
                params.append(str(body["name"]).strip())
            if "base_url" in body:
                fields.append("base_url = ?")
                params.append(normalize_base_url(str(body["base_url"])))
            target_platform = str(body.get("platform") or site.get("platform") or "newapi").strip().lower()
            if target_platform not in {"newapi", "sub2api"}:
                return json_response(self, {"success": False, "message": "platform invalid"}, 400)
            if "platform" in body:
                fields.append("platform = ?")
                params.append(target_platform)
            if "enabled" in body:
                fields.append("enabled = ?")
                params.append(1 if body["enabled"] else 0)
            if "interval_minutes" in body:
                fields.append("interval_minutes = ?")
                params.append(max(MIN_INTERVAL_MINUTES, int(body["interval_minutes"])))
            if "notify_all_groups" in body or "notify_groups" in body:
                notify_all_groups = bool(body.get("notify_all_groups", not bool(notification_groups_for_site(site))))
                notify_groups = normalize_notify_groups(body.get("notify_groups", notification_groups_for_site(site)))
                if not notify_all_groups and not notify_groups:
                    return json_response(self, {"success": False, "message": "指定分组通知模式至少需要选择一个分组"}, 400)
                fields.append("notify_groups_json = ?")
                params.append(None if notify_all_groups else json.dumps(notify_groups, ensure_ascii=False))
            if "balance_alert_enabled" in body:
                balance_alert_enabled = bool(body["balance_alert_enabled"])
                if target_platform == "newapi" and balance_alert_enabled and not bool(body.get("login_enabled", site.get("login_enabled"))):
                    return json_response(self, {"success": False, "message": "NewAPI 余额监控需要开启认证增强监控"}, 400)
                fields.append("balance_alert_enabled = ?")
                params.append(1 if balance_alert_enabled else 0)
                if not balance_alert_enabled:
                    fields.append("balance_alert_active = 0")
            if "balance_alert_threshold" in body:
                threshold = float(body["balance_alert_threshold"] or 0)
                if threshold < 0:
                    return json_response(self, {"success": False, "message": "余额预警阈值不能小于 0"}, 400)
                fields.append("balance_alert_threshold = ?")
                params.append(threshold)
            if "login_enabled" in body:
                login_enabled = bool(body["login_enabled"])
                login_username = str(body.get("login_username") or "").strip()
                login_password = str(body.get("login_password") or "")
                access_token = str(body.get("access_token") or "").strip()
                access_user_id = str(body.get("access_user_id") or "").strip()
                refresh_token = str(body.get("refresh_token") or "").strip()
                token_expires_at = str(body.get("token_expires_at") or "").strip()
                auth_mode = str(body.get("auth_mode") or site.get("auth_mode") or "password").strip().lower()
                existing_access_token = site.get("access_token") or ""
                existing_access_user_id = site.get("access_user_id") or ""
                existing_refresh_token = site.get("refresh_token") or ""
                existing_username = site.get("login_username") or ""
                existing_password = site.get("login_password") or ""
                if auth_mode not in {"password", "token"}:
                    return json_response(self, {"success": False, "message": "auth_mode invalid"}, 400)
                if target_platform == "newapi":
                    has_token_after_update = bool(access_token or existing_access_token)
                    has_user_id_after_update = bool(access_user_id or existing_access_user_id)
                    if login_enabled and (not has_token_after_update or not has_user_id_after_update):
                        return json_response(self, {"success": False, "message": "使用系统访问令牌时需要填写 NewAPI 用户 ID"}, 400)
                if target_platform == "sub2api" and auth_mode == "password" and (not (login_username or existing_username) or not (login_password or existing_password)):
                    return json_response(self, {"success": False, "message": "sub2api 需要填写普通用户邮箱和密码"}, 400)
                if target_platform == "sub2api" and auth_mode == "token" and not (access_token or existing_access_token):
                    return json_response(self, {"success": False, "message": "导入登录态时需要填写 auth_token"}, 400)
                fields.append("login_enabled = ?")
                params.append(1 if (login_enabled or target_platform == "sub2api") else 0)
                fields.append("auth_mode = ?")
                params.append(auth_mode if target_platform == "sub2api" else "password")
                if target_platform == "sub2api":
                    fields.append("auth_alert_active = 0")
                    if auth_mode == "password" and login_username:
                        fields.append("login_username = ?")
                        params.append(login_username)
                    if auth_mode == "password" and login_password:
                        fields.append("login_password = ?")
                        params.append(login_password)
                    if auth_mode == "token":
                        fields.append("login_username = ?")
                        params.append("")
                        fields.append("login_password = ?")
                        params.append("")
                        if access_token:
                            fields.append("access_token = ?")
                            params.append(access_token)
                        if refresh_token or not existing_refresh_token:
                            fields.append("refresh_token = ?")
                            params.append(refresh_token)
                        fields.append("token_expires_at = ?")
                        params.append(token_expires_at)
                    else:
                        fields.append("access_token = ?")
                        params.append("")
                        fields.append("refresh_token = ?")
                        params.append("")
                        fields.append("token_expires_at = ?")
                        params.append("")
                    fields.append("access_user_id = ?")
                    params.append("")
                else:
                    fields.append("login_username = ?")
                    params.append("")
                    fields.append("login_password = ?")
                    params.append("")
                    fields.append("refresh_token = ?")
                    params.append("")
                    fields.append("token_expires_at = ?")
                    params.append("")
                    if not login_enabled:
                        fields.append("access_token = ?")
                        params.append("")
                        fields.append("access_user_id = ?")
                        params.append("")
                    if login_enabled and access_token:
                        fields.append("access_token = ?")
                        params.append(access_token)
                    if login_enabled and access_user_id:
                        fields.append("access_user_id = ?")
                        params.append(access_user_id)
            if "status" in body:
                fields.append("status = ?")
                params.append(str(body["status"]))

            if not fields:
                return json_response(self, {"success": False, "message": "no fields"}, 400)

            fields.append("updated_at = ?")
            params.append(utc_now_iso())
            params.append(site_id)

            db_execute(f"UPDATE sites SET {', '.join(fields)} WHERE id = ?", params)
            return json_response(self, {"success": True})

        if path == "/api/notifications/settings":
            body = read_json_body(self)
            try:
                update_notification_settings(body)
            except ValueError as exc:
                return json_response(self, {"success": False, "message": str(exc)}, 400)
            return json_response(self, {"success": True, "data": notification_settings_payload()})

        self.send_error(HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        path = urlparse(self.path).path
        if not self._require_auth(api_request=True):
            return
        if path.startswith("/api/sites/"):
            try:
                site_id = int(path.split("/")[3])
            except Exception:
                return json_response(self, {"success": False, "message": "invalid site id"}, 400)
            db_execute("DELETE FROM sites WHERE id = ?", (site_id,))
            return json_response(self, {"success": True})
        self.send_error(HTTPStatus.NOT_FOUND)


def bootstrap_demo_data() -> None:
    if db_query_one("SELECT id FROM sites LIMIT 1"):
        return

    now = utc_now_iso()
    db_execute(
        """
        INSERT INTO sites
        (name, base_url, platform, enabled, interval_minutes, status, last_error, last_check_at, next_check_at, consecutive_failures, current_groups_json, created_at, updated_at)
        VALUES (?, ?, 'newapi', 1, 3, 'unknown', NULL, NULL, ?, 0, NULL, ?, ?)
        """,
        (
            "Demo NewAPI",
            "http://127.0.0.1:3000",
            next_check_iso(3),
            now,
            now,
        ),
    )


def main() -> None:
    ensure_dirs()
    ensure_auth_config()
    init_db()
    bootstrap_demo_data()

    worker = threading.Thread(target=schedule_worker, daemon=True)
    worker.start()

    server = ThreadingHTTPServer((SERVER_HOST, SERVER_PORT), Handler)
    print(f"Upstream Ratio Watch running at http://{SERVER_HOST}:{SERVER_PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        STOP_EVENT.set()
        server.server_close()


if __name__ == "__main__":
    main()
