import sqlite3 as stdlib_sqlite
import libsql
import os
import re
import html
import threading
import secrets
import hashlib
import base64
import time
from datetime import datetime
from zoneinfo import ZoneInfo
from urllib.parse import quote
from typing import Optional
from fastapi import FastAPI, Form, Request, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response as StarletteResponse
from contextlib import asynccontextmanager

# We keep the local name `sqlite3` bound to the `libsql` module so every
# `sqlite3.execute(...)`, `sqlite3.OperationalError`, etc. reference already
# in this file keeps working unchanged.
sqlite3 = libsql

# IMPORTANT, found by testing directly against a live libsql connection:
# libsql does NOT raise sqlite3.OperationalError / IntegrityError like
# stdlib SQLite does - it raises a plain ValueError for everything
# (duplicate columns, UNIQUE violations, missing tables, syntax errors,
# all of it). This file has ~19 `except sqlite3.OperationalError` /
# `except sqlite3.IntegrityError` guards (idempotent ALTER TABLE ADD
# COLUMN calls, duplicate-insert guards) that would silently stop
# catching anything under real Turso traffic if we didn't account for
# this. Pointing all three names at the same ValueError class means
# every existing `except sqlite3.OperationalError` / `except
# sqlite3.IntegrityError` / `except sqlite3.Error` in this file keeps
# catching exactly what libsql actually throws, with zero call-site
# changes needed anywhere else in the file.
sqlite3.OperationalError = ValueError
sqlite3.IntegrityError = ValueError
sqlite3.Error = ValueError
sqlite3.DatabaseError = ValueError

# -------------------------------------------------------------
# Turso Cloud Database Configuration
# -------------------------------------------------------------
def _clean_env(name: str) -> str:
    """Read an env var and strip surrounding whitespace/newlines.

    Root cause of the `Hrana: http error: InvalidHeaderValue` crash:
    TURSO_AUTH_TOKEN gets sent straight into the HTTP Authorization
    header libsql builds for every request, and Vercel's Environment
    Variables UI (or copy-pasting a JWT out of a terminal/file) can
    silently attach a trailing newline or space to the pasted value.
    HTTP header values can't contain control characters like \\n or \\r,
    so the underlying Rust `http` crate rejects the request outright
    with InvalidHeaderValue the moment a query actually runs - which is
    exactly the crash in your traceback.
    """
    value = os.getenv(name) or ""
    return value.strip()


TURSO_DATABASE_URL = _clean_env("TURSO_DATABASE_URL")
TURSO_AUTH_TOKEN = _clean_env("TURSO_AUTH_TOKEN")

if not TURSO_DATABASE_URL or not TURSO_AUTH_TOKEN:
    raise RuntimeError(
        "TURSO_DATABASE_URL and TURSO_AUTH_TOKEN must both be set as "
        "environment variables (you've set these in Vercel already - "
        "this only fires if they're missing locally, e.g. forgetting to "
        "`vercel env pull` or export them before running uvicorn)."
    )

# Extra guard: if stripping the ends wasn't enough, there's a
# whitespace/control character stuck INSIDE the value - the token was
# corrupted during copy-paste and stripping can't fix that. Fail with a
# clear, actionable message instead of the cryptic Hrana crash.
_bad_url_chars = any(ord(c) < 0x21 or ord(c) == 0x7F for c in TURSO_DATABASE_URL)
_bad_token_chars = any(ord(c) < 0x21 or ord(c) == 0x7F for c in TURSO_AUTH_TOKEN)
if _bad_url_chars or _bad_token_chars:
    bad_var = "TURSO_AUTH_TOKEN" if _bad_token_chars else "TURSO_DATABASE_URL"
    raise RuntimeError(
        f"{bad_var} contains a whitespace/control character in the "
        "middle of the value, not just at the ends - it was likely "
        "corrupted when pasted into Vercel's Environment Variables UI "
        "(a stray newline is the usual culprit, e.g. from `cat token.txt` "
        "including the file's trailing newline). Generate a fresh value "
        "(`turso db tokens create <db-name>` for the token, `turso db "
        "show <db-name> --url` for the URL), paste it into Vercel's "
        "dashboard field directly rather than via a file, and redeploy."
    )


# Process-wide cached connection - see get_db_connection() below for why
# this is reused across requests instead of reconnecting every time.
_CACHED_TURSO_CONNECTION = None
_CONNECTION_LOCK = threading.Lock()


class LibsqlRow:
    """
    Drop-in replacement for sqlite3.Row when working with the libsql
    client. libsql's Connection object (a Rust/PyO3 object) does not
    support `conn.row_factory = ...` - it raises AttributeError, since
    the underlying object doesn't allow arbitrary attribute assignment.
    Its cursors instead return raw tuples from fetchone()/fetchall().

    This class wraps a raw tuple together with the column names taken
    from cursor.description, so existing code that does `row["col"]`,
    `row[0]`, `dict(row)`, `"col" in row.keys()`, or `for v in row` keeps
    working exactly as it did with sqlite3.Row.
    """
    __slots__ = ("_data", "_columns")

    def __init__(self, columns, data):
        self._columns = columns
        self._data = data

    def __getitem__(self, key):
        if isinstance(key, str):
            try:
                idx = self._columns.index(key)
            except ValueError:
                raise KeyError(key)
            return self._data[idx]
        return self._data[key]

    def keys(self):
        return list(self._columns)

    def __contains__(self, key):
        return key in self._columns

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)

    def __eq__(self, other):
        if isinstance(other, LibsqlRow):
            return self._data == other._data
        return self._data == other

    def __repr__(self):
        return f"<LibsqlRow {dict(zip(self._columns, self._data))!r}>"


class _TursoCursorWrapper:
    """
    Wraps a raw libsql cursor so fetchone()/fetchall()/fetchmany() return
    LibsqlRow objects (built from cursor.description) instead of plain
    tuples - mirroring sqlite3's Row-based access without needing the
    unsupported conn.row_factory. Everything else (execute, executemany,
    description, lastrowid, rowcount, close, ...) is delegated straight
    through to the underlying raw cursor.
    """

    def __init__(self, raw_cursor):
        self._raw_cursor = raw_cursor

    def _columns(self):
        desc = self._raw_cursor.description
        return [d[0] for d in desc] if desc else []

    def execute(self, *args, **kwargs):
        # Serialized against every other statement in the app (see
        # _CONNECTION_LOCK): FastAPI runs sync routes in a thread pool, so
        # without this, two concurrent requests could issue raw execute()
        # calls against the same shared libsql connection at the same
        # instant. The lock is only held for this one call, never across
        # calls, so it cannot deadlock a request that forgets to release
        # anything - it just guarantees no two statements ever hit the
        # underlying connection at the exact same moment.
        with _CONNECTION_LOCK:
            try:
                self._raw_cursor.execute(*args, **kwargs)
            except Exception:
                # Don't leave a broken connection cached for every future
                # request to keep failing against. Drop it so the next
                # get_db_connection() call creates a fresh one. We deliberately
                # do NOT retry the write right here - silently re-issuing an
                # INSERT/UPDATE after an ambiguous network failure risks
                # executing it twice, which is worse than surfacing this one
                # error to the caller (existing except sqlite3.OperationalError
                # / IntegrityError handling elsewhere in this file still works
                # unchanged, since we re-raise the exact original exception).
                _reset_db_connection()
                raise
        return self

    def executemany(self, *args, **kwargs):
        with _CONNECTION_LOCK:
            self._raw_cursor.executemany(*args, **kwargs)
        return self

    def executescript(self, *args, **kwargs):
        with _CONNECTION_LOCK:
            self._raw_cursor.executescript(*args, **kwargs)
        return self

    def fetchone(self):
        with _CONNECTION_LOCK:
            row = self._raw_cursor.fetchone()
            columns = self._columns()
        if row is None:
            return None
        return LibsqlRow(columns, row)

    def fetchall(self):
        with _CONNECTION_LOCK:
            columns = self._columns()
            raw_rows = self._raw_cursor.fetchall()
        return [LibsqlRow(columns, r) for r in raw_rows]

    def fetchmany(self, size=None):
        with _CONNECTION_LOCK:
            columns = self._columns()
            raw_rows = self._raw_cursor.fetchmany(size) if size is not None else self._raw_cursor.fetchmany()
        return [LibsqlRow(columns, r) for r in raw_rows]

    def __iter__(self):
        with _CONNECTION_LOCK:
            columns = self._columns()
            raw_rows = list(self._raw_cursor)
        for row in raw_rows:
            yield LibsqlRow(columns, row)

    def __getattr__(self, name):
        return getattr(self._raw_cursor, name)


class _TursoConnectionWrapper:
    """
    Thin wrapper around the raw libsql connection. We can't set attributes
    (like row_factory) directly on the raw connection object, so instead
    we intercept cursor() to hand back a _TursoCursorWrapper that produces
    dict/index-accessible rows. Everything else (commit, close, execute,
    etc.) passes straight through.
    """

    def __init__(self, raw_conn):
        self._raw_conn = raw_conn

    def cursor(self):
        return _TursoCursorWrapper(self._raw_conn.cursor())

    def execute(self, *args, **kwargs):
        return self.cursor().execute(*args, **kwargs)

    def close(self):
        # Intentionally a no-op. get_db_connection() now hands out a
        # single shared, cached connection reused across requests (see
        # its docstring). Every route in this file calls conn.close()
        # when it's done with its own queries - previously that was
        # correct (each route had its own private connection), but now
        # that would tear down the *shared* connection and break every
        # request that runs afterward until one got lazily recreated.
        # We honor the call as "this route is done with the connection
        # for now" without actually closing the underlying libsql
        # connection. Use _reset_db_connection() if you need to force a
        # genuine reconnect (e.g. after detecting the connection is bad).
        pass

    def commit(self):
        # Same reasoning as _TursoCursorWrapper.execute(): serialize this
        # against every other statement/commit in the app so one thread's
        # commit can never fire in the middle of another thread's
        # not-yet-committed statements on the shared connection.
        with _CONNECTION_LOCK:
            self._raw_conn.commit()

    def rollback(self):
        with _CONNECTION_LOCK:
            self._raw_conn.rollback()

    def __getattr__(self, name):
        return getattr(self._raw_conn, name)


def get_db_connection():
    """
    Returns a connection to the Turso Cloud database.

    Reuses a single lazily-created libsql connection for the lifetime of
    this warm process/instance, instead of opening a brand-new HTTP/Hrana
    connection (TCP + TLS + auth handshake) on every single call. This is
    the main latency cost when talking to a remote Turso replica (even a
    nearby one like `bom`/Mumbai) - repeating that handshake on every
    query is far more expensive than reusing one already-open connection.

    This remains safe for serverless: a cold start just lazily creates a
    fresh connection on first use (exactly like before), and a warm
    invocation that reuses the same process now skips the handshake
    entirely. If a query ever fails on the cached connection (network
    blip, an idle-connection timeout from Turso's edge, etc.), the
    cursor wrapper invalidates this cache so the very next call gets a
    brand-new connection - a bad connection never stays cached and
    failing forever. The failing call itself still raises normally
    (we don't blind-retry writes in place, since silently re-issuing an
    INSERT/UPDATE after an ambiguous network failure risks executing it
    twice).
    """
    global _CACHED_TURSO_CONNECTION
    if _CACHED_TURSO_CONNECTION is None:
        # Double-checked locking: FastAPI's sync `def` routes run in a
        # thread pool, so two requests can race to create the first
        # connection on a cold start. The lock only guards creation - it
        # is not held during actual query execution, so concurrent
        # requests still run their queries in parallel once the shared
        # connection exists.
        with _CONNECTION_LOCK:
            if _CACHED_TURSO_CONNECTION is None:
                raw_conn = libsql.connect(database=TURSO_DATABASE_URL, auth_token=TURSO_AUTH_TOKEN)
                _CACHED_TURSO_CONNECTION = _TursoConnectionWrapper(raw_conn)
    return _CACHED_TURSO_CONNECTION


def _reset_db_connection():
    """Drop the cached connection so the next get_db_connection() call
    creates a fresh one. Used when a query fails in a way that suggests
    the underlying connection itself has gone stale."""
    global _CACHED_TURSO_CONNECTION
    _CACHED_TURSO_CONNECTION = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_standard_tests_and_parameters()
    yield

app = FastAPI(lifespan=lifespan)

# Static files folder configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
# Guarded: Vercel's deployment root is read-only, so os.makedirs() can
# raise there. We swallow that, and only mount /static if a directory
# actually ends up existing (e.g. bundled in the repo already) - this
# is what stops static file setup from crashing app startup on Vercel.
STATIC_DIR = os.path.join(BASE_DIR, "static")

if not os.path.isdir(STATIC_DIR):
    try:
        os.makedirs(STATIC_DIR, exist_ok=True)
    except OSError:
        pass

if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

# -------------------------------------------------------------
# -------------------------------------------------------------
# SRI LANKA TIMEZONE (Asia/Colombo, UTC+5:30)
# -------------------------------------------------------------
# All "Received On" / "Reported On" / "Printed On" timestamps must reflect
# Sri Lankan wall-clock time regardless of what timezone the server (or
# Turso's underlying host) actually runs in. datetime.now(SRI_LANKA_TZ)
# returns the current moment converted into this timezone directly, so it
# is correct even if the server's OS clock/timezone is UTC or anything
# else - unlike bare datetime.now(), which just trusts the server's local
# settings.
SRI_LANKA_TZ = ZoneInfo("Asia/Colombo")


def now_colombo() -> datetime:
    """Current date & time, always in Asia/Colombo (UTC+5:30)."""
    return datetime.now(SRI_LANKA_TZ)


# -------------------------------------------------------------
# RBAC: ROLES & GRANULAR PERMISSIONS
# -------------------------------------------------------------
# Every permission a user can be individually granted. Keys are what get
# stored (comma-separated) in users.permissions; labels are only for the
# checkboxes on the Manage Users screen.
PERMISSIONS = {
    "add_patient":   "Add Patient",
    "add_test":      "Add Test",
    "manage_tests":  "Manage Tests",
    "manage_doctors":"Manage Doctors",
    "manage_centers":"Manage Centers",
    "reports":       "Reports & Analytics",
    "manage_users":  "Manage Users",
    "share_reports": "Share Reports",
    "print_settings":"Print Layout Settings",
}

# -------------------------------------------------------------
# GRANULAR PERMISSION FLAGS (dedicated integer columns on `users`)
# -------------------------------------------------------------
# These are stored as real INTEGER columns rather than inside the
# comma-separated `permissions` text column above, and - critically -
# they are always read back FROM THE DATABASE at check time, never from
# a cookie. See the note on get_user_flags() below for why that matters.
#
# Shape: column_name -> (checkbox label, default value for new users)
GRANULAR_PERMISSIONS = {
    "can_cancel_bills":  ("🚫 Special Permission: Allow Bill Cancellation", 0),
    "can_view_reports":  ("📊 View Sales Analytics & Financial Summaries", 0),
    "can_edit_results":  ("🧪 Enter / Modify Test Results", 1),
    "can_edit_patients": ("👤 Update Patient Profile Details", 1),
    "can_manage_users":  ("👥 Access User Management", 0),
}

# The primary super-admin account. This username is hidden from every
# user-management listing and can never be edited or deleted through the
# UI, but always retains unrestricted access when logged in.
SUPER_ADMIN_USERNAME = "admin"


def is_super_admin(user: dict) -> bool:
    """True for the built-in primary admin account only."""
    return (user or {}).get("username", "").strip().lower() == SUPER_ADMIN_USERNAME


# -------------------------------------------------------------
# PASSWORD HASHING (stdlib-only PBKDF2-HMAC-SHA256, no passlib/bcrypt
# dependency required) + legacy-plaintext auto-migration on login.
# -------------------------------------------------------------
_PBKDF2_ITERATIONS = 260000


def hash_password(password: str) -> str:
    """Self-describing hash string so a future algorithm change stays
    backward compatible: 'pbkdf2_sha256$<iterations>$<salt_hex>$<hash_hex>'."""
    salt = secrets.token_bytes(16)
    derived = hashlib.pbkdf2_hmac("sha256", (password or "").encode("utf-8"), salt, _PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${_PBKDF2_ITERATIONS}${salt.hex()}${derived.hex()}"


def is_hashed_password(stored: str) -> bool:
    return isinstance(stored, str) and stored.startswith("pbkdf2_sha256$")


def verify_password(stored: str, provided: str) -> bool:
    """Verifies `provided` against `stored`, whether `stored` is already
    one of our pbkdf2_sha256$... hashes or (for not-yet-migrated legacy
    rows) a plain-text password. Never raises on malformed stored values -
    just fails closed. Uses a constant-time comparison for the actual
    hash/plaintext check to avoid timing side channels."""
    if not stored or provided is None:
        return False
    if is_hashed_password(stored):
        try:
            _, iterations_str, salt_hex, hash_hex = stored.split("$", 3)
            iterations = int(iterations_str)
            salt = bytes.fromhex(salt_hex)
            expected = bytes.fromhex(hash_hex)
        except (ValueError, TypeError):
            return False
        derived = hashlib.pbkdf2_hmac("sha256", provided.encode("utf-8"), salt, iterations)
        return secrets.compare_digest(derived, expected)
    # Legacy plaintext row - direct comparison. The caller (login_post)
    # re-hashes and saves the upgraded value on a successful match.
    return secrets.compare_digest(stored, provided)

# -------------------------------------------------------------
# PRINT LAYOUT SETTINGS (dashboard-configurable report styling)
# -------------------------------------------------------------
DEFAULT_PRINT_SETTINGS = {
    "row_padding_px": 4,
    "base_font_size_px": 11,
    "header_font_size_px": 11,
    "line_height": 1.25,
    "footer_gap_px": 18,
    "page_side_margin_mm": 15,
    "default_letterhead": 0,
    "patient_box_font_size_px": 11,
    "patient_box_padding_px": 4,
    "mlt_signature_font_size_px": 9,
    "mlt_details_font_size_px": 8,
    "show_printed_on": 1,
    "fia_margin_top_px": 0,
    "fia_margin_bottom_px": 0,
    "fia_margin_left_px": 0,
    "fia_margin_right_px": 0,
    "category_note_font_size": 10,
    # Signature image fine-tuning (admin-adjustable from Print Settings).
    # Negative margins are intentionally allowed so the gap between the
    # signature image and the name/details below it can be tightened.
    "sig_margin_top_px": -45,
    "sig_margin_bottom_px": -32,
    "sig_margin_left_px": 10,
    "sig_margin_right_px": 0,
    "sig_img_height_px": 135,
}


def get_print_settings() -> dict:
    """
    Reads the single system_print_settings row. Deliberately defensive:
    if the table/row is ever missing, or the DB is briefly unreachable,
    this falls back to DEFAULT_PRINT_SETTINGS instead of raising - a
    settings lookup problem must never be able to break report
    generation or printing.
    """
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT row_padding_px, base_font_size_px, header_font_size_px,
                   line_height, footer_gap_px, page_side_margin_mm, default_letterhead,
                   patient_box_font_size_px, patient_box_padding_px,
                   mlt_signature_font_size_px, mlt_details_font_size_px,
                   show_printed_on,
                   fia_margin_top_px, fia_margin_bottom_px, fia_margin_left_px, fia_margin_right_px,
                   category_note_font_size,
                   sig_margin_top_px, sig_margin_bottom_px, sig_margin_left_px, sig_margin_right_px, sig_img_height_px
            FROM system_print_settings WHERE id = 1
        """)
        row = cursor.fetchone()
        conn.close()
        if row:
            keys = list(DEFAULT_PRINT_SETTINGS.keys())
            return {k: (row[i] if row[i] is not None else DEFAULT_PRINT_SETTINGS[k]) for i, k in enumerate(keys)}
    except Exception:
        pass
    return dict(DEFAULT_PRINT_SETTINGS)


def _clamp(value, lo, hi, default):
    """Small helper to keep saved print settings within sane, safe ranges
    regardless of what gets submitted from the form."""
    try:
        value = float(value)
    except (TypeError, ValueError):
        return default
    return max(lo, min(hi, value))

# Roles that always bypass permission checks entirely, regardless of what
# is (or isn't) stored in their `permissions` column.
FULL_ACCESS_ROLES = {"owner", "admin"}


def get_current_user(request: Request):
    """Reads the username/role/permissions cookies set at login and returns
    a small dict describing the logged-in user. Never raises - callers get
    a safe "no access" shape if cookies are missing/malformed."""
    username = request.cookies.get("username", "")
    role = (request.cookies.get("role", "") or "").strip()
    perms_raw = request.cookies.get("permissions", "") or ""
    permissions = {p for p in perms_raw.split(",") if p}
    return {"username": username, "role": role, "permissions": permissions}


def user_has_access(user: dict, permission_key: str) -> bool:
    """Owner/Admin roles always have full access. Everyone else needs the
    specific permission key present in their granted permissions."""
    role_lower = (user.get("role") or "").strip().lower()
    if role_lower in FULL_ACCESS_ROLES:
        return True
    return permission_key in user.get("permissions", set())


def get_user_flags(username: str) -> dict:
    """
    Reads the granular permission columns for `username` straight from the
    database.

    Deliberately NOT cookie-based. get_current_user() above reads role and
    permissions from cookies, which the browser owns and a user can edit
    freely - anyone could set role=owner and bypass every check. For a
    high-consequence permission like bill cancellation that is not good
    enough, so these flags are always re-read from the users table at the
    moment of the check. The cookie is only used to say *which* user to
    look up, never what they are allowed to do.

    Returns the defaults from GRANULAR_PERMISSIONS if the user row or
    column is missing, so an older database degrades safely instead of
    raising.
    """
    flags = {col: default for col, (_label, default) in GRANULAR_PERMISSIONS.items()}
    username = (username or "").strip()
    if not username:
        return {col: 0 for col in GRANULAR_PERMISSIONS}
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ? LIMIT 1", (username,))
        row = cursor.fetchone()
        conn.close()
        if row:
            row_keys = row.keys()
            for col in GRANULAR_PERMISSIONS:
                if col in row_keys and row[col] is not None:
                    flags[col] = int(row[col] or 0)
    except Exception:
        pass
    return flags


def user_can(user: dict, flag_column: str) -> bool:
    """
    Granular permission check for a single `users.<flag_column>` column.

    Order of precedence:
      1. The primary super admin always passes.
      2. Owner/Admin roles always pass (consistent with user_has_access).
      3. Otherwise the flag must be 1 in the database.
    """
    if is_super_admin(user):
        return True
    if (user.get("role") or "").strip().lower() in FULL_ACCESS_ROLES:
        return True
    return bool(get_user_flags(user.get("username", "")).get(flag_column, 0))


def user_can_or_legacy(user: dict, flag_column: str, permission_key: str) -> bool:
    """
    Passes if EITHER the new granular flag is set OR the user already holds
    the equivalent legacy permission key.

    This matters on deploy: the new columns are added with DEFAULT 0, so
    every pre-existing user starts with can_view_reports = 0 and
    can_manage_users = 0. Gating those screens on the flag alone would
    instantly lock out staff who legitimately have access today. The OR
    keeps them working until an admin ticks the new boxes, while still
    letting the flag grant access on its own.

    Bill cancellation deliberately does NOT use this - it is checked with
    user_can() alone, because tightening that specific action is the point
    of the feature.
    """
    return user_can(user, flag_column) or user_has_access(user, permission_key)


def render_locked_page(feature_label: str) -> HTMLResponse:
    """A clean 'Access Denied' screen shown IN PLACE OF the page content
    when a logged-in user lacks a permission. Navigation tabs stay visible
    everywhere else in the app - only the restricted page's body is
    replaced with this, so the layout never breaks."""
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Access Denied</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
            body {{
                background: #f4f7fe; min-height: 100vh; display: flex;
                align-items: center; justify-content: center; color: #1b2559;
            }}
            .locked-card {{
                background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px;
                box-shadow: 0px 8px 24px rgba(0,0,0,0.06); padding: 48px 40px;
                text-align: center; max-width: 420px;
            }}
            .locked-card i {{ font-size: 42px; color: #e53e3e; margin-bottom: 18px; }}
            .locked-card h2 {{ font-size: 20px; margin-bottom: 10px; }}
            .locked-card p {{ color: #707eae; font-size: 14px; margin-bottom: 22px; }}
            .back-btn {{
                display: inline-block; background: #0d47a1; color: #fff; text-decoration: none;
                padding: 10px 22px; border-radius: 8px; font-weight: 700; font-size: 14px;
            }}
        </style>
    </head>
    <body>
        <div class="locked-card">
            <i class="fa-solid fa-lock"></i>
            <h2>Access Denied</h2>
            <p>You don't have permission to access <strong>{html.escape(feature_label)}</strong>.
            Contact your Owner/Admin if you believe this is a mistake.</p>
            <a href="/dashboard" class="back-btn"><i class="fa-solid fa-arrow-left"></i> Back to Dashboard</a>
        </div>
    </body>
    </html>
    """, status_code=403)


def render_cancelled_bill_page(ref_display: str = "") -> HTMLResponse:
    """Shown IN PLACE OF the page content whenever a cancelled bill's
    result-entry/report/print URL is opened directly. Cancelled bills
    must never be usable for entering results or generating a report,
    even if someone still has the old link/URL."""
    ref_html = f"<p style='color:#94a3b8; font-size:13px; margin-top:-8px; margin-bottom:22px;'>{html.escape(ref_display)}</p>" if ref_display else ""
    return HTMLResponse(f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Bill Cancelled</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
            body {{ background: #f4f7fe; min-height: 100vh; display: flex; align-items: center; justify-content: center; color: #1b2559; }}
            .locked-card {{ background: #ffffff; border: 1px solid #e2e8f0; border-radius: 16px; box-shadow: 0px 8px 24px rgba(0,0,0,0.06); padding: 48px 40px; text-align: center; max-width: 440px; }}
            .locked-card i {{ font-size: 42px; color: #b91c1c; margin-bottom: 18px; }}
            .locked-card h2 {{ font-size: 20px; margin-bottom: 10px; }}
            .locked-card p.msg {{ color: #707eae; font-size: 14px; margin-bottom: 22px; }}
            .back-btn {{ display: inline-block; background: #0d47a1; color: #fff; text-decoration: none; padding: 10px 22px; border-radius: 8px; font-weight: 700; font-size: 14px; }}
        </style>
    </head>
    <body>
        <div class="locked-card">
            <i class="fa-solid fa-ban"></i>
            <h2>This Bill Has Been Cancelled</h2>
            {ref_html}
            <p class="msg">This bill was cancelled and is excluded from active reports. It can't be used to enter results or generate a report. It's still viewable under Sales Analytics &rarr; Cancelled Invoices for audit purposes.</p>
            <a href="/patients-dashboard" class="back-btn"><i class="fa-solid fa-arrow-left"></i> Back to Dashboard</a>
        </div>
    </body>
    </html>
    """, status_code=403)


# -------------------------------------------------------------
# GLOBAL SESSION / CROSS-TAB LOGOUT SYNCHRONIZATION
# -------------------------------------------------------------
# Every system page receives this small client-side guard.  The browser
# storage event is shared between tabs of the same origin, so a logout in
# one tab immediately tells all other open tabs to leave the system.
LOGOUT_SYNC_SCRIPT = """
<script>
(function () {
    const LOGOUT_KEY = "lab_logout_event";
    const isLoginPage = window.location.pathname === "/login" || window.location.pathname === "/";

    function forceLogout() {
        if (!isLoginPage) {
            window.location.replace("/login");
        }
    }

    window.addEventListener("storage", function (event) {
        if (event.key === LOGOUT_KEY && event.newValue) {
            forceLogout();
        }
    });

    // If the cookie has already disappeared (for example after logout in
    // another tab), also protect the currently opened page on load.
    if (!isLoginPage && !document.cookie.split("; ").some(function (c) {
        return c.indexOf("username=") === 0 && c.substring(9) !== "";
    })) {
        forceLogout();
    }
})();
</script>
"""

# Public (no-login) QR report pages. They must never run the staff
# logout-sync script and must never emit a Set-Cookie header.
PUBLIC_REPORT_PATH_PREFIXES = ("/public-report/",)

PUBLIC_REPORT_HEADERS = {
    "Cache-Control": "no-store, max-age=0",
    "Pragma": "no-cache",
    "X-Robots-Tag": "noindex, nofollow, noarchive",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
}


# -------------------------------------------------------------
# SESSION STORE + LOGIN RATE LIMIT (in-memory, zero schema change)
# Server-side sessions keyed by a random opaque token stored in an
# httponly cookie. No DB columns are added; existing plaintext
# passwords are auto-hashed on first successful login (see login_post).
# -------------------------------------------------------------
SESSION_TTL_SECONDS = 12 * 3600  # 12 hours
_sessions: dict = {}
_sessions_lock = threading.Lock()
# key: (client_ip, username_lower) -> {"count": int, "first_ts": float}
_failed_logins: dict = {}

LOGIN_RATE_LIMIT_MAX = 5
LOGIN_RATE_LIMIT_WINDOW = 900  # 15 minutes


def _create_session(username: str) -> str:
    token = secrets.token_urlsafe(32)
    now = time.time()
    with _sessions_lock:
        _sessions[token] = {"username": username, "created": now, "expires": now + SESSION_TTL_SECONDS}
    return token


def _get_session(token: str):
    """Return session dict if valid, else None. Expired entries are removed."""
    if not token:
        return None
    with _sessions_lock:
        sess = _sessions.get(token)
        if sess is None:
            return None
        if time.time() > sess["expires"]:
            _sessions.pop(token, None)
            return None
        return sess


def _pop_session(token: str) -> None:
    if not token:
        return
    with _sessions_lock:
        _sessions.pop(token, None)


def _login_rate_limited(client_ip: str, username: str) -> bool:
    """True if this (ip, username) has >= LOGIN_RATE_LIMIT_MAX failures
    inside the current window."""
    key = (client_ip, (username or "").strip().lower())
    now = time.time()
    with _sessions_lock:
        rec = _failed_logins.get(key)
        if rec and rec["count"] >= LOGIN_RATE_LIMIT_MAX and (now - rec["first_ts"]) < LOGIN_RATE_LIMIT_WINDOW:
            return True
    return False


def _record_failed_login(client_ip: str, username: str) -> None:
    key = (client_ip, (username or "").strip().lower())
    now = time.time()
    with _sessions_lock:
        rec = _failed_logins.get(key)
        if rec is None or (now - rec["first_ts"]) >= LOGIN_RATE_LIMIT_WINDOW:
            _failed_logins[key] = {"count": 1, "first_ts": now}
        else:
            rec["count"] += 1


def _clear_failed_login(client_ip: str, username: str) -> None:
    key = (client_ip, (username or "").strip().lower())
    with _sessions_lock:
        _failed_logins.pop(key, None)


@app.middleware("http")
async def inject_logout_sync(request: Request, call_next):
    response = await call_next(request)

    if request.url.path.startswith(PUBLIC_REPORT_PATH_PREFIXES):
        # A public report response can NEVER create a session.
        response.raw_headers[:] = [
            (k, v) for (k, v) in response.raw_headers if k.lower() != b"set-cookie"
        ]
        for _hk, _hv in PUBLIC_REPORT_HEADERS.items():
            response.headers[_hk] = _hv
        return response

    content_type = response.headers.get("content-type", "")
    body = getattr(response, "body", None)

    if body is not None and "text/html" in content_type:
        try:
            body_text = body.decode("utf-8")
            marker = "</body>"
            if marker in body_text.lower():
                idx = body_text.lower().rfind(marker)
                body_text = body_text[:idx] + LOGOUT_SYNC_SCRIPT + body_text[idx:]
            else:
                body_text += LOGOUT_SYNC_SCRIPT

            body_bytes = body_text.encode("utf-8")
            response.body = body_bytes
            response.headers["content-length"] = str(len(body_bytes))
        except Exception:
            pass

    return response


# -------------------------------------------------------------
# AUTH MIDDLEWARE (added AFTER inject_logout_sync): server-side
# session enforcement. Legacy username/role/permissions cookies are
# still read by get_current_user() inside routes (untouched); this
# middleware adds a server-verified session and sets request.state.user
# from the DB (never from cookies).
# CSRF: the session_token cookie is SameSite=Strict (set at login),
# which blocks cross-site POST submissions. Per-form CSRF tokens are a
# recommended next step but are NOT injected here, to avoid breaking
# the 28 existing HTML pages/forms.
# -------------------------------------------------------------
PUBLIC_PATHS = {"/", "/login", "/logout", "/favicon.ico"}
PUBLIC_PREFIXES = ("/public-report", "/shared-report", "/static", "/docs", "/openapi.json", "/redoc")


@app.middleware("http")
async def session_auth_middleware(request: Request, call_next):
    path = request.url.path

    # Logout: invalidate the server-side session token. The logout
    # route's signature is fixed (no Request parameter), so we do it
    # here in addition to its existing cookie clearing.
    if path == "/logout":
        _pop_session(request.cookies.get("session_token"))
        return await call_next(request)

    if path in PUBLIC_PATHS or any(path.startswith(p) for p in PUBLIC_PREFIXES):
        return await call_next(request)

    token = request.cookies.get("session_token")
    sess = _get_session(token)
    if sess is None:
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            return JSONResponse(status_code=401, content={"error": "unauthorized"})
        return RedirectResponse(url="/login", status_code=302)

    # Valid session: look up the user from the DB (never trust cookies
    # for role/permissions). This is a new query added by the security
    # hardening; no existing query is modified.
    row = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (sess["username"],))
        row = cursor.fetchone()
        conn.close()
    except Exception:
        row = None

    if row is None:
        # User no longer exists; kill the stale session.
        _pop_session(token)
        if request.method in ("POST", "PUT", "DELETE", "PATCH"):
            return JSONResponse(status_code=401, content={"error": "unauthorized"})
        return RedirectResponse(url="/login", status_code=302)

    request.state.user = {
        "username": row["username"],
        "role": row["role"] or "",
        "permissions": {p for p in (row["permissions"] or "").split(",") if p},
        "flags": {c: int(row[c] or 0) for c in GRANULAR_PERMISSIONS if c in row.keys() and row[c] is not None},
    }
    return await call_next(request)


# -------------------------------------------------------------
# UI-UNIFICATION MIDDLEWARE: post-processes HTML responses to inject
# a consistent design system (CSS variables + base styles), a toast
# banner driven by URL params (msg/updated/error/saved), and replaces
# the two known off-primary hex colors (#0f4c81, #1b2559) with the
# canonical #0d47a1 in inline style/bgcolor attributes. Zero route
# changes. Print/public/download pages are skipped so their exact
# layout is preserved.
# -------------------------------------------------------------
_SKIP_HTML_REWRITE_PREFIXES = (
    "/print-report", "/report-download", "/report-letterhead-preview",
    "/public-report", "/shared-report",
)

_UNIFY_CSS = """<style>
:root{--primary:#0d47a1;--primary-dark:#08306b;--accent:#1565c0;--bg:#f4f6fb;--card-bg:#ffffff;--text:#1a2332;--text-muted:#5a6b82;--border:#d8e0ec;}
*{box-sizing:border-box;}
body{font-family:system-ui,'Segoe UI',Roboto,sans-serif;background:var(--bg);color:var(--text);margin:0;}
h1,h2,h3{color:var(--primary);font-weight:600;}
.card{background:var(--card-bg);border:1px solid var(--border);border-radius:8px;padding:20px;margin:12px 0;box-shadow:0 1px 3px rgba(13,71,161,.08);}
table{border-collapse:collapse;width:100%;}
th{background:var(--primary);color:#fff;padding:10px 12px;text-align:left;font-weight:600;}
td{padding:8px 12px;border-bottom:1px solid var(--border);}
input,select,textarea{font-family:inherit;font-size:14px;padding:8px 10px;border:1px solid var(--border);border-radius:6px;background:#fff;color:var(--text);}
button,.btn{background:var(--primary);color:#fff;border:none;border-radius:6px;padding:9px 18px;font-size:14px;cursor:pointer;font-family:inherit;display:inline-block;text-decoration:none;}
button:hover,.btn:hover{background:var(--primary-dark);}
a.btn{text-decoration:none;color:#fff;}
#__toast_container{position:fixed;top:12px;left:50%;transform:translateX(-50%);z-index:99999;display:flex;flex-direction:column;gap:8px;align-items:center;}
.__toast{padding:12px 22px;border-radius:8px;color:#fff;font-size:14px;box-shadow:0 4px 14px rgba(0,0,0,.18);cursor:pointer;max-width:90vw;}
.__toast_success{background:#2e7d32;}
.__toast_info{background:#1565c0;}
.__toast_error{background:#c62828;}
</style>"""

_UNIFY_SCRIPT = """<div id="__toast_container"></div>
<script>
(function(){
  var params=new URLSearchParams(window.location.search);
  var msg=params.get('msg')||params.get('saved')||params.get('updated');
  var err=params.get('error');
  var container=document.getElementById('__toast_container');
  function show(text,cls){
    if(!text||!container)return;
    var el=document.createElement('div');
    el.className='__toast '+cls;
    el.textContent=text;
    el.title='Click to dismiss';
    el.onclick=function(){el.remove();};
    container.appendChild(el);
    setTimeout(function(){if(el.parentNode)el.remove();},4000);
  }
  if(err){show(err,'__toast_error');}
  else if(msg){show(msg,'__toast_success');}
  document.addEventListener('DOMContentLoaded',function(){
    var bad=['#0f4c81','#1b2559'];
    function fix(s){
      if(!s)return s;
      for(var i=0;i<bad.length;i++){
        s=s.replace(new RegExp(bad[i],'gi'),'#0d47a1');
      }
      return s;
    }
    var all=document.querySelectorAll('*');
    for(var i=0;i<all.length;i++){
      var el=all[i];
      if(el.getAttribute){
        var st=el.getAttribute('style');
        if(st){el.setAttribute('style',fix(st));}
        var bg=el.getAttribute('bgcolor');
        if(bg){el.setAttribute('bgcolor',fix(bg));}
      }
    }
  });
})();
</script>"""


@app.middleware("http")
async def ui_unify_middleware(request: Request, call_next):
    response = await call_next(request)
    path = request.url.path
    if response.status_code != 200:
        return response
    content_type = response.headers.get("content-type", "")
    if not content_type.startswith("text/html"):
        return response
    if any(path.startswith(p) for p in _SKIP_HTML_REWRITE_PREFIXES):
        return response
    if response.headers.get("content-disposition", "").startswith("attachment"):
        return response
    body = getattr(response, "body", None)
    if body is None:
        return response
    try:
        body_text = body.decode("utf-8")
        lower = body_text.lower()
        # (a) inject design-system CSS right before </head>
        idx = lower.rfind("</head>")
        if idx != -1:
            body_text = body_text[:idx] + _UNIFY_CSS + body_text[idx:]
        # (b)+(c) inject toast container + hex-unify script after <body>
        bidx = lower.find("<body")
        insert_at = -1
        if bidx != -1:
            gt = lower.find(">", bidx)
            if gt != -1:
                insert_at = gt + 1
        if insert_at != -1:
            body_text = body_text[:insert_at] + _UNIFY_SCRIPT + body_text[insert_at:]
        body_bytes = body_text.encode("utf-8")
        response.body = body_bytes
        response.headers["content-length"] = str(len(body_bytes))
    except Exception:
        pass
    return response


# -------------------------------------------------------------
# APP SHELL: one shared header + grouped left sidebar for EVERY page
# -------------------------------------------------------------
# The dashboard owns its own full layout (see _DASHBOARD_TEMPLATE) but
# builds its header/sidebar from the same functions below. Every other
# authenticated HTML page is wrapped by `app_shell_middleware` so that
# all 30+ legacy pages get the same look, the same left sidebar, and no
# more "Back to Dashboard" buttons - without rewriting each route.

# (key, label, icon, href, legacy_permission_key, granular_flag_column)
_SHELL_NAV = [
    ("Main", [
        ("dashboard", "Dashboard", "fa-house", "/dashboard", None, None),
        ("register", "Register Patient", "fa-user-plus", "/add-patient", "add_patient", None),
        ("results", "Test Results & Print", "fa-print", "/patients-dashboard", None, None),
        ("entry", "Result Entry", "fa-file-pen", "/select-patient", None, None),
        ("cancel", "Cancel Bills", "fa-ban", "/patients-dashboard?tab=cancel_bills", None, "can_cancel_bills"),
    ]),
    ("Analytics", [
        ("reports", "Reports & Analytics", "fa-chart-line", "/reports", "reports", "can_view_reports"),
        ("sales", "Sales & Finance", "fa-sack-dollar", "/reports/sales-analytics", "reports", "can_view_reports"),
        ("pricelist", "Test Price List", "fa-tags", "/reports?report_type=pricelist", "reports", "can_view_reports"),
        ("share", "Share Reports", "fa-share-nodes", "/share-reports", "share_reports", None),
    ]),
    ("Setup", [
        ("tests", "Manage Tests", "fa-gear", "/manage-tests", "manage_tests", None),
        ("doctors", "Manage Doctors", "fa-user-doctor", "/manage-doctors", "manage_doctors", None),
        ("centers", "Centers", "fa-hospital", "/manage-centers", "manage_centers", None),
        ("print", "Print Settings", "fa-sliders", "/print-settings", "print_settings", None),
    ]),
    ("Admin", [
        ("users", "Manage Users", "fa-user-gear", "/manage-users", "manage_users", "can_manage_users"),
    ]),
]

# Which sidebar item is "active" for which URL path (first match wins).
_SHELL_MATCH = [
    ("sales", ("/reports/sales-analytics",)),
    ("reports", ("/reports",)),
    ("results", ("/patients-dashboard", "/patient-results", "/patient-tests", "/test-entry")),
    ("entry", ("/select-patient", "/add-test-entry")),
    ("register", ("/add-patient",)),
    ("share", ("/share-reports",)),
    ("tests", ("/manage-tests", "/edit-test-category", "/manage-ranges", "/edit-parameter", "/load-standard-templates")),
    ("doctors", ("/manage-doctors",)),
    ("centers", ("/manage-centers",)),
    ("print", ("/print-settings",)),
    ("users", ("/manage-users", "/edit-user")),
    ("dashboard", ("/dashboard",)),
]


def _shell_can(user: dict, perm, flag) -> bool:
    """Used ONLY to decide which sidebar links to show. Real access control
    still happens inside every route - hiding a link is never security."""
    if perm is None and flag is None:
        return True
    if is_super_admin(user):
        return True
    if (user.get("role") or "").strip().lower() in FULL_ACCESS_ROLES:
        return True
    if perm and perm in (user.get("permissions") or set()):
        return True
    if flag and (user.get("flags") or {}).get(flag):
        return True
    return False


def _shell_active_key(path: str, query: str) -> str:
    q = query or ""
    if path == "/patients-dashboard" and "tab=cancel_bills" in q:
        return "cancel"
    if path == "/reports" and "report_type=pricelist" in q:
        return "pricelist"
    for key, prefixes in _SHELL_MATCH:
        for p in prefixes:
            if path == p or path.startswith(p + "/"):
                return key
    return ""


def _shell_nav_item(key: str):
    for _sec, items in _SHELL_NAV:
        for it in items:
            if it[0] == key:
                return it
    return None


def _shell_header_html(user: dict) -> str:
    raw = (user.get("username") or "").strip() or "User"
    name = html.escape(raw[:1].upper() + raw[1:])
    role = html.escape((user.get("role") or "").strip() or "User")

    new_btn = ""
    if _shell_can(user, "add_patient", None):
        new_btn = ('<a href="/add-patient" class="ms-newpt" title="Register a new patient (Alt+N)">'
                   '<i class="fa-solid fa-user-plus"></i><span>New Patient</span></a>')

    menu_links = ""
    if _shell_can(user, "manage_users", "can_manage_users"):
        menu_links += '<a href="/manage-users"><i class="fa-solid fa-user-gear"></i> Manage Users</a>'
    if _shell_can(user, "print_settings", None):
        menu_links += '<a href="/print-settings"><i class="fa-solid fa-sliders"></i> Print Settings</a>'
    menu_links += '<a href="/logout"><i class="fa-solid fa-right-from-bracket"></i> Logout</a>'

    return f"""<header class="ms-header">
  <div class="ms-brand">
    <button class="ms-burger" id="msBurger" type="button" aria-label="Menu"><i class="fa-solid fa-bars"></i></button>
    <a href="/dashboard" class="ms-brandlink">
      <div class="ms-logo"><i class="fa-solid fa-flask-vial"></i></div>
      <div class="ms-brandtxt"><h1>MEDISTAR MEDICAL LABORATORY</h1><p>Patient &amp; Laboratory Report Management System</p></div>
    </a>
  </div>
  <div class="ms-hright">
    <form class="ms-search" action="/patients-dashboard" method="get" role="search">
      <i class="fa-solid fa-magnifying-glass"></i>
      <input type="text" name="search" id="msGlobalSearch" placeholder="Search patient name or ref no..." autocomplete="off">
      <kbd>/</kbd>
    </form>
    <div class="ms-clock">
      <i class="fa-regular fa-clock"></i>
      <div><b id="msClock">--:--:--</b><span id="msClockDate">&nbsp;</span></div>
    </div>
    {new_btn}
    <div class="ms-theme">
      <i class="fa-solid fa-sun"></i>
      <select id="themeSwitcher" onchange="changeTheme(this.value)" aria-label="Theme">
        <option value="light">Classic Blue</option>
        <option value="dark">Dark Mode</option>
        <option value="emerald">Emerald Green</option>
      </select>
    </div>
    <div class="ms-user" id="msUser">
      <button class="ms-user-btn" id="msUserBtn" type="button">
        <span class="ms-avatar"><i class="fa-solid fa-circle-user"></i></span>
        <span class="nm">{name}</span>
        <i class="fa-solid fa-chevron-down" style="font-size: 11px;"></i>
      </button>
      <div class="ms-user-menu" id="msUserMenu">
        <div class="ms-um-head"><b>{name}</b><span>{role}</span></div>
        {menu_links}
      </div>
    </div>
    <a href="/logout" class="ms-logout"><i class="fa-solid fa-right-from-bracket"></i> Logout</a>
  </div>
</header>"""


def _shell_sidebar_html(user: dict, active: str) -> str:
    parts = []
    for sec, items in _SHELL_NAV:
        links = []
        for key, label, icon, href, perm, flag in items:
            if not _shell_can(user, perm, flag):
                continue
            cls = ' class="active"' if key == active else ""
            esc = html.escape(label)
            links.append(f'<a href="{href}"{cls} title="{esc}"><i class="fa-solid {icon}"></i><span class="lbl">{esc}</span></a>')
        if links:
            parts.append(f'<div class="ms-sec"><span>{sec}</span></div>' + "".join(links))
    return (
        '<aside class="ms-sidebar" id="msSidebar">'
        '<div class="ms-mobile-only ms-m-tools">'
        '<form action="/patients-dashboard" method="get"><i class="fa-solid fa-magnifying-glass"></i>'
        '<input type="text" name="search" placeholder="Search patient..." autocomplete="off"></form>'
        '<select class="ms-theme-m" onchange="changeTheme(this.value)" aria-label="Theme">'
        '<option value="light">Classic Blue</option><option value="dark">Dark Mode</option><option value="emerald">Emerald Green</option></select>'
        '</div>'
        '<button class="ms-collapse" id="msCollapse" type="button" title="Collapse / expand menu">'
        '<i class="fa-solid fa-angles-left"></i><span class="lbl">Collapse menu</span></button>'
        '<nav class="ms-nav">' + "".join(parts) + '</nav>'
        '<div class="ms-side-foot"><i class="fa-solid fa-heart-pulse"></i>'
        '<p>Better Care<br>Through Accurate Results</p></div>'
        '</aside><div class="ms-scrim" id="msScrim"></div>'
    )


def _shell_quick_actions_html(user: dict) -> str:
    items = [
        ("blue", "fa-user-plus", "Register Patient", "/add-patient", "add_patient", None),
        ("green", "fa-print", "Test Results & Print", "/patients-dashboard", None, None),
        ("purple", "fa-chart-line", "Reports & Analytics", "/reports", "reports", "can_view_reports"),
        ("orange", "fa-flask", "Manage Tests", "/manage-tests", "manage_tests", None),
        ("green", "fa-sack-dollar", "Sales & Finance", "/reports/sales-analytics", "reports", "can_view_reports"),
        ("blue", "fa-share-nodes", "Share Reports", "/share-reports", "share_reports", None),
        ("orange", "fa-tags", "Test Price List", "/reports?report_type=pricelist", "reports", "can_view_reports"),
        ("purple", "fa-ban", "Cancel Bills", "/patients-dashboard?tab=cancel_bills", None, "can_cancel_bills"),
    ]
    out = []
    for color, icon, label, href, perm, flag in items:
        if not _shell_can(user, perm, flag):
            continue
        out.append(f'<a href="{href}" class="ms-qa {color}"><i class="fa-solid {icon} ic"></i> {html.escape(label)} '
                   f'<i class="fa-solid fa-chevron-right ar"></i></a>')
    return "".join(out)


_SHELL_HEAD_SCRIPT = """<script>
(function () {
  try {
    var t = localStorage.getItem('lab_theme');
    if (t && t !== 'light') { document.documentElement.setAttribute('data-theme', t); }
    if (localStorage.getItem('lab_sidebar') === '1') { document.documentElement.classList.add('ms-collapsed'); }
  } catch (e) {}
})();
</script>"""

# Theme variables + header + sidebar styles for WRAPPED pages (the dashboard
# template already carries its own copy of these).
_SHELL_BASE_CSS = """
:root{--bg:#eef3fb;--header-bg:linear-gradient(90deg,#0f3b8f 0%,#0d47a1 100%);--sidebar-bg:#f4f7fd;--card:#ffffff;--text:#12296b;--muted:#6b7a99;--border:#e3eaf6;--primary:#0d47a1;--primary-soft:#dce8fb;--shadow:0 6px 22px rgba(13,71,161,.07);}
[data-theme="dark"]{--bg:#0b1437;--header-bg:linear-gradient(90deg,#0d1840,#111c44);--sidebar-bg:#0f1a40;--card:#111c44;--text:#ffffff;--muted:#8f9bba;--border:#1e2b5c;--primary:#38bdf8;--primary-soft:#1b2a5e;--shadow:0 6px 22px rgba(0,0,0,.35);}
[data-theme="emerald"]{--bg:#effaf3;--header-bg:linear-gradient(90deg,#064e3b,#065f46);--sidebar-bg:#f1fbf5;--card:#ffffff;--text:#064e3b;--muted:#4d8a74;--border:#cdeedd;--primary:#065f46;--primary-soft:#d3f3e2;--shadow:0 6px 22px rgba(6,95,70,.08);}
html body.ms{margin:0 !important;padding:0 !important;display:block !important;background:var(--bg) !important;color:var(--text);font-family:'Segoe UI',system-ui,Roboto,sans-serif !important;min-height:100vh;}
.ms-header,.ms-header *,.ms-sidebar,.ms-sidebar *,.ms-crumb,.ms-crumb *{box-sizing:border-box;}
.ms-header a,.ms-sidebar a,.ms-crumb a{text-decoration:none;}
.ms-header{background:var(--header-bg);color:#fff;height:84px;padding:0 26px;display:flex;align-items:center;justify-content:space-between;gap:14px;box-shadow:0 4px 14px rgba(0,0,0,.12);position:relative;z-index:30;}
.ms-brand{display:flex;align-items:center;gap:14px;min-width:0;}
.ms-brandlink{display:flex;align-items:center;gap:14px;color:#fff;min-width:0;}
.ms-burger{display:none;background:rgba(255,255,255,.15);color:#fff;border:0;width:40px;height:40px;border-radius:10px;font-size:17px;cursor:pointer;padding:0;}
.ms-logo{font-size:38px;line-height:1;}
.ms-brand h1{margin:0;color:#fff;font-size:24px;font-weight:800;letter-spacing:.6px;white-space:nowrap;}
.ms-brand p{margin:3px 0 0;font-size:13px;color:#fff;opacity:.92;}
.ms-hright{display:flex;align-items:center;gap:12px;}
.ms-clock{display:flex;align-items:center;gap:10px;border:1px solid rgba(255,255,255,.3);border-radius:26px;padding:7px 18px;background:rgba(255,255,255,.06);}
.ms-clock i{font-size:20px;}
.ms-clock b{display:block;font-size:14px;font-weight:700;line-height:1.2;}
.ms-clock span{display:block;font-size:12px;opacity:.85;line-height:1.2;}
.ms-theme{display:flex;align-items:center;gap:8px;background:#1d5bc4;border-radius:26px;padding:0 14px;height:44px;}
[data-theme="dark"] .ms-theme{background:#26357a;}
[data-theme="emerald"] .ms-theme{background:#0a7a58;}
.ms-theme i{color:#ffc83d;font-size:18px;}
.ms-theme select{appearance:none;-webkit-appearance:none;width:auto;background:transparent;border:0;outline:none;color:#fff;font-weight:700;font-size:13.5px;padding:0 22px 0 0;margin:0;cursor:pointer;font-family:inherit;box-shadow:none;border-radius:0;background-image:url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'><path d='M1 1l5 5 5-5' fill='none' stroke='white' stroke-width='2' stroke-linecap='round'/></svg>");background-repeat:no-repeat;background-position:right center;}
.ms-theme select option{background:#111c44;color:#fff;}
.ms-user{position:relative;}
.ms-user-btn{display:flex;align-items:center;gap:9px;background:transparent;border:0;color:#fff;cursor:pointer;font-family:inherit;font-size:14px;font-weight:700;padding:4px 6px;border-radius:26px;width:auto;margin:0;}
.ms-user-btn:hover{background:rgba(255,255,255,.12);}
.ms-avatar{width:38px;height:38px;border-radius:50%;background:#fff;color:#1d5bc4;display:grid;place-items:center;font-size:20px;}
.ms-user-menu{display:none;position:absolute;right:0;top:52px;min-width:210px;background:var(--card);color:var(--text);border:1px solid var(--border);border-radius:12px;box-shadow:var(--shadow);overflow:hidden;z-index:60;}
.ms-user-menu.open{display:block;}
.ms-user-menu .ms-um-head{padding:12px 16px;border-bottom:1px solid var(--border);}
.ms-user-menu .ms-um-head b{display:block;font-size:14px;}
.ms-user-menu .ms-um-head span{font-size:12px;color:var(--muted);}
.ms-user-menu a{display:flex;align-items:center;gap:10px;padding:11px 16px;color:var(--text);font-size:13.5px;font-weight:600;}
.ms-user-menu a:hover{background:var(--primary-soft);}
.ms-user-menu a i{width:16px;color:var(--primary);}
.ms-logout{background:#ef4444;color:#fff;border:0;border-radius:10px;padding:0 20px;height:44px;font-weight:700;font-size:14px;display:inline-flex;align-items:center;gap:8px;cursor:pointer;font-family:inherit;}
.ms-logout:hover{background:#dc2626;color:#fff;}
.ms-layout{display:grid;grid-template-columns:260px minmax(0,1fr);min-height:calc(100vh - 84px);}
.ms-sidebar{background:var(--sidebar-bg);border-right:1px solid var(--border);padding:14px 14px 20px;display:flex;flex-direction:column;position:sticky;top:0;height:calc(100vh - 84px);overflow-y:auto;}
.ms-nav{display:flex;flex-direction:column;gap:4px;}
.ms-nav a{display:flex;align-items:center;gap:16px;padding:11px 16px;border-radius:12px;color:var(--text);font-size:15px;font-weight:600;transition:background .15s,transform .15s;}
.ms-nav a i{width:24px;text-align:center;font-size:19px;color:var(--primary);opacity:.8;}
.ms-nav a:hover{background:var(--primary-soft);}
.ms-nav a.active{background:var(--primary-soft);font-weight:700;}
.ms-nav a.active i{opacity:1;}
.ms-side-foot{margin-top:auto;text-align:center;padding:24px 8px 6px;color:var(--muted);}
.ms-side-foot i{font-size:38px;color:#38a3e8;display:block;margin-bottom:8px;}
.ms-side-foot p{margin:0;font-family:'Segoe Script','Brush Script MT',cursive;font-style:italic;font-size:15px;line-height:1.5;}
.ms-scrim{display:none;}
.ms-main{padding:18px 28px 30px;min-width:0;}
@media (max-width:992px){
 .ms-burger{display:inline-block;}
 .ms-layout{grid-template-columns:minmax(0,1fr);}
 .ms-sidebar{position:fixed;top:84px;left:0;width:270px;height:calc(100vh - 84px);z-index:50;transform:translateX(-102%);transition:transform .25s;box-shadow:8px 0 30px rgba(0,0,0,.2);}
 .ms-sidebar.open{transform:translateX(0);}
 .ms-scrim.open{display:block;position:fixed;inset:84px 0 0 0;background:rgba(8,20,60,.4);z-index:40;}
 .ms-clock,.ms-brand p{display:none;}
}
@media (max-width:640px){
 .ms-header{padding:0 12px;}
 .ms-brand h1{font-size:15px;white-space:normal;line-height:1.15;}
 .ms-logo,.ms-theme{display:none;}
 .ms-user-btn .nm{display:none;}
 .ms-main{padding:14px 10px 24px;}
}
"""

# Extra rules shared by the dashboard AND wrapped pages: global search,
# New Patient button, sidebar section labels, collapse, breadcrumb, page panel.
_SHELL_EXTRA_CSS = """
.ms-brandlink{display:flex;align-items:center;gap:14px;color:#fff;min-width:0;text-decoration:none;}
.ms-brandtxt{min-width:0;}
.ms-brandtxt h1{margin:0;color:#fff;font-size:24px;font-weight:800;letter-spacing:.6px;white-space:nowrap;line-height:1.15;}
.ms-brandtxt p{margin:3px 0 0;font-size:13px;color:#fff;opacity:.92;line-height:1.2;white-space:nowrap;}
.ms-logo{flex:0 0 auto;font-size:38px;line-height:1;}
.ms-brand{flex:0 1 auto;}
html body.ms{overflow-x:hidden;}
.ms-layout,.ms-main{min-width:0;}
.ms-mobile-only{display:none;}
@media (max-width:1100px){.ms-brandtxt h1{font-size:19px;letter-spacing:.3px;}}
@media (max-width:992px){
 .ms-header{height:64px;padding:0 12px;gap:8px;}
 .ms-burger{display:inline-flex;align-items:center;justify-content:center;flex:0 0 auto;width:44px;height:44px;}
 .ms-brandtxt h1{font-size:15px;white-space:normal;line-height:1.1;letter-spacing:.2px;}
 .ms-brandtxt p{display:none;}
 .ms-logo{font-size:26px;}
 .ms-brandlink{gap:8px;}
 .ms-search,.ms-clock,.ms-theme,.ms-logout{display:none !important;}
 .ms-newpt{height:40px;padding:0 12px;}
 .ms-newpt span{display:none;}
 .ms-hright{gap:6px;flex:0 0 auto;}
 .ms-user-btn .nm,.ms-user-btn > i.fa-chevron-down{display:none;}
 .ms-avatar{width:40px;height:40px;}
 .ms-user-menu{top:48px;}
 .ms-sidebar{top:64px !important;height:calc(100vh - 64px) !important;height:calc(100dvh - 64px) !important;width:280px;}
 .ms-scrim.open{inset:64px 0 0 0 !important;}
 .ms-layout{min-height:calc(100vh - 64px);}
 .ms-mobile-only{display:block;}
 .ms-m-tools{padding:2px 4px 10px;display:flex;flex-direction:column;gap:10px;}
 .ms-m-tools form{display:flex;align-items:center;gap:8px;background:var(--card);border:1px solid var(--border);border-radius:12px;padding:0 12px;height:42px;margin:0;}
 .ms-m-tools input{flex:1;min-width:0;border:0;outline:none;background:transparent;color:var(--text);font-size:14px;padding:0;box-shadow:none;}
 .ms-m-tools select{width:100%;height:42px;border:1px solid var(--border);border-radius:12px;background:var(--card);color:var(--text);font-size:14px;font-weight:600;padding:0 10px;}
 .ms-collapse{display:none;}
 .ms-main{padding:14px 10px 24px;}
 .ms-page{overflow-x:auto;-webkit-overflow-scrolling:touch;}
}
@media (max-width:420px){.ms-brandtxt h1{font-size:13px;}}
.ms-hright{flex:1;justify-content:flex-end;min-width:0;}
.ms-search{display:flex;align-items:center;gap:8px;flex:1;max-width:330px;min-width:140px;height:44px;background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.28);border-radius:26px;padding:0 14px;margin:0;}
.ms-search:focus-within{background:rgba(255,255,255,.24);}
.ms-search i{color:#fff;opacity:.85;font-size:15px;}
.ms-search input{flex:1;min-width:0;width:100%;height:auto;background:transparent;border:0;outline:none;box-shadow:none;border-radius:0;padding:0;margin:0;color:#fff;font-size:13.5px;font-family:inherit;}
.ms-search input::placeholder{color:rgba(255,255,255,.75);}
.ms-search kbd{font-family:inherit;font-size:11px;font-weight:700;background:rgba(255,255,255,.22);border-radius:6px;padding:2px 7px;color:#fff;}
.ms-newpt{background:#22c55e;color:#fff;border-radius:26px;height:44px;padding:0 18px;display:inline-flex;align-items:center;gap:8px;font-weight:700;font-size:13.5px;white-space:nowrap;box-shadow:0 4px 12px rgba(0,0,0,.18);text-decoration:none;}
.ms-newpt:hover{background:#16a34a;color:#fff;}
.ms-sec{padding:14px 16px 4px;font-size:11px;font-weight:800;letter-spacing:1.1px;text-transform:uppercase;color:var(--muted);}
.ms-sec:first-child{padding-top:4px;}
.ms-nav a{padding:10px 16px;}
.ms-collapse{display:flex;align-items:center;gap:14px;background:transparent;border:1px dashed var(--border);color:var(--muted);border-radius:10px;padding:7px 16px;margin:0 0 10px;font-size:12.5px;font-weight:700;cursor:pointer;font-family:inherit;width:100%;}
.ms-collapse i{width:24px;text-align:center;transition:transform .2s;}
.ms-collapse:hover{background:var(--primary-soft);color:var(--primary);}
.ms-crumb{display:flex;align-items:center;gap:10px;font-size:13.5px;font-weight:600;color:var(--muted);margin:0 0 14px;flex-wrap:wrap;}
.ms-crumb a{color:var(--primary);font-weight:700;}
.ms-crumb .sep{font-size:10px;opacity:.7;}
.ms-crumb span{color:var(--text);font-weight:800;display:inline-flex;align-items:center;gap:8px;}
.ms-crumb span i{color:var(--primary);}
.ms-page{color:#1e293b;overflow-x:auto;border-radius:16px;}
[data-theme="dark"] .ms-page{background:#f4f7fb;padding:16px;border:1px solid var(--border);}
html body.ms .ms-page > .header{border-radius:12px;margin-bottom:16px;}
@media (min-width:993px){
 html.ms-collapsed .ms-layout{grid-template-columns:78px minmax(0,1fr);}
 html.ms-collapsed .ms-sidebar{padding:14px 10px 20px;}
 html.ms-collapsed .ms-nav a{justify-content:center;padding:11px 8px;gap:0;}
 html.ms-collapsed .ms-nav a .lbl,html.ms-collapsed .ms-sec span,html.ms-collapsed .ms-collapse .lbl,html.ms-collapsed .ms-side-foot p{display:none;}
 html.ms-collapsed .ms-sec{padding:8px 0 2px;border-bottom:1px solid var(--border);margin-bottom:4px;}
 html.ms-collapsed .ms-collapse{justify-content:center;padding:7px 0;}
 html.ms-collapsed .ms-collapse i{transform:rotate(180deg);}
 html.ms-collapsed .ms-side-foot{padding-top:12px;}
 html.ms-collapsed .ms-side-foot i{font-size:26px;}
}
@media (max-width:1500px){.ms-clock{display:none;}}
@media (max-width:1300px){.ms-newpt span{display:none;}.ms-newpt{padding:0 14px;}}
@media (max-width:1200px){.ms-brand p{display:none;}}
@media (max-height:900px){.ms-side-foot{display:none;}}
@media print{
 .ms-header,.ms-sidebar,.ms-scrim,.ms-crumb{display:none !important;}
 .ms-layout{display:block !important;}
 html body.ms .ms-main{padding:0 !important;}
 .ms-page{background:#fff !important;padding:0 !important;border:0 !important;overflow:visible !important;}
}
"""

_SHELL_CORE_JS = """
(function () {
  var $ = function (i) { return document.getElementById(i); };
  var MONTHS = ['January','February','March','April','May','June','July','August','September','October','November','December'];
  function two(n) { return String(n).padStart(2, '0'); }
  function tick() {
    var el = $('msClock'); if (!el) return;
    var d = new Date(), h = d.getHours(), ap = h >= 12 ? 'PM' : 'AM'; h = h % 12 || 12;
    el.textContent = two(h) + ':' + two(d.getMinutes()) + ':' + two(d.getSeconds()) + ' ' + ap;
    var s = $('msClockDate'); if (s) s.textContent = MONTHS[d.getMonth()].slice(0, 3) + ' ' + d.getDate() + ', ' + d.getFullYear();
  }
  tick(); setInterval(tick, 1000);

  window.changeTheme = function (t) {
    if (t === 'light') { document.documentElement.removeAttribute('data-theme'); }
    else { document.documentElement.setAttribute('data-theme', t); }
    try { localStorage.setItem('lab_theme', t); } catch (e) {}
  };
  var sel = $('themeSwitcher');
  if (sel) { var t = 'light'; try { t = localStorage.getItem('lab_theme') || 'light'; } catch (e) {} sel.value = t; }

  var userBtn = $('msUserBtn'), userMenu = $('msUserMenu');
  if (userBtn && userMenu) {
    userBtn.addEventListener('click', function (e) { e.stopPropagation(); userMenu.classList.toggle('open'); });
    document.addEventListener('click', function (e) { var u = $('msUser'); if (u && !u.contains(e.target)) userMenu.classList.remove('open'); });
  }
  var side = $('msSidebar'), scrim = $('msScrim'), burger = $('msBurger');
  function toggleSide(open) { if (side) side.classList.toggle('open', open); if (scrim) scrim.classList.toggle('open', open); }
  if (burger && side) burger.addEventListener('click', function () { toggleSide(!side.classList.contains('open')); });
  if (scrim) scrim.addEventListener('click', function () { toggleSide(false); });
})();
"""

# Used on BOTH the dashboard and wrapped pages (idempotent, no overlap with core).
_SHELL_EXTRA_JS = """
(function () {
  var tm = document.querySelector('.ms-theme-m');
  if (tm) { var tv = 'light'; try { tv = localStorage.getItem('lab_theme') || 'light'; } catch (e) {} tm.value = tv; }
  var sbar = document.getElementById('msSidebar');
  if (sbar) sbar.addEventListener('click', function (e) {
    if (e.target.closest && e.target.closest('a') && window.innerWidth <= 992) {
      sbar.classList.remove('open'); var sc = document.getElementById('msScrim'); if (sc) sc.classList.remove('open');
    }
  });
  var btn = document.getElementById('msCollapse');
  if (btn) btn.addEventListener('click', function () {
    var c = document.documentElement.classList.toggle('ms-collapsed');
    try { localStorage.setItem('lab_sidebar', c ? '1' : '0'); } catch (e) {}
  });
  document.addEventListener('keydown', function (e) {
    var t = e.target;
    var typing = t && (/^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName) || t.isContentEditable);
    if (e.key === '/' && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
      var s = document.getElementById('msGlobalSearch');
      if (s) { e.preventDefault(); s.focus(); s.select(); }
    }
    if (e.altKey && !e.ctrlKey && !e.metaKey) {
      var k = (e.key || '').toLowerCase();
      if (k === 'n') { var a = document.querySelector('.ms-newpt'); if (a) { e.preventDefault(); location.href = a.getAttribute('href'); } }
      else if (k === 'h') { e.preventDefault(); location.href = '/dashboard'; }
    }
    if (e.key === 'Escape') { var m = document.getElementById('msUserMenu'); if (m) m.classList.remove('open'); }
  });
})();
"""

_RE_SHELL_HEAD = re.compile(r"<head[^>]*>(.*?)</head>", re.I | re.S)
_RE_SHELL_BODY = re.compile(r"<body[^>]*>(.*)</body>", re.I | re.S)
_RE_SHELL_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_RE_SHELL_DASH_LINK = re.compile(r"<a\b[^>]*\bhref=[\"']/dashboard[\"'][^>]*>(?:(?!</a>).)*</a>", re.I | re.S)


def wrap_page_in_shell(page_html: str, user: dict, path: str, query: str):
    """Returns the page re-rendered inside the shared header + sidebar, or
    None when the page should be left exactly as it is."""
    if 'id="msSidebar"' in page_html:
        return None
    body_m = _RE_SHELL_BODY.search(page_html)
    if not body_m:
        return None
    head_m = _RE_SHELL_HEAD.search(page_html)
    head_inner = head_m.group(1) if head_m else ""
    body_inner = body_m.group(1)

    title_m = _RE_SHELL_TITLE.search(head_inner)
    page_title = ""
    if title_m:
        page_title = html.unescape(re.sub(r"<[^>]+>", "", title_m.group(1))).strip()
        page_title = re.sub(r"^Lab System\s*-\s*", "", page_title)
        page_title = re.sub(r"\s*-\s*MEDISTAR MEDICAL LABORATORY.*$", "", page_title)

    # Remove every "Back to Dashboard" style link - the sidebar replaces them.
    body_inner = _RE_SHELL_DASH_LINK.sub("", body_inner)

    active = _shell_active_key(path, query)
    nav_item = _shell_nav_item(active)
    icon = nav_item[2] if nav_item else "fa-file-lines"
    crumb_title = html.escape(page_title or (nav_item[1] if nav_item else "Page"))
    crumb = (
        '<div class="ms-crumb"><a href="/dashboard"><i class="fa-solid fa-house"></i> Dashboard</a>'
        '<i class="fa-solid fa-chevron-right sep"></i>'
        f'<span><i class="fa-solid {icon}"></i> {crumb_title}</span></div>'
    )

    fa_link = ""
    if "font-awesome" not in head_inner.lower():
        fa_link = '<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">'

    return (
        '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        + head_inner + fa_link
        + "<style>" + _SHELL_BASE_CSS + _SHELL_EXTRA_CSS + "</style>"
        + _SHELL_HEAD_SCRIPT
        + '</head><body class="ms ms-wrapped">'
        + _shell_header_html(user)
        + '<div class="ms-layout">' + _shell_sidebar_html(user, active)
        + '<main class="ms-main">' + crumb + '<div class="ms-page">' + body_inner + '</div></main></div>'
        + "<script>" + _SHELL_CORE_JS + "</script><script>" + _SHELL_EXTRA_JS + "</script>"
        + "</body></html>"
    )


_SHELL_SKIP_EXACT = {"/", "/login", "/logout", "/dashboard", "/favicon.ico"}
_SHELL_SKIP_PREFIXES = (
    "/public-report", "/shared-report", "/static", "/docs", "/openapi.json", "/redoc",
    "/print-report", "/report-view", "/report-download", "/report-letterhead-preview", "/api/",
)


@app.middleware("http")
async def app_shell_middleware(request: Request, call_next):
    # Added AFTER every other middleware, so it is the outermost one and sees
    # the finished response of every page.
    response = await call_next(request)
    path = request.url.path
    if request.method != "GET" or response.status_code != 200:
        return response
    if path in _SHELL_SKIP_EXACT or path.startswith(_SHELL_SKIP_PREFIXES):
        return response
    if not response.headers.get("content-type", "").startswith("text/html"):
        return response
    if response.headers.get("content-disposition", "").startswith("attachment"):
        return response
    user = getattr(request.state, "user", None)
    if not user:
        return response

    iterator = getattr(response, "body_iterator", None)
    if iterator is not None:
        chunks = []
        async for chunk in iterator:
            chunks.append(chunk if isinstance(chunk, bytes) else str(chunk).encode("utf-8"))
        original = b"".join(chunks)
    else:
        original = getattr(response, "body", b"") or b""

    out = original
    try:
        wrapped = wrap_page_in_shell(original.decode("utf-8"), user, path, request.url.query)
        if wrapped is not None:
            out = wrapped.encode("utf-8")
    except Exception:
        out = original

    new_response = StarletteResponse(content=out, status_code=response.status_code)
    new_response.raw_headers = [
        (k, v) for (k, v) in response.raw_headers if k.lower() != b"content-length"
    ] + [(b"content-length", str(len(out)).encode("ascii"))]
    return new_response


# 2. Logout Route
@app.get("/logout")
def logout():
    # The logout page removes the shared auth cookies and writes a
    # localStorage event.  Other tabs receive the event immediately.
    response = HTMLResponse(
        content="""
        <!DOCTYPE html>
        <html>
        <head><meta charset="UTF-8"><title>Logging out...</title></head>
        <body>
        <script>
            try {
                localStorage.setItem("lab_logout_event", String(Date.now()));
            } catch (e) {}
            window.location.replace("/login");
        </script>
        </body>
        </html>
        """,
        status_code=200
    )
    response.delete_cookie("username")
    response.delete_cookie("role")
    response.delete_cookie("permissions")
    return response

# -------------------------------------------------------------
# 0. ROOT & LOGIN ROUTES
# -------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def root():
    return RedirectResponse(url="/login", status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_page(error: str = ""):
    error_html = (
        f'<div class="err"><i class="fa-solid fa-circle-exclamation"></i> {html.escape(error)}</div>'
        if error else ""
    )
    page = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>MEDISTAR MEDICAL LABORATORY - Login</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<script>
  (function () { try { var t = localStorage.getItem('lab_theme'); if (t && t !== 'light') document.documentElement.setAttribute('data-theme', t); } catch (e) {} })();
</script>
<style>
  :root { --a1:#0f3b8f; --a2:#0d47a1; --accent:#0d47a1; --accent-dark:#08306b; --soft:#dce8fb; --ov1:rgba(14,53,90,.85); --ov2:rgba(10,30,55,.90); --bgc:#0a1e37; }
  [data-theme="dark"] { --a1:#0d1840; --a2:#111c44; --accent:#38bdf8; --accent-dark:#0ea5e9; --soft:#1b2a5e; --ov1:rgba(8,14,40,.90); --ov2:rgba(5,9,28,.94); --bgc:#050a1c; }
  [data-theme="emerald"] { --a1:#064e3b; --a2:#065f46; --accent:#065f46; --accent-dark:#044e3a; --soft:#d3f3e2; --ov1:rgba(4,60,45,.86); --ov2:rgba(3,38,30,.92); --bgc:#032a20; }
  * { box-sizing: border-box; }
  body { margin:0; min-height:100vh; display:flex; justify-content:center; align-items:center; padding:20px;
         font-family:'Segoe UI',system-ui,Roboto,sans-serif;
         background-image: linear-gradient(135deg, var(--ov1), var(--ov2)), url('/static/bg-lab.jpg');
         background-size:cover; background-position:center; background-repeat:no-repeat; background-attachment:fixed; background-color:var(--bgc); }
  .login-card { width:100%; max-width:420px; background:#fff; border-radius:18px; overflow:hidden; box-shadow:0 20px 50px rgba(0,0,0,.35); }
  .card-top { background:linear-gradient(90deg,var(--a1),var(--a2)); padding:22px 24px 18px; text-align:center; color:#fff; }
  .login-logo { display:block; width:130px; height:130px; object-fit:contain; margin:0 auto 10px; background:#fff; border-radius:50%; padding:10px; }
  .card-top h2 { margin:0; font-size:19px; font-weight:800; letter-spacing:.5px; }
  .card-top p { margin:4px 0 0; font-size:12.5px; opacity:.9; }
  .card-body { padding:26px 28px 28px; }
  .card-body h3 { margin:0 0 4px; color:#12296b; font-size:18px; }
  [data-theme="emerald"] .card-body h3 { color:#064e3b; }
  .sub { margin:0 0 18px; color:#64748b; font-size:13px; }
  .err { background:#fee2e2; color:#b91c1c; border:1px solid #fecaca; border-radius:10px; padding:10px 12px; font-size:13px; font-weight:600; margin-bottom:14px; }
  .field { margin-bottom:14px; }
  .field label { display:block; font-size:12px; font-weight:700; color:#475569; margin-bottom:6px; }
  .input-wrap { position:relative; display:flex; align-items:center; }
  .input-wrap > i.ic { position:absolute; left:14px; color:#94a3b8; font-size:14px; }
  .input-wrap input { width:100%; height:46px; padding:0 44px 0 40px; border:1px solid #cbd5e1; border-radius:12px; font-size:14.5px; outline:none; background:#f8fafc; color:#0f172a; font-family:inherit; }
  .input-wrap input:focus { border-color:var(--accent); background:#fff; box-shadow:0 0 0 3px rgba(13,71,161,.14); }
  .eye { position:absolute; right:6px; width:36px; height:36px; border:0; background:transparent; color:#94a3b8; cursor:pointer; border-radius:8px; font-size:15px; }
  .eye:hover { color:var(--accent); background:var(--soft); }
  .btn-login { width:100%; height:48px; margin-top:6px; border:0; border-radius:12px; cursor:pointer; font-size:15px; font-weight:800; color:#fff; font-family:inherit;
               background:linear-gradient(90deg,var(--a1),var(--a2)); box-shadow:0 6px 16px rgba(13,71,161,.3); display:flex; align-items:center; justify-content:center; gap:8px; }
  [data-theme="dark"] .btn-login { color:#07122e; background:linear-gradient(90deg,#38bdf8,#0ea5e9); }
  .btn-login:hover { filter:brightness(1.08); }
  .btn-login:disabled { opacity:.75; cursor:wait; }
  .foot { text-align:center; margin-top:16px; font-size:11.5px; color:#94a3b8; }
  @media (max-width:420px) { .card-body { padding:22px 18px 22px; } .login-logo { width:104px; height:104px; } }
</style>
</head>
<body>
  <div class="login-card">
    <div class="card-top">
      <img src="/static/logo.png" alt="Medistar Medical Laboratory Logo" class="login-logo">
      <h2>MEDISTAR MEDICAL LABORATORY</h2>
      <p>Patient &amp; Laboratory Report Management System</p>
    </div>
    <div class="card-body">
      <h3>Welcome back</h3>
      <p class="sub">Sign in to your account to continue</p>
      __ERROR__
      <form method="POST" action="/login" id="loginForm">
        <div class="field">
          <label for="u">Username</label>
          <div class="input-wrap"><i class="fa-solid fa-user ic"></i>
            <input type="text" id="u" name="username" required placeholder="Enter username" autocomplete="username" autofocus></div>
        </div>
        <div class="field">
          <label for="p">Password</label>
          <div class="input-wrap"><i class="fa-solid fa-lock ic"></i>
            <input type="password" id="p" name="password" required placeholder="Enter password" autocomplete="current-password">
            <button type="button" class="eye" id="eye" aria-label="Show or hide password"><i class="fa-regular fa-eye"></i></button></div>
        </div>
        <button type="submit" class="btn-login" id="loginBtn"><i class="fa-solid fa-right-to-bracket"></i> Login</button>
      </form>
      <div class="foot">Better Care Through Accurate Results</div>
    </div>
  </div>
<script>
  var eye = document.getElementById('eye'), pw = document.getElementById('p');
  eye.addEventListener('click', function () {
    var show = pw.type === 'password'; pw.type = show ? 'text' : 'password';
    eye.innerHTML = '<i class="fa-regular ' + (show ? 'fa-eye-slash' : 'fa-eye') + '"></i>';
  });
  document.getElementById('loginForm').addEventListener('submit', function () {
    var b = document.getElementById('loginBtn'); b.disabled = true;
    b.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Signing in...';
  });
</script>
</body>
</html>"""
    return page.replace("__ERROR__", error_html)

@app.post("/login")
async def login_post(request: Request):
    form_data = await request.form()
    username = form_data.get("username", "").strip()
    password = form_data.get("password", "").strip()
    
    # Rate-limit check (per client IP + username) before touching the DB.
    client_ip = request.client.host if request.client else "unknown"
    if _login_rate_limited(client_ip, username):
        return RedirectResponse(url="/login?error=Too many failed attempts. Try again in 15 minutes.", status_code=303)

    # Database Check (hardcoded admin bypass removed for security;
    # the seeded admin row is verified against the users table like
    # every other account, and its plaintext password is auto-hashed
    # on first successful login by the upgrade step below).
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                username TEXT, 
                password TEXT, 
                role TEXT,
                permissions TEXT
            )
        """)
        
        cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()

        if user and verify_password(user["password"], password):
            # Legacy-plaintext auto-migration: if the stored value wasn't
            # already one of our pbkdf2_sha256$... hashes, upgrade it now
            # that we've just verified the plaintext password was correct.
            # One-time, silent, on the very next successful login for that
            # account - nothing else about the row changes.
            if not is_hashed_password(user["password"]):
                cursor.execute("UPDATE users SET password = ? WHERE id = ?", (hash_password(password), user["id"]))
                conn.commit()

            # Role එකක් නැත්නම් default 'MLT' විදිහට ගන්නවා
            user_role = user["role"] if "role" in user.keys() and user["role"] else "MLT"
            user_permissions = user["permissions"] if "permissions" in user.keys() and user["permissions"] else ""
            
            conn.close()

            # හැමෝම Dashboard එකට යවනවා සහ Cookies සෙට් කරනවා
            resp = RedirectResponse(url="/dashboard", status_code=303)
            # Legacy cookies (read by existing page JS): keep names/values
            # exactly, add SameSite=Strict. Do NOT mark httponly here -
            # the existing frontend JS reads these cookies.
            resp.set_cookie(key="username", value=username, samesite="strict")
            resp.set_cookie(key="role", value=user_role, samesite="strict")
            resp.set_cookie(key="permissions", value=user_permissions, samesite="strict")
            # Server-side session token: httponly (JS cannot read),
            # SameSite=Strict (primary CSRF defense).
            # TODO: set secure=True when deployed behind HTTPS.
            session_token = _create_session(username)
            resp.set_cookie(key="session_token", value=session_token, httponly=True, samesite="strict", secure=False, max_age=SESSION_TTL_SECONDS, path="/")
            _clear_failed_login(client_ip, username)
            return resp

        conn.close()
            
    except Exception as e:
        pass
    
    # වැරදි නම් එරර් එකක් සමඟ නැවත ලොගින් පේජ් එකටම යැවීම
    _record_failed_login(client_ip, username)
    msg = "Invalid Username or Password!"
    return RedirectResponse(url=f"/login?error={msg}", status_code=303)

# -------------------------------------------------------------
# USER MANAGEMENT ROUTES (Add Users, View List & Delete)
# -------------------------------------------------------------
@app.post("/add-user")
async def add_user(request: Request):
    form_data = await request.form()
    username = form_data.get("username", "").strip()
    password = form_data.get("password", "").strip()
    role = form_data.get("role", "").strip()
    selected_permissions = form_data.getlist("permissions")
    permissions_str = ",".join(p for p in selected_permissions if p in PERMISSIONS)

    # Never allow a second account to be created under the reserved
    # super-admin username - that row is hidden from this UI and must stay
    # the single built-in account.
    if username.strip().lower() == SUPER_ADMIN_USERNAME:
        return RedirectResponse(url="/manage-users", status_code=303)

    if username and password and role:
        # Column names come from the GRANULAR_PERMISSIONS constant (never
        # from the request), and every value is bound as a ? parameter.
        flag_cols = list(GRANULAR_PERMISSIONS.keys())
        flag_values = [1 if form_data.get(col) else 0 for col in flag_cols]
        col_sql = ", ".join(flag_cols)
        placeholders = ", ".join("?" for _ in flag_cols)

        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            f"INSERT INTO users (username, password, role, permissions, {col_sql}) "
            f"VALUES (?, ?, ?, ?, {placeholders})",
            tuple([username, hash_password(password), role, permissions_str] + flag_values)
        )
        conn.commit()
        conn.close()
        
    return RedirectResponse(url="/manage-users", status_code=303)


@app.get("/edit-user/{user_id}", response_class=HTMLResponse)
def edit_user_page(user_id: int, request: Request):
    current_user = get_current_user(request)
    if not user_can_or_legacy(current_user, "can_manage_users", "manage_users"):
        return render_locked_page("Manage Users")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    u = cursor.fetchone()
    conn.close()
    if not u:
        return HTMLResponse("<h3>User not found.</h3><a href='/manage-users'>Back</a>", status_code=404)

    # The primary super admin is hidden from User Management, so its edit
    # page is closed too - otherwise the account would still be reachable
    # by guessing its row id in the URL.
    if str(u["username"]).strip().lower() == SUPER_ADMIN_USERNAME:
        return HTMLResponse("<h3>User not found.</h3><a href='/manage-users'>Back</a>", status_code=404)

    u_role = (u["role"] if "role" in u.keys() and u["role"] else "MLT")
    u_perms = set((u["permissions"] if "permissions" in u.keys() and u["permissions"] else "").split(","))

    checkboxes_html = ""
    for perm_key, perm_label in PERMISSIONS.items():
        checked = "checked" if perm_key in u_perms else ""
        checkboxes_html += f"""
        <label style="display:flex; align-items:center; gap:8px; margin-bottom:8px; font-size:14px; font-weight:600;">
            <input type="checkbox" name="permissions" value="{perm_key}" {checked}> {html.escape(perm_label)}
        </label>
        """

    u_keys = u.keys()
    granular_checkboxes = ""
    for _col, (_label, _default) in GRANULAR_PERMISSIONS.items():
        _current = int(u[_col] or 0) if _col in u_keys and u[_col] is not None else _default
        _highlight = "background:#fff5f5; border:1px solid #fed7d7; padding:8px 10px; border-radius:8px;" if _col == "can_cancel_bills" else ""
        granular_checkboxes += f"""
        <label style="display:flex; align-items:center; gap:8px; margin-bottom:8px; font-size:14px; font-weight:600; {_highlight}">
            <input type="checkbox" name="{_col}" value="1" {"checked" if _current else ""}> {html.escape(_label)}
        </label>
        """

    role_options = ""
    for r in ["Owner", "MLT", "Phlebotomist"]:
        selected = "selected" if r.lower() == u_role.lower() else ""
        role_options += f'<option value="{r}" {selected}>{r}</option>'

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Edit User</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
            body {{ background: #f4f7fe; color: #1b2559; }}
            .header {{ background: #0d47a1; color: white; padding: 14px 28px; }}
            .container {{ padding: 25px; max-width: 500px; margin: auto; }}
            .card {{ background: #fff; padding: 24px; border-radius: 14px; box-shadow: 0px 8px 24px rgba(0,0,0,0.05); border: 1px solid #e2e8f0; }}
            .form-group {{ margin-bottom: 15px; }}
            .form-group label {{ display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; }}
            .form-control {{ width: 100%; padding: 10px 14px; border: 1px solid #e2e8f0; border-radius: 8px; font-size: 14px; }}
            .submit-btn {{ background: #0d47a1; color: white; border: none; padding: 10px 20px; border-radius: 8px; font-weight: 700; cursor: pointer; }}
        </style>
    </head>
    <body>
        <div class="header"><h2><i class="fa-solid fa-user-pen"></i> Edit User: {html.escape(u["username"])}</h2></div>
        <div class="container">
            <div class="card">
                <form action="/edit-user/{user_id}" method="POST">
                    <div class="form-group">
                        <label>Role</label>
                        <select name="role" class="form-control">
                            {role_options}
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Reset Password (leave blank to keep current password)</label>
                        <input type="password" name="new_password" class="form-control" placeholder="New password" autocomplete="new-password">
                    </div>
                    <div class="form-group">
                        <label>Permissions (ignored if role is Owner - Owner always has full access)</label>
                        {checkboxes_html}
                    </div>
                    <div class="form-group">
                        <label>Granular Access Controls</label>
                        {granular_checkboxes}
                    </div>
                    <button type="submit" class="submit-btn"><i class="fa-solid fa-check"></i> Save Changes</button>
                    <a href="/manage-users" style="margin-left:12px;">Cancel</a>
                </form>
            </div>
        </div>
    </body>
    </html>
    """


@app.post("/edit-user/{user_id}")
async def edit_user_post(user_id: int, request: Request):
    current_user = get_current_user(request)
    if not user_can_or_legacy(current_user, "can_manage_users", "manage_users"):
        return render_locked_page("Manage Users")

    form_data = await request.form()
    role = form_data.get("role", "").strip()
    new_password = (form_data.get("new_password", "") or "").strip()
    selected_permissions = form_data.getlist("permissions")
    permissions_str = ",".join(p for p in selected_permissions if p in PERMISSIONS)

    conn = get_db_connection()
    cursor = conn.cursor()

    # Refuse to modify the hidden super-admin row even if its id is posted
    # directly - the UI never exposes it, so any such request is forged.
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    target = cursor.fetchone()
    if not target or str(target["username"]).strip().lower() == SUPER_ADMIN_USERNAME:
        conn.close()
        return RedirectResponse(url="/manage-users", status_code=303)

    # Column names are constants from GRANULAR_PERMISSIONS; all values bound as ?.
    flag_cols = list(GRANULAR_PERMISSIONS.keys())
    flag_values = [1 if form_data.get(col) else 0 for col in flag_cols]
    flag_set_sql = ", ".join(f"{col} = ?" for col in flag_cols)

    if new_password:
        cursor.execute(
            f"UPDATE users SET role = ?, permissions = ?, password = ?, {flag_set_sql} WHERE id = ?",
            tuple([role, permissions_str, hash_password(new_password)] + flag_values + [user_id])
        )
    else:
        cursor.execute(
            f"UPDATE users SET role = ?, permissions = ?, {flag_set_sql} WHERE id = ?",
            tuple([role, permissions_str] + flag_values + [user_id])
        )
    conn.commit()
    conn.close()
    return RedirectResponse(url="/manage-users", status_code=303)

@app.get("/delete-user/{user_id}")
def delete_user(user_id: int, request: Request):
    current_user = get_current_user(request)
    if not user_can_or_legacy(current_user, "can_manage_users", "manage_users"):
        return render_locked_page("Manage Users")

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    target = cursor.fetchone()
    if not target:
        conn.close()
        return RedirectResponse(url="/manage-users", status_code=303)

    target_username = str(target["username"] or "").strip()

    # The primary super admin can never be deleted through the UI.
    if target_username.lower() == SUPER_ADMIN_USERNAME:
        conn.close()
        return RedirectResponse(url="/manage-users", status_code=303)

    # Self-deletion guard: a logged-in user can't delete their own active
    # account (which would otherwise leave their session pointing at a
    # user row that no longer exists).
    if target_username.lower() == (current_user.get("username") or "").strip().lower():
        conn.close()
        return RedirectResponse(url="/manage-users?error=self_delete", status_code=303)

    cursor.execute("DELETE FROM users WHERE id = ? AND username != ?", (user_id, SUPER_ADMIN_USERNAME))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/manage-users", status_code=303)

# -----------------------------
# HELPER FUNCTIONS
def parse_age_components(age_raw: str):
    """Parse a free-text age string into (years, months, days, ok).

    Infant/child safe. The previous inline parser used an *optional* year
    suffix, so a bare number followed by a month/day unit was also swallowed
    by the year pattern - "5 D" parsed as 5 YEARS and 5 days, "8 months" as
    8 years and 8 months, "15 days" as 15 years. That silently corrupted
    infant records and broke every age-aware reference range for paediatric
    patients using the legacy free-text age path.

    The fix: each unit is matched with an explicit, mandatory suffix, and a
    bare number (no unit at all) is the ONLY case treated as years.

    Accepts: "25", "25 Y", "25Y 3M", "0Y 3M 5D", "3M", "5 D", "8 months",
             "15 days", "1Y 6M 20D".
    Returns ok=False only when the string is non-empty and unparseable.
    """
    text = str(age_raw or "").strip()
    if not text:
        return 0, 0, 0, True

    # Explicit, mandatory unit suffixes. Order matters inside each
    # alternation: longest spelling first so "months" isn't cut to "m".
    y_match = re.search(r"(\d+(?:\.\d+)?)\s*(?:years|year|yrs|yr|y)\b", text, re.I)
    m_match = re.search(r"(\d+)\s*(?:months|month|mos|mo|m)\b", text, re.I)
    d_match = re.search(r"(\d+)\s*(?:days|day|d)\b", text, re.I)

    age_years = age_months = age_days = 0
    matched_any = False

    if y_match:
        matched_any = True
        try:
            age_years = max(0, int(float(y_match.group(1))))
        except (TypeError, ValueError):
            age_years = 0
    if m_match:
        matched_any = True
        age_months = max(0, min(11, int(m_match.group(1))))
    if d_match:
        matched_any = True
        age_days = max(0, min(30, int(d_match.group(1))))

    if not matched_any:
        # No unit anywhere - a bare number means years.
        plain = re.fullmatch(r"\d+(?:\.\d+)?", text)
        if not plain:
            return 0, 0, 0, False
        age_years = max(0, int(float(text)))

    return age_years, age_months, age_days, True



# -----------------------------
def clean_display_range(ref_range, unit):
    if not ref_range:
        return ""
    res = str(ref_range)
    if unit:
        res = res.replace(unit, "").strip()
    return res


def calculate_flag(val_str, ref_range):
    """
    Robust reference-range evaluator used for quick flagging.
    Extracts the first numeric value from val_str and compares it against
    a reference range expressed as 'low - high', '< high' or '> low'.
    Tolerant of negative numbers, extra whitespace, thousands separators,
    and malformed/non-numeric input (never raises).
    """
    if not val_str or not ref_range:
        return ""
    try:
        val_match = re.search(r"[-+]?\d*\.\d+|[-+]?\d+", str(val_str).replace(",", ""))
        if not val_match:
            return ""
        val_num = float(val_match.group())
        rr = str(ref_range).strip().replace(",", "")

        if "<" in rr:
            high_m = re.search(r"[-+]?\d*\.\d+|[-+]?\d+", rr.split("<", 1)[1])
            if high_m:
                high_lim = float(high_m.group())
                if val_num > high_lim:
                    return '<span style="color:#000; font-weight:bold;">H</span>'

        elif ">" in rr:
            low_m = re.search(r"[-+]?\d*\.\d+|[-+]?\d+", rr.split(">", 1)[1])
            if low_m:
                low_lim = float(low_m.group())
                if val_num < low_lim:
                    return '<span style="color:#000; font-weight:bold;">L</span>'

        else:
            # "low - high" style range. Match explicitly so a leading
            # negative sign on either bound isn't mistaken for the
            # separator (e.g. "-2 - 5" or "-10 - -2").
            range_m = re.match(r"^\s*([-+]?\d*\.?\d+)\s*-\s*([-+]?\d*\.?\d+)\s*$", rr)
            if range_m:
                low_lim = float(range_m.group(1))
                high_lim = float(range_m.group(2))
                if low_lim > high_lim:
                    low_lim, high_lim = high_lim, low_lim
                if val_num > high_lim:
                    return '<span style="color:#000; font-weight:bold;">H</span>'
                if val_num < low_lim:
                    return '<span style="color:#000; font-weight:bold;">L</span>'
    except Exception:
        pass
    return ""


def evaluate_result_flag(res_str, range_str):
    if res_str is None or range_str is None: return "", False
    rr=str(range_str).strip()
    if not rr: return "", False
    try:
        m=re.search(r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)",str(res_str).replace(",",""))
        if not m: return "",False
        value=float(m.group(0))
        rr=rr.replace(",","").replace("–","-").replace("—","-").replace("−","-").strip()
        num=r"[-+]?(?:\d+(?:\.\d*)?|\.\d+)"
        m=re.search(r"(?:<=|≤|<)\s*("+num+r")",rr)
        if m: return ("H",True) if value>float(m.group(1)) else ("",False)
        m=re.search(r"(?:>=|≥|>)\s*("+num+r")",rr)
        if m: return ("L",True) if value<float(m.group(1)) else ("",False)
        m=re.match(r"^\s*("+num+r")\s*(?:-\s*|\bto\b\s*)("+num+r")\s*$",rr,re.I)
        if m:
            low,high=float(m.group(1)),float(m.group(2))
            if low>high: low,high=high,low
            if value>high: return "H",True
            if value<low: return "L",True
    except (ValueError,TypeError,IndexError,OverflowError): return "",False
    return "",False

def age_parts_to_days(y: int, m: int, d: int) -> int:
    y = int(y or 0)
    m = int(m or 0)
    d = int(d or 0)
    return y * 365 + m * 30 + d


def format_age(y: int, m: int, d: int) -> str:
    y = int(y or 0)
    m = int(m or 0)
    d = int(d or 0)
    parts = []
    if y:
        parts.append(f"{y}Y")
    if m:
        parts.append(f"{m}M")
    if d or not parts:
        parts.append(f"{d}D")
    return " ".join(parts)


def days_to_age_str(days: int) -> str:
    days = int(days or 0)
    y = days // 365
    rem = days % 365
    m = rem // 30
    d = rem % 30
    return format_age(y, m, d)


def bounds_to_ref_text(low, high) -> str:
    if low is not None and high is not None:
        return f"{low} - {high}"
    if high is not None:
        return f"< {high}"
    if low is not None:
        return f"> {low}"
    return ""


def normalize_patient_gender(gender) -> str:
    value = str(gender or "").strip().lower()
    if value in {"male", "m", "man", "boy", "master"}: return "Male"
    if value in {"female", "f", "woman", "girl", "mrs", "miss"}: return "Female"
    return ""

def patient_age_to_days(patient_row) -> int:
    def get_int(*keys):
        for key in keys:
            try: value = patient_row[key]
            except Exception: value = None
            if value not in (None, ""):
                try: return max(0, int(float(value)))
                except (TypeError, ValueError): pass
        return 0
    years=get_int("age_years"); months=get_int("age_months"); days=get_int("age_days")
    if years==0 and months==0 and days==0: years=get_int("age")
    return age_parts_to_days(years, months, days)

def select_best_ref_range(cursor, param_id: int, patient_gender: str, age_days: int):
    try:
        gender=normalize_patient_gender(patient_gender); age_days=max(0,int(age_days or 0))
        cursor.execute("""SELECT id, gender, age_from_days, age_to_days, low, high FROM param_ref_ranges
            WHERE param_id=? AND COALESCE(age_from_days,0)<=? AND COALESCE(age_to_days,73000)>=?
            AND (LOWER(TRIM(COALESCE(gender,'Both')))= 'both' OR LOWER(TRIM(COALESCE(gender,'')))=?)""",
            (param_id,age_days,age_days,gender.lower()))
        rows=cursor.fetchall()
    except sqlite3.Error: return None
    if not rows: return None
    def key(r):
        rg=normalize_patient_gender(r["gender"]); exact=0 if gender and rg==gender else 1
        width=max(0,int(r["age_to_days"])-int(r["age_from_days"]))
        center=(int(r["age_from_days"])+int(r["age_to_days"]))/2
        return (exact,width,abs(center-age_days),r["id"])
    best=sorted(rows,key=key)[0]
    return bounds_to_ref_text(best["low"],best["high"])

def parse_optional_float(x: str):
    if x is None:
        return None
    s = str(x).strip()
    if s == "":
        return None
    return float(s)


# -------------------------------------------------------------
# DATABASE INITIALIZATION (ටේබල්ස් මැකීයාමෙන් තොරව සුරක්ෂිතව සෑදීම)
# -------------------------------------------------------------
def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Results Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER,
            patient_id INTEGER,
            test_id INTEGER,
            param_id INTEGER,
            result_value TEXT
        )
    """)

    # 2. Users Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    # RBAC: idempotently add role & permissions columns without losing
    # existing data. Safe to run every startup — ALTER TABLE ADD COLUMN
    # fails harmlessly (caught below) if the column already exists.
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT DEFAULT 'MLT'")
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN permissions TEXT DEFAULT ''")
    except Exception:
        pass

    # Granular permission flags. Each column is added independently so one
    # already-existing column can never abort the others (libsql raises on
    # a duplicate column, which would short-circuit a shared try block).
    for _col, (_label, _default) in GRANULAR_PERMISSIONS.items():
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {_col} INTEGER DEFAULT {int(_default)}")
        except Exception:
            pass
    conn.commit()

    # 3. Patients Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patients (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT DEFAULT 'Mr.',
            name TEXT NOT NULL,
            age INTEGER,
            age_years INTEGER DEFAULT 0,
            age_months INTEGER DEFAULT 0,
            age_days INTEGER DEFAULT 0,
            gender TEXT,
            phone TEXT,
            doctor TEXT,
            collecting_center TEXT DEFAULT 'Main Branch',
            department TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # 4. Tests Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_name TEXT UNIQUE NOT NULL,
            price REAL DEFAULT 0.0,
            department TEXT,
            specimen TEXT,
            show_fia_graph INTEGER DEFAULT 0
        )
    """)

    # 5. Patient Assigned Tests Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patient_assigned_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER,
            test_id INTEGER,
            result TEXT,
            assigned_date TEXT
        )
    """)

    # 6. Test Parameters Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS test_parameters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            test_id INTEGER,
            param_name TEXT NOT NULL,
            unit TEXT,
            ref_range TEXT,
            FOREIGN KEY (test_id) REFERENCES tests (id)
        )
    """)

    # 7. Param Ref Ranges Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS param_ref_ranges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            param_id INTEGER NOT NULL,
            gender TEXT NOT NULL DEFAULT 'Both',
            age_from_days INTEGER NOT NULL DEFAULT 0,
            age_to_days INTEGER NOT NULL DEFAULT 73000,
            low REAL,
            high REAL,
            FOREIGN KEY (param_id) REFERENCES test_parameters (id)
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_prr_param_id ON param_ref_ranges(param_id)")

    # 8. Reports Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER,
            test_id INTEGER,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (patient_id) REFERENCES patients (id),
            FOREIGN KEY (test_id) REFERENCES tests (id)
        )
    """)

    # 9. Report Results Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS report_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            report_id INTEGER,
            param_id INTEGER,
            result_value TEXT,
            FOREIGN KEY (report_id) REFERENCES reports (id),
            FOREIGN KEY (param_id) REFERENCES test_parameters (id)
        )
    """)

    # 10. Doctors Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS doctors (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            code TEXT UNIQUE,
            name TEXT,
            specialization TEXT,
            phone TEXT
        )
    """)

    # 11. Collecting Centers Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS collecting_centers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            center_name TEXT,
            location TEXT,
            phone TEXT
        )
    """)

    # 12. Share Links Table (Shareable WhatsApp report links)
    # Brand-new, additive-only table - does not touch/alter any existing
    # table or column, so it carries zero risk to existing patient data.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS share_links (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            patient_id INTEGER NOT NULL,
            test_id INTEGER NOT NULL,
            created_at TEXT,
            created_by TEXT
        )
    """)
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_share_links_token ON share_links(token)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_share_links_patient_test ON share_links(patient_id, test_id)")
    conn.commit()

    # 13. Print Layout Settings Table (dashboard-configurable report styling)
    # Brand-new, additive-only table - does not touch/alter any existing
    # table or column. Deliberately a single-row "singleton" table
    # (CHECK (id = 1)) since these are global print preferences, not
    # per-user settings. Seeded once with sensible defaults; safe to run
    # on every startup since INSERT OR IGNORE is a no-op once the row
    # already exists, so it never overwrites an admin's saved settings.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS system_print_settings (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            row_padding_px INTEGER DEFAULT 4,
            base_font_size_px INTEGER DEFAULT 11,
            header_font_size_px INTEGER DEFAULT 11,
            line_height REAL DEFAULT 1.25,
            footer_gap_px INTEGER DEFAULT 18,
            page_side_margin_mm INTEGER DEFAULT 15,
            default_letterhead INTEGER DEFAULT 0,
            show_printed_on INTEGER DEFAULT 1,
            fia_margin_top_px INTEGER DEFAULT 0,
            fia_margin_bottom_px INTEGER DEFAULT 0,
            fia_margin_left_px INTEGER DEFAULT 0,
            fia_margin_right_px INTEGER DEFAULT 0,
            updated_at TEXT
        )
    """)

    # Safe, additive column migration for the Patient Details Box layout
    # controls. Each ALTER TABLE is guarded independently (not chained in
    # one try/except - see the /add-main-test and /edit-test-category
    # fixes earlier in this file for why chaining is unsafe with libsql:
    # once one column already exists, its error would abort the whole
    # block and the other ALTER would never run). Existing rows
    # automatically receive the DEFAULT value SQLite applies for a
    # constant DEFAULT on ADD COLUMN, so this never leaves NULLs behind
    # on your already-seeded settings row.
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN patient_box_font_size_px INTEGER DEFAULT 11")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN patient_box_padding_px INTEGER DEFAULT 4")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN mlt_signature_font_size_px INTEGER DEFAULT 9")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN mlt_details_font_size_px INTEGER DEFAULT 8")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN show_printed_on INTEGER DEFAULT 1")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # FIA Graph Box position fine-tuning (admin-adjustable nudges, all
    # default to 0 = no change from the existing hardcoded layout).
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN fia_margin_top_px INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN fia_margin_bottom_px INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN fia_margin_left_px INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN fia_margin_right_px INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN category_note_font_size INTEGER DEFAULT 10")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Signature image fine-tuning columns. Additive only - existing rows
    # take the DEFAULT, so current reports render exactly as before until
    # an admin changes a value.
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN sig_margin_top_px INTEGER DEFAULT -45")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN sig_margin_bottom_px INTEGER DEFAULT -32")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN sig_margin_left_px INTEGER DEFAULT 10")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN sig_margin_right_px INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE system_print_settings ADD COLUMN sig_img_height_px INTEGER DEFAULT 135")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE tests ADD COLUMN show_fia_graph INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    cursor.execute("""
        INSERT OR IGNORE INTO system_print_settings
            (id, row_padding_px, base_font_size_px, header_font_size_px, line_height, footer_gap_px, page_side_margin_mm, default_letterhead, patient_box_font_size_px, patient_box_padding_px, mlt_signature_font_size_px, mlt_details_font_size_px, show_printed_on, updated_at)
        VALUES (1, 4, 11, 11, 1.25, 18, 15, 0, 11, 4, 9, 8, 1, NULL)
    """)
    conn.commit()

    # Indexes for the columns actually filtered/joined on throughout the
    # app (patient lookups, assigned-test lookups by patient/test,
    # parameter lookups by test, report joins). Turso/libsql round-trips
    # over HTTP are far more latency-sensitive than local SQLite, so a
    # full table scan that was invisible on a local .db file becomes a
    # real, measurable delay against a remote Mumbai (bom) replica.
    # CREATE INDEX IF NOT EXISTS is idempotent - safe to run every startup.
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pat_patient_id ON patient_assigned_tests(patient_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pat_test_id ON patient_assigned_tests(test_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_pat_patient_test ON patient_assigned_tests(patient_id, test_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_test_parameters_test_id ON test_parameters(test_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_results_patient_test_param ON results(patient_id, test_id, param_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_patient_id ON reports(patient_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_reports_test_id ON reports(test_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_report_results_report_id ON report_results(report_id)")
    cursor.execute("CREATE INDEX IF NOT EXISTS idx_tests_department ON tests(department)")
    conn.commit()

    # Compatibility migrations for databases created by older project versions.
    cursor.execute("PRAGMA table_info(patients)")
    patient_columns = {row[1] for row in cursor.fetchall()}
    if "center" not in patient_columns:
        cursor.execute("ALTER TABLE patients ADD COLUMN center TEXT DEFAULT 'Main Branch'")
    if "result_status" not in patient_columns:
        cursor.execute("ALTER TABLE patients ADD COLUMN result_status TEXT DEFAULT 'PENDING'")
    # Additive-only migration for the optional manual bill number.
    # Existing patient records are untouched and receive NULL/blank until
    # a manual bill number is entered for a new or edited record.
    if "manual_bill_no" not in patient_columns:
        cursor.execute("ALTER TABLE patients ADD COLUMN manual_bill_no TEXT")
    # Additive-only migration for bill/invoice cancellation. Existing rows
    # are untouched and default to 0 (not cancelled) - a patient's whole
    # visit/bill is the natural "invoice" granularity in this system (one
    # registration covers all of that patient's assigned tests).
    if "is_cancelled" not in patient_columns:
        cursor.execute("ALTER TABLE patients ADD COLUMN is_cancelled INTEGER DEFAULT 0")

    cursor.execute("PRAGMA table_info(patient_assigned_tests)")
    assigned_columns = {row[1] for row in cursor.fetchall()}
    if "verified" not in assigned_columns:
        cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN verified INTEGER DEFAULT 0")
    if "verified_at" not in assigned_columns:
        cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN verified_at TEXT")
    if "saved_at" not in assigned_columns:
        cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN saved_at TEXT")

    # Additive-only migration for the Sales & Financial Analytics module's
    # doctor commission breakdown. Existing doctors get a 0% rate (i.e.
    # no behavior change to any existing report) until someone sets a
    # real rate; nothing about the doctors table's existing columns or
    # rows is touched.
    cursor.execute("PRAGMA table_info(doctors)")
    doctor_columns = {row[1] for row in cursor.fetchall()}
    if "commission_rate" not in doctor_columns:
        cursor.execute("ALTER TABLE doctors ADD COLUMN commission_rate REAL DEFAULT 0")

    # Default admin user (username: admin, password: 1234)
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', '1234')")

    # The primary super admin always carries owner role + every granular
    # flag, so it keeps unrestricted access no matter what an operator
    # toggles elsewhere. It is hidden from the User Management UI, so this
    # row can never be edited or downgraded through the app.
    try:
        _flag_set_sql = ", ".join(f"{col} = 1" for col in GRANULAR_PERMISSIONS)
        cursor.execute(
            f"UPDATE users SET role = 'owner', {_flag_set_sql} WHERE username = ?",
            (SUPER_ADMIN_USERNAME,)
        )
    except Exception:
        pass

    # ---------------------------------------------------------
    # Calculation metadata / result storage migrations
    # ---------------------------------------------------------
    # These migrations are intentionally additive: existing patient/test data
    # is preserved and existing custom parameters are not overwritten.
    cursor.execute("PRAGMA table_info(test_parameters)")
    tp_columns = {row[1] for row in cursor.fetchall()}
    if "is_calculated" not in tp_columns:
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN is_calculated INTEGER DEFAULT 0")
    if "calculation_key" not in tp_columns:
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN calculation_key TEXT")

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patient_parameter_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER NOT NULL,
            test_id INTEGER NOT NULL,
            parameter_id INTEGER NOT NULL,
            result_value TEXT,
            UNIQUE(patient_id, test_id, parameter_id)
        )
    """)

    # Tombstone table for explicitly-deleted standard-test parameters.
    #
    # ROOT CAUSE of "deleted parameters come back": seed_standard_tests_
    # and_parameters() runs on every cold start (Vercel spins up a fresh
    # process regularly), and it works by checking "does a parameter with
    # this name already exist for this test?" - if a user had deleted a
    # standard parameter (e.g. "Monocytes" under FBC), the very next cold
    # start saw it missing and silently re-inserted it. This table records
    # every parameter a user explicitly deletes (by test_id + lower-cased
    # name) so the seeder can check it and permanently skip re-adding
    # anything a user chose to remove, while still being able to add
    # genuinely new standard parameters in future app updates.
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS deleted_standard_parameters (
            test_id INTEGER NOT NULL,
            param_name_lower TEXT NOT NULL,
            deleted_at TEXT,
            PRIMARY KEY (test_id, param_name_lower)
        )
    """)

    # Compatibility migrations for tables/columns that used to only be
    # created lazily inside individual routes (each costing a network
    # round-trip to Turso on every single page load). Guaranteeing them
    # here, once per cold start, means those per-route ALTER TABLE guards
    # are now redundant and safe to skip on the hot paths that had them.
    cursor.execute("PRAGMA table_info(tests)")
    tests_columns = {row[1] for row in cursor.fetchall()}
    if "notes" not in tests_columns:
        cursor.execute("ALTER TABLE tests ADD COLUMN notes TEXT")
    if "col_alignments" not in tests_columns:
        cursor.execute("ALTER TABLE tests ADD COLUMN col_alignments TEXT")

    if "result" not in assigned_columns:
        cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN result TEXT")
    if "comment" not in assigned_columns:
        cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN comment TEXT")

    conn.commit()
    conn.close()

# NOTE: `app` and `lifespan` were already created once at the top of this
# file (right after DB_PATH). They used to be redefined here as well, which
# silently wiped out every route registered above this point.

# -------------------------------------------------------------
# 1. MAIN DASHBOARD (sidebar layout, live stats, registrations
#    chart, calendar, quick actions). Same links / same data as before.
# -------------------------------------------------------------
def _dash_trend_html(cur, prev):
    """Small coloured trend chip comparing `cur` against `prev`."""
    if prev <= 0:
        if cur > 0:
            return '<span class="ms-trend up"><i class="fa-solid fa-arrow-up"></i> New</span>'
        return '<span class="ms-trend flat"><i class="fa-solid fa-minus"></i> 0%</span>'
    pct = int(round((cur - prev) * 100.0 / prev))
    if pct > 0:
        return f'<span class="ms-trend up"><i class="fa-solid fa-arrow-up"></i> +{pct}%</span>'
    if pct < 0:
        return f'<span class="ms-trend down"><i class="fa-solid fa-arrow-down"></i> {pct}%</span>'
    return '<span class="ms-trend flat"><i class="fa-solid fa-minus"></i> 0%</span>'


_DASHBOARD_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Lab System - Dashboard</title>
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
<script>
  (function () {
    try {
      var t = localStorage.getItem('lab_theme');
      if (t && t !== 'light') { document.documentElement.setAttribute('data-theme', t); }
    } catch (e) {}
  })();
</script>
<style>
  :root {
    --bg: #eef3fb;
    --header-bg: linear-gradient(90deg, #0f3b8f 0%, #0d47a1 100%);
    --sidebar-bg: #f4f7fd;
    --card: #ffffff;
    --text: #12296b;
    --muted: #6b7a99;
    --border: #e3eaf6;
    --primary: #0d47a1;
    --primary-soft: #dce8fb;
    --table-head: #0d47a1;
    --row-hover: rgba(13, 71, 161, 0.04);
    --chart-line: #2563eb;
    --green: #16a34a;
    --red: #dc2626;
    --shadow: 0 6px 22px rgba(13, 71, 161, 0.07);
    --tint-blue: linear-gradient(135deg, #eaf1ff, #ffffff);
    --tint-green: linear-gradient(135deg, #e8f8ef, #ffffff);
    --tint-purple: linear-gradient(135deg, #f1eaff, #ffffff);
    --qa-blue: #e6efff;
    --qa-green: #e5f7ec;
    --qa-purple: #efe8ff;
    --qa-orange: #fff0e1;
    --help-bg: linear-gradient(90deg, #0f3b8f, #0d47a1);
  }
  [data-theme="dark"] {
    --bg: #0b1437;
    --header-bg: linear-gradient(90deg, #0d1840, #111c44);
    --sidebar-bg: #0f1a40;
    --card: #111c44;
    --text: #ffffff;
    --muted: #8f9bba;
    --border: #1e2b5c;
    --primary: #38bdf8;
    --primary-soft: #1b2a5e;
    --table-head: #1b2a5e;
    --row-hover: rgba(255, 255, 255, 0.04);
    --chart-line: #38bdf8;
    --green: #4ade80;
    --red: #f87171;
    --shadow: 0 6px 22px rgba(0, 0, 0, 0.35);
    --tint-blue: linear-gradient(135deg, #16246a, #111c44);
    --tint-green: linear-gradient(135deg, #123a3a, #111c44);
    --tint-purple: linear-gradient(135deg, #2a2468, #111c44);
    --qa-blue: #17265f;
    --qa-green: #123a3a;
    --qa-purple: #2a2468;
    --qa-orange: #3a2a1a;
    --help-bg: linear-gradient(90deg, #1b2a5e, #16246a);
  }
  [data-theme="emerald"] {
    --bg: #effaf3;
    --header-bg: linear-gradient(90deg, #064e3b, #065f46);
    --sidebar-bg: #f1fbf5;
    --card: #ffffff;
    --text: #064e3b;
    --muted: #4d8a74;
    --border: #cdeedd;
    --primary: #065f46;
    --primary-soft: #d3f3e2;
    --table-head: #065f46;
    --row-hover: rgba(6, 95, 70, 0.05);
    --chart-line: #059669;
    --green: #059669;
    --red: #dc2626;
    --shadow: 0 6px 22px rgba(6, 95, 70, 0.08);
    --tint-blue: linear-gradient(135deg, #e3f6ec, #ffffff);
    --tint-green: linear-gradient(135deg, #e8f8ef, #ffffff);
    --tint-purple: linear-gradient(135deg, #e9f7f2, #ffffff);
    --qa-blue: #dff5e9;
    --qa-green: #e5f7ec;
    --qa-purple: #e3f4ef;
    --qa-orange: #fdf1e0;
    --help-bg: linear-gradient(90deg, #064e3b, #065f46);
  }

  html body.ms { margin: 0; background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, Roboto, sans-serif; min-height: 100vh; }
  .ms *, .ms *::before, .ms *::after { box-sizing: border-box; }
  .ms a { text-decoration: none; }

  /* ---------- Header ---------- */
  .ms-header { background: var(--header-bg); color: #fff; height: 84px; padding: 0 26px; display: flex; align-items: center; justify-content: space-between; gap: 14px; box-shadow: 0 4px 14px rgba(0, 0, 0, 0.12); position: relative; z-index: 30; }
  .ms-brand { display: flex; align-items: center; gap: 14px; min-width: 0; }
  .ms-burger { display: none; background: rgba(255, 255, 255, 0.15); color: #fff; border: 0; width: 40px; height: 40px; border-radius: 10px; font-size: 17px; cursor: pointer; padding: 0; }
  .ms-burger:hover { background: rgba(255, 255, 255, 0.25); }
  .ms-logo { font-size: 38px; line-height: 1; }
  .ms-brand h1 { margin: 0; color: #fff; font-size: 24px; font-weight: 800; letter-spacing: 0.6px; white-space: nowrap; }
  .ms-brand p { margin: 3px 0 0; font-size: 13px; color: #fff; opacity: 0.92; }
  .ms-hright { display: flex; align-items: center; gap: 12px; }
  .ms-clock { display: flex; align-items: center; gap: 10px; border: 1px solid rgba(255, 255, 255, 0.3); border-radius: 26px; padding: 7px 18px; background: rgba(255, 255, 255, 0.06); }
  .ms-clock i { font-size: 20px; }
  .ms-clock b { display: block; font-size: 14px; font-weight: 700; line-height: 1.2; }
  .ms-clock span { display: block; font-size: 12px; opacity: 0.85; line-height: 1.2; }
  .ms-theme { display: flex; align-items: center; gap: 8px; background: #1d5bc4; border-radius: 26px; padding: 0 14px; height: 44px; }
  [data-theme="dark"] .ms-theme { background: #26357a; }
  [data-theme="emerald"] .ms-theme { background: #0a7a58; }
  .ms-theme i { color: #ffc83d; font-size: 18px; }
  .ms-theme select { appearance: none; -webkit-appearance: none; background: transparent; border: 0; outline: none; color: #fff; font-weight: 700; font-size: 13.5px; padding: 0 22px 0 0; cursor: pointer; font-family: inherit; background-image: url("data:image/svg+xml;utf8,<svg xmlns='http://www.w3.org/2000/svg' width='12' height='8' viewBox='0 0 12 8'><path d='M1 1l5 5 5-5' fill='none' stroke='white' stroke-width='2' stroke-linecap='round'/></svg>"); background-repeat: no-repeat; background-position: right center; }
  .ms-theme select option { background: #111c44; color: #fff; }
  .ms-user { position: relative; }
  .ms-user-btn { display: flex; align-items: center; gap: 9px; background: transparent; border: 0; color: #fff; cursor: pointer; font-family: inherit; font-size: 14px; font-weight: 700; padding: 4px 6px; border-radius: 26px; }
  .ms-user-btn:hover { background: rgba(255, 255, 255, 0.12); }
  .ms-avatar { width: 38px; height: 38px; border-radius: 50%; background: #fff; color: #1d5bc4; display: grid; place-items: center; font-size: 20px; }
  .ms-user-menu { display: none; position: absolute; right: 0; top: 52px; min-width: 210px; background: var(--card); color: var(--text); border: 1px solid var(--border); border-radius: 12px; box-shadow: var(--shadow); overflow: hidden; z-index: 60; }
  .ms-user-menu.open { display: block; }
  .ms-user-menu .ms-um-head { padding: 12px 16px; border-bottom: 1px solid var(--border); }
  .ms-user-menu .ms-um-head b { display: block; font-size: 14px; }
  .ms-user-menu .ms-um-head span { font-size: 12px; color: var(--muted); }
  .ms-user-menu a { display: flex; align-items: center; gap: 10px; padding: 11px 16px; color: var(--text); font-size: 13.5px; font-weight: 600; }
  .ms-user-menu a:hover { background: var(--primary-soft); }
  .ms-user-menu a i { width: 16px; color: var(--primary); }
  .ms-logout { background: #ef4444; color: #fff; border: 0; border-radius: 10px; padding: 0 20px; height: 44px; font-weight: 700; font-size: 14px; display: inline-flex; align-items: center; gap: 8px; cursor: pointer; font-family: inherit; }
  .ms-logout:hover { background: #dc2626; color: #fff; }

  /* ---------- Layout ---------- */
  .ms-layout { display: grid; grid-template-columns: 260px minmax(0, 1fr); min-height: calc(100vh - 84px); }
  .ms-sidebar { background: var(--sidebar-bg); border-right: 1px solid var(--border); padding: 18px 14px 20px; display: flex; flex-direction: column; position: sticky; top: 0; height: calc(100vh - 84px); overflow-y: auto; }
  .ms-nav { display: flex; flex-direction: column; gap: 6px; }
  .ms-nav a { display: flex; align-items: center; gap: 16px; padding: 13px 16px; border-radius: 12px; color: var(--text); font-size: 15px; font-weight: 600; transition: background 0.15s, transform 0.15s; }
  .ms-nav a i { width: 24px; text-align: center; font-size: 19px; color: var(--primary); opacity: 0.8; }
  .ms-nav a:hover { background: var(--primary-soft); }
  .ms-nav a.active { background: var(--primary-soft); font-weight: 700; }
  .ms-nav a.active i { opacity: 1; }
  .ms-side-foot { margin-top: auto; text-align: center; padding: 30px 8px 6px; color: var(--muted); }
  .ms-side-foot i { font-size: 38px; color: #38a3e8; display: block; margin-bottom: 8px; }
  .ms-side-foot p { margin: 0; font-family: 'Segoe Script', 'Brush Script MT', cursive; font-style: italic; font-size: 15px; line-height: 1.5; }
  .ms-scrim { display: none; }

  .ms-main { padding: 22px 28px 30px; min-width: 0; }
  .ms-welcome { display: flex; align-items: center; justify-content: space-between; gap: 14px; margin-bottom: 18px; }
  .ms-welcome-l { display: flex; align-items: center; gap: 14px; }
  .ms-wave { font-size: 40px; line-height: 1; }
  .ms-welcome h2 { margin: 0; font-size: 24px; font-weight: 800; color: var(--text); }
  .ms-welcome p { margin: 3px 0 0; color: var(--muted); font-size: 14px; }
  .ms-datechip { background: var(--card); border: 1px solid var(--border); box-shadow: var(--shadow); border-radius: 12px; padding: 11px 18px; font-weight: 700; font-size: 13.5px; display: inline-flex; align-items: center; gap: 10px; white-space: nowrap; }
  .ms-datechip i { color: var(--primary); }

  .ms-grid { display: grid; grid-template-columns: minmax(0, 1fr) 400px; gap: 20px; align-items: start; }
  .ms-col { display: flex; flex-direction: column; gap: 20px; min-width: 0; }

  .ms-panel { background: var(--card); border: 1px solid var(--border); border-radius: 16px; box-shadow: var(--shadow); padding: 20px 22px; }
  .ms-panel-head { display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 14px; }
  .ms-panel-title { display: flex; align-items: center; gap: 12px; min-width: 0; }
  .ms-panel-title > i { font-size: 26px; color: var(--primary); }
  .ms-panel-title h3 { margin: 0; font-size: 17px; font-weight: 800; color: var(--text); }
  .ms-panel-title p { margin: 2px 0 0; font-size: 12.5px; color: var(--muted); }
  .ms-viewall { background: var(--primary-soft); color: var(--primary); font-size: 12.5px; font-weight: 700; border-radius: 20px; padding: 8px 16px; display: inline-flex; align-items: center; gap: 8px; white-space: nowrap; }
  .ms-viewall:hover { filter: brightness(0.96); }

  /* ---------- Stat cards ---------- */
  .ms-stats { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 18px; }
  .ms-stat { border: 1px solid var(--border); border-radius: 16px; box-shadow: var(--shadow); padding: 20px; display: flex; gap: 16px; align-items: flex-start; }
  .ms-stat.blue { background: var(--tint-blue); }
  .ms-stat.green { background: var(--tint-green); }
  .ms-stat.purple { background: var(--tint-purple); }
  .ms-stat-ico { width: 56px; height: 56px; flex: 0 0 56px; border-radius: 50%; display: grid; place-items: center; color: #fff; font-size: 23px; }
  .blue .ms-stat-ico { background: linear-gradient(135deg, #3b82f6, #2563eb); }
  .green .ms-stat-ico { background: linear-gradient(135deg, #22c55e, #15803d); }
  .purple .ms-stat-ico { background: linear-gradient(135deg, #a855f7, #7c3aed); }
  .ms-stat h4 { margin: 0; font-size: 15px; font-weight: 800; }
  .blue h4 { color: #1d4ed8; } .green h4 { color: #15803d; } .purple h4 { color: #7c3aed; }
  [data-theme="dark"] .blue h4 { color: #7fb1ff; } [data-theme="dark"] .green h4 { color: #6ee7a0; } [data-theme="dark"] .purple h4 { color: #c4a1ff; }
  .ms-stat .ms-num { font-size: 34px; font-weight: 800; line-height: 1.15; margin: 4px 0 6px; color: var(--text); }
  .ms-stat-sub { display: flex; align-items: center; gap: 8px; font-size: 11.5px; color: var(--muted); }
  .ms-trend { font-weight: 800; font-size: 12.5px; display: inline-flex; align-items: center; gap: 4px; }
  .ms-trend.up { color: var(--green); } .ms-trend.down { color: var(--red); } .ms-trend.flat { color: var(--muted); }
  .ms-trend-badge { background: rgba(22, 163, 74, 0.1); border-radius: 6px; padding: 3px 8px; font-size: 11px; }

  /* ---------- Chart ---------- */
  .ms-chart-wrap { display: grid; grid-template-columns: minmax(0, 1fr) 270px; gap: 18px; align-items: stretch; }
  #msChart { width: 100%; min-height: 210px; }
  #msChart svg { display: block; width: 100%; height: auto; overflow: visible; }
  .ms-axis { fill: var(--muted); font-size: 11px; }
  .ms-grid-line { stroke: var(--border); stroke-width: 1; stroke-dasharray: 3 4; }
  .ms-line { fill: none; stroke: var(--chart-line); stroke-width: 2.2; stroke-linecap: round; }
  .ms-dot { fill: var(--chart-line); stroke: var(--card); stroke-width: 2; cursor: pointer; }
  .ms-minis { display: flex; flex-direction: column; gap: 10px; }
  .ms-mini { flex: 1; border: 1px solid var(--border); border-radius: 12px; padding: 10px 14px; display: flex; align-items: center; gap: 12px; background: var(--card); }
  .ms-mini > i { font-size: 22px; color: var(--primary); width: 30px; text-align: center; }
  .ms-mini small { display: block; color: var(--muted); font-size: 12px; }
  .ms-mini b { font-size: 21px; font-weight: 800; }
  .ms-mini .ms-trend { margin-left: auto; background: rgba(22, 163, 74, 0.08); border-radius: 6px; padding: 3px 8px; font-size: 11px; }
  .ms-mini .ms-trend.down { background: rgba(220, 38, 38, 0.08); }
  .ms-mini .ms-trend.flat { background: rgba(107, 122, 153, 0.1); }

  /* ---------- Table ---------- */
  .ms-table-scroll { overflow-x: auto; }
  .ms-table { width: 100%; border-collapse: collapse; font-size: 13.5px; }
  .ms-table th { background: var(--table-head); color: #fff; text-align: left; padding: 9px 12px; font-weight: 700; font-size: 13px; }
  .ms-table td { padding: 8px 12px; border-bottom: 1px solid var(--border); color: var(--text); }
  .ms-table tbody tr:hover { background: var(--row-hover); }
  .ms-table .c { text-align: center; }
  .ms-table .mut { color: var(--muted); }
  .ms-table .strong { font-weight: 700; }
  .ms-view { background: var(--primary-soft); color: var(--primary); font-weight: 700; font-size: 12px; border-radius: 16px; padding: 5px 14px; display: inline-flex; align-items: center; gap: 6px; }
  .ms-view:hover { background: var(--primary); color: #fff; }

  /* ---------- Status card ---------- */
  .ms-status { display: flex; align-items: flex-start; gap: 16px; position: relative; overflow: hidden; }
  .ms-status-ico { width: 58px; height: 58px; flex: 0 0 58px; border-radius: 50%; display: grid; place-items: center; font-size: 28px; color: #fff; background: linear-gradient(135deg, #22c55e, #16a34a); }
  .ms-status-ico.info { background: linear-gradient(135deg, #3b82f6, #2563eb); }
  .ms-status-ico.warn { background: linear-gradient(135deg, #f59e0b, #d97706); }
  .ms-status h4 { margin: 0; font-size: 15px; font-weight: 800; }
  .ms-status .ms-sval { font-size: 28px; font-weight: 800; color: var(--green); line-height: 1.2; }
  .ms-status .ms-sval.info { color: var(--primary); }
  .ms-status .ms-sval.warn { color: #d97706; }
  .ms-status p { margin: 2px 0 0; color: var(--muted); font-size: 13px; }
  .ms-arrows { margin-left: auto; display: flex; gap: 8px; }
  .ms-arrow { width: 32px; height: 32px; border-radius: 50%; border: 1px solid var(--border); background: var(--card); color: var(--text); cursor: pointer; display: grid; place-items: center; font-size: 12px; padding: 0; }
  .ms-arrow:hover { background: var(--primary-soft); }
  .ms-shield { position: absolute; right: 18px; bottom: 8px; font-size: 46px; color: var(--green); opacity: 0.12; }

  /* ---------- Calendar ---------- */
  .ms-cal-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 14px; }
  .ms-cal-head .t { display: flex; align-items: center; gap: 12px; font-weight: 800; font-size: 16px; }
  .ms-cal-head .t i { color: var(--primary); font-size: 20px; }
  .ms-cal-week, .ms-cal-days { display: grid; grid-template-columns: repeat(7, 1fr); text-align: center; }
  .ms-cal-week { font-size: 12px; font-weight: 700; color: var(--muted); margin-bottom: 8px; }
  .ms-cal-days { gap: 6px 4px; }
  .ms-cal-day { height: 34px; width: 34px; margin: 0 auto; border-radius: 50%; display: grid; place-items: center; font-size: 12.5px; font-weight: 600; background: var(--primary-soft); color: var(--text); }
  .ms-cal-day.out { opacity: 0.4; background: transparent; }
  .ms-cal-day.today { background: var(--primary); color: #fff; font-weight: 800; box-shadow: 0 4px 10px rgba(13, 71, 161, 0.35); }
  [data-theme="dark"] .ms-cal-day.today { color: #0b1437; }

  /* ---------- Quick actions ---------- */
  .ms-qa-title { display: flex; align-items: center; gap: 10px; font-weight: 800; font-size: 15px; margin-bottom: 12px; }
  .ms-qa-title i { color: #3b82f6; }
  .ms-qa-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; }
  .ms-qa { display: flex; align-items: center; gap: 10px; padding: 12px 12px; border-radius: 12px; color: var(--text); font-size: 12px; font-weight: 700; transition: transform 0.15s, box-shadow 0.15s; }
  .ms-qa:hover { transform: translateY(-2px); box-shadow: var(--shadow); }
  .ms-qa i.ic { font-size: 24px; }
  .ms-qa i.ar { margin-left: auto; font-size: 11px; opacity: 0.7; }
  .ms-qa.blue { background: var(--qa-blue); } .ms-qa.blue i.ic { color: #2563eb; }
  .ms-qa.green { background: var(--qa-green); } .ms-qa.green i.ic { color: #16a34a; }
  .ms-qa.purple { background: var(--qa-purple); } .ms-qa.purple i.ic { color: #7c3aed; }
  .ms-qa.orange { background: var(--qa-orange); } .ms-qa.orange i.ic { color: #f97316; }
  .ms-help { background: var(--help-bg); color: #fff; border-radius: 14px; padding: 16px 18px; display: flex; align-items: center; gap: 14px; }
  .ms-help > i { font-size: 34px; }
  .ms-help b { display: block; font-size: 14.5px; }
  .ms-help span { font-size: 12px; opacity: 0.85; }
  .ms-support { margin-left: auto; background: rgba(255, 255, 255, 0.18); border: 0; color: #fff; font-weight: 700; font-size: 12.5px; border-radius: 10px; padding: 9px 16px; cursor: pointer; font-family: inherit; display: inline-flex; align-items: center; gap: 8px; }
  .ms-support:hover { background: rgba(255, 255, 255, 0.28); }

  /* ---------- Modal ---------- */
  .ms-modal { display: none; position: fixed; inset: 0; background: rgba(8, 20, 60, 0.55); z-index: 90; align-items: center; justify-content: center; padding: 20px; }
  .ms-modal.open { display: flex; }
  .ms-modal-box { background: var(--card); color: var(--text); border-radius: 16px; padding: 26px; max-width: 380px; width: 100%; text-align: center; box-shadow: 0 20px 50px rgba(0, 0, 0, 0.3); }
  .ms-modal-box i { font-size: 36px; color: var(--primary); }
  .ms-modal-box h3 { margin: 10px 0 6px; color: var(--text); }
  .ms-modal-box p { margin: 0 0 18px; color: var(--muted); font-size: 14px; }
  .ms-modal-box button { background: var(--primary); color: #fff; border: 0; border-radius: 10px; padding: 10px 26px; font-weight: 700; cursor: pointer; font-family: inherit; }

  /* ---------- Responsive ---------- */
  @media (max-width: 1280px) {
    .ms-grid { grid-template-columns: minmax(0, 1fr); }
    .ms-chart-wrap { grid-template-columns: minmax(0, 1fr) 250px; }
  }
  @media (max-width: 992px) {
    .ms-burger { display: inline-block; }
    .ms-layout { grid-template-columns: minmax(0, 1fr); }
    .ms-sidebar { position: fixed; top: 84px; left: 0; width: 270px; height: calc(100vh - 84px); z-index: 50; transform: translateX(-102%); transition: transform 0.25s; box-shadow: 8px 0 30px rgba(0, 0, 0, 0.2); }
    .ms-sidebar.open { transform: translateX(0); }
    .ms-scrim.open { display: block; position: fixed; inset: 84px 0 0 0; background: rgba(8, 20, 60, 0.4); z-index: 40; }
    .ms-clock, .ms-brand p { display: none; }
    .ms-stats { grid-template-columns: minmax(0, 1fr); }
    .ms-chart-wrap { grid-template-columns: minmax(0, 1fr); }
    .ms-minis { flex-direction: row; flex-wrap: wrap; }
    .ms-mini { min-width: 200px; }
  }
  @media (max-width: 640px) {
    .ms-header { padding: 0 12px; }
    .ms-brand h1 { font-size: 15px; white-space: normal; line-height: 1.15; }
    .ms-logo { display: none; }
    .ms-theme { display: none; }
    .ms-user-btn .nm { display: none; }
    .ms-main { padding: 16px 12px 24px; }
    .ms-welcome { flex-direction: column; align-items: flex-start; }
    .ms-qa-grid { grid-template-columns: 1fr; }
    .ms-help { flex-wrap: wrap; }
  }
</style>__SHELL_HEAD_EXTRA__</head>
<body class="ms">

__SHELL_HEADER__

<div class="ms-layout">
  __SHELL_SIDEBAR__

  <main class="ms-main">
    <div class="ms-welcome">
      <div class="ms-welcome-l">
        <div class="ms-wave">&#128075;</div>
        <div>
          <h2>Welcome Back, __USERNAME__!</h2>
          <p>Here's what's happening at your laboratory today.</p>
        </div>
      </div>
      <div class="ms-datechip"><i class="fa-regular fa-calendar-days"></i> <span id="msDateChip">&nbsp;</span></div>
    </div>

    <div class="ms-grid">
      <!-- ===== LEFT COLUMN ===== -->
      <div class="ms-col">
        <div class="ms-stats">
          <div class="ms-stat blue">
            <div class="ms-stat-ico"><i class="fa-solid fa-user-group"></i></div>
            <div>
              <h4>Total Patients</h4>
              <div class="ms-num">__TOTAL_PATIENTS__</div>
              <div class="ms-stat-sub">__PATIENT_TREND__ <span>vs last month</span></div>
            </div>
          </div>
          <div class="ms-stat green">
            <div class="ms-stat-ico"><i class="fa-solid fa-print"></i></div>
            <div>
              <h4>Completed Reports</h4>
              <div class="ms-num">__COMPLETED__</div>
              <div class="ms-stat-sub"><span>__COMPLETED_SUB__</span></div>
            </div>
          </div>
          <div class="ms-stat purple">
            <div class="ms-stat-ico"><i class="fa-solid fa-vial"></i></div>
            <div>
              <h4>Available Tests</h4>
              <div class="ms-num">__TESTS__</div>
              <div class="ms-stat-sub"><span>__TESTS_SUB__</span></div>
            </div>
          </div>
        </div>

        <section class="ms-panel">
          <div class="ms-panel-head">
            <div class="ms-panel-title">
              <i class="fa-solid fa-chart-column"></i>
              <div>
                <h3>Patient Registrations Overview</h3>
                <p>Recent patient registrations in the system</p>
              </div>
            </div>
            <a href="/patients-dashboard" class="ms-viewall">View All <i class="fa-solid fa-chevron-right" style="font-size: 10px;"></i></a>
          </div>
          <div class="ms-chart-wrap">
            <div id="msChart"></div>
            <div class="ms-minis">
              <div class="ms-mini"><i class="fa-solid fa-user-group"></i><div><small>Today's Registrations</small><b>__TODAY_COUNT__</b></div>__TODAY_TREND__</div>
              <div class="ms-mini"><i class="fa-regular fa-calendar-check"></i><div><small>This Week</small><b>__WEEK_COUNT__</b></div>__WEEK_TREND__</div>
              <div class="ms-mini"><i class="fa-regular fa-calendar"></i><div><small>This Month</small><b>__MONTH_COUNT__</b></div>__MONTH_TREND__</div>
            </div>
          </div>
        </section>

        <section class="ms-panel">
          <div class="ms-panel-head">
            <div class="ms-panel-title">
              <i class="fa-solid fa-user-gear"></i>
              <h3>Recent Patient Registrations</h3>
            </div>
            <a href="/patients-dashboard" class="ms-viewall">View All <i class="fa-solid fa-chevron-right" style="font-size: 10px;"></i></a>
          </div>
          <div class="ms-table-scroll">
            <table class="ms-table">
              <thead>
                <tr><th>Ref</th><th>Name</th><th>Phone</th><th>Doctor</th><th class="c">Action</th></tr>
              </thead>
              <tbody>
                __RECENT_ROWS__
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <!-- ===== RIGHT COLUMN ===== -->
      <div class="ms-col">
        <section class="ms-panel ms-status" id="msStatus">
          <div class="ms-status-ico" id="msStatusIco"><i class="fa-solid fa-check"></i></div>
          <div>
            <h4 id="msStatusLabel">Status</h4>
            <div class="ms-sval" id="msStatusVal">Active</div>
            <p id="msStatusSub">System is running smoothly</p>
          </div>
          <div class="ms-arrows">
            <button class="ms-arrow" id="msStPrev" type="button" aria-label="Previous"><i class="fa-solid fa-chevron-left"></i></button>
            <button class="ms-arrow" id="msStNext" type="button" aria-label="Next"><i class="fa-solid fa-chevron-right"></i></button>
          </div>
          <i class="fa-solid fa-shield-halved ms-shield"></i>
        </section>

        <section class="ms-panel">
          <div class="ms-cal-head">
            <div class="t"><i class="fa-regular fa-calendar-days"></i> <span id="msCalTitle">Month Year</span></div>
            <div class="ms-arrows">
              <button class="ms-arrow" id="msCalPrev" type="button" aria-label="Previous month"><i class="fa-solid fa-chevron-left"></i></button>
              <button class="ms-arrow" id="msCalNext" type="button" aria-label="Next month"><i class="fa-solid fa-chevron-right"></i></button>
            </div>
          </div>
          <div class="ms-cal-week"><div>Su</div><div>Mo</div><div>Tu</div><div>We</div><div>Th</div><div>Fr</div><div>Sa</div></div>
          <div class="ms-cal-days" id="msCalDays"></div>
        </section>

        <section class="ms-panel">
          <div class="ms-qa-title"><i class="fa-solid fa-bolt"></i> Quick Actions</div>
          <div class="ms-qa-grid">__QUICK_ACTIONS__</div>
        </section>

        <div class="ms-help">
          <i class="fa-solid fa-flask-vial"></i>
          <div><b>Need Help?</b><span>Contact your system administrator</span></div>
          <button class="ms-support" id="msSupportBtn" type="button"><i class="fa-solid fa-headset"></i> Support</button>
        </div>
      </div>
    </div>
  </main>
</div>

<div class="ms-modal" id="msModal">
  <div class="ms-modal-box">
    <i class="fa-solid fa-headset"></i>
    <h3>Need Help?</h3>
    <p>Please contact your system administrator for support with the laboratory system.</p>
    <button type="button" id="msModalClose">Close</button>
  </div>
</div>

<script>
  var CHART_DATA = __CHART_JSON__;
  var STATUS_SLIDES = __STATUS_JSON__;

  /* ---------- Clock + date ---------- */
  var DAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
  var MONTHS = ['January', 'February', 'March', 'April', 'May', 'June', 'July', 'August', 'September', 'October', 'November', 'December'];
  function two(n) { return String(n).padStart(2, '0'); }
  function tick() {
    var d = new Date();
    var h = d.getHours(), ap = h >= 12 ? 'PM' : 'AM';
    h = h % 12 || 12;
    document.getElementById('msClock').textContent = two(h) + ':' + two(d.getMinutes()) + ':' + two(d.getSeconds()) + ' ' + ap;
    var short = MONTHS[d.getMonth()].slice(0, 3);
    document.getElementById('msClockDate').textContent = short + ' ' + d.getDate() + ', ' + d.getFullYear();
    document.getElementById('msDateChip').textContent = DAYS[d.getDay()] + ', ' + d.getDate() + ' ' + short + ' ' + d.getFullYear();
  }
  tick(); setInterval(tick, 1000);

  /* ---------- Theme ---------- */
  function changeTheme(t) {
    if (t === 'light') { document.documentElement.removeAttribute('data-theme'); }
    else { document.documentElement.setAttribute('data-theme', t); }
    try { localStorage.setItem('lab_theme', t); } catch (e) {}
  }
  (function () {
    var sel = document.getElementById('themeSwitcher');
    var t = 'light';
    try { t = localStorage.getItem('lab_theme') || 'light'; } catch (e) {}
    sel.value = t;
  })();

  /* ---------- User menu / sidebar / modal ---------- */
  var userBtn = document.getElementById('msUserBtn'), userMenu = document.getElementById('msUserMenu');
  userBtn.addEventListener('click', function (e) { e.stopPropagation(); userMenu.classList.toggle('open'); });
  document.addEventListener('click', function (e) { if (!document.getElementById('msUser').contains(e.target)) userMenu.classList.remove('open'); });
  var side = document.getElementById('msSidebar'), scrim = document.getElementById('msScrim');
  function toggleSide(open) { side.classList.toggle('open', open); scrim.classList.toggle('open', open); }
  document.getElementById('msBurger').addEventListener('click', function () { toggleSide(!side.classList.contains('open')); });
  scrim.addEventListener('click', function () { toggleSide(false); });
  var modal = document.getElementById('msModal');
  document.getElementById('msSupportBtn').addEventListener('click', function () { modal.classList.add('open'); });
  document.getElementById('msModalClose').addEventListener('click', function () { modal.classList.remove('open'); });
  modal.addEventListener('click', function (e) { if (e.target === modal) modal.classList.remove('open'); });

  /* ---------- Status card slider ---------- */
  var stIdx = 0;
  function showStatus() {
    var s = STATUS_SLIDES[stIdx];
    document.getElementById('msStatusLabel').textContent = s.label;
    var v = document.getElementById('msStatusVal');
    v.textContent = s.value; v.className = 'ms-sval ' + s.tone;
    document.getElementById('msStatusSub').textContent = s.sub;
    var ico = document.getElementById('msStatusIco');
    ico.className = 'ms-status-ico ' + s.tone;
    ico.innerHTML = '<i class="fa-solid ' + s.icon + '"></i>';
  }
  document.getElementById('msStPrev').addEventListener('click', function () { stIdx = (stIdx - 1 + STATUS_SLIDES.length) % STATUS_SLIDES.length; showStatus(); });
  document.getElementById('msStNext').addEventListener('click', function () { stIdx = (stIdx + 1) % STATUS_SLIDES.length; showStatus(); });
  showStatus();

  /* ---------- Calendar ---------- */
  var calNow = new Date(), calY = calNow.getFullYear(), calM = calNow.getMonth();
  function renderCal() {
    document.getElementById('msCalTitle').textContent = MONTHS[calM] + ' ' + calY;
    var first = new Date(calY, calM, 1).getDay();
    var start = new Date(calY, calM, 1 - first);
    var html = '';
    var today = new Date();
    for (var i = 0; i < 42; i++) {
      var d = new Date(start.getFullYear(), start.getMonth(), start.getDate() + i);
      var cls = 'ms-cal-day';
      if (d.getMonth() !== calM) cls += ' out';
      if (d.getFullYear() === today.getFullYear() && d.getMonth() === today.getMonth() && d.getDate() === today.getDate()) cls += ' today';
      html += '<div><div class="' + cls + '">' + d.getDate() + '</div></div>';
    }
    document.getElementById('msCalDays').innerHTML = html;
  }
  document.getElementById('msCalPrev').addEventListener('click', function () { calM--; if (calM < 0) { calM = 11; calY--; } renderCal(); });
  document.getElementById('msCalNext').addEventListener('click', function () { calM++; if (calM > 11) { calM = 0; calY++; } renderCal(); });
  renderCal();

  /* ---------- Registrations chart (inline SVG, no library) ---------- */
  function renderChart() {
    var box = document.getElementById('msChart');
    var data = CHART_DATA;
    if (!box || !data.length) return;
    var W = Math.max(box.clientWidth, 320), H = 220, pl = 34, pr = 16, pt = 14, pb = 30;
    var max = 0;
    data.forEach(function (d) { if (d.value > max) max = d.value; });
    var rough = Math.max(max, 1) / 4;
    var mag = Math.pow(10, Math.floor(Math.log(rough) / Math.LN10));
    var norm = rough / mag;
    var step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10) * mag;
    var top = Math.max(step * Math.ceil(max / step), step);
    var n = data.length;
    var pts = data.map(function (d, i) {
      return { x: pl + (n === 1 ? 0 : i * (W - pl - pr) / (n - 1)), y: pt + (H - pt - pb) * (1 - d.value / top), d: d };
    });
    var svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Patient registrations, last 7 days">';
    svg += '<defs><linearGradient id="msArea" x1="0" y1="0" x2="0" y2="1"><stop offset="0%" style="stop-color:var(--chart-line);stop-opacity:0.28"/><stop offset="100%" style="stop-color:var(--chart-line);stop-opacity:0.02"/></linearGradient></defs>';
    for (var v = 0; v <= top + 0.0001; v += step) {
      var y = pt + (H - pt - pb) * (1 - v / top);
      svg += '<line class="ms-grid-line" x1="' + pl + '" x2="' + (W - pr) + '" y1="' + y + '" y2="' + y + '"/>';
      svg += '<text class="ms-axis" x="' + (pl - 8) + '" y="' + (y + 4) + '" text-anchor="end">' + v + '</text>';
    }
    var path = 'M' + pts[0].x + ' ' + pts[0].y;
    for (var i = 0; i < pts.length - 1; i++) {
      var p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
      var c1x = p1.x + (p2.x - p0.x) / 6, c1y = p1.y + (p2.y - p0.y) / 6;
      var c2x = p2.x - (p3.x - p1.x) / 6, c2y = p2.y - (p3.y - p1.y) / 6;
      c1y = Math.min(Math.max(c1y, pt), H - pb); c2y = Math.min(Math.max(c2y, pt), H - pb);
      path += ' C' + c1x + ' ' + c1y + ',' + c2x + ' ' + c2y + ',' + p2.x + ' ' + p2.y;
    }
    var baseY = H - pb;
    svg += '<path d="' + path + ' L' + pts[pts.length - 1].x + ' ' + baseY + ' L' + pts[0].x + ' ' + baseY + ' Z" fill="url(#msArea)"/>';
    svg += '<path class="ms-line" d="' + path + '"/>';
    pts.forEach(function (p) {
      svg += '<circle class="ms-dot" cx="' + p.x + '" cy="' + p.y + '" r="4"><title>' + p.d.label + ': ' + p.d.value + ' patient' + (p.d.value === 1 ? '' : 's') + '</title></circle>';
      svg += '<text class="ms-axis" x="' + p.x + '" y="' + (H - 8) + '" text-anchor="middle">' + p.d.label + '</text>';
    });
    svg += '</svg>';
    box.innerHTML = svg;
  }
  renderChart();
  var rzT; window.addEventListener('resize', function () { clearTimeout(rzT); rzT = setTimeout(renderChart, 120); });
</script>
__SHELL_EXTRA_JS__
</body>
</html>
"""


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request):
    import json as _json
    from datetime import timedelta

    user = getattr(request.state, "user", None) or get_current_user(request)
    raw_name = (user.get("username") or "").strip() or "User"
    display_name = raw_name[:1].upper() + raw_name[1:]
    role_label = (user.get("role") or "").strip() or "User"

    today = now_colombo().date()

    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM patients")
    total_patients = cursor.fetchone()[0]

    try:
        cursor.execute("SELECT COUNT(DISTINCT patient_id) FROM patient_assigned_tests WHERE result IS NOT NULL AND result != ''")
        completed_reports = cursor.fetchone()[0]
    except Exception:
        completed_reports = 0

    cursor.execute("SELECT COUNT(*) FROM tests")
    total_tests = cursor.fetchone()[0]

    try:
        cursor.execute("SELECT COUNT(DISTINCT department) FROM tests WHERE department IS NOT NULL AND department != ''")
        dept_count = cursor.fetchone()[0]
    except Exception:
        dept_count = 0

    cursor.execute("SELECT id, title, name, phone, doctor FROM patients WHERE (is_cancelled IS NULL OR is_cancelled = 0) ORDER BY id DESC LIMIT 5")
    recent_patients = cursor.fetchall()

    # Registrations per day (created_at is stored as local Colombo time,
    # so the first 10 chars are the local calendar date).
    month_start = today.replace(day=1)
    prev_month_end = month_start - timedelta(days=1)
    prev_month_start = prev_month_end.replace(day=1)
    earliest = min(prev_month_start, today - timedelta(days=13))
    daily = {}
    try:
        cursor.execute(
            "SELECT substr(created_at, 1, 10), COUNT(*) FROM patients "
            "WHERE (is_cancelled IS NULL OR is_cancelled = 0) AND created_at IS NOT NULL "
            "AND substr(created_at, 1, 10) >= ? GROUP BY substr(created_at, 1, 10)",
            (earliest.isoformat(),),
        )
        for r in cursor.fetchall():
            daily[str(r[0])] = int(r[1])
    except Exception:
        daily = {}

    try:
        cursor.execute(
            "SELECT COUNT(DISTINCT patient_id) FROM patient_assigned_tests "
            "WHERE (result IS NULL OR result = '') "
            "AND patient_id IN (SELECT id FROM patients WHERE is_cancelled IS NULL OR is_cancelled = 0)"
        )
        pending_reports = cursor.fetchone()[0]
    except Exception:
        pending_reports = 0

    today_revenue = None
    if _shell_can(user, "reports", "can_view_reports"):
        try:
            cursor.execute(
                "SELECT COALESCE(SUM(COALESCE(t.price, 0)), 0) FROM patients p "
                "JOIN patient_assigned_tests pat ON pat.patient_id = p.id "
                "JOIN tests t ON t.id = pat.test_id "
                "WHERE substr(p.created_at, 1, 10) = ? AND (p.is_cancelled IS NULL OR p.is_cancelled = 0)",
                (today.isoformat(),),
            )
            today_revenue = float(cursor.fetchone()[0] or 0)
        except Exception:
            today_revenue = None

    conn.close()

    def span(a, b):
        return sum(daily.get((a + timedelta(days=i)).isoformat(), 0) for i in range((b - a).days + 1))

    today_c = daily.get(today.isoformat(), 0)
    yest_c = daily.get((today - timedelta(days=1)).isoformat(), 0)
    week_c = span(today - timedelta(days=6), today)
    prev_week_c = span(today - timedelta(days=13), today - timedelta(days=7))
    month_c = span(month_start, today)
    prev_month_c = span(prev_month_start, prev_month_end)

    chart = []
    for i in range(6, -1, -1):
        d = today - timedelta(days=i)
        chart.append({"label": f"{d.strftime('%b')} {d.day}", "value": daily.get(d.isoformat(), 0)})

    rate = int(round(completed_reports * 100.0 / total_patients)) if total_patients else 0
    status_slides = [
        {"label": "Status", "value": "Active", "sub": "System is running smoothly", "tone": "ok", "icon": "fa-check"},
        {"label": "Today", "value": str(today_c), "sub": "patients registered today", "tone": "info", "icon": "fa-user-group"},
        {"label": "Pending Reports", "value": str(pending_reports), "sub": "patients awaiting results", "tone": "warn", "icon": "fa-hourglass-half"},
    ]
    if today_revenue is not None:
        status_slides.append({"label": "Today's Revenue", "value": f"Rs. {today_revenue:,.0f}", "sub": "billed today (cancelled bills excluded)", "tone": "ok", "icon": "fa-sack-dollar"})

    recent_rows = ""
    if recent_patients:
        for p in recent_patients:
            p_id, title, name, phone, doctor = p
            p_name = html.escape(f"{title or ''} {name or ''}".strip())
            p_phone = html.escape(str(phone)) if phone else "N/A"
            p_doctor = html.escape(str(doctor)) if doctor else "&mdash;"
            recent_rows += (
                f'<tr><td class="strong">#{p_id}</td><td class="strong">{p_name}</td>'
                f'<td class="mut">{p_phone}</td><td>{p_doctor}</td>'
                f'<td class="c"><a href="/patient-results/{p_id}" class="ms-view"><i class="fa-solid fa-eye"></i> View</a></td></tr>'
            )
    else:
        recent_rows = '<tr><td colspan="5" class="c mut" style="padding: 20px;">No patients registered yet.</td></tr>'

    replacements = {
        "__USERNAME__": html.escape(display_name),
        "__SHELL_HEADER__": _shell_header_html(user),
        "__SHELL_SIDEBAR__": _shell_sidebar_html(user, "dashboard"),
        "__QUICK_ACTIONS__": _shell_quick_actions_html(user),
        "__SHELL_HEAD_EXTRA__": "<style>" + _SHELL_EXTRA_CSS + "</style>" + _SHELL_HEAD_SCRIPT,
        "__SHELL_EXTRA_JS__": "<script>" + _SHELL_EXTRA_JS + "</script>",
        "__ROLE__": html.escape(role_label),
        "__TOTAL_PATIENTS__": str(total_patients),
        "__PATIENT_TREND__": _dash_trend_html(month_c, prev_month_c),
        "__COMPLETED__": str(completed_reports),
        "__COMPLETED_SUB__": f"{rate}% of all patients",
        "__TESTS__": str(total_tests),
        "__TESTS_SUB__": f"across {dept_count} department{'s' if dept_count != 1 else ''}",
        "__RECENT_ROWS__": recent_rows,
        "__TODAY_COUNT__": str(today_c),
        "__TODAY_TREND__": _dash_trend_html(today_c, yest_c),
        "__WEEK_COUNT__": str(week_c),
        "__WEEK_TREND__": _dash_trend_html(week_c, prev_week_c),
        "__MONTH_COUNT__": str(month_c),
        "__MONTH_TREND__": _dash_trend_html(month_c, prev_month_c),
        "__CHART_JSON__": _json.dumps(chart),
        "__STATUS_JSON__": _json.dumps(status_slides),
    }
    page = _DASHBOARD_TEMPLATE
    for key, val in replacements.items():
        page = page.replace(key, val)
    return page


# -------------------------------------------------------------
# 2. MANAGE USERS ROUTE (100% Crash-Proof & Error-Free)
# -------------------------------------------------------------
@app.get("/manage-users", response_class=HTMLResponse)
def manage_users(request: Request):
    current_user = get_current_user(request)
    if not user_can_or_legacy(current_user, "can_manage_users", "manage_users"):
        return render_locked_page("Manage Users")

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Ensure table and columns exist properly
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            role TEXT
        )
    ''')
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN role TEXT")
        conn.commit()
    except Exception:
        pass
    try:
        cursor.execute("ALTER TABLE users ADD COLUMN permissions TEXT")
        conn.commit()
    except Exception:
        pass
        
    # Hide the primary super-admin account from the User Management table.
    # It keeps full access when logged in, but is invisible to (and so
    # cannot be edited or deleted by) anyone managing users here.
    cursor.execute("SELECT * FROM users WHERE username != ?", (SUPER_ADMIN_USERNAME,))
    users = cursor.fetchall()
    conn.close()

    users_rows = ""
    if users:
        for u in users:
            # Safe extraction preventing any KeyError / IndexError
            try:
                u_id = u["id"]
            except Exception:
                u_id = u[0] if len(u) > 0 else 1
            
            try:
                u_name = u["username"]
            except Exception:
                u_name = u[1] if len(u) > 1 else "Unknown"
            
            try:
                u_role = u["role"] if "role" in u.keys() and u["role"] else "MLT"
            except Exception:
                u_role = "MLT"

            try:
                u_perms_raw = u["permissions"] if "permissions" in u.keys() and u["permissions"] else ""
            except Exception:
                u_perms_raw = ""
            u_perms_set = {p for p in u_perms_raw.split(",") if p}
            if u_role.strip().lower() in FULL_ACCESS_ROLES:
                perms_display = "All (Owner)"
            elif u_perms_set:
                perms_display = ", ".join(PERMISSIONS.get(p, p) for p in u_perms_set)
            else:
                perms_display = "<span style='color:#a0aec0;'>None</span>"

            users_rows += f"""
            <tr>
                <td style="padding: 12px; font-weight: 700;">#{u_id}</td>
                <td style="padding: 12px; font-weight: 600;">{u_name}</td>
                <td style="padding: 12px;">
                    <span style="background: rgba(13, 71, 161, 0.1); color: var(--btn-color); padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; text-transform: uppercase;">
                        {u_role}
                    </span>
                </td>
                <td style="padding: 12px; font-size: 12px;">{perms_display}</td>
                <td style="padding: 12px; text-align: center; white-space: nowrap;">
                    <a href="/edit-user/{u_id}" style="color: #0d47a1; text-decoration: none; font-weight: 700; font-size: 12px; background: rgba(13, 71, 161, 0.1); padding: 6px 12px; border-radius: 6px; margin-right: 6px;">
                        <i class="fa-solid fa-pen"></i> Edit
                    </a>
                    <a href="/delete-user/{u_id}" onclick="return confirm('Are you sure you want to delete this user?');" style="color: #e53e3e; text-decoration: none; font-weight: 700; font-size: 12px; background: rgba(229, 62, 62, 0.1); padding: 6px 12px; border-radius: 6px;">
                        <i class="fa-solid fa-trash"></i> Delete
                    </a>
                </td>
            </tr>
            """
    else:
        users_rows = '<tr><td colspan="5" style="padding: 20px; text-align: center; color: var(--text-muted);">No users found. Create a new user below.</td></tr>'

    permission_checkboxes = ""
    for perm_key, perm_label in PERMISSIONS.items():
        permission_checkboxes += f"""
        <label style="display:flex; align-items:center; gap:8px; margin-bottom:8px; font-size:14px; font-weight:600;">
            <input type="checkbox" name="permissions" value="{perm_key}"> {html.escape(perm_label)}
        </label>
        """

    granular_checkboxes = ""
    for _col, (_label, _default) in GRANULAR_PERMISSIONS.items():
        _highlight = "background:#fff5f5; border:1px solid #fed7d7; padding:8px 10px; border-radius:8px;" if _col == "can_cancel_bills" else ""
        granular_checkboxes += f"""
        <label style="display:flex; align-items:center; gap:8px; margin-bottom:8px; font-size:14px; font-weight:600; {_highlight}">
            <input type="checkbox" name="{_col}" value="1" {"checked" if _default else ""}> {html.escape(_label)}
        </label>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Lab System - Manage Users</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {{
                --bg-color: #f4f7fe;
                --header-bg: #0d47a1;
                --card-bg: #ffffff;
                --text-main: #1b2559;
                --text-muted: #707eae;
                --border-color: #e2e8f0;
                --btn-color: #0d47a1;
                --shadow: 0px 8px 24px rgba(0, 0, 0, 0.05);
            }}
            * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
            body {{ background: var(--bg-color); color: var(--text-main); }}
            
            .header {{
                background: var(--header-bg);
                color: white;
                padding: 14px 28px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }}
            .header h2 {{ font-size: 20px; font-weight: 700; display: flex; align-items: center; gap: 10px; }}
            
            .back-btn {{
                background: rgba(255, 255, 255, 0.2);
                color: white;
                text-decoration: none;
                padding: 6px 14px;
                border-radius: 20px;
                font-size: 13px;
                font-weight: 600;
                transition: 0.2s;
            }}
            .back-btn:hover {{ background: rgba(255, 255, 255, 0.3); }}

            .container {{ padding: 25px; max-width: 900px; margin: auto; }}
            
            .card {{
                background: var(--card-bg);
                padding: 24px;
                border-radius: 14px;
                box-shadow: var(--shadow);
                border: 1px solid var(--border-color);
                margin-bottom: 25px;
            }}
            
            .card h3 {{ margin-bottom: 16px; font-size: 16px; font-weight: 700; color: var(--text-main); display: flex; align-items: center; gap: 8px; }}

            .form-group {{ margin-bottom: 15px; }}
            .form-group label {{ display: block; font-size: 13px; font-weight: 600; margin-bottom: 6px; }}
            .form-control {{ width: 100%; padding: 10px 14px; border: 1px solid var(--border-color); border-radius: 8px; font-size: 14px; outline: none; }}
            .form-control:focus {{ border-color: var(--btn-color); }}

            .submit-btn {{
                background: var(--btn-color);
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 8px;
                font-weight: 700;
                font-size: 14px;
                cursor: pointer;
                transition: 0.2s;
            }}
            .submit-btn:hover {{ opacity: 0.9; }}

            table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
            th {{ background: var(--header-bg); color: white; text-align: left; padding: 12px; font-weight: 600; }}
            td {{ border-bottom: 1px solid var(--border-color); }}
            tr:hover {{ background: rgba(0,0,0,0.01); }}
        </style>
    </head>
    <body>
        <div class="header">
            <h2><i class="fa-solid fa-user-gear"></i> User Management</h2>
            <a href="/dashboard" class="back-btn"><i class="fa-solid fa-arrow-left"></i> Back to Dashboard</a>
        </div>

        <div class="container">
            <!-- Add User Form -->
            <div class="card">
                <h3><i class="fa-solid fa-user-plus"></i> Add New System User</h3>
                <form action="/add-user" method="POST">
                    <div class="form-group">
                        <label>Username</label>
                        <input type="text" name="username" class="form-control" required placeholder="Enter username">
                    </div>
                    <div class="form-group">
                        <label>Password</label>
                        <input type="password" name="password" class="form-control" required placeholder="Enter password">
                    </div>
                    <div class="form-group">
                        <label>Role</label>
                        <select name="role" class="form-control">
                            <option value="Owner">Owner</option>
                            <option value="MLT" selected>MLT</option>
                            <option value="Phlebotomist">Phlebotomist</option>
                        </select>
                    </div>
                    <div class="form-group">
                        <label>Permissions (ignored if role is Owner - Owner always has full access)</label>
                        {permission_checkboxes}
                    </div>
                    <div class="form-group">
                        <label>Granular Access Controls</label>
                        {granular_checkboxes}
                    </div>
                    <button type="submit" class="submit-btn"><i class="fa-solid fa-check"></i> Create User</button>
                </form>
            </div>

            <!-- Existing Users Table -->
            <div class="card">
                <h3><i class="fa-solid fa-users"></i> Existing Users</h3>
                <table>
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Username</th>
                            <th>Role</th>
                            <th>Permissions</th>
                            <th style="text-align: center;">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users_rows}
                    </tbody>
                </table>
            </div>
        </div>
    </body>
    </html>
    """

# -------------------------------------------------------------
# 2. REPORTS & ANALYTICS PAGE
# -------------------------------------------------------------
@app.get("/reports", response_class=HTMLResponse)
def reports_page(request: Request, start_date: str = "", end_date: str = "", report_type: str = "sales"):
    current_user = get_current_user(request)
    if not user_can_or_legacy(current_user, "can_view_reports", "reports"):
        return render_locked_page("Reports & Analytics")

    conn = get_db_connection()
    cursor = conn.cursor()
    
    table_headers = ""
    table_rows = ""
    report_title = ""

    date_filter_sql = "(is_cancelled IS NULL OR is_cancelled = 0)"
    params = []
    
    if start_date and end_date:
        # Keep the cancellation exclusion even when a date range is applied -
        # previously this replaced the filter entirely, letting cancelled
        # bills leak back into date-filtered revenue/patient counts.
        date_filter_sql = "date(created_at) BETWEEN ? AND ? AND (is_cancelled IS NULL OR is_cancelled = 0)"
        params = [start_date, end_date]

    try:
        if report_type == "doctor":
            report_title = "Doctor-wise Performance Report"
            table_headers = "<th>Doctor Name</th><th style='text-align: center;'>Total Patients Referred</th>"
            
            query = f"SELECT doctor, COUNT(*) FROM patients WHERE {date_filter_sql} GROUP BY doctor"
            cursor.execute(query, params)
            results = cursor.fetchall()
            
            for r in results:
                doc_name, count = r
                table_rows += f"""
                <tr style="border-bottom: 1px solid var(--border-color);">
                    <td style="padding: 12px; font-weight: bold;">{doc_name if doc_name else 'Not Specified'}</td>
                    <td style="padding: 12px; text-align: center;">{count}</td>
                </tr>
                """
        elif report_type == "pricelist":
            report_title = "Test Price List"
            table_headers = ("<th style='width:50px;'>#</th><th>Code</th><th>Test Name</th>"
                             "<th>Department</th><th>Specimen</th>"
                             "<th style='text-align: right;'>Price (Rs.)</th>")

            cursor.execute(
                "SELECT test_code, test_name, department, specimen, COALESCE(price, 0) "
                "FROM tests ORDER BY COALESCE(department, ''), test_name"
            )
            results = cursor.fetchall()

            for i, r in enumerate(results, 1):
                t_code, t_name, t_dept, t_spec, t_price = r
                table_rows += f"""
                <tr style="border-bottom: 1px solid var(--border-color);">
                    <td style="padding: 9px 10px; color: var(--text-muted);">{i}</td>
                    <td style="padding: 9px 10px;">{html.escape(t_code or '-')}</td>
                    <td style="padding: 9px 10px; font-weight: bold;">{html.escape(t_name or '')}</td>
                    <td style="padding: 9px 10px;">{html.escape(t_dept or '-')}</td>
                    <td style="padding: 9px 10px;">{html.escape(t_spec or '-')}</td>
                    <td style="padding: 9px 10px; text-align: right; font-weight: bold;">{float(t_price or 0):,.2f}</td>
                </tr>
                """
        elif report_type == "center":
            report_title = "Center-wise Collection / Patient Report"
            table_headers = "<th>Center Name</th><th style='text-align: center;'>Total Patients</th>"
            
            query = f"SELECT center, COUNT(*) FROM patients WHERE {date_filter_sql} GROUP BY center"
            cursor.execute(query, params)
            results = cursor.fetchall()
            
            for r in results:
                center_name, count = r
                table_rows += f"""
                <tr style="border-bottom: 1px solid var(--border-color);">
                    <td style="padding: 12px; font-weight: bold;">{center_name if center_name else 'Main Lab'}</td>
                    <td style="padding: 12px; text-align: center;">{count}</td>
                </tr>
                """
        else:
            report_title = "Detailed Sales / Patient Records Report"
            table_headers = "<th>Ref ID</th><th>Patient Name</th><th>Phone</th><th>Doctor</th><th>Center</th><th style='text-align: right;'>Actions</th>"
            
            query = f"SELECT id, title, name, phone, doctor, center FROM patients WHERE {date_filter_sql} ORDER BY id DESC"
            cursor.execute(query, params)
            results = cursor.fetchall()
            
            for r in results:
                p_id, title, name, phone, doctor, center = r
                table_rows += f"""
                <tr style="border-bottom: 1px solid var(--border-color);">
                    <td style="padding: 10px;">#{p_id}</td>
                    <td style="padding: 10px; font-weight: bold;">{title} {name}</td>
                    <td style="padding: 10px;">{phone if phone else 'N/A'}</td>
                    <td style="padding: 10px;">{doctor if doctor else 'N/A'}</td>
                    <td style="padding: 10px;">{center if center else 'Main Lab'}</td>
                    <td style="padding: 10px; text-align: right;"><a href="/patient-results/{p_id}" style="color: var(--btn-color); text-decoration: none; font-weight: bold;">View Report</a></td>
                </tr>
                """
    except Exception as e:
        table_rows = f'<tr><td colspan="6" style="padding: 20px; text-align: center; color: #e74c3c;">Error loading data: {str(e)}</td></tr>'

    if not table_rows:
        table_rows = '<tr><td colspan="6" style="padding: 20px; text-align: center; color: var(--text-muted);">No records found for the selected date range.</td></tr>'

    conn.close()

    if report_type == "pricelist":
        date_line = f"As of {now_colombo().strftime('%Y-%m-%d')}"
    else:
        date_line = f"Date Range: {start_date if start_date else 'All Time'} to {end_date if end_date else 'Present'}"

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Lab System - Reports & Analytics</title>
        <style>
            :root {{
                --bg-color: #f4f7fb;
                --header-bg: #0f4c81;
                --card-bg: #ffffff;
                --text-main: #1e293b;
                --text-muted: #64748b;
                --border-color: #cbd5e1;
                --btn-color: #0f4c81;
                --btn-hover-bg: #0f4c81;
                --card-border: #0f4c81;
            }}
            [data-theme="dark"] {{
                --bg-color: #0f172a; --header-bg: #1e293b; --card-bg: #1e293b;
                --text-main: #f8fafc; --text-muted: #94a3b8; --border-color: #334155; --btn-color: #38bdf8;
            }}
            [data-theme="emerald"] {{
                --bg-color: #f0fdf4; --header-bg: #065f46; --card-bg: #ffffff;
                --text-main: #064e3b; --text-muted: #047857; --border-color: #a7f3d0; --btn-color: #065f46;
            }}
            body {{ font-family: Arial, sans-serif; background: var(--bg-color); color: var(--text-main); margin: 0; padding: 0; }}
            .header {{ background: var(--header-bg); color: white; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            .header h2 {{ margin: 0; font-size: 20px; }}
            .container {{ padding: 30px; max-width: 1200px; margin: auto; }}
            
            .filter-box {{ background: var(--card-bg); padding: 20px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); border: 1px solid var(--border-color); margin-bottom: 25px; display: flex; gap: 15px; flex-wrap: wrap; align-items: flex-end; }}
            .filter-group {{ display: flex; flex-direction: column; gap: 5px; }}
            .filter-group label {{ font-size: 12px; font-weight: bold; color: var(--text-muted); }}
            .filter-group input, .filter-group select {{ padding: 8px 12px; border: 1px solid var(--border-color); border-radius: 5px; background: var(--card-bg); color: var(--text-main); outline: none; }}
            
            .btn-primary {{ background: var(--btn-color); color: white; border: none; padding: 9px 20px; border-radius: 5px; font-weight: bold; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; }}
            .btn-secondary {{ background: #64748b; color: white; border: none; padding: 9px 20px; border-radius: 5px; font-weight: bold; cursor: pointer; text-decoration: none; }}
            
            .report-card {{ background: var(--card-bg); padding: 25px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); border: 1px solid var(--border-color); }}
            .report-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; border-bottom: 2px solid var(--border-color); padding-bottom: 12px; }}
            
            table {{ width: 100%; border-collapse: collapse; }}
            th {{ padding: 10px; font-size: 13px; color: var(--text-muted); text-align: left; border-bottom: 2px solid var(--border-color); }}
            
            @media print {{
                .no-print {{ display: none !important; }}
                body {{ background: white; color: black; }}
                .report-card {{ border: none; box-shadow: none; padding: 0; }}
            }}
        </style>
    </head>
    <body>
        <div class="header no-print">
            <div>
                <h2>MEDISTAR MEDICAL LABORATORY - REPORTS</h2>
            </div>
            <div>
                <a href="/reports/sales-analytics" class="btn-secondary" style="padding: 6px 14px; font-size: 13px; background:#27ae60; margin-right:8px;">💰 Sales & Financial Analytics</a>
                <a href="/dashboard" class="btn-secondary" style="padding: 6px 14px; font-size: 13px;">← Back to Dashboard</a>
            </div>
        </div>

        <div class="container">
            <form method="GET" action="/reports" class="filter-box no-print">
                <div class="filter-group">
                    <label>Report Type</label>
                    <select name="report_type">
                        <option value="sales" {'selected' if report_type == 'sales' else ''}>📊 Detailed Sales / Patient Report</option>
                        <option value="doctor" {'selected' if report_type == 'doctor' else ''}>👨‍⚕️ Doctor-wise Performance</option>
                        <option value="center" {'selected' if report_type == 'center' else ''}>🏥 Center-wise Report</option>
                        <option value="pricelist" {'selected' if report_type == 'pricelist' else ''}>💲 Test Price List</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Start Date</label>
                    <input type="date" name="start_date" value="{start_date}">
                </div>
                <div class="filter-group">
                    <label>End Date</label>
                    <input type="date" name="end_date" value="{end_date}">
                </div>
                <div class="filter-group">
                    <button type="submit" class="btn-primary">Generate Report</button>
                </div>
                <div class="filter-group" style="margin-left: auto;">
                    <button type="button" onclick="window.print()" class="btn-primary" style="background: #27ae60;">🖨️ Print / Save PDF</button>
                </div>
            </form>

            <div class="report-card">
                <div class="report-header">
                    <div>
                        <h3 style="margin: 0; font-size: 18px;">{report_title}</h3>
                        <p style="margin: 4px 0 0 0; font-size: 12px; color: var(--text-muted);">{date_line}</p>
                    </div>
                    <div>
                        <span style="font-size: 12px; font-weight: bold; color: var(--text-muted);">MEDISTAR MEDICAL LABORATORY</span>
                    </div>
                </div>

                <table>
                    <tr>
                        {table_headers}
                    </tr>
                    {table_rows}
                </table>
            </div>
        </div>
    </body>
    </html>
    """

# -------------------------------------------------------------
# 2. PATIENTS LIST DASHBOARD (Smart UI + Fully Fixed Backend)
# -------------------------------------------------------------

# Cached once per warm process (same pattern as _CACHED_TURSO_CONNECTION
# above). These PRAGMA/ALTER schema checks used to run on EVERY request
# to this route - each one its own network round trip to Turso - even
# though the schema they check only ever changes once, right after a
# cold start. Checking it once per process instead of once per page
# load removes 2 extra round trips from every single dashboard request.
_PATIENTS_DASHBOARD_SCHEMA_READY = False
_PATIENTS_DASHBOARD_TEST_CODE_COL = None
_PATIENTS_DASHBOARD_SCHEMA_LOCK = threading.Lock()

# How many patients are shown per page. Kept as a module constant so it
# is easy to tune (25-50 is the sweet spot: enough to be useful, small
# enough that the batch queries below stay fast).
PATIENTS_DASHBOARD_PAGE_SIZE = 25


def _ensure_patients_dashboard_schema(conn, cursor):
    """One-time (per warm process) schema check/migration for the
    patients-dashboard route. Returns the column on `tests` to display
    as the "test code" (test_code / code / short_name / name / id,
    whichever exists first)."""
    global _PATIENTS_DASHBOARD_SCHEMA_READY, _PATIENTS_DASHBOARD_TEST_CODE_COL
    if _PATIENTS_DASHBOARD_SCHEMA_READY:
        return _PATIENTS_DASHBOARD_TEST_CODE_COL

    with _PATIENTS_DASHBOARD_SCHEMA_LOCK:
        if _PATIENTS_DASHBOARD_SCHEMA_READY:
            return _PATIENTS_DASHBOARD_TEST_CODE_COL

        cursor.execute("PRAGMA table_info(patient_assigned_tests);")
        columns = [col[1] for col in cursor.fetchall()]
        if not columns:
            cursor.execute("CREATE TABLE patient_assigned_tests (patient_id INTEGER, test_id INTEGER, result TEXT)")
            conn.commit()
        elif "result" not in columns:
            cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN result TEXT;")
            conn.commit()

        cursor.execute("PRAGMA table_info(tests);")
        test_cols = [col[1] for col in cursor.fetchall()]
        test_code_col = "id"
        for col_candidate in ["test_code", "code", "short_name", "name"]:
            if col_candidate in test_cols:
                test_code_col = col_candidate
                break

        _PATIENTS_DASHBOARD_TEST_CODE_COL = test_code_col
        _PATIENTS_DASHBOARD_SCHEMA_READY = True
        return test_code_col


def _render_cancel_bills_tab(conn, cursor, search, msg):
    """Renders the dedicated 'Cancel Bills' tab: a list of ACTIVE
    (not yet cancelled) bills with a Cancel Bill action per row, plus a
    search filter by Lab/Invoice No or Patient Name. Cancelled bills are
    excluded here too - once cancelled they only appear under Sales
    Analytics -> Cancelled Invoices for audit purposes."""
    where_sql = "WHERE (p.is_cancelled IS NULL OR p.is_cancelled = 0)"
    where_params = []

    if search and search.strip():
        search_term = f"%{search.strip()}%"
        where_sql += " AND (p.name LIKE ? OR p.manual_bill_no LIKE ? OR CAST(p.id AS TEXT) LIKE ?)"
        where_params.extend([search_term, search_term, search_term])

    try:
        cursor.execute(f"""
            SELECT p.id as patient_id, p.title, p.name, p.created_at, p.manual_bill_no,
                   COALESCE(d.name, p.doctor, 'Not Specified') as doctor_name,
                   COALESCE(p.center, p.collecting_center, 'Main Branch') as center_name,
                   SUM(COALESCE(t.price, 0)) as amount
            FROM patients p
            LEFT JOIN patient_assigned_tests pat ON pat.patient_id = p.id
            LEFT JOIN tests t ON t.id = pat.test_id
            LEFT JOIN doctors d ON d.code = p.doctor
            {where_sql}
            GROUP BY p.id
            ORDER BY p.id DESC
            LIMIT 300
        """, where_params)
        rows = cursor.fetchall()
    except Exception:
        rows = []
    conn.close()

    rows_html = ""
    for r in rows:
        p_id = r["patient_id"]
        p_name = f"{(r['title'] or '').strip()} {(r['name'] or '').strip()}".strip()
        ref_no = f"Med-{p_id:04d}"
        manual_bill_no = str(r["manual_bill_no"] or "").strip()
        display_ref_no = f"{ref_no} / {manual_bill_no}" if manual_bill_no else ref_no
        date_str = str(r["created_at"] or "N/A")
        amount = r["amount"] or 0
        rows_html += f"""
        <tr style="border-bottom: 1px solid #eee; background: #fff;" onmouseover="this.style.background='#f9f9f9'" onmouseout="this.style.background='#fff'">
            <td style="padding: 12px 15px; color: #64748b; font-size: 13px;">{date_str}</td>
            <td style="padding: 12px 15px; font-weight: bold; color: #0f4c81;">{display_ref_no}</td>
            <td style="padding: 12px 15px; color: #333; font-weight: 500;">{p_name}</td>
            <td style="padding: 12px 15px; color: #475569;">{r['doctor_name']}</td>
            <td style="padding: 12px 15px; color: #475569;">{r['center_name']}</td>
            <td style="padding: 12px 15px; color: #475569; text-align:right;">{amount:,.2f}</td>
            <td style="padding: 12px 15px;">
                <form method="post" action="/invoices/{p_id}/cancel" style="margin:0;"
                      onsubmit="return confirm('Are you sure you want to cancel Bill {display_ref_no}? This will permanently remove it from active reports.');">
                    <button type="submit" style="background:#b91c1c; color:#fff; border:none; padding:7px 14px; border-radius:6px; font-size:12.5px; font-weight:700; cursor:pointer;">🚫 Cancel Bill</button>
                </form>
            </td>
        </tr>"""

    if not rows_html:
        rows_html = """<tr><td colspan="7" style="text-align:center; padding:30px; color:#666; font-size:14px;">No active bills found.</td></tr>"""

    msg_html = ""
    if msg:
        msg_html = f"""
        <div style="background:#dcfce7; border:1px solid #86efac; color:#15803d; padding:12px 18px; border-radius:8px; margin-bottom:16px; font-weight:bold; display:flex; align-items:center; gap:10px;">
            <i class="fa-solid fa-circle-check"></i> {html.escape(msg)}
        </div>
        """

    return HTMLResponse(content=f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cancel Bills - Patients Dashboard</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 30px; margin: 0; }}
            .container {{ max-width: 1250px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            h2 {{ color: #0f4c81; margin-top: 0; font-size: 22px; margin-bottom: 20px; }}
            .filter-card {{ background: #f8fafc; padding: 16px; border-radius: 8px; border: 1px solid #e2e8f0; margin-bottom: 20px; display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }}
            .filter-card input {{ padding: 9px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; outline: none; min-width: 280px; }}
            .btn-search {{ background: #0f4c81; color: white; border: none; padding: 10px 22px; font-size: 14px; border-radius: 6px; cursor: pointer; font-weight: bold; }}
            .btn-reset {{ background: #e2e8f0; color: #334155; border: none; padding: 10px 15px; font-size: 14px; border-radius: 6px; cursor: pointer; font-weight: bold; text-decoration: none; display: inline-flex; align-items: center; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; text-align: left; }}
            th {{ background: #0f4c81; color: white; padding: 12px 15px; font-size: 13px; font-weight: bold; text-transform: uppercase; }}
            .back-link {{ display: inline-block; margin-bottom: 15px; color: #0f4c81; text-decoration: none; font-weight: bold; font-size: 13px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/dashboard" class="back-link">&larr; Back to Dashboard</a>
            <h2>🚫 Cancel Bills</h2>

            <div style="display:flex; gap:8px; margin-bottom:18px;">
                <a href="/patients-dashboard" style="background:#fff; color:#0f4c81; border:1px solid #0f4c81; padding:8px 16px; border-radius:6px; text-decoration:none; font-weight:bold; font-size:13px;">📋 Active Patients</a>
                <a href="/patients-dashboard?tab=cancel_bills" style="background:#b91c1c; color:white; padding:8px 16px; border-radius:6px; text-decoration:none; font-weight:bold; font-size:13px;">🚫 Cancel Bills</a>
            </div>

            {msg_html}

            <form method="get" action="/patients-dashboard" class="filter-card">
                <input type="hidden" name="tab" value="cancel_bills">
                <input type="text" name="search" value="{search if search else ''}" placeholder="Search by Lab/Invoice No or Patient Name...">
                <button type="submit" class="btn-search">🔍 Search</button>
                <a href="/patients-dashboard?tab=cancel_bills" class="btn-reset">Reset</a>
            </form>

            <table>
                <thead>
                    <tr>
                        <th>Date / Time</th>
                        <th>Lab / Invoice No</th>
                        <th>Patient Name</th>
                        <th>Doctor</th>
                        <th>Collecting Center</th>
                        <th style="text-align:right;">Total Amount (LKR)</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>
                    {rows_html}
                </tbody>
            </table>
        </div>
    </body>
    </html>""")


@app.get("/patients-dashboard", response_class=HTMLResponse)
def patients_dashboard(
    request: Request,
    search: Optional[str] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    cancelled_bill: Optional[str] = Query(None),
    tab: str = Query("active"),
    msg: Optional[str] = Query(None),
):
    conn = get_db_connection()
    cursor = conn.cursor()

    test_code_col = _ensure_patients_dashboard_schema(conn, cursor)

    if tab == "cancel_bills":
        return _render_cancel_bills_tab(conn, cursor, search, msg)

    # Shared WHERE clause, built once and reused for both the COUNT
    # query (for pagination) and the actual page fetch, so the two
    # never drift out of sync with each other.
    # Cancelled bills must never appear in the active patient list.
    where_sql = "WHERE (is_cancelled IS NULL OR is_cancelled = 0)"
    where_params = []

    if search and search.strip():
        search_term = f"%{search.strip()}%"
        where_sql += " AND (CAST(id AS TEXT) LIKE ? OR name LIKE ?)"
        where_params.extend([search_term, search_term])

    if start_date and start_date.strip():
        where_sql += " AND DATE(created_at) >= ?"
        where_params.append(start_date.strip())

    if end_date and end_date.strip():
        where_sql += " AND DATE(created_at) <= ?"
        where_params.append(end_date.strip())

    # 1. Total matching patients (for the pager) - a single lightweight
    # COUNT(*), never the full row set.
    cursor.execute(f"SELECT COUNT(*) FROM patients {where_sql}", where_params)
    total_patients = cursor.fetchone()[0] or 0

    page_size = PATIENTS_DASHBOARD_PAGE_SIZE
    total_pages = max(1, (total_patients + page_size - 1) // page_size)
    page = min(max(1, page), total_pages)
    offset = (page - 1) * page_size

    # 2. Only the current page of patients, and only the columns the
    # table actually renders (id, title, name, created_at) - not the
    # entire patients row, and not the entire patient history.
    query = f"""
        SELECT id, title, name, created_at
        FROM patients
        {where_sql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
    """
    cursor.execute(query, where_params + [page_size, offset])
    patients = cursor.fetchall()

    patient_ids = [pat["id"] for pat in patients]

    # 3. Batch-fetch assigned test codes and verified/pending status for
    # just this page of patients, in a fixed handful of queries.
    #
    # ROOT CAUSE of the 7+ second load: the old version ran a per-patient
    # loop that fired 3 extra queries for EVERY row on the page (assigned
    # test codes, assigned-test results, parameter results) - each query
    # is a full network round trip to Turso, not a local disk read. With
    # up to 100 patients on screen that was 100 x 3 = 300+ round trips on
    # a single page load. Below, the whole page's data is fetched with
    # 3 queries total (regardless of how many patients are on the page),
    # using WHERE patient_id IN (...) plus in-memory grouping.
    tests_by_patient = {}
    verified_patient_ids = set()

    if patient_ids:
        placeholders = ",".join("?" for _ in patient_ids)

        cursor.execute(f"""
            SELECT pat.patient_id as patient_id, t.{test_code_col} as test_code
            FROM patient_assigned_tests pat
            LEFT JOIN tests t ON pat.test_id = t.id
            WHERE pat.patient_id IN ({placeholders})
        """, patient_ids)
        for row in cursor.fetchall():
            if row["test_code"]:
                tests_by_patient.setdefault(row["patient_id"], []).append(str(row["test_code"]))

        cursor.execute(f"""
            SELECT patient_id, result
            FROM patient_assigned_tests
            WHERE patient_id IN ({placeholders})
        """, patient_ids)
        for row in cursor.fetchall():
            p_id_row = row["patient_id"]
            if p_id_row in verified_patient_ids:
                continue
            res_val = str(row["result"] or "")
            clean_text = re.sub(r'<[^>]*>', '', res_val).replace('&nbsp;', '').strip()
            if clean_text and clean_text.lower() != "none" and clean_text not in ["", "<p></p>", "<p><br></p>"]:
                verified_patient_ids.add(p_id_row)

        cursor.execute(f"""
            SELECT DISTINCT patient_id
            FROM patient_parameter_results
            WHERE patient_id IN ({placeholders})
              AND result_value IS NOT NULL AND TRIM(result_value) != ''
        """, patient_ids)
        for row in cursor.fetchall():
            verified_patient_ids.add(row["patient_id"])

    table_rows_html = ""
    for pat in patients:
        p_id = pat["id"]
        ref_no = f"#{p_id}"

        title_val = pat["title"] if "title" in pat.keys() and pat["title"] else ""
        name_val = pat["name"] if "name" in pat.keys() and pat["name"] else ""
        patient_name = f"{title_val} {name_val}".strip()

        created_at_raw = pat["created_at"] if "created_at" in pat.keys() and pat["created_at"] else ""
        date_str = str(created_at_raw).split()[0] if created_at_raw else "N/A"

        test_codes_list = tests_by_patient.get(p_id, [])
        tests_display = ", ".join(test_codes_list) if test_codes_list else '<span style="color: #94a3b8; font-style: italic;">No tests</span>'

        has_any_result = p_id in verified_patient_ids
        status_badge = '<span style="background: #27ae60; color: white; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold;">✓ Verified</span>' if has_any_result else '<span style="background: #e74c3c; color: white; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold;">⏳ Pending</span>'

        table_rows_html += f"""
        <tr style="border-bottom: 1px solid #eee; background: #fff;" onmouseover="this.style.background='#f9f9f9'" onmouseout="this.style.background='#fff'">
            <td style="padding: 12px 15px; font-weight: bold; color: #0f4c81;">{ref_no}</td>
            <td style="padding: 12px 15px; color: #333; font-weight: 500;">{patient_name}</td>
            <td style="padding: 12px 15px; color: #475569; font-weight: 500;">{tests_display}</td>
            <td style="padding: 12px 15px; color: #64748b; font-size: 13px;">{date_str}</td>
            <td style="padding: 12px 15px;">
                <a href="/patient-results/{p_id}" style="text-decoration: none;">{status_badge}</a>
            </td>
        </tr>"""

    if not table_rows_html:
        table_rows_html = """
        <tr>
            <td colspan="5" style="text-align: center; padding: 30px; color: #666; font-size: 14px;">
                🔍 කිසිදු රෝගියෙකු හමු නොවී ඇත (No matching patients found).
            </td>
        </tr>
        """

    conn.close()

    # Prev/Next pagination controls, preserving the current search/date
    # filters in the querystring so paging never loses the active filter.
    def _page_url(target_page):
        qs = [f"page={target_page}"]
        if search:
            qs.append(f"search={quote(search)}")
        if start_date:
            qs.append(f"start_date={quote(start_date)}")
        if end_date:
            qs.append(f"end_date={quote(end_date)}")
        return "/patients-dashboard?" + "&".join(qs)

    prev_disabled = "pointer-events:none; opacity:0.4;" if page <= 1 else ""
    next_disabled = "pointer-events:none; opacity:0.4;" if page >= total_pages else ""
    range_start = (offset + 1) if total_patients else 0
    range_end = min(offset + page_size, total_patients)

    pagination_html = f"""
    <div style="display:flex; justify-content:space-between; align-items:center; margin-top:16px; flex-wrap:wrap; gap:10px;">
        <span style="font-size:12.5px; color:#64748b;">
            Showing {range_start}-{range_end} of {total_patients} patients &nbsp;|&nbsp; Page {page} of {total_pages}
        </span>
        <div style="display:flex; gap:8px;">
            <a href="{_page_url(page - 1)}" style="{prev_disabled} background:#e2e8f0; color:#334155; padding:8px 16px; border-radius:6px; text-decoration:none; font-weight:bold; font-size:13px;">&larr; Previous</a>
            <a href="{_page_url(page + 1)}" style="{next_disabled} background:#0f4c81; color:white; padding:8px 16px; border-radius:6px; text-decoration:none; font-weight:bold; font-size:13px;">Next &rarr;</a>
        </div>
    </div>
    """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Patients Result Management Dashboard</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 30px; margin: 0; }}
            .container {{ max-width: 1150px; margin: auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            h2 {{ color: #0f4c81; margin-top: 0; font-size: 22px; margin-bottom: 20px; }}
            .filter-card {{ background: #f8fafc; padding: 20px; border-radius: 8px; border: 1px solid #e2e8f0; margin-bottom: 20px; display: flex; gap: 15px; flex-wrap: wrap; align-items: flex-end; }}
            .filter-group {{ display: flex; flex-direction: column; flex: 1; min-width: 220px; }}
            .filter-group label {{ font-size: 13px; font-weight: bold; color: #334155; margin-bottom: 6px; }}
            .filter-group input {{ padding: 9px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; outline: none; background: white; }}
            .btn-search {{ background: #0f4c81; color: white; border: none; padding: 10px 22px; font-size: 14px; border-radius: 6px; cursor: pointer; font-weight: bold; height: 38px; }}
            .btn-reset {{ background: #e2e8f0; color: #334155; border: none; padding: 10px 15px; font-size: 14px; border-radius: 6px; cursor: pointer; font-weight: bold; height: 38px; text-decoration: none; display: inline-flex; align-items: center; justify-content: center; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 10px; text-align: left; }}
            th {{ background: #0f4c81; color: white; padding: 12px 15px; font-size: 13px; font-weight: bold; text-transform: uppercase; }}
            .back-link {{ display: inline-block; margin-bottom: 15px; color: #0f4c81; text-decoration: none; font-weight: bold; font-size: 13px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/dashboard" class="back-link">&larr; Back to Dashboard</a>
            <h2>Patients Result Management Dashboard</h2>

            <div style="display:flex; gap:8px; margin-bottom:18px;">
                <a href="/patients-dashboard" style="background:#0f4c81; color:white; padding:8px 16px; border-radius:6px; text-decoration:none; font-weight:bold; font-size:13px;">📋 Active Patients</a>
                <a href="/patients-dashboard?tab=cancel_bills" style="background:#fff; color:#b91c1c; border:1px solid #b91c1c; padding:8px 16px; border-radius:6px; text-decoration:none; font-weight:bold; font-size:13px;">🚫 Cancel Bills</a>
            </div>

            {f'''
            <div style="background:#fdecea; border:1px solid #f5c6cb; color:#c0392b; padding:12px 18px; border-radius:8px; margin-bottom:16px; font-weight:bold; display:flex; align-items:center; gap:10px;">
                <i class="fa-solid fa-circle-check"></i> Bill {html.escape(cancelled_bill)} has been cancelled and moved to Cancelled Records.
            </div>
            ''' if cancelled_bill else ''}
            
            <form method="get" action="/patients-dashboard" class="filter-card">
                <div class="filter-group" style="flex: 2;">
                    <label>Search Patient (Name, Ref No)</label>
                    <input type="text" name="search" value="{search if search else ''}" placeholder="Type name or ref no...">
                </div>
                <div class="filter-group">
                    <label>Start Date</label>
                    <input type="date" name="start_date" value="{start_date if start_date else ''}">
                </div>
                <div class="filter-group">
                    <label>End Date</label>
                    <input type="date" name="end_date" value="{end_date if end_date else ''}">
                </div>
                <div style="display: flex; gap: 8px;">
                    <button type="submit" class="btn-search">🔍 Search</button>
                    <a href="/patients-dashboard" class="btn-reset">Reset</a>
                </div>
            </form>
            
            <table>
                <thead>
                    <tr>
                        <th>Ref No</th>
                        <th>Patient Name</th>
                        <th>Assigned Tests</th>
                        <th>Date</th>
                        <th>Status / Action</th>
                    </tr>
                </thead>
                <tbody>
                    {table_rows_html}
                </tbody>
            </table>

            {pagination_html}
        </div>
    </body>
    </html>"""

# -------------------------------------------------------------
# 1. REGISTER PATIENT FORM (GET) - Dynamic Doctors & Centers Dropdowns
# -------------------------------------------------------------
@app.get("/api/lookup-patient-by-phone")
def lookup_patient_by_phone(request: Request, phone: str = ""):
    """
    Read-only lookup used by the New Patient form's phone-number auto-fill.
    Returns the most recently registered patient matching this exact phone
    number, or found=false if none exists. Never modifies any data.
    """
    current_user = get_current_user(request)
    if not user_has_access(current_user, "add_patient"):
        return {"found": False}

    phone = (phone or "").strip()
    if not phone:
        return {"found": False}

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT title, name, age_years, age_months, age_days, gender, doctor, collecting_center "
        "FROM patients WHERE phone = ? ORDER BY id DESC LIMIT 1",
        (phone,)
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return {"found": False}

    return {
        "found": True,
        "title": row[0] or "",
        "name": row[1] or "",
        "age_years": row[2] if row[2] is not None else 0,
        "age_months": row[3] if row[3] is not None else 0,
        "age_days": row[4] if row[4] is not None else 0,
        "gender": row[5] or "",
        "doctor": row[6] or "",
        "collecting_center": row[7] or "",
    }



# -------------------------------------------------------------
# DOCTOR / CENTER PICKER HELPERS (shared by register + result entry)
# -------------------------------------------------------------
# patients.doctor stores a doctor CODE when picked from the list (so
# commission reports can join to the doctors table) or plain typed text
# when a manual name is used (no commission rate, reported by name).
MANUAL_DOCTOR_VALUE = "__manual__"

def _resolve_doctor_value(select_val, manual_val):
    sel = (select_val or "").strip()
    if sel == MANUAL_DOCTOR_VALUE:
        return (manual_val or "").strip() or "None"
    return sel or "None"


def build_doctor_center_fields(cursor, current_doctor, current_center,
                               doctor_name, manual_name, center_name, input_style=""):
    """Returns (doctor_html, center_html): dropdowns pre-selected with the
    patient's current doctor / center. Doctor dropdown also has a
    'Type manually' option that reveals a free-text box."""
    cursor.execute("SELECT code, name FROM doctors ORDER BY name")
    doctors = cursor.fetchall()
    cursor.execute("SELECT center_name FROM collecting_centers ORDER BY center_name")
    centers = [c[0] for c in cursor.fetchall() if c[0]]

    cur_doc = (current_doctor or "").strip()
    codes = {str(d[0]): str(d[1]) for d in doctors}
    names_to_code = {str(d[1]).strip().lower(): str(d[0]) for d in doctors}
    manual_text = ""
    if cur_doc in codes:
        selected_val = cur_doc
    elif cur_doc.lower() in names_to_code:
        selected_val = names_to_code[cur_doc.lower()]
    elif cur_doc in ("", "None"):
        selected_val = "None"
    else:
        selected_val = MANUAL_DOCTOR_VALUE
        manual_text = cur_doc

    def _sel(v):
        return " selected" if v == selected_val else ""

    d_opts = f'<option value="None"{_sel("None")}>-- None --</option>'
    for code, name in codes.items():
        d_opts += f'<option value="{html.escape(code)}"{_sel(code)}>{html.escape(name)} ({html.escape(code)})</option>'
    d_opts += f'<option value="{MANUAL_DOCTOR_VALUE}"{_sel(MANUAL_DOCTOR_VALUE)}>&#9998; Type doctor name manually...</option>'

    show_manual = "block" if selected_val == MANUAL_DOCTOR_VALUE else "none"
    doctor_html = (
        f'<select name="{doctor_name}" style="{input_style}" '
        f'onchange="var m=this.parentNode.querySelector(\'.doctor-manual\'); '
        f'm.style.display=(this.value===\'{MANUAL_DOCTOR_VALUE}\')?\'block\':\'none\'; '
        f'if(m.style.display===\'block\') m.focus();">{d_opts}</select>'
        f'<input type="text" class="doctor-manual" name="{manual_name}" value="{html.escape(manual_text)}" '
        f'placeholder="Type doctor name" style="{input_style} display:{show_manual}; margin-top:6px;">'
    )

    cur_center = (current_center or "").strip()
    center_list = list(centers)
    if cur_center and cur_center not in center_list:
        center_list.insert(0, cur_center)
    if not center_list:
        center_list = ["Main Branch"]
    c_opts = "".join(
        f'<option value="{html.escape(c)}"{" selected" if c == cur_center else ""}>{html.escape(c)}</option>'
        for c in center_list
    )
    center_html = f'<select name="{center_name}" style="{input_style}">{c_opts}</select>'
    return doctor_html, center_html

@app.get("/add-patient", response_class=HTMLResponse)
def add_patient_page(request: Request, saved_id: int = None):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "add_patient"):
        return render_locked_page("Add Patient")

    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Fetch Tests (name වෙනුවට test_name දාලා ඇත)
    cursor.execute("SELECT id, test_name, COALESCE(price, 0) FROM tests")
    tests = cursor.fetchall()

    # 2. Fetch Doctors from Database
    cursor.execute("SELECT code, name FROM doctors ORDER BY name")
    doctors = cursor.fetchall()

    # 3. Fetch Collecting Centers from Database
    cursor.execute("SELECT center_name FROM collecting_centers ORDER BY center_name")
    centers = cursor.fetchall()

    # 4. Get Next Patient ID
    cursor.execute("SELECT seq FROM sqlite_sequence WHERE name='patients'")
    seq_row = cursor.fetchone()
    next_id = (seq_row[0] + 1) if seq_row and seq_row[0] else 1

    conn.close()

    success_banner = ""
    if saved_id:
        success_banner = f"""
        <div style="background: #d4edda; color: #155724; padding: 10px 14px; border-radius: 6px; margin-bottom: 12px; border: 1px solid #c3e6cb; font-weight: bold; font-size: 15px; text-align: center;">
            ✓ Patient Saved Successfully! Reference No: #{saved_id}
        </div>
        """

    # Generate Doctors Options dynamically
    doctor_options = '<option value="None">-- None --</option>'
    for d in doctors:
        # d[0] = code, d[1] = name
        doctor_options += f'<option value="{d[0]}">{d[1]} ({d[0]})</option>'
    doctor_options += f'<option value="{MANUAL_DOCTOR_VALUE}">&#9998; Type doctor name manually...</option>'

    # Generate Collecting Centers Options dynamically
    center_options = '<option value="">-- Select Center --</option>'
    for c in centers:
        # c[0] = center_name
        center_options += f'<option value="{c[0]}">{c[0]}</option>'
    
    if not centers:
        center_options = '<option value="Main Branch">Main Branch</option>'

    test_checkboxes = "".join([f"""
        <label class="test-item" data-name="{t[1].lower()}" data-label="{html.escape(t[1])}" style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px; font-weight: normal; cursor: pointer; font-size: 14px;">
            <input type="checkbox" name="test_ids" value="{t[0]}" style="width: 16px; height: 16px; accent-color: #0f4c81;"> <span>{t[1]}</span>
        </label>
    """ for t in tests])

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Lab System - New Patient</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 15px; }}
            .form-card {{ 
                background: white; 
                padding: 20px 25px; 
                border-radius: 10px; 
                width: 520px; 
                min-width: 380px; 
                min-height: 520px;
                max-width: 95vw; 
                margin: auto; 
                box-shadow: 0 4px 15px rgba(0,0,0,0.1); 
                resize: both; 
                overflow: auto; 
                border: 2px solid #cbd5e1;
            }}
            .form-card h2 {{ color: #0f4c81; margin-top: 0; margin-bottom: 12px; font-size: 20px; display: flex; justify-content: space-between; align-items: center; }}
            .ref-badge {{ background: #e2e8f0; color: #1e293b; padding: 5px 10px; border-radius: 6px; font-size: 15px; font-weight: bold; }}
            .form-group {{ margin-bottom: 12px; }}
            .form-group label {{ display: block; margin-bottom: 4px; color: #333; font-weight: bold; font-size: 13px; }}
            .form-group input, .form-group select {{ width: 100%; padding: 9px; border: 1px solid #cbd5e1; border-radius: 5px; box-sizing: border-box; font-size: 14px; }}
            .row-group {{ display: flex; gap: 10px; }}
            .col-title {{ flex: 1; }}
            .col-name {{ flex: 3; }}
            .age-row {{ display: flex; gap: 8px; }}
            .age-row input {{ flex: 1; }}
            .btn-save {{ background: #27ae60; color: white; border: none; padding: 12px; width: 100%; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; margin-top: 10px; }}
            .back-link {{ display: inline-block; margin-bottom: 10px; color: #0f4c81; text-decoration: none; font-weight: bold; font-size: 13px; }}
            .test-search {{ margin-bottom: 6px; padding: 7px; font-size: 13px; border: 1px solid #cbd5e1; border-radius: 4px; width: 100%; box-sizing: border-box; }}
            .test-box {{ border: 1px solid #cbd5e1; padding: 10px; max-height: 220px; overflow-y: auto; border-radius: 5px; background: #fafafa; }}
            .sel-box {{ margin-top: 8px; border: 1px solid #bfdbfe; background: #eff6ff; border-radius: 6px; padding: 8px 10px; }}
            .sel-head {{ display: flex; justify-content: space-between; font-size: 13px; font-weight: bold; color: #0f4c81; margin-bottom: 4px; }}
            .sel-item {{ display: flex; align-items: center; gap: 8px; font-size: 13px; padding: 3px 0; border-top: 1px dashed #bfdbfe; }}
            .sel-item .nm {{ flex: 1; }}
            .sel-item button {{ border: none; background: #fee2e2; color: #b91c1c; border-radius: 4px; cursor: pointer; font-weight: bold; padding: 0 7px; }}
        </style>
    </head>
    <body>
        <div class="form-card">
            <a href="/dashboard" class="back-link">&larr; Back to Dashboard</a>
            <h2>
                <span>Register New Patient</span>
                <span class="ref-badge">Ref No: #{next_id}</span>
            </h2>
            {success_banner}
            <form action="/add-patient" method="post" onsubmit="return confirmNoTests()">
                <div class="form-group" style="margin-bottom: 10px;">
                    <label>Manual Bill No.:</label>
                    <input type="text" name="manual_bill_no" inputmode="numeric" maxlength="4" pattern="[0-9]{{1,4}}"
                           placeholder="e.g. 042" style="max-width: 150px;">
                </div>
                <div class="form-group row-group">
                    <div class="col-title">
                        <label>Title:</label>
                        <select name="title" id="titleSelect" onchange="autoSelectGender()">
                            <option value="Mr.">Mr.</option>
                            <option value="Mrs.">Mrs.</option>
                            <option value="Ms.">Ms.</option>
                            <option value="Miss">Miss</option>
                            <option value="Rev.">Rev.</option>
                            <option value="Dr.">Dr.</option>
                            <option value="Master">Master</option>
                            <option value="Baby">Baby</option>
                        </select>
                    </div>
                    <div class="col-name">
                        <label>Patient Name:</label>
                        <input type="text" name="name" id="nameInput" required placeholder="Ex: A.B. Perera">
                    </div>
                </div>

                <div class="form-group">
                    <label>Age (Y / M / D):</label>
                    <div class="age-row">
                        <input type="number" name="age_years" id="ageYearsInput" min="0" value="0" placeholder="Years">
                        <input type="number" name="age_months" id="ageMonthsInput" min="0" max="11" value="0" placeholder="Months">
                        <input type="number" name="age_days" id="ageDaysInput" min="0" max="30" value="0" placeholder="Days">
                    </div>
                </div>

                <div class="form-group row-group">
                    <div style="flex: 1;">
                        <label>Gender:</label>
                        <select name="gender" id="genderSelect">
                            <option value="Male">Male</option>
                            <option value="Female">Female</option>
                        </select>
                    </div>
                    <div style="flex: 1;">
                        <label>Phone Number:</label>
                        <input type="text" name="phone" id="phoneInput" placeholder="0771234567" oninput="onPhoneInput()">
                        <span id="phoneLookupStatus" style="font-size:12px; color:#0f4c81; display:block; margin-top:3px;"></span>
                    </div>
                </div>

                <div class="form-group row-group">
                    <div style="flex: 1;">
                        <label>Referred Doctor:</label>
                        <select name="doctor" id="doctorSelect" required onchange="toggleDoctorManual()">
                            {doctor_options}
                        </select>
                        <input type="text" name="doctor_manual" id="doctorManual" placeholder="Type doctor name" style="display:none; margin-top:6px;">
                    </div>
                    <div style="flex: 1;">
                        <label>Collecting Center:</label>
                        <select name="collecting_center" id="centerSelect" required>
                            {center_options}
                        </select>
                    </div>
                </div>

                <div class="form-group">
                    <label>Select Required Tests:</label>
                    <input type="text" id="testSearchInput" class="test-search" placeholder="Type to search tests..." onkeyup="filterTests()">
                    <div class="test-box" id="testContainer">
                        {test_checkboxes}
                    </div>
                    <div class="sel-box">
                        <div class="sel-head"><span>Selected Tests: <span id="selCount">0</span></span></div>
                        <div id="selList"><em style="font-size:12px; color:#64748b;">No tests selected yet</em></div>
                    </div>
                </div>

                <button type="submit" class="btn-save">Save & Register Patient</button>
            </form>
        </div>

        <script>
            function autoSelectGender() {{
                const title = document.getElementById("titleSelect").value;
                const gender = document.getElementById("genderSelect");
                if (title === "Mr." || title === "Master") {{
                    gender.value = "Male";
                }} else if (title === "Mrs." || title === "Ms." || title === "Miss") {{
                    gender.value = "Female";
                }}
            }}

            // Auto-fill by phone number: after a short pause in typing,
            // look up existing patients with this exact phone number and
            // fill in the rest of the form. Every filled field stays a
            // normal, fully editable input - this only pre-populates it.
            let phoneLookupTimer = null;
            function onPhoneInput() {{
                clearTimeout(phoneLookupTimer);
                const phone = document.getElementById("phoneInput").value.trim();
                const status = document.getElementById("phoneLookupStatus");
                if (phone.length < 7) {{
                    status.textContent = "";
                    return;
                }}
                phoneLookupTimer = setTimeout(() => lookupPatientByPhone(phone), 450);
            }}

            async function lookupPatientByPhone(phone) {{
                const status = document.getElementById("phoneLookupStatus");
                try {{
                    status.textContent = "Searching...";
                    const res = await fetch("/api/lookup-patient-by-phone?phone=" + encodeURIComponent(phone));
                    const data = await res.json();
                    if (!data.found) {{
                        status.textContent = "No existing patient found for this number - new record.";
                        return;
                    }}
                    if (data.title) document.getElementById("titleSelect").value = data.title;
                    if (data.name) document.getElementById("nameInput").value = data.name;
                    document.getElementById("ageYearsInput").value = data.age_years ?? 0;
                    document.getElementById("ageMonthsInput").value = data.age_months ?? 0;
                    document.getElementById("ageDaysInput").value = data.age_days ?? 0;
                    if (data.gender) document.getElementById("genderSelect").value = data.gender;
                    if (data.doctor) {{
                        const doctorSel = document.getElementById("doctorSelect");
                        if ([...doctorSel.options].some(o => o.value === data.doctor)) {{ doctorSel.value = data.doctor; }}
                        else if (data.doctor && data.doctor !== "None") {{ doctorSel.value = "__manual__"; document.getElementById("doctorManual").value = data.doctor; }}
                        toggleDoctorManual();
                    }}
                    if (data.collecting_center) {{
                        const centerSel = document.getElementById("centerSelect");
                        if ([...centerSel.options].some(o => o.value === data.collecting_center)) centerSel.value = data.collecting_center;
                    }}
                    status.textContent = "Existing patient found - fields auto-filled. You can still edit them.";
                }} catch (err) {{
                    status.textContent = "";
                }}
            }}

            function filterTests() {{
                const input = document.getElementById("testSearchInput").value.toLowerCase();
                const container = document.getElementById("testContainer");
                const items = container.getElementsByClassName("test-item");

                for (let i = 0; i < items.length; i++) {{
                    const testName = items[i].getAttribute("data-name");
                    if (testName.includes(input)) {{
                        items[i].style.display = "flex";
                    }} else {{
                        items[i].style.display = "none";
                    }}
                }}
            }}

            function toggleDoctorManual() {{
                const sel = document.getElementById("doctorSelect");
                const man = document.getElementById("doctorManual");
                man.style.display = (sel.value === "__manual__") ? "block" : "none";
                if (sel.value === "__manual__") man.focus();
            }}

            // Live "selected tests" summary (stays visible even when the
            // search box hides ticked tests).
            function updateSelected() {{
                const boxes = document.querySelectorAll('#testContainer input[name="test_ids"]:checked');
                const list = document.getElementById("selList");
                list.innerHTML = "";
                boxes.forEach(cb => {{
                    const lab = cb.closest(".test-item");
                    const row = document.createElement("div");
                    row.className = "sel-item";
                    const nm = document.createElement("span");
                    nm.className = "nm";
                    nm.textContent = lab.getAttribute("data-label");
                    const x = document.createElement("button");
                    x.type = "button";
                    x.textContent = "\u00d7";
                    x.title = "Remove";
                    x.onclick = () => {{ cb.checked = false; updateSelected(); }};
                    row.appendChild(nm); row.appendChild(x);
                    list.appendChild(row);
                }});
                if (!boxes.length) list.innerHTML = '<em style="font-size:12px; color:#64748b;">No tests selected yet</em>';
                document.getElementById("selCount").textContent = boxes.length;
            }}
            document.getElementById("testContainer").addEventListener("change", updateSelected);

            function confirmNoTests() {{
                const n = document.querySelectorAll('#testContainer input[name="test_ids"]:checked').length;
                if (n === 0) return confirm("No tests are selected. Save this patient without any tests?");
                return true;
            }}

            window.onload = function() {{ autoSelectGender(); updateSelected(); }};
        </script>
    </body>
    </html>
    """ 

# -------------------------------------------------------------
# 2. REGISTER PATIENT (POST) - Redirects with Reference ID
# -------------------------------------------------------------
@app.post("/add-patient")
async def add_patient_post(request: Request):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "add_patient"):
        return render_locked_page("Add Patient")
    try:
        form_data = await request.form()
        selected_tests = form_data.getlist("test_ids")

        conn = get_db_connection()
        cursor = conn.cursor()

        # Safety check for older production databases: make sure the optional
        # manual bill column exists before the INSERT. This is additive-only
        # and preserves every existing patient row. The same migration also
        # runs during startup, but keeping this guard here prevents a first
        # registration request from failing if the database was deployed
        # before the startup migration ran.
        cursor.execute("PRAGMA table_info(patients)")
        patient_columns = {row[1] for row in cursor.fetchall()}
        if "manual_bill_no" not in patient_columns:
            cursor.execute("ALTER TABLE patients ADD COLUMN manual_bill_no TEXT")
            conn.commit()

        # Use the server's actual local date/time (not SQLite's built-in
        # CURRENT_TIMESTAMP default, which is UTC) so "Received On" reflects
        # correct local registration time.
        registration_timestamp = now_colombo().isoformat(timespec="seconds")

        manual_bill_no = str(form_data.get("manual_bill_no") or "").strip()
        if manual_bill_no and len(manual_bill_no) > 10:
            return HTMLResponse("<h3>Invalid Manual Bill No.</h3><p>Manual Bill No. must be 10 characters or less.</p><a href='/add-patient'>Go Back</a>", status_code=400)

        cursor.execute("""
            INSERT INTO patients (title, name, age_years, age_months, age_days, gender, phone, doctor, collecting_center, center, created_at, manual_bill_no)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            form_data.get("title"),
            form_data.get("name"),
            form_data.get("age_years", 0),
            form_data.get("age_months", 0),
            form_data.get("age_days", 0),
            form_data.get("gender"),
            form_data.get("phone"),
            _resolve_doctor_value(form_data.get("doctor"), form_data.get("doctor_manual")),
            form_data.get("collecting_center", "Main Branch"),
            form_data.get("collecting_center", "Main Branch"),
            registration_timestamp,
            manual_bill_no or None
        ))
        
        patient_id = cursor.lastrowid

        if selected_tests:
            for test_id in selected_tests:
                cursor.execute("""
                    INSERT INTO patient_assigned_tests (patient_id, test_id, assigned_date)
                    VALUES (?, ?, datetime('now'))
                """, (patient_id, test_id))

        conn.commit()
        conn.close()
        
        # Save වූ පසු අදාළ ID එක සමඟ නැවතත් මෙම පේජ් එකටම පැමිණේ
        return RedirectResponse(url=f"/add-patient?saved_id={patient_id}", status_code=303)

    except Exception as e:
        print("ERROR IN ADD PATIENT:", str(e))
        return f"<h3>Database Error: {str(e)}</h3><a href='/add-patient'>Go Back</a>"

from fastapi import Form

# --- DOCTORS MANAGEMENT ---
@app.get("/manage-doctors", response_class=HTMLResponse)
def manage_doctors(request: Request):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "manage_doctors"):
        return render_locked_page("Manage Doctors")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM doctors ORDER BY name")
    doctors = cursor.fetchall()
    conn.close()

    rows = "".join([f"""
        <tr>
            <td>{d['code']}</td>
            <td>{d['name']}</td>
            <td>{d['specialization'] or '-'}</td>
            <td>{d['phone'] or '-'}</td>
            <td>
                <form action="/update-doctor-commission/{d['id']}" method="post" style="display:flex; gap:4px; align-items:center;">
                    <input type="number" name="commission_rate" step="0.1" min="0" max="100" value="{d['commission_rate'] if 'commission_rate' in d.keys() and d['commission_rate'] is not None else 0}" style="width:60px; padding:4px; border:1px solid #cbd5e1; border-radius:4px; font-size:12px;">
                    <span style="font-size:12px;">%</span>
                    <button type="submit" style="background:#0f4c81; color:white; border:none; padding:4px 8px; border-radius:4px; font-size:11px; cursor:pointer;">Save</button>
                </form>
            </td>
            <td style="text-align:center;">
                <a href="/delete-doctor/{d['id']}" onclick="return confirm('Delete this doctor? Existing patient records/reports that already reference this doctor by name are not affected.');"
                   style="color:#e53e3e; text-decoration:none; font-weight:700; font-size:12px; background:rgba(229,62,62,0.1); padding:5px 10px; border-radius:5px;">
                    <i class="fa-solid fa-trash"></i> Delete
                </a>
            </td>
        </tr>
    """ for d in doctors])

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Manage Doctors</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 20px; }}
            .container {{ max-width: 700px; margin: auto; background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            .form-group {{ margin-bottom: 12px; }}
            .form-group label {{ display: block; font-weight: bold; margin-bottom: 5px; font-size: 13px; }}
            .form-group input {{ width: 100%; padding: 8px; border: 1px solid #cbd5e1; border-radius: 5px; box-sizing: border-box; }}
            .btn {{ background: #0f4c81; color: white; border: none; padding: 10px; width: 100%; border-radius: 5px; font-weight: bold; cursor: pointer; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #cbd5e1; padding: 8px; text-align: left; font-size: 13px; }}
            th {{ background: #0f4c81; color: white; }}
            .back-link {{ display: inline-block; margin-bottom: 15px; color: #0f4c81; text-decoration: none; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/dashboard" class="back-link">&larr; Back to Dashboard</a>
            <h2 style="color: #0f4c81; margin-top: 0;">Manage Doctors</h2>
            
            <form action="/add-doctor" method="post">
                <div class="form-group">
                    <label>Doctor Code (e.g., DOC001):</label>
                    <input type="text" name="code" required placeholder="Enter unique code">
                </div>
                <div class="form-group">
                    <label>Doctor Name:</label>
                    <input type="text" name="name" required placeholder="Dr. Perera">
                </div>
                <div class="form-group">
                    <label>Specialization:</label>
                    <input type="text" name="specialization" placeholder="Cardiologist / MBBS">
                </div>
                <div class="form-group">
                    <label>Phone Number:</label>
                    <input type="text" name="phone" placeholder="0771234567">
                </div>
                <div class="form-group">
                    <label>Commission Rate (%):</label>
                    <input type="number" name="commission_rate" step="0.1" min="0" max="100" value="0" placeholder="e.g. 10">
                </div>
                <button type="submit" class="btn">Add Doctor</button>
            </form>

            <h3 style="margin-top: 25px; color: #333;">Existing Doctors</h3>
            <table>
                <tr>
                    <th>Code</th>
                    <th>Name</th>
                    <th>Specialization</th>
                    <th>Phone</th>
                    <th>Commission %</th>
                    <th style="text-align:center;">Action</th>
                </tr>
                {rows if rows else '<tr><td colspan="6" style="text-align:center;">No doctors added yet.</td></tr>'}
            </table>
        </div>
    </body>
    </html>
    """

@app.post("/add-doctor")
def add_doctor(code: str = Form(...), name: str = Form(...), specialization: str = Form(None), phone: str = Form(None), commission_rate: float = Form(0.0)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO doctors (code, name, specialization, phone, commission_rate) VALUES (?, ?, ?, ?, ?)", 
                       (code, name, specialization, phone, commission_rate))
        conn.commit()
    except sqlite3.IntegrityError:
        pass # Code එක කලින් තිබුණොත් ignore කරයි
    conn.close()
    return RedirectResponse(url="/manage-doctors", status_code=303)


@app.post("/update-doctor-commission/{doctor_id}")
def update_doctor_commission(doctor_id: int, request: Request, commission_rate: float = Form(0.0)):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "manage_doctors"):
        return render_locked_page("Manage Doctors")

    commission_rate = max(0.0, min(100.0, commission_rate))
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE doctors SET commission_rate = ? WHERE id = ?", (commission_rate, doctor_id))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/manage-doctors", status_code=303)


@app.get("/delete-doctor/{doctor_id}")
def delete_doctor(doctor_id: int, request: Request):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "manage_doctors"):
        return render_locked_page("Manage Doctors")

    # Safe delete: patients.doctor stores the doctor's NAME as plain text
    # (not a foreign key to doctors.id), so removing a doctor from this
    # list only affects future selection - it cannot alter or break any
    # existing patient record or previously generated report, since those
    # already have the doctor's name saved directly on them.
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM doctors WHERE id = ?", (doctor_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/manage-doctors", status_code=303)

# --- COLLECTING CENTERS MANAGEMENT ---
@app.get("/manage-centers", response_class=HTMLResponse)
def manage_centers(request: Request):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "manage_centers"):
        return render_locked_page("Manage Centers")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM collecting_centers ORDER BY center_name")
    centers = cursor.fetchall()
    conn.close()

    rows = "".join([f"""
        <tr>
            <td>{c['center_name']}</td>
            <td>{c['location'] or '-'}</td>
            <td>{c['phone'] or '-'}</td>
            <td style="text-align:center;">
                <a href="/delete-center/{c['id']}" onclick="return confirm('Delete this collecting center? Existing patient records/reports that already reference this center by name are not affected.');"
                   style="color:#e53e3e; text-decoration:none; font-weight:700; font-size:12px; background:rgba(229,62,62,0.1); padding:5px 10px; border-radius:5px;">
                    <i class="fa-solid fa-trash"></i> Delete
                </a>
            </td>
        </tr>
    """ for c in centers])

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Manage Collecting Centers</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 20px; }}
            .container {{ max-width: 700px; margin: auto; background: white; padding: 25px; border-radius: 10px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            .form-group {{ margin-bottom: 12px; }}
            .form-group label {{ display: block; font-weight: bold; margin-bottom: 5px; font-size: 13px; }}
            .form-group input {{ width: 100%; padding: 8px; border: 1px solid #cbd5e1; border-radius: 5px; box-sizing: border-box; }}
            .btn {{ background: #27ae60; color: white; border: none; padding: 10px; width: 100%; border-radius: 5px; font-weight: bold; cursor: pointer; }}
            table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
            th, td {{ border: 1px solid #cbd5e1; padding: 8px; text-align: left; font-size: 13px; }}
            th {{ background: #27ae60; color: white; }}
            .back-link {{ display: inline-block; margin-bottom: 15px; color: #0f4c81; text-decoration: none; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/dashboard" class="back-link">&larr; Back to Dashboard</a>
            <h2 style="color: #27ae60; margin-top: 0;">Manage Collecting Centers</h2>
            
            <form action="/add-center" method="post">
                <div class="form-group">
                    <label>Center Name:</label>
                    <input type="text" name="center_name" required placeholder="Main Branch / City Lab Negombo">
                </div>
                <div class="form-group">
                    <label>Location / Address:</label>
                    <input type="text" name="location" placeholder="Town Hall, Colombo">
                </div>
                <div class="form-group">
                    <label>Phone Number:</label>
                    <input type="text" name="phone" placeholder="0312233445">
                </div>
                <button type="submit" class="btn">Add Collecting Center</button>
            </form>

            <h3 style="margin-top: 25px; color: #333;">Existing Centers</h3>
            <table>
                <tr>
                    <th>Center Name</th>
                    <th>Location</th>
                    <th>Phone</th>
                    <th style="text-align:center;">Action</th>
                </tr>
                {rows if rows else '<tr><td colspan="4" style="text-align:center;">No collecting centers added yet.</td></tr>'}
            </table>
        </div>
    </body>
    </html>
    """

@app.post("/add-center")
def add_center(center_name: str = Form(...), location: str = Form(None), phone: str = Form(None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO collecting_centers (center_name, location, phone) VALUES (?, ?, ?)", 
                   (center_name, location, phone))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/manage-centers", status_code=303)


@app.get("/delete-center/{center_id}")
def delete_center(center_id: int, request: Request):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "manage_centers"):
        return render_locked_page("Manage Centers")

    # Safe delete: patients.collecting_center/center store the center's
    # NAME as plain text (not a foreign key to collecting_centers.id), so
    # removing a center from this list only affects future selection - it
    # cannot alter or break any existing patient record or previously
    # generated report, since those already have the center name saved
    # directly on them.
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM collecting_centers WHERE id = ?", (center_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/manage-centers", status_code=303)


# -------------------------------------------------------------
# 3. SELECT PATIENT LIST (Step 1)
# -------------------------------------------------------------
@app.get("/add-test-entry", response_class=HTMLResponse)
def add_test_entry(request: Request, search: str = "", selected_patient_id: int = None):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "add_test"):
        return render_locked_page("Add Test")
    conn = get_db_connection()
    cursor = conn.cursor()

    if search:
        search_term = f"%{search}%"
        cursor.execute("""
            SELECT p.id, p.title, p.name, p.age_years, p.age_months, p.age_days, p.gender, p.phone
            FROM patients p
            WHERE (p.name LIKE ? OR p.phone LIKE ?) AND (p.is_cancelled IS NULL OR p.is_cancelled = 0)
            ORDER BY p.id DESC
        """, (search_term, search_term))
    else:
        cursor.execute("""
            SELECT p.id, p.title, p.name, p.age_years, p.age_months, p.age_days, p.gender, p.phone
            FROM patients p
            WHERE (p.is_cancelled IS NULL OR p.is_cancelled = 0)
            ORDER BY p.id DESC
            LIMIT 20
        """)
    patients = cursor.fetchall()
    conn.close()

    patient_cards = ""
    for row in patients:
        age_str = f"{row['age_years']}Y {row['age_months']}M {row['age_days']}D"
        checked = "checked" if selected_patient_id and row["id"] == selected_patient_id else ""

        patient_cards += f"""
            <label style="display: flex; align-items: center; justify-content: space-between; padding: 12px 15px; border-bottom: 1px solid #eee; cursor: pointer;">
                <div style="display: flex; align-items: center; gap: 12px;">
                    <input type="radio" name="selected_patient_id" value="{row["id"]}" {checked} onclick="document.getElementById('patient_id_input').value = '{row["id"]}'" style="width: 18px; height: 18px; accent-color: #0f4c81;">
                    <div>
                        <div style="font-size: 16px; font-weight: bold; color: #333;">{row["title"]} {row["name"]}</div>
                        <div style="font-size: 13px; color: #666; margin-top: 3px;">Age: {age_str} | Gender: {row["gender"]} | Ph: {row["phone"] if row["phone"] else "N/A"}</div>
                    </div>
                </div>
            </label>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Lab System - Select Patient</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 40px; }}
            .form-card {{ background: white; padding: 30px; border-radius: 12px; max-width: 650px; margin: auto; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            .btn-next {{ background: #0f4c81; color: white; border: none; padding: 12px; width: 100%; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; margin-top: 20px; }}
            .btn-search {{ background: #2980b9; color: white; border: none; padding: 10px 15px; border-radius: 6px; font-weight: bold; cursor: pointer; }}
            .back-link {{ display: inline-block; margin-bottom: 15px; color: #0f4c81; text-decoration: none; font-weight: bold; }}
            .patient-list-container {{ max-height: 320px; overflow-y: auto; border: 1px solid #ccc; border-radius: 8px; background: white; }}
        </style>
    </head>
    <body>
        <div class="form-card">
            <a href="/dashboard" class="back-link">&larr; Back to Dashboard</a>
            <h2 style="color: #0f4c81; margin-top: 0;">Step 1: Select Patient</h2>

            <form action="/add-test-entry" method="get" style="margin-bottom: 15px;">
                <div style="display: flex; gap: 8px;">
                    <input type="text" name="search" value="{search}" placeholder="Search name or phone..." style="flex: 1; padding: 10px; border: 1px solid #ccc; border-radius: 6px;">
                    <button type="submit" class="btn-search">Search</button>
                </div>
            </form>

            <form action="/patient-tests" method="get">
                <input type="hidden" id="patient_id_input" name="patient_id" value="{selected_patient_id if selected_patient_id else ''}">
                <div class="patient-list-container">
                    {patient_cards}
                </div>
                <button type="submit" class="btn-next">Next: View Patient Tests</button>
            </form>
        </div>
    </body>
    </html>
    """

    # ... (ඔයාගේ පරණ කෝඩ් එක මෙතන තියෙන්න දෙන්න)


# -------------------------------------------------------------
# 1. PATIENT DASHBOARD (UPDATE & LIST TESTS)
# -------------------------------------------------------------
@app.get("/patient-tests", response_class=HTMLResponse)
def patient_tests(patient_id: int = None, selected_patient_id: int = None):
    p_id = patient_id if patient_id else selected_patient_id
    if not p_id:
        return RedirectResponse(url="/select-patient", status_code=303)

    conn = get_db_connection()
    cursor = conn.cursor()

    # රෝගියාගේ විස්තර
    cursor.execute("SELECT * FROM patients WHERE id = ?", (p_id,))
    patient_row = cursor.fetchone()

    if not patient_row:
        conn.close()
        return RedirectResponse(url="/select-patient", status_code=303)

    patient = dict(patient_row)

    # ටෙස්ට් ටික අරගන්න
    cursor.execute("""
        SELECT t.id as test_id, t.test_name, t.department, t.specimen, pat.result
        FROM patient_assigned_tests pat
        JOIN tests t ON pat.test_id = t.id
        WHERE pat.patient_id = ?
    """, (p_id,))
    assigned_tests = cursor.fetchall()

    test_cards = ""
    for t in assigned_tests:
        cursor.execute("SELECT id FROM reports WHERE patient_id = ? AND test_id = ? ORDER BY id DESC LIMIT 1", (p_id, t['test_id']))
        report = cursor.fetchone()
        report_id = report['id'] if report else None

        if t['result'] and report_id:
            status_badge = '<span style="background: #27ae60; color: white; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold;">Verify</span>'
            action_btn = f'<a href="/print-report/{report_id}" style="background: #27ae60; color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 13px; font-weight: bold;">Print Report</a>'
        else:
            status_badge = '<span style="background: #e74c3c; color: white; padding: 4px 10px; border-radius: 4px; font-size: 12px; font-weight: bold;">Pending</span>'
            action_btn = f'<a href="/enter-results?patient_id={p_id}&test_id={t["test_id"]}" style="background: #0f4c81; color: white; padding: 6px 12px; border-radius: 4px; text-decoration: none; font-size: 13px; font-weight: bold;">Enter Result</a>'
        
        test_cards += f"""
            <div style="display: flex; align-items: center; justify-content: space-between; padding: 12px; border-bottom: 1px solid #eee; background: #fff; margin-bottom: 8px; border-radius: 6px;">
                <div>
                    <h4 style="margin: 0; color: #0f4c81;">{t['test_name']}</h4>
                    <p style="margin: 3px 0 0 0; font-size: 12px; color: #666;">Dept: {t.get('department') or 'N/A'}</p>
                    <div style="margin-top: 5px;">{status_badge}</div>
                </div>
                <div>{action_btn}</div>
            </div>
        """
    conn.close()

    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Patient Dashboard</title></head>
    <body style="font-family: Arial; background: #f4f7fb; padding: 20px;">
        <div style="max-width: 1000px; margin: auto; background: white; padding: 20px; border-radius: 10px;">
            <a href="/patients-dashboard" style="color: #0f4c81;">&larr; Back to Dashboard</a>
            <h2>Patient Management</h2>
            <div style="display: flex; gap: 20px;">
                <div style="flex: 1;">
                    <form action="/update-patient-details" method="post">
                        <input type="hidden" name="patient_id" value="{patient['id']}">
                        <label>Name</label><input type="text" name="name" value="{patient.get('name', '')}" style="width: 100%; margin-bottom: 10px;">
                        <label>Age</label><input type="text" name="age" value="{patient.get('age', '')}" style="width: 100%; margin-bottom: 10px;">
                        <button type="submit" style="background: #2980b9; color: white; border: none; padding: 10px; width: 100%;">Update Details</button>
                    </form>
                </div>
                <div style="flex: 2;">
                    <h3>Assigned Tests</h3>
                    {test_cards if test_cards else "<p>No tests assigned.</p>"}
                </div>
            </div>
        </div>
    </body>
    </html>
    """

# Fallback for old save-results route to prevent 500 errors if cached


# -----------------------------
# 4. MANAGE TEST CATEGORIES & TEMPLATES
# -----------------------------
@app.get("/manage-tests", response_class=HTMLResponse)
def manage_tests(request: Request, dept: str = ""):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "manage_tests"):
        return render_locked_page("Manage Tests")

    conn = get_db_connection()
    cursor = conn.cursor()

    # Safety checks for columns (Including 'notes' for rich test description)
    try:
        cursor.execute("ALTER TABLE tests ADD COLUMN test_code TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE tests ADD COLUMN notes TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN input_type TEXT DEFAULT 'numeric'")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Fetch unique departments for filter tabs
    cursor.execute("SELECT DISTINCT department FROM tests WHERE department IS NOT NULL AND department != ''")
    depts = [row[0] for row in cursor.fetchall()]

    if dept:
        cursor.execute("SELECT id, test_name, price, department, specimen, test_code FROM tests WHERE department = ?", (dept,))
    else:
        cursor.execute("SELECT id, test_name, price, department, specimen, test_code FROM tests")
    
    tests = cursor.fetchall()

    # Fetch all parameter counts in a single grouped query instead of one
    # round-trip per test row (previously an N+1 query - a lab with 100
    # test categories meant 100 extra Turso HTTP round-trips just to
    # render this page). Missing tests (0 parameters) simply won't appear
    # as a key, handled by the .get(test_id, 0) default below.
    cursor.execute("SELECT test_id, COUNT(*) FROM test_parameters GROUP BY test_id")
    param_counts = {row[0]: row[1] for row in cursor.fetchall()}

    test_list_html = ""
    for test_id, test_name, price, department, specimen, test_code in tests:
        param_count = param_counts.get(test_id, 0)

        code_badge = f"<span style='background:#0f4c81; color:white; padding:3px 8px; border-radius:4px; font-size:12px; margin-right:8px;'>{test_code}</span>" if test_code else ""

        test_list_html += f"""
        <div class="test-card" style="background:#fff; border:1px solid #e0e0e0; padding:18px 20px; margin-bottom:15px; border-radius:8px; display:flex; justify-content:space-between; align-items:center; box-shadow:0 2px 5px rgba(0,0,0,0.02);">
            <div>
                <h3 style="margin:0 0 5px 0; color:#0f4c81; font-size:18px; display:flex; align-items:center;">{code_badge}{test_name}</h3>
                <span style="color:#666; font-size:13px; font-weight:600;">Parameters: {param_count} | Price: Rs.{price} | Dept: {department or 'N/A'} | Specimen: {specimen or 'N/A'}</span>
            </div>
            <div>
                <a href="/edit-test-category/{test_id}" style="background:#f39c12; color:white; padding:10px 15px; text-decoration:none; border-radius:6px; font-size:13px; font-weight:bold; margin-right:5px;">Edit Info</a>
                <a href="/manage-tests/{test_id}" style="background:#0f4c81; color:white; padding:10px 18px; text-decoration:none; border-radius:6px; font-size:13px; font-weight:bold; margin-right:5px;">Manage Parameters</a>
                <button type="button" onclick="openDeleteCategoryModal({test_id}, {repr(test_name)})" style="background:#b91c1c; color:white; border:none; padding:10px 15px; border-radius:6px; font-size:13px; font-weight:bold; cursor:pointer;">Delete</button>
            </div>
        </div>
        """

    conn.close()

    # Department filter tabs HTML
    dept_tabs = f"<a href='/manage-tests' style='padding:6px 14px; background: {'#0f4c81' if not dept else '#e2e8f0'}; color: {'white' if not dept else '#333'}; border-radius:20px; text-decoration:none; font-size:13px; font-weight:bold;'>All Departments</a>"
    for d in depts:
        is_active = (dept == d)
        dept_tabs += f"<a href='/manage-tests?dept={d}' style='padding:6px 14px; background: {'#0f4c81' if is_active else '#e2e8f0'}; color: {'white' if is_active else '#333'}; border-radius:20px; text-decoration:none; font-size:13px; font-weight:bold;'>{d}</a>"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Manage Test Categories</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 40px; }}
            .container {{ max-width: 950px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            h2 {{ color: #0f4c81; margin-top: 0; }}
            .back-link {{ display: inline-block; margin-bottom: 15px; color: #0f4c81; text-decoration: none; font-weight: bold; }}
            .top-actions {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; flex-wrap: wrap; gap: 10px; }}
            .template-btn {{ background: #27ae60; color: white; padding: 10px 16px; border-radius: 6px; text-decoration: none; font-weight: bold; font-size: 13px; }}
            .add-test-box {{ background: #eaf3fb; padding: 20px; border-radius: 8px; margin-bottom: 25px; display: flex; flex-direction: column; gap: 10px; }}
            .search-bar {{ margin-bottom: 20px; }}
            .search-bar input {{ width: 100%; padding: 12px; border: 1px solid #ccc; border-radius: 6px; font-size: 15px; box-sizing: border-box; }}
            .row-inputs {{ display: flex; gap: 10px; flex-wrap: wrap; }}
            .row-inputs input, .row-inputs select {{ flex: 1; min-width: 150px; padding: 10px; border: 1px solid #ccc; border-radius: 6px; }}
            textarea {{ width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; resize: vertical; min-height: 80px; font-family: Arial, sans-serif; }}
            .dept-filters {{ display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; }}
            
            /* Editor Toolbar Styles */
            .editor-toolbar {{ display: flex; gap: 5px; background: #dfe6e9; padding: 6px; border-radius: 6px 6px 0 0; border: 1px solid #ccc; border-bottom: none; flex-wrap: wrap; }}
            .editor-toolbar button {{ background: #fff; border: 1px solid #b2bec3; padding: 4px 10px; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 12px; color: #2d3436; }}
            .editor-toolbar button:hover {{ background: #0f4c81; color: white; border-color: #0f4c81; }}
        </style>
        <script>
            function searchTests() {{
                let filter = document.getElementById('searchBox').value.toUpperCase();
                let cards = document.getElementsByClassName('test-card');
                for (let i = 0; i < cards.length; i++) {{
                    let title = cards[i].getElementsByTagName("h3")[0];
                    if (title.innerHTML.toUpperCase().indexOf(filter) > -1) {{
                        cards[i].style.display = "flex";
                    }} else {{
                        cards[i].style.display = "none";
                    }}
                }}
            }}

            // Two-step category deletion:
            // Step 1 = open the confirmation modal.
            // Step 2 = explicitly press the final Delete button in the modal.
            let pendingDeleteCategoryId = null;

            function openDeleteCategoryModal(testId, testName) {{
                pendingDeleteCategoryId = testId;
                document.getElementById('deleteCategoryName').textContent = testName || 'this test category';
                document.getElementById('deleteCategoryForm').action = '/delete-test/' + testId;
                document.getElementById('deleteCategoryModal').style.display = 'flex';
            }}

            function closeDeleteCategoryModal() {{
                pendingDeleteCategoryId = null;
                document.getElementById('deleteCategoryModal').style.display = 'none';
            }}

            // Formatting helper for notes textarea
            function insertTag(tagOpen, tagClose) {{
                let textarea = document.getElementById('testNotes');
                let start = textarea.selectionStart;
                let end = textarea.selectionEnd;
                let text = textarea.value;
                let selectedText = text.substring(start, end);
                let replacement = tagOpen + selectedText + tagClose;
                textarea.value = text.substring(0, start) + replacement + text.substring(end);
                textarea.focus();
                textarea.setSelectionRange(start + tagOpen.length, end + tagOpen.length);
            }}
        </script>
    </head>
    <body>
        <div class="container">
            <div class="top-actions">
                <a href="/dashboard" class="back-link" style="margin-bottom:0;">← Back to Dashboard</a>
                <a href="/load-standard-templates" class="template-btn" onclick="return confirm('Load standard Sri Lankan lab tests (FBC, LFT, Lipid, UFR, etc.)?');">⚡ Load Standard Lab Templates</a>
            </div>
            
            <h2 style="margin-top:15px;">Test Categories List</h2>

            <div class="dept-filters">
                {dept_tabs}
            </div>

            <div class="search-bar">
                <input type="text" id="searchBox" placeholder="🔍 Search Test Categories or Codes..." onkeyup="searchTests()">
            </div>

            <form action="/add-main-test" method="post" class="add-test-box">
                <h3 style="margin:0 0 10px 0; color:#0f4c81; font-size:16px;">Create New Test Category</h3>
                <div class="row-inputs">
                    <input type="text" name="test_code" placeholder="Test Code (e.g. FBC)" style="flex: 1;">
                    <input type="text" name="test_name" placeholder="Test Category Name (Required)" required style="flex: 2;">
                    <input type="number" step="0.01" name="price" placeholder="Price (Rs)" style="flex: 1;">
                </div>
                <div class="row-inputs">
                    <input type="text" name="department" placeholder="Department (e.g. Biochemistry)">
                    <input type="text" name="specimen" placeholder="Specimen (e.g. Blood, Urine)">
                </div>
                <label style="display:flex;align-items:center;gap:8px;margin:8px 0 12px;font-size:13px;font-weight:700;color:#0f4c81;">
                    <input type="checkbox" name="show_fia_graph" value="1" style="width:18px;height:18px;">
                    Show FIA Graph on final report for this test
                </label>

                <!-- Notes / Description Section with Formatting Toolbar -->
                <div>
                    <label style="font-weight:bold; font-size:13px; color:#0f4c81; display:block; margin-bottom:5px;">Test Notes / Description (Will print at the bottom of the report):</label>
                    <div class="editor-toolbar">
                        <button type="button" onclick="insertTag('<b>', '</b>')"><b>B</b></button>
                        <button type="button" onclick="insertTag('<i>', '</i>')"><i>I</i></button>
                        <button type="button" onclick="insertTag('<u>', '</u>')"><u>U</u></button>
                        <button type="button" onclick="insertTag('<span style=\'font-size:14px;\'>', '</span>')">Larger Text</button>
                        <button type="button" onclick="insertTag('<hr style=\'border:0; border-top:1px solid #ccc; margin:10px 0;\'>', '')">Insert Line</button>
                        <button type="button" onclick="insertTag('<div style=\'border:1px solid #0f4c81; padding:8px; border-radius:4px; margin:5px 0;\'>', '</div>')">Box Border</button>
                        <button type="button" onclick="insertTag('<br>', '')">New Line</button>
                    </div>
                    <textarea id="testNotes" name="notes" placeholder="Enter clinical notes, description or instructions here..."></textarea>
                </div>

                <div style="background:#fff; padding:10px; border-radius:6px; border:1px solid #ccc;">
                    <label style="font-weight:bold; font-size:13px; color:#555;">Report Column Alignments & Widths:</label>
                    <div class="row-inputs" style="margin-top:8px;">
                        <select name="align_inv"><option value="left">Investigation: Left</option><option value="center">Center</option><option value="right">Right</option><option value="none">Hide / None</option></select>
                        <select name="align_res"><option value="center">Result: Center</option><option value="left">Left</option><option value="right">Right</option><option value="none">Hide / None</option></select>
                        <select name="align_flag"><option value="center">Flag: Center</option><option value="left">Left</option><option value="right">Right</option><option value="none">Hide / None</option></select>
                        <select name="align_unit"><option value="left">Unit: Left</option><option value="center">Center</option><option value="right">Right</option><option value="none">Hide / None</option></select>
                        <select name="align_ref"><option value="left">Ref Range: Left</option><option value="center">Center</option><option value="right">Right</option><option value="none">Hide / None</option></select>
                    </div>
                    <div class="row-inputs" style="margin-top:6px;">
                        <input type="number" name="width_inv" value="38" min="1" max="100" step="1" placeholder="Investigation width">
                        <input type="number" name="width_res" value="13" min="1" max="100" step="1" placeholder="Result width">
                        <input type="number" name="width_flag" value="8" min="1" max="100" step="1" placeholder="Flag width">
                        <input type="number" name="width_unit" value="14" min="1" max="100" step="1" placeholder="Unit width">
                        <input type="number" name="width_ref" value="27" min="1" max="100" step="1" placeholder="Reference width">
                    </div>
                    <div style="font-size:11px;color:#777;margin-top:5px;">Width values are relative. Hidden columns are removed and remaining columns automatically expand to fill the report width.</div>
                </div>

                <button type="submit" style="background:#0f4c81; color:white; border:none; padding:12px 20px; border-radius:6px; font-weight:bold; cursor:pointer; font-size:14px; margin-top:5px;">Create Category</button>
            </form>

            {test_list_html}
        </div>

        <!-- Two-step delete confirmation modal -->
        <div id="deleteCategoryModal" style="display:none; position:fixed; inset:0; background:rgba(0,0,0,.55); z-index:9999; align-items:center; justify-content:center; padding:20px;">
            <div style="width:100%; max-width:460px; background:#fff; border-radius:10px; padding:24px; box-shadow:0 15px 40px rgba(0,0,0,.25); border:1px solid #111;">
                <h3 style="margin:0 0 10px; color:#111;">Confirm Test Category Deletion</h3>
                <p style="margin:0 0 18px; color:#333; line-height:1.5;">
                    You are about to permanently delete <strong id="deleteCategoryName"></strong>.
                    This action may remove its parameters and related stored results.
                    <strong>This cannot be undone.</strong>
                </p>
                <div style="display:flex; justify-content:flex-end; gap:10px;">
                    <button type="button" onclick="closeDeleteCategoryModal()" style="background:#fff; color:#111; border:1px solid #777; padding:9px 16px; border-radius:6px; font-weight:700; cursor:pointer;">Cancel</button>
                    <form id="deleteCategoryForm" method="post" style="margin:0;">
                        <button type="submit" style="background:#b91c1c; color:#fff; border:1px solid #7f1d1d; padding:9px 16px; border-radius:6px; font-weight:700; cursor:pointer;">Yes, Permanently Delete</button>
                    </form>
                </div>
            </div>
        </div>
    </body>
    </html>
    """

# -------------------------------------------------------------
# SMART STANDARD TEST SEEDING + CALCULATION ENGINE
# -------------------------------------------------------------

def _ensure_column(cursor, table_name, column_name, column_sql):
    cursor.execute(f"PRAGMA table_info({table_name})")
    columns = {row[1] for row in cursor.fetchall()}
    if column_name not in columns:
        cursor.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_sql}")


def seed_standard_tests_and_parameters():
    """
    Idempotent standard-test seeder.

    - Creates missing standard tests/parameters.
    - Never deletes existing data.
    - Never overwrites a parameter's current reference range or customisation.
    - Adds calculation metadata only to the calculated parameters we own.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        _ensure_column(cursor, "tests", "test_code", "test_code TEXT")
        _ensure_column(cursor, "test_parameters", "display_order", "display_order INTEGER DEFAULT 0")
        _ensure_column(cursor, "test_parameters", "default_result", "default_result TEXT")
        _ensure_column(cursor, "test_parameters", "input_type", "input_type TEXT DEFAULT 'numeric'")
        _ensure_column(cursor, "test_parameters", "is_calculated", "is_calculated INTEGER DEFAULT 0")
        _ensure_column(cursor, "test_parameters", "calculation_key", "calculation_key TEXT")
        _ensure_column(cursor, "test_parameters", "is_bold", "is_bold INTEGER DEFAULT 0")
        # Per-RESULT bold flag, set by the operator on the Result Entry
        # screen. Distinct from test_parameters.is_bold above, which is a
        # per-parameter *config* flag that bolds the parameter NAME for
        # every patient. This one bolds one specific patient's result
        # VALUE for one specific test.
        _ensure_column(cursor, "patient_parameter_results", "is_bold", "is_bold INTEGER DEFAULT 0")
        # Per-assigned-test flag: when set, the ABST / antibiotic
        # susceptibility section is omitted from the printed report
        # (used for "No Growth" culture reports).
        _ensure_column(cursor, "patient_assigned_tests", "hide_abst", "hide_abst INTEGER DEFAULT 0")

        standards = [
            {
                "code": "FBC", "name": "FULL BLOOD COUNT (FBC)", "price": 1200.0,
                "dept": "Hematology", "specimen": "Blood (EDTA)",
                "params": [
                    ("White Blood Cell (WBC)", "10^3/uL", "4.0 - 11.0", "numeric", "", False, None),
                    ("Red Blood Cell (RBC)", "10^6/uL", "4.5 - 5.5", "numeric", "", False, None),
                    ("Hemoglobin (Hb)", "g/dL", "13.0 - 17.0", "numeric", "", False, None),
                    ("Hematocrit (PCV)", "%", "40.0 - 50.0", "numeric", "", False, None),
                    ("Platelets", "10^3/uL", "150 - 450", "numeric", "", False, None),
                    ("Neutrophils", "%", "40 - 75", "numeric", "", False, None),
                    ("Lymphocytes", "%", "20 - 45", "numeric", "", False, None),
                    ("Eosinophils", "%", "1 - 6", "numeric", "", False, None),
                    ("Monocytes", "%", "2 - 10", "numeric", "", False, None),
                ],
            },
            {
                "code": "LIPID", "name": "LIPID PROFILE", "price": 2500.0,
                "dept": "Biochemistry", "specimen": "Blood (Serum)",
                "params": [
                    ("Total Cholesterol", "mg/dL", "< 200", "numeric", "", False, None),
                    ("Triglycerides", "mg/dL", "< 150", "numeric", "", False, None),
                    ("HDL Cholesterol", "mg/dL", "> 40", "numeric", "", False, None),
                    ("LDL Cholesterol", "mg/dL", "< 100", "numeric", "", True, "friedewald_ldl"),
                    ("VLDL Cholesterol", "mg/dL", "2 - 30", "numeric", "", True, "vldl"),
                    ("Total Cholesterol / HDL Ratio", "ratio", "", "numeric", "", True, "chol_hdl_ratio"),
                ],
            },
            {
                "code": "RFT", "name": "RENAL PROFILE (RFT)", "price": 2500.0,
                "dept": "Biochemistry", "specimen": "Blood (Serum)",
                "params": [
                    ("Blood Urea", "mg/dL", "15 - 45", "numeric", "", False, None),
                    ("Serum Creatinine", "mg/dL", "0.6 - 1.3", "numeric", "", False, None),
                    ("eGFR", "mL/min/1.73m²", "", "numeric", "", True, "ckd_epi_2021"),
                    ("Serum Sodium", "mmol/L", "135 - 145", "numeric", "", False, None),
                    ("Serum Potassium", "mmol/L", "3.5 - 5.1", "numeric", "", False, None),
                ],
            },
            {
                "code": "CREAT-EGFR", "name": "CREATININE WITH eGFR", "price": 1500.0,
                "dept": "Biochemistry", "specimen": "Blood (Serum)",
                "params": [
                    ("Serum Creatinine", "mg/dL", "0.6 - 1.3", "numeric", "", False, None),
                    ("Estimated GFR", "mL/min/1.73m²", ">= 90", "numeric", "", True, "ckd_epi_2021"),
                ],
            },
            {
                "code": "LFT", "name": "LIVER FUNCTION TEST (LFT)", "price": 3000.0,
                "dept": "Biochemistry", "specimen": "Blood (Serum)",
                "params": [
                    ("Total Bilirubin", "mg/dL", "0.2 - 1.2", "numeric", "", False, None),
                    ("Direct Bilirubin", "mg/dL", "0.0 - 0.3", "numeric", "", False, None),
                    ("SGOT (AST)", "U/L", "10 - 40", "numeric", "", False, None),
                    ("SGPT (ALT)", "U/L", "7 - 56", "numeric", "", False, None),
                    ("Alkaline Phosphatase", "U/L", "44 - 147", "numeric", "", False, None),
                    ("Total Protein", "g/dL", "6.0 - 8.3", "numeric", "", False, None),
                    ("Albumin", "g/dL", "3.5 - 5.0", "numeric", "", False, None),
                ],
            },
            {
                "code": "FBS", "name": "FASTING BLOOD SUGAR (FBS)", "price": 500.0,
                "dept": "Biochemistry", "specimen": "Blood (Fluoride)",
                "params": [("Fasting Blood Sugar", "mg/dL", "70 - 99", "numeric", "", False, None)],
            },
            {
                "code": "UFR", "name": "URINE FULL REPORT (UFR)", "price": 600.0,
                "dept": "Pathology", "specimen": "Urine",
                "params": [
                    ("Color", "", "Yellow / Pale", "text", "Yellow", False, None),
                    ("Appearance", "", "Clear", "text", "Clear", False, None),
                    ("Albumin", "", "Negative", "text", "Nil", False, None),
                    ("Sugar", "", "Negative", "text", "Nil", False, None),
                    ("Pus Cells", "/HPF", "0 - 5", "text", "0 - 2", False, None),
                    ("RBCs", "/HPF", "0 - 2", "text", "Nil", False, None),
                    ("Epithelial Cells", "/HPF", "Occasional", "text", "Occasional", False, None),
                ],
            },
            {
                "code": "HBA1C", "name": "HbA1c", "price": 1800.0,
                "dept": "Biochemistry", "specimen": "EDTA Blood",
                "params": [("HbA1c", "%", "4.0 - 5.6", "numeric", "", False, None)],
            },
        ]

        for item in standards:
            cursor.execute("SELECT id FROM tests WHERE test_code = ? OR LOWER(test_name) = LOWER(?) LIMIT 1",
                           (item["code"], item["name"]))
            row = cursor.fetchone()
            if row:
                test_id = row[0]
            else:
                cursor.execute("""
                    INSERT INTO tests (test_name, price, department, specimen, test_code)
                    VALUES (?, ?, ?, ?, ?)
                """, (item["name"], item["price"], item["dept"], item["specimen"], item["code"]))
                test_id = cursor.lastrowid

            for idx, (p_name, unit, ref, inp_type, def_res, calculated, calc_key) in enumerate(item["params"], 1):
                cursor.execute("SELECT id FROM test_parameters WHERE test_id = ? AND LOWER(param_name) = LOWER(?) LIMIT 1",
                               (test_id, p_name))
                existing = cursor.fetchone()
                if existing:
                    param_id = existing[0]
                    # Only update calculation metadata for the specific calculated parameters.
                    if calculated:
                        cursor.execute("""
                            UPDATE test_parameters
                            SET is_calculated = 1, calculation_key = ?
                            WHERE id = ?
                        """, (calc_key, param_id))
                    continue

                # Respect an explicit user deletion: never resurrect a
                # standard parameter the user removed via /delete-parameter.
                cursor.execute(
                    "SELECT 1 FROM deleted_standard_parameters WHERE test_id = ? AND param_name_lower = ? LIMIT 1",
                    (test_id, p_name.strip().lower())
                )
                if cursor.fetchone():
                    continue

                cursor.execute("""
                    INSERT INTO test_parameters
                    (test_id, param_name, unit, ref_range, display_order, default_result,
                     input_type, is_calculated, calculation_key)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (test_id, p_name, unit, ref, idx, def_res, inp_type,
                      1 if calculated else 0, calc_key))

        conn.commit()
    finally:
        conn.close()


def _numeric_result(results, *names):
    """Find a numeric result using tolerant parameter-name matching."""
    normalized = {re.sub(r"[^a-z0-9]+", "", str(k).lower()): v for k, v in results.items()}
    for name in names:
        key = re.sub(r"[^a-z0-9]+", "", str(name).lower())
        value = normalized.get(key)
        if value is None or str(value).strip() == "":
            continue
        try:
            return float(str(value).replace(",", "").strip())
        except (TypeError, ValueError):
            continue
    return None


def calculate_parameter_result(calculation_key, results, patient_age_years=None, patient_gender=None):
    """Central calculation engine. Returns (value, note); never invents a value."""
    tc = _numeric_result(results, "Total Cholesterol")
    tg = _numeric_result(results, "Triglycerides")
    hdl = _numeric_result(results, "HDL Cholesterol", "HDL")

    if calculation_key == "vldl":
        if tg is None or tg < 0:
            return None, "Waiting for valid Triglycerides"
        return round(tg / 5.0, 2), "Calculated from Triglycerides"

    if calculation_key == "friedewald_ldl":
        if tc is None or tg is None or hdl is None:
            return None, "Waiting for Total Cholesterol, Triglycerides and HDL"
        if tg < 0 or tc < 0 or hdl <= 0:
            return None, "Invalid lipid input"
        if tg >= 400:
            return None, "TG ≥ 400 mg/dL - direct LDL recommended"
        ldl = tc - hdl - (tg / 5.0)
        if ldl < 0:
            return None, "Calculated LDL is below zero; verify inputs"
        return round(ldl, 2), "Friedewald calculation"

    if calculation_key == "chol_hdl_ratio":
        if tc is None or hdl is None or tc < 0 or hdl <= 0:
            return None, "Waiting for valid Total Cholesterol and HDL"
        return round(tc / hdl, 2), "Total Cholesterol / HDL"

    if calculation_key == "ckd_epi_2021":
        scr = _numeric_result(results, "Serum Creatinine", "Creatinine")
        try:
            age = float(patient_age_years)
        except (TypeError, ValueError):
            age = None
        gender = normalize_patient_gender(patient_gender)
        if scr is None or scr <= 0:
            return None, "Waiting for valid Serum Creatinine"
        if age is None or age < 18:
            return None, "Adult CKD-EPI 2021 requires age ≥ 18"
        if gender == "Female":
            kappa, alpha, sex_factor = 0.7, -0.241, 1.012
        elif gender == "Male":
            kappa, alpha, sex_factor = 0.9, -0.302, 1.0
        else:
            return None, "Patient gender required for eGFR"
        ratio = scr / kappa
        egfr = 142 * (min(ratio, 1) ** alpha) * (max(ratio, 1) ** -1.200) * (0.9938 ** age) * sex_factor
        return round(egfr, 1), "CKD-EPI 2021"

    return None, "Unknown calculation"


def _patient_age_years_from_row(row):
    try:
        years = int(float(row["age_years"])) if row["age_years"] not in (None, "") else 0
    except Exception:
        years = 0
    if years:
        return years
    try:
        return int(float(row["age"])) if row["age"] not in (None, "") else 0
    except Exception:
        return 0


def calculate_and_save_derived_results(cursor, patient_id, test_id):
    """Calculate all derived parameters after manual results are saved."""
    cursor.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
    patient = cursor.fetchone()
    if not patient:
        return []

    cursor.execute("""
        SELECT tp.id, tp.param_name, tp.calculation_key
        FROM test_parameters tp
        WHERE tp.test_id = ? AND COALESCE(tp.is_calculated, 0) = 1
        ORDER BY COALESCE(tp.display_order, 0), tp.id
    """, (test_id,))
    calculated_params = cursor.fetchall()
    if not calculated_params:
        return []

    cursor.execute("""
        SELECT tp.param_name, ppr.result_value
        FROM test_parameters tp
        LEFT JOIN patient_parameter_results ppr
          ON ppr.parameter_id = tp.id
         AND ppr.patient_id = ?
         AND ppr.test_id = ?
        WHERE tp.test_id = ?
    """, (patient_id, test_id, test_id))
    results = {row[0]: row[1] for row in cursor.fetchall()}

    age_years = _patient_age_years_from_row(patient)
    gender = patient["gender"] if "gender" in patient.keys() else ""
    saved = []

    for param_id, param_name, calculation_key in calculated_params:
        value, note = calculate_parameter_result(calculation_key, results, age_years, gender)
        if value is None:
            # Clear stale auto-result only if the parameter is explicitly calculated.
            cursor.execute("""
                DELETE FROM patient_parameter_results
                WHERE patient_id = ? AND test_id = ? AND parameter_id = ?
            """, (patient_id, test_id, param_id))
            continue
        cursor.execute("""
            INSERT INTO patient_parameter_results
                (patient_id, test_id, parameter_id, result_value)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(patient_id, test_id, parameter_id)
            DO UPDATE SET result_value = excluded.result_value
        """, (patient_id, test_id, param_id, str(value)))
        results[param_name] = str(value)
        saved.append((param_name, value, note))

    return saved


# -----------------------------
# LOAD STANDARD LAB TEMPLATES ROUTE
# -----------------------------
@app.get("/load-standard-templates")
def load_standard_templates():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Safety checks to ensure all columns exist in 'tests' table
    try:
        cursor.execute("ALTER TABLE tests ADD COLUMN notes TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE tests ADD COLUMN col_alignments TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("ALTER TABLE tests ADD COLUMN test_code TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    # Ensure columns exist in 'test_parameters' table
    try:
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN default_result TEXT")
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN input_type TEXT DEFAULT 'numeric'")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    standards = [
        {
            "code": "FBC", "name": "FULL BLOOD COUNT (FBC)", "price": 1200.0, "dept": "Hematology", "specimen": "Blood (EDTA)",
            "params": [
                ("White Blood Cell (WBC)", "10^3/uL", "4.0 - 11.0", "numeric", ""),
                ("Red Blood Cell (RBC)", "10^6/uL", "4.5 - 5.5", "numeric", ""),
                ("Hemoglobin (Hb)", "g/dL", "13.0 - 17.0", "numeric", ""),
                ("Hematocrit (PCV)", "%", "40.0 - 50.0", "numeric", ""),
                ("Platelets", "10^3/uL", "150 - 450", "numeric", ""),
                ("Neutrophils", "%", "40 - 75", "numeric", ""),
                ("Lymphocytes", "%", "20 - 45", "numeric", ""),
                ("Eosinophils", "%", "1 - 6", "numeric", ""),
                ("Monocytes", "%", "2 - 10", "numeric", "")
            ]
        },
        {
            "code": "LIPID", "name": "LIPID PROFILE", "price": 2500.0, "dept": "Biochemistry", "specimen": "Blood (Serum)",
            "params": [
                ("Total Cholesterol", "mg/dL", "< 200", "numeric", ""),
                ("Triglycerides", "mg/dL", "< 150", "numeric", ""),
                ("HDL Cholesterol", "mg/dL", "> 40", "numeric", ""),
                ("LDL Cholesterol", "mg/dL", "< 100", "numeric", ""),
                ("VLDL Cholesterol", "mg/dL", "2 - 30", "numeric", "")
            ]
        },
        {
            "code": "CREAT-EGFR", "name": "CREATININE WITH eGFR", "price": 1500.0, "dept": "Biochemistry", "specimen": "Blood (Serum)",
            "params": [
                ("Serum Creatinine", "mg/dL", "0.6 - 1.3", "numeric", ""),
                ("Estimated GFR", "mL/min/1.73m²", ">= 90", "numeric", ""),
            ]
        },
        {
            "code": "LFT", "name": "LIVER FUNCTION TEST (LFT)", "price": 3000.0, "dept": "Biochemistry", "specimen": "Blood (Serum)",
            "params": [
                ("Total Bilirubin", "mg/dL", "0.2 - 1.2", "numeric", ""),
                ("Direct Bilirubin", "mg/dL", "0.0 - 0.3", "numeric", ""),
                ("SGOT (AST)", "U/L", "10 - 40", "numeric", ""),
                ("SGPT (ALT)", "U/L", "7 - 56", "numeric", ""),
                ("Alkaline Phosphatase", "U/L", "44 - 147", "numeric", ""),
                ("Total Protein", "g/dL", "6.0 - 8.3", "numeric", ""),
                ("Albumin", "g/dL", "3.5 - 5.0", "numeric", "")
            ]
        },
        {
            "code": "UFR", "name": "URINE FULL REPORT (UFR)", "price": 600.0, "dept": "Pathology", "specimen": "Urine",
            "params": [
                ("Color", "", "Yellow / Pale", "text", "Yellow"),
                ("Appearance", "", "Clear", "text", "Clear"),
                ("Albumin", "", "Negative", "text", "Nil"),
                ("Sugar", "", "Negative", "text", "Nil"),
                ("Pus Cells", "/HPF", "0 - 5", "text", "0 - 2"),
                ("RBCs", "/HPF", "0 - 2", "text", "Nil"),
                ("Epithelial Cells", "/HPF", "Occasional", "text", "Occasional")
            ]
        },
        {
            "code": "FBS", "name": "FASTING BLOOD SUGAR (FBS)", "price": 500.0, "dept": "Biochemistry", "specimen": "Blood (Fluoride)",
            "params": [
                ("Fasting Blood Sugar", "mg/dL", "70 - 99", "numeric", "")
            ]
        }
    ]

    for item in standards:
        # Check if test code exists
        cursor.execute("SELECT id FROM tests WHERE test_code = ? OR test_name = ?", (item["code"], item["name"]))
        existing = cursor.fetchone()
        
        if not existing:
            cursor.execute("""
                INSERT INTO tests (test_code, test_name, price, department, specimen, col_alignments)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (item["code"], item["name"], item["price"], item["dept"], item["specimen"], "left,center,center,left,left"))
            test_id = cursor.lastrowid
        else:
            test_id = existing[0]

        # Insert standard parameters
        for idx, (p_name, unit, ref, inp_type, def_res) in enumerate(item["params"], start=1):
            cursor.execute("""
                SELECT id FROM test_parameters WHERE test_id = ? AND param_name = ?
            """, (test_id, p_name))
            if not cursor.fetchone():
                cursor.execute("""
                    INSERT INTO test_parameters (test_id, param_name, unit, ref_range, display_order, default_result, input_type)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (test_id, p_name, unit, ref, idx, def_res, inp_type))

    conn.commit()
    conn.close()
    return RedirectResponse(url="/manage-tests", status_code=303)

# -----------------------------
# 4.1 MANAGE PARAMETERS WITH INPUT TYPE
# -----------------------------
@app.get("/manage-tests/{test_id}", response_class=HTMLResponse)
def manage_test_parameters(test_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()

    # NOTE: default_result / input_type / is_bold used to be ALTER TABLE'd
    # into existence on every single page view here (3 extra Turso round
    # trips per visit). seed_standard_tests_and_parameters() now guarantees
    # these columns exist once at process startup (see init_db/_ensure_column),
    # so that redundant per-request migration has been removed.

    cursor.execute("SELECT test_name FROM tests WHERE id = ?", (test_id,))
    test = cursor.fetchone()
    if not test:
        conn.close()
        return HTMLResponse("Test Not Found", status_code=404)
    test_name = test[0]

    cursor.execute("SELECT id, param_name, unit, ref_range, display_order, default_result, input_type, COALESCE(is_bold, 0) FROM test_parameters WHERE test_id = ? ORDER BY display_order ASC, id ASC", (test_id,))
    params = cursor.fetchall()
    conn.close()

    param_rows = ""
    for p_id, p_name, unit, ref_range, d_order, def_res, inp_type, is_bold in params:
        clean_ref = clean_display_range(ref_range, unit)
        bold_checked = "checked" if int(is_bold or 0) else ""
        type_badge = "<span style='background:#e2e8f0; color:#333; padding:2px 6px; border-radius:4px; font-size:11px;'>Numeric</span>" if inp_type == 'numeric' else "<span style='background:#fef3c7; color:#d97706; padding:2px 6px; border-radius:4px; font-size:11px;'>Text/Dropdown</span>"
        
        param_rows += f"""
        <tr>
            <td style="padding:12px; border-bottom: 1px solid #eee; text-align:center;">
                <input type="number" name="order_{p_id}" value="{d_order}" style="width:60px; padding:5px; text-align:center; border:1px solid #ccc; border-radius:4px;">
            </td>
            <td style="padding:12px; border-bottom: 1px solid #eee; font-weight: 600;">{p_name} <br>{type_badge}</td>
            <td style="padding:12px; border-bottom: 1px solid #eee; text-align:center; white-space:nowrap;">
                <label style="display:inline-flex; align-items:center; gap:6px; cursor:pointer; font-size:12px; font-weight:700; color:#334155;">
                    <input type="checkbox" name="bold_{p_id}" value="1" {bold_checked} style="width:16px; height:16px; accent-color:#0f4c81;">
                    Bold in Report
                </label>
            </td>
            <td style="padding:12px; border-bottom: 1px solid #eee; color: #555;">{unit or ""}</td>
            <td style="padding:12px; border-bottom: 1px solid #eee; color: #555;">{clean_ref}</td>
            <td style="padding:12px; border-bottom: 1px solid #eee; color: #27ae60; font-weight:bold;">{def_res or "-"}</td>
            <td style="padding:12px; border-bottom: 1px solid #eee; text-align:right; white-space:nowrap;">
                <a href="/manage-ranges/{p_id}" style="background:#2980b9; color:white; padding:6px 10px; text-decoration:none; border-radius:4px; font-size:12px; font-weight:bold; margin-right:5px;">Ranges</a>
                <a href="/edit-parameter/{p_id}" style="background:#f39c12; color:white; padding:6px 10px; text-decoration:none; border-radius:4px; font-size:12px; font-weight:bold; margin-right:5px;">Edit</a>
                <a href="/delete-parameter/{p_id}" onclick="return confirm('Delete this parameter? This will also remove any saved reference-range rules for it.');" style="background:#e74c3c; color:white; padding:6px 10px; text-decoration:none; border-radius:4px; font-size:12px; font-weight:bold;">Delete</a>
            </td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Parameters - {test_name}</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 40px; }}
            .container {{ max-width: 1100px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            h2 {{ color: #0f4c81; margin-top: 0; }}
            .back-link {{ display: inline-block; margin-bottom: 15px; color: #0f4c81; text-decoration: none; font-weight: bold; }}
            .add-box {{ background: #f8f9fa; border: 1px solid #ddd; padding: 20px; border-radius: 8px; margin-top: 25px; }}
            .row-inputs {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }}
            .row-inputs input, .row-inputs select {{ padding: 10px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/manage-tests" class="back-link">← Back to Test Categories</a>
            <h2>{test_name} - Parameters Management</h2>

            <form action="/update-param-orders" method="post">
                <input type="hidden" name="test_id" value="{test_id}">
                <table style="width:100%; border-collapse:collapse; background:white; margin-top: 20px;">
                    <tr style="background:#0f4c81; color: white; text-align:left;">
                        <th style="padding:12px; width:70px; text-align:center;">Order</th>
                        <th style="padding:12px;">Parameter Name / Type</th>
                        <th style="padding:12px; width:130px; text-align:center;">Report Style</th>
                        <th style="padding:12px; width:120px;">Unit</th>
                        <th style="padding:12px; width:200px;">Default Ref Range</th>
                        <th style="padding:12px; width:150px;">Default Result</th>
                        <th style="padding:12px; text-align:right; width:220px;">Actions</th>
                    </tr>
                    {param_rows}
                </table>
                <div style="text-align:left; margin-top:10px;">
                    <button type="submit" style="background:#34495e; color:white; border:none; padding:10px 15px; border-radius:6px; font-weight:bold; cursor:pointer;">💾 Save Parameter Order</button>
                    <span style="font-size:12px; color:#666; margin-left:10px;">(Change numbers and click Save to reorder)</span>
                </div>
            </form>

            <div class="add-box">
                <h3 style="margin-top:0; color:#0f4c81; font-size: 16px;">Add New Parameter to {test_name}</h3>
                <form action="/add-parameter" method="post">
                    <input type="hidden" name="test_id" value="{test_id}">
                    <div class="row-inputs">
                        <input type="text" name="param_name" placeholder="Parameter Name (Required)" required style="flex:2; min-width:220px;">
                        <input type="text" name="unit" placeholder="Unit (Ex: mg/dL)" style="flex:1; min-width:130px;">
                        <input type="text" name="ref_range" placeholder="Default Ref (Ex: 70 - 99)" style="flex:1; min-width:180px;">
                    </div>
                    <div class="row-inputs">
                        <input type="text" name="default_result" placeholder="Default Result (Ex: Nil, Negative)" style="flex:1; min-width:200px;">
                        <select name="input_type" style="flex:1; min-width:200px;">
                            <option value="numeric">Input Type: Numeric (Numbers)</option>
                            <option value="text">Input Type: Text / Dropdown</option>
                        </select>
                        <label style="display:flex; align-items:center; gap:8px; min-height:40px; padding:0 12px; border:1px solid #d1d5db; border-radius:6px; background:#fff; font-weight:700; color:#334155; cursor:pointer;">
                            <input type="checkbox" name="is_bold" value="1" style="width:16px; height:16px; accent-color:#0f4c81;">
                            Bold in Report
                        </label>
                        <button type="submit" style="background:#27ae60; color:white; border:none; padding:10px 20px; border-radius:6px; font-weight:bold; cursor:pointer; flex:1;">Add Parameter</button>
                    </div>
                </form>
            </div>
        </div>
    </body>
    </html>
    """

@app.post("/add-parameter")
def add_parameter(
    test_id: int = Form(...), 
    param_name: str = Form(...), 
    unit: str = Form(""), 
    ref_range: str = Form(""),
    default_result: str = Form(""),
    input_type: str = Form("numeric"),
    is_bold: int = Form(0)
):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN default_result TEXT")
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN input_type TEXT DEFAULT 'numeric'")
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN is_bold INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    cursor.execute("SELECT MAX(display_order) FROM test_parameters WHERE test_id = ?", (test_id,))
    max_order = cursor.fetchone()[0]
    next_order = (max_order + 1) if max_order is not None else 1

    cursor.execute(
        "INSERT INTO test_parameters (test_id, param_name, unit, ref_range, display_order, default_result, input_type, is_bold) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (test_id, param_name, unit, ref_range, next_order, default_result, input_type, 1 if is_bold else 0)
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/manage-tests/{test_id}", status_code=303)

# -----------------------------
# EDIT/DELETE PARAMETER ROUTES
# -----------------------------
@app.get("/edit-parameter/{param_id}", response_class=HTMLResponse)
def edit_parameter_page(param_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN is_bold INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    cursor.execute("SELECT id, test_id, param_name, unit, ref_range, default_result, input_type, COALESCE(is_bold, 0) FROM test_parameters WHERE id = ?", (param_id,))
    param = cursor.fetchone()
    conn.close()

    if not param:
        return HTMLResponse("Parameter Not Found", status_code=404)

    def sel(val, target): return "selected" if val == target else ""

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Edit Parameter</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 40px; }}
            .form-card {{ background: white; padding: 30px; border-radius: 12px; max-width: 520px; margin: auto; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            .form-card h2 {{ color: #0f4c81; margin-top: 0; }}
            .form-group {{ margin-bottom: 15px; }}
            .form-group label {{ display: block; margin-bottom: 5px; color: #555; font-weight: bold; }}
            .form-group input, .form-group select {{ width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }}
            .btn-save {{ background: #27ae60; color: white; border: none; padding: 12px; width: 100%; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; }}
            .back-link {{ display: inline-block; margin-bottom: 15px; color: #0f4c81; text-decoration: none; font-weight: bold; }}
        </style>
    </head>
    <body>
        <div class="form-card">
            <a href="/manage-tests/{param[1]}" class="back-link">← Back to Parameters</a>
            <h2>Edit Test Parameter</h2>
            <form action="/edit-parameter/{param[0]}" method="post">
                <div class="form-group">
                    <label>Parameter Name:</label>
                    <input type="text" name="param_name" value="{param[2]}" required>
                </div>
                <div class="form-group">
                    <label>Unit:</label>
                    <input type="text" name="unit" value="{param[3] if param[3] else ''}">
                </div>
                <div class="form-group">
                    <label>Default Reference Range:</label>
                    <input type="text" name="ref_range" value="{param[4] if param[4] else ''}">
                </div>
                <div class="form-group">
                    <label>Default Result (e.g. Nil, Negative):</label>
                    <input type="text" name="default_result" value="{param[5] if param[5] else ''}">
                </div>
                <div class="form-group">
                    <label>Input Type:</label>
                    <select name="input_type">
                        <option value="numeric" {sel(param[6], 'numeric')}>Numeric (Numbers only)</option>
                        <option value="text" {sel(param[6], 'text')}>Text / Dropdown (Words)</option>
                    </select>
                </div>
                <div class="form-group">
                    <label style="display:flex; align-items:center; gap:8px; cursor:pointer;">
                        <input type="checkbox" name="is_bold" value="1" {'checked' if int(param[7] or 0) else ''} style="width:17px; height:17px; accent-color:#0f4c81;">
                        <span>Show this parameter name in <strong>bold</strong> on the laboratory report</span>
                    </label>
                </div>
                <button type="submit" class="btn-save">Update Parameter</button>
            </form>
        </div>
    </body>
    </html>
    """

@app.post("/edit-parameter/{param_id}")
def update_parameter(
    param_id: int, 
    param_name: str = Form(...), 
    unit: str = Form(""), 
    ref_range: str = Form(""), 
    default_result: str = Form(""),
    input_type: str = Form("numeric"),
    is_bold: int = Form(0)
):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT test_id FROM test_parameters WHERE id = ?", (param_id,))
    res = cursor.fetchone()
    test_id = res[0] if res else 1

    cursor.execute(
        "UPDATE test_parameters SET param_name = ?, unit = ?, ref_range = ?, default_result = ?, input_type = ?, is_bold = ? WHERE id = ?",
        (param_name, unit, ref_range, default_result, input_type, 1 if is_bold else 0, param_id)
    )
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/manage-tests/{test_id}", status_code=303)


@app.post("/delete-test/{test_id}")
def delete_test(test_id: int):
    """
    Permanently deletes a test category only after the UI's explicit
    two-step confirmation. Related parameter rules/results/assignments
    are cleaned in the same SQLite transaction.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT test_name FROM tests WHERE id = ?", (test_id,))
        if not cursor.fetchone():
            conn.close()
            return RedirectResponse(url="/manage-tests", status_code=303)

        # Delete dependent data when the corresponding tables exist.
        cleanup_statements = [
            ("DELETE FROM param_ref_ranges WHERE param_id IN (SELECT id FROM test_parameters WHERE test_id = ?)", (test_id,)),
            ("DELETE FROM patient_parameter_results WHERE test_id = ?", (test_id,)),
            ("DELETE FROM report_results WHERE report_id IN (SELECT id FROM reports WHERE test_id = ?)", (test_id,)),
            ("DELETE FROM reports WHERE test_id = ?", (test_id,)),
            ("DELETE FROM results WHERE test_id = ?", (test_id,)),
            ("DELETE FROM patient_assigned_tests WHERE test_id = ?", (test_id,)),
            ("DELETE FROM test_parameters WHERE test_id = ?", (test_id,)),
            ("DELETE FROM tests WHERE id = ?", (test_id,))
        ]

        for statement, params in cleanup_statements:
            try:
                cursor.execute(statement, params)
            except sqlite3.OperationalError as exc:
                # Older databases may not have optional compatibility tables.
                if "no such table" not in str(exc).lower():
                    raise

        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    return RedirectResponse(url="/manage-tests", status_code=303)


@app.get("/delete-parameter/{param_id}")
def delete_parameter(param_id: int):
    """
    Deletes a test parameter and cleans up everything that references it
    (its reference-range rules and any previously saved patient results),
    so the parent test's parameter list stays consistent.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    # Work out which test this parameter belongs to (and its name, for the
    # tombstone below) so we can redirect back to it.
    cursor.execute("SELECT test_id, param_name FROM test_parameters WHERE id = ?", (param_id,))
    row = cursor.fetchone()
    test_id = row[0] if row else None

    if row:
        param_name = row[1] or ""
        # Tombstone this (test_id, name) pair permanently, so the standard-
        # test seeder (which runs again on every cold start) never
        # re-inserts it after the user explicitly deleted it. This is the
        # actual fix for "deleted parameters still show up" - without this,
        # a parameter that matches a seeded standard test's parameter list
        # would silently reappear the next time the app cold-starts.
        try:
            cursor.execute(
                "INSERT OR IGNORE INTO deleted_standard_parameters (test_id, param_name_lower, deleted_at) VALUES (?, ?, ?)",
                (test_id, param_name.strip().lower(), now_colombo().isoformat())
            )
        except sqlite3.OperationalError:
            pass

        # Remove any age/gender reference-range rules tied to this parameter.
        cursor.execute("DELETE FROM param_ref_ranges WHERE param_id = ?", (param_id,))

        # Remove any saved patient results tied to this parameter, if that table exists.
        try:
            cursor.execute("DELETE FROM patient_parameter_results WHERE parameter_id = ?", (param_id,))
        except sqlite3.OperationalError:
            pass

        # Finally remove the parameter itself.
        cursor.execute("DELETE FROM test_parameters WHERE id = ?", (param_id,))
        conn.commit()

    conn.close()

    if test_id:
        return RedirectResponse(url=f"/manage-tests/{test_id}", status_code=303)
    return RedirectResponse(url="/manage-tests", status_code=303)


@app.post("/update-param-orders")
async def update_param_orders(request: Request):
    """
    Saves the display order typed into the parameter list on the
    'Manage Parameters' page (the form referenced by manage_test_parameters).
    """
    form_data = await request.form()
    test_id_raw = form_data.get("test_id")
    # Bind a real int (not the raw form string) for every test_id
    # comparison below, removing any ambiguity about how the underlying
    # driver compares a TEXT-typed bound parameter against an INTEGER
    # column. test_id keeps its original (possibly-None/invalid) form
    # so the existing "if test_id" fallbacks below still behave the same.
    try:
        test_id = int(test_id_raw)
    except (TypeError, ValueError):
        test_id = None

    conn = get_db_connection()
    cursor = conn.cursor()

    # NOTE: is_bold is now guaranteed to exist by
    # seed_standard_tests_and_parameters() at process startup, so the
    # per-request ALTER TABLE that used to live here has been removed.

    # Rebuild the order deterministically.  The old implementation accepted
    # duplicate order numbers (e.g. 1,1,2,3), so SQLite could still return
    # parameters in an unexpected order.  We now sort the submitted values,
    # then rewrite display_order as a unique sequence 1..N.
    submitted = []
    for key, value in form_data.items():
        if not key.startswith("order_"):
            continue
        param_id = key.split("_", 1)[1]
        try:
            order_val = int(value)
            param_id_int = int(param_id)
        except (ValueError, TypeError):
            continue
        submitted.append((order_val, param_id_int))

    submitted.sort(key=lambda x: (x[0], x[1]))

    # Only parameters belonging to this test may be reordered.
    valid_rows = cursor.execute(
        "SELECT id FROM test_parameters WHERE test_id = ?",
        (test_id,)
    ).fetchall() if test_id else []

    valid_ids = {int(row[0]) for row in valid_rows}
    ordered_ids = []
    seen = set()

    for _, param_id in submitted:
        if param_id in valid_ids and param_id not in seen:
            ordered_ids.append(param_id)
            seen.add(param_id)

    # Preserve any parameters omitted by the form.
    remaining = cursor.execute(
        "SELECT id FROM test_parameters WHERE test_id = ? "
        "ORDER BY COALESCE(display_order, 0), id",
        (test_id,)
    ).fetchall() if test_id else []

    for row in remaining:
        pid = int(row[0])
        if pid not in seen:
            ordered_ids.append(pid)
            seen.add(pid)

    for new_order, param_id in enumerate(ordered_ids, start=1):
        cursor.execute(
            "UPDATE test_parameters SET display_order = ?, is_bold = ? WHERE id = ? AND test_id = ?",
            (new_order, 1 if form_data.get(f"bold_{param_id}") else 0, param_id, test_id)
        )

    conn.commit()
    conn.close()

    if test_id:
        return RedirectResponse(url=f"/manage-tests/{test_id}", status_code=303)
    return RedirectResponse(url="/manage-tests", status_code=303)

    # -----------------------------
# ADD MAIN TEST CATEGORY ROUTE
# -----------------------------
@app.post("/add-main-test")
def add_main_test(
    test_code: str = Form(""),
    test_name: str = Form(...), 
    price: float = Form(0.0), 
    department: str = Form(""), 
    specimen: str = Form(""), 
    notes: str = Form(""),
    show_fia_graph: Optional[str] = Form(None),
    align_inv: str = Form("left"),
    align_res: str = Form("center"),
    align_flag: str = Form("center"),
    align_unit: str = Form("left"),
    align_ref: str = Form("left"),
    width_inv: float = Form(38), width_res: float = Form(13), width_flag: float = Form(8),
    width_unit: float = Form(14), width_ref: float = Form(27)
):
    alignments = f"{align_inv},{align_res},{align_flag},{align_unit},{align_ref},{width_inv},{width_res},{width_flag},{width_unit},{width_ref}"
    conn = get_db_connection()
    cursor = conn.cursor()

    # Safety checks for columns — each ALTER TABLE guarded independently.
    # Chaining these in a single try/except is unsafe with libsql: once any
    # one column already exists, its "duplicate column" error (raised as
    # ValueError, aliased above to sqlite3.OperationalError) aborts the
    # whole block, so later ALTERs never get a chance to run. Each column
    # gets its own try/except so the others always still get applied.
    try:
        cursor.execute("ALTER TABLE tests ADD COLUMN notes TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE tests ADD COLUMN col_alignments TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE tests ADD COLUMN test_code TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass
    try:
        cursor.execute("ALTER TABLE tests ADD COLUMN show_fia_graph INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("""
            INSERT INTO tests (test_code, test_name, price, department, specimen, notes, col_alignments, show_fia_graph) 
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (test_code.upper(), test_name.upper(), price, department, specimen, notes, alignments, 1 if show_fia_graph else 0))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    conn.close()
    return RedirectResponse(url="/manage-tests", status_code=303)

# -----------------------------
# EDIT TEST CATEGORY INFO ROUTES
# -----------------------------
@app.get("/edit-test-category/{test_id}", response_class=HTMLResponse)
def edit_test_category_page(test_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Ensure every column this page reads actually exists, independent of
    # whether /add-main-test has ever run. Each guarded separately so one
    # already-existing column never blocks the others (see /add-main-test
    # for why chaining these in a single try/except is unsafe with libsql).
    for col_def in ("notes TEXT", "col_alignments TEXT", "test_code TEXT", "show_fia_graph INTEGER DEFAULT 0"):
        try:
            cursor.execute(f"ALTER TABLE tests ADD COLUMN {col_def}")
            conn.commit()
        except sqlite3.OperationalError:
            pass

    cursor.execute("SELECT test_name, price, department, specimen, notes, col_alignments, test_code, COALESCE(show_fia_graph, 0) FROM tests WHERE id = ?", (test_id,))
    test = cursor.fetchone()
    conn.close()

    if not test:
        return HTMLResponse("Test Not Found", status_code=404)

    aligns = test[5].split(',') if test[5] else ['left','center','center','left','left','38','13','8','14','27']
    if len(aligns) < 5: aligns = ['left','center','center','left','left'] + aligns[5:]
    default_widths = ['38','13','8','14','27']
    if len(aligns) < 10: aligns += default_widths[len(aligns)-5:]
    aligns = aligns[:10]

    def sel(val, target): return "selected" if val == target else ""

    notes_value = test[4] if test[4] else ""
    price_value = test[1] if test[1] is not None else 0.0
    department_value = test[2] if test[2] else ""
    specimen_value = test[3] if test[3] else ""
    test_code_value = test[6] if test[6] else ""
    show_fia_graph_value = bool(test[7]) if len(test) > 7 else False

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Edit Test Category</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 40px; }}
            .container {{ max-width: 700px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            h2 {{ color: #0f4c81; margin-top: 0; }}
            .back-link {{ display: inline-block; margin-bottom: 15px; color: #0f4c81; text-decoration: none; font-weight: bold; }}
            .form-group {{ margin-bottom: 15px; }}
            label {{ display: block; margin-bottom: 5px; color: #555; font-weight: bold; }}
            input, textarea, select {{ width: 100%; padding: 10px; border: 1px solid #ccc; border-radius: 6px; box-sizing: border-box; }}
            textarea {{ min-height: 100px; resize: vertical; }}
            .row {{ display: flex; gap: 10px; margin-bottom: 15px; }}
            .row > div {{ flex: 1; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/manage-tests" class="back-link">← Back to Categories</a>
            <h2>Edit Category: {test[0]}</h2>
            
            <form action="/edit-test-category/{test_id}" method="post">
                <div class="row">
                    <div style="flex: 1;">
                        <label>Test Code:</label>
                        <input type="text" name="test_code" value="{test_code_value}">
                    </div>
                    <div style="flex: 2;">
                        <label>Test Category Name:</label>
                        <input type="text" name="test_name" value="{test[0]}" required>
                    </div>
                </div>
                <div class="row">
                    <div>
                        <label>Price (Rs):</label>
                        <input type="number" step="0.01" name="price" value="{price_value}">
                    </div>
                    <div>
                        <label>Department:</label>
                        <input type="text" name="department" value="{department_value}">
                    </div>
                    <div>
                        <label>Specimen:</label>
                        <input type="text" name="specimen" value="{specimen_value}">
                    </div>
                </div>
                <div class="form-group">
                    <label>Notes / Details (Appears below print results):</label>
                    <textarea name="notes">{notes_value}</textarea>
                </div>
                <div class="form-group" style="padding:10px 12px;border:1px solid #dbeafe;background:#f8fbff;border-radius:7px;">
                    <label style="display:flex;align-items:center;gap:8px;margin:0;color:#0f4c81;">
                        <input type="checkbox" name="show_fia_graph" value="1" style="width:18px;height:18px;" {"checked" if show_fia_graph_value else ""}>
                        Show FIA Graph on final report for this test
                    </label>
                </div>

                <div class="form-group" style="background:#f9f9f9; padding:15px; border-radius:8px; border:1px solid #eee;">
                    <label style="color:#0f4c81;">Report Column Alignments & Widths:</label>
                    <div class="row" style="margin-bottom:0; margin-top:10px;">
                        <div>
                            <small>Investigation</small>
                            <select name="align_inv"><option value="left" {sel(aligns[0],'left')}>Left</option><option value="center" {sel(aligns[0],'center')}>Center</option><option value="right" {sel(aligns[0],'right')}>Right</option><option value="none" {sel(aligns[0],'none')}>Hide / None</option></select>
                        </div>
                        <div>
                            <small>Result</small>
                            <select name="align_res"><option value="left" {sel(aligns[1],'left')}>Left</option><option value="center" {sel(aligns[1],'center')}>Center</option><option value="right" {sel(aligns[1],'right')}>Right</option><option value="none" {sel(aligns[1],'none')}>Hide / None</option></select>
                        </div>
                        <div>
                            <small>Flag</small>
                            <select name="align_flag"><option value="left" {sel(aligns[2],'left')}>Left</option><option value="center" {sel(aligns[2],'center')}>Center</option><option value="right" {sel(aligns[2],'right')}>Right</option><option value="none" {sel(aligns[2],'none')}>Hide / None</option></select>
                        </div>
                        <div>
                            <small>Unit</small>
                            <select name="align_unit"><option value="left" {sel(aligns[3],'left')}>Left</option><option value="center" {sel(aligns[3],'center')}>Center</option><option value="right" {sel(aligns[3],'right')}>Right</option><option value="none" {sel(aligns[3],'none')}>Hide / None</option></select>
                        </div>
                        <div>
                            <small>Ref Range</small>
                            <select name="align_ref"><option value="left" {sel(aligns[4],'left')}>Left</option><option value="center" {sel(aligns[4],'center')}>Center</option><option value="right" {sel(aligns[4],'right')}>Right</option><option value="none" {sel(aligns[4],'none')}>Hide / None</option></select>
                        </div>
                    </div>
                    <div class="row" style="margin-top:8px; margin-bottom:0;">
                        <div><small>Investigation Width</small><input type="number" name="width_inv" value="{aligns[5]}" min="1" max="100" step="1"></div>
                        <div><small>Result Width</small><input type="number" name="width_res" value="{aligns[6]}" min="1" max="100" step="1"></div>
                        <div><small>Flag Width</small><input type="number" name="width_flag" value="{aligns[7]}" min="1" max="100" step="1"></div>
                        <div><small>Unit Width</small><input type="number" name="width_unit" value="{aligns[8]}" min="1" max="100" step="1"></div>
                        <div><small>Ref Range Width</small><input type="number" name="width_ref" value="{aligns[9]}" min="1" max="100" step="1"></div>
                    </div>
                    <div style="font-size:11px;color:#777;margin-top:5px;">Higher value = more space. Hidden columns are removed and remaining columns automatically expand to fill the report width.</div>
                </div>

                <button type="submit" style="background:#27ae60; color:white; border:none; padding:12px; width:100%; border-radius:6px; font-weight:bold; cursor:pointer; font-size:16px;">Update Category</button>
            </form>
        </div>
    </body>
    </html>
    """

@app.post("/edit-test-category/{test_id}")
def update_test_category(
    test_id: int,
    test_code: str = Form(""),
    test_name: str = Form(...), price: float = Form(0.0), 
    department: str = Form(""), specimen: str = Form(""), notes: str = Form(""),
    show_fia_graph: Optional[str] = Form(None),
    align_inv: str = Form("left"), align_res: str = Form("center"),
    align_flag: str = Form("center"), align_unit: str = Form("left"), align_ref: str = Form("left"),
    width_inv: float = Form(38), width_res: float = Form(13), width_flag: float = Form(8),
    width_unit: float = Form(14), width_ref: float = Form(27)
):
    alignments = f"{align_inv},{align_res},{align_flag},{align_unit},{align_ref},{width_inv},{width_res},{width_flag},{width_unit},{width_ref}"
    conn = get_db_connection()
    cursor = conn.cursor()

    # Same independent per-column guards as the GET page and /add-main-test,
    # so saving never fails with "no such column" regardless of DB history.
    for col_def in ("notes TEXT", "col_alignments TEXT", "test_code TEXT", "show_fia_graph INTEGER DEFAULT 0"):
        try:
            cursor.execute(f"ALTER TABLE tests ADD COLUMN {col_def}")
            conn.commit()
        except sqlite3.OperationalError:
            pass

    # Confirm the row still exists before updating, so a stale/bad test_id
    # gives a clear message instead of a silent no-op update.
    cursor.execute("SELECT id FROM tests WHERE id = ?", (test_id,))
    if not cursor.fetchone():
        conn.close()
        return HTMLResponse(f"<h3>Test category #{test_id} not found.</h3><a href='/manage-tests'>Back</a>", status_code=404)

    try:
        cursor.execute("""
            UPDATE tests 
            SET test_code = ?, test_name = ?, price = ?, department = ?, specimen = ?, notes = ?, col_alignments = ?, show_fia_graph = ?
            WHERE id = ?
        """, (test_code.upper(), test_name.upper(), price, department, specimen, notes, alignments, 1 if show_fia_graph else 0, test_id))
        conn.commit()
    except sqlite3.IntegrityError:
        # test_name is UNIQUE - another category already has this exact
        # name. Fail gracefully instead of a raw 500 error.
        conn.close()
        return HTMLResponse(
            f"<h3>Could not update: another test category is already named '{html.escape(test_name.upper())}'.</h3>"
            f"<a href='/edit-test-category/{test_id}'>Go Back and Try Again</a>",
            status_code=409
        )
    conn.close()
    return RedirectResponse(url="/manage-tests", status_code=303)



# -----------------------------
# MANAGE RANGE RULES (Age+Gender) - (Unchanged)
# -----------------------------
@app.get("/manage-ranges/{param_id}", response_class=HTMLResponse)
def manage_ranges(param_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT tp.id, tp.test_id, tp.param_name, tp.unit, tp.ref_range, t.test_name
        FROM test_parameters tp
        JOIN tests t ON tp.test_id = t.id
        WHERE tp.id = ?
    """, (param_id,))
    param = cursor.fetchone()
    if not param:
        conn.close()
        return HTMLResponse("Parameter not found", status_code=404)

    cursor.execute("""
        SELECT id, gender, age_from_days, age_to_days, low, high
        FROM param_ref_ranges
        WHERE param_id = ?
        ORDER BY gender, age_from_days
    """, (param_id,))
    rules = cursor.fetchall()
    conn.close()

    rule_rows = ""
    for rid, gender, a_from, a_to, low, high in rules:
        rule_rows += f"""
        <tr>
            <td style="padding:10px; border-bottom:1px solid #eee;">{gender}</td>
            <td style="padding:10px; border-bottom:1px solid #eee;">{days_to_age_str(a_from)}</td>
            <td style="padding:10px; border-bottom:1px solid #eee;">{days_to_age_str(a_to)}</td>
            <td style="padding:10px; border-bottom:1px solid #eee;">{bounds_to_ref_text(low, high)}</td>
            <td style="padding:10px; border-bottom:1px solid #eee; text-align:right;">
                <a href="/delete-range/{rid}?param_id={param_id}" onclick="return confirm('Delete this range rule?');"
                   style="background:#e74c3c; color:#fff; padding:6px 10px; text-decoration:none; border-radius:4px; font-size:12px; font-weight:bold;">Delete</a>
            </td>
        </tr>
        """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Manage Ranges - {param[2]}</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 40px; }}
            .container {{ max-width: 980px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.1); }}
            h2 {{ color: #0f4c81; margin-top: 0; }}
            .back-link {{ display: inline-block; margin-bottom: 15px; color: #0f4c81; text-decoration: none; font-weight: bold; }}
            .info {{ background:#eaf3fb; padding:12px 14px; border-radius:8px; margin: 15px 0; color:#0f4c81; font-weight:bold; }}
            .box {{ background:#f8f9fa; border:1px solid #ddd; padding:18px; border-radius:10px; margin-top:18px; }}
            .row {{ display:flex; gap:10px; flex-wrap:wrap; }}
            .row > div {{ flex:1; min-width:140px; }}
            label {{ display:block; font-weight:bold; color:#555; margin-bottom:6px; }}
            input, select {{ width:100%; padding:10px; border:1px solid #ccc; border-radius:6px; box-sizing:border-box; }}
            button {{ background:#27ae60; color:white; border:none; padding:12px 18px; border-radius:6px; font-weight:bold; cursor:pointer; }}
            table {{ width:100%; border-collapse:collapse; margin-top:15px; }}
            th {{ background:#0f4c81; color:#fff; text-align:left; padding:10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a class="back-link" href="/manage-tests/{param[1]}">Back to Parameters</a>
            <h2>Reference Range Rules</h2>

            <div class="info">
                Test: {param[5]}<br>
                Parameter: {param[2]} &nbsp;&nbsp; Unit: {param[3] or ""}<br>
                Default Ref (fallback): {clean_display_range(param[4], param[3])}
            </div>

            <div class="box">
                <h3 style="margin-top:0; color:#0f4c81;">Add New Rule</h3>
                <form action="/add-range" method="post">
                    <input type="hidden" name="param_id" value="{param_id}">
                    <div class="row">
                        <div>
                            <label>Gender</label>
                            <select name="gender">
                                <option value="Both">Both</option>
                                <option value="Male">Male</option>
                                <option value="Female">Female</option>
                            </select>
                        </div>
                        <div>
                            <label>Age From (Y)</label>
                            <input type="number" name="from_y" min="0" value="0">
                        </div>
                        <div>
                            <label>Age From (M)</label>
                            <input type="number" name="from_m" min="0" max="11" value="0">
                        </div>
                        <div>
                            <label>Age From (D)</label>
                            <input type="number" name="from_d" min="0" max="30" value="0">
                        </div>
                        <div>
                            <label>Age To (Y)</label>
                            <input type="number" name="to_y" min="0" value="200">
                        </div>
                        <div>
                            <label>Age To (M)</label>
                            <input type="number" name="to_m" min="0" max="11" value="0">
                        </div>
                        <div>
                            <label>Age To (D)</label>
                            <input type="number" name="to_d" min="0" max="30" value="0">
                        </div>
                    </div>

                    <div class="row" style="margin-top:12px;">
                        <div>
                            <label>Low (optional)</label>
                            <input type="number" step="0.01" name="low" placeholder="Ex: 70">
                        </div>
                        <div>
                            <label>High (optional)</label>
                            <input type="number" step="0.01" name="high" placeholder="Ex: 99">
                        </div>
                        <div style="display:flex; align-items:flex-end;">
                            <button type="submit" style="width:100%;">Add Rule</button>
                        </div>
                    </div>
                    <p style="margin:10px 0 0; color:#666; font-size:12px;">
                        Note: Low/High දෙකෙන් එකක් හෝ දෙකම දෙන්න. (e.g. only High = "&lt; High", only Low = "&gt; Low")
                    </p>
                </form>
            </div>

            <div class="box">
                <h3 style="margin-top:0; color:#0f4c81;">Existing Rules</h3>
                <table>
                    <tr>
                        <th>Gender</th>
                        <th>Age From</th>
                        <th>Age To</th>
                        <th>Range</th>
                        <th style="text-align:right;">Action</th>
                    </tr>
                    {rule_rows if rule_rows else '<tr><td colspan="5" style="padding:12px; color:#666;">No rules yet. Default ref-range will be used.</td></tr>'}
                </table>
            </div>
        </div>
    </body>
    </html>
    """

@app.post("/add-range")
def add_range(
    param_id: int = Form(...),
    gender: str = Form("Both"),
    from_y: int = Form(0),
    from_m: int = Form(0),
    from_d: int = Form(0),
    to_y: int = Form(200),
    to_m: int = Form(0),
    to_d: int = Form(0),
    low: str = Form(""),
    high: str = Form("")
):
    age_from_days = age_parts_to_days(from_y, from_m, from_d)
    age_to_days = age_parts_to_days(to_y, to_m, to_d)
    if age_to_days < age_from_days:
        age_from_days, age_to_days = age_to_days, age_from_days

    low_v = parse_optional_float(low)
    high_v = parse_optional_float(high)

    if low_v is None and high_v is None:
        return RedirectResponse(url=f"/manage-ranges/{param_id}", status_code=303)

    if gender not in ("Male", "Female", "Both"):
        gender = "Both"

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO param_ref_ranges (param_id, gender, age_from_days, age_to_days, low, high)
        VALUES (?, ?, ?, ?, ?, ?)
    """, (param_id, gender, age_from_days, age_to_days, low_v, high_v))
    conn.commit()
    conn.close()

    return RedirectResponse(url=f"/manage-ranges/{param_id}", status_code=303)


@app.get("/delete-range/{range_id}")
def delete_range(range_id: int, param_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM param_ref_ranges WHERE id = ?", (range_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/manage-ranges/{param_id}", status_code=303)



@app.get("/select-patient", response_class=HTMLResponse)
def select_patient(search: str = "", selected_patient_id: int = None, status: str = "all"):
    """Result Entry: pick a patient and jump straight into their results.

    Status is computed from the REAL result tables (patient_assigned_tests.result
    and patient_parameter_results) - the old version joined the unused `reports`
    table, so every patient stayed "Pending" forever after results were saved.
    """
    status = status if status in ("all", "pending", "partial", "done") else "all"
    conn = get_db_connection()
    cursor = conn.cursor()

    where_sql = "WHERE (p.is_cancelled IS NULL OR p.is_cancelled = 0)"
    params = []
    if search and search.strip():
        term = f"%{search.strip()}%"
        where_sql += " AND (p.name LIKE ? OR p.phone LIKE ? OR CAST(p.id AS TEXT) LIKE ? OR p.manual_bill_no LIKE ?)"
        params += [term, term, term, term]

    cursor.execute(f"""
        SELECT p.id, p.title, p.name, p.age_years, p.age_months, p.age_days, p.gender, p.phone, p.created_at
        FROM patients p {where_sql}
        ORDER BY p.id DESC LIMIT 150
    """, params)
    patients = cursor.fetchall()
    ids = [r["id"] for r in patients]

    tests_by_patient = {}
    done_pairs = set()
    if ids:
        ph = ",".join("?" for _ in ids)
        cursor.execute(f"""
            SELECT pat.patient_id, pat.test_id, pat.result,
                   COALESCE(NULLIF(t.test_code, ''), t.test_name, 'Test') AS label
            FROM patient_assigned_tests pat
            LEFT JOIN tests t ON t.id = pat.test_id
            WHERE pat.patient_id IN ({ph})
            ORDER BY pat.id
        """, ids)
        for r in cursor.fetchall():
            tests_by_patient.setdefault(r["patient_id"], []).append((r["test_id"], str(r["label"]), r["result"]))
        cursor.execute(f"""
            SELECT DISTINCT patient_id, test_id FROM patient_parameter_results
            WHERE patient_id IN ({ph}) AND result_value IS NOT NULL AND TRIM(result_value) != ''
        """, ids)
        for r in cursor.fetchall():
            done_pairs.add((r["patient_id"], r["test_id"]))
    conn.close()

    def _has_text(v):
        txt = re.sub(r"<[^>]*>", "", str(v or "")).replace("&nbsp;", "").strip()
        return bool(txt) and txt.lower() != "none"

    counts = {"all": 0, "pending": 0, "partial": 0, "done": 0}
    cards = []
    for row in patients:
        tests = tests_by_patient.get(row["id"], [])
        total = len(tests)
        finished = sum(1 for (tid, _l, res) in tests if _has_text(res) or (row["id"], tid) in done_pairs)
        if total == 0:
            st = "pending"
        elif finished >= total:
            st = "done"
        elif finished == 0:
            st = "pending"
        else:
            st = "partial"
        counts["all"] += 1
        counts[st] += 1
        if status != "all" and st != status:
            continue
        if len(cards) >= 40:
            continue

        badge = {
            "done": ("#16a34a", "&#10003; Completed"),
            "partial": ("#f59e0b", "&#9201; Partial"),
            "pending": ("#e74c3c", "&#9203; Pending"),
        }[st]
        age_str = f"{row['age_years'] or 0}Y {row['age_months'] or 0}M {row['age_days'] or 0}D"
        chips = "".join(
            f'<span class="chip{" ok" if (_r and _has_text(_r)) or (row["id"], _t) in done_pairs else ""}">{html.escape(_l)}</span>'
            for (_t, _l, _r) in tests
        ) or '<span style="color:#94a3b8;font-size:12px;">No tests assigned</span>'
        date_str = str(row["created_at"] or "").split("T")[0].split(" ")[0]
        cards.append(f"""
        <a class="pt-row" href="/patient-results/{row['id']}">
            <div class="pt-main">
                <div class="pt-name">{html.escape(((row['title'] or '') + ' ' + (row['name'] or '')).strip())}
                    <span class="pt-ref">#{row['id']}</span></div>
                <div class="pt-meta">Age: {age_str} &nbsp;|&nbsp; {html.escape(row['gender'] or '-')} &nbsp;|&nbsp; Ph: {html.escape(row['phone'] or 'N/A')} &nbsp;|&nbsp; {date_str}</div>
                <div class="pt-chips">{chips}</div>
            </div>
            <div class="pt-side">
                <span class="pt-badge" style="background:{badge[0]};">{badge[1]} ({finished}/{total})</span>
                <span class="pt-go">Enter Result &rarr;</span>
            </div>
        </a>""")

    def _tab(key, label):
        qs = f"status={key}" + (f"&search={quote(search)}" if search else "")
        active = " active" if status == key else ""
        return f'<a class="tab{active}" href="/select-patient?{qs}">{label} <b>{counts[key]}</b></a>'

    empty = '<div style="padding:34px; text-align:center; color:#94a3b8;">No patients found.</div>'
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Result Entry</title>
        <style>
            .re-wrap {{ max-width: 980px; margin: auto; }}
            .re-card {{ background:#fff; border:1px solid #e2e8f0; border-radius:14px; padding:20px; box-shadow:0 4px 15px rgba(0,0,0,0.06); }}
            .re-card h2 {{ margin:0 0 4px; color:#0f4c81; font-size:20px; }}
            .re-sub {{ color:#64748b; font-size:13px; margin-bottom:14px; }}
            .re-search {{ display:flex; gap:8px; margin-bottom:12px; }}
            .re-search input {{ flex:1; min-width:0; padding:11px 14px; border:1px solid #cbd5e1; border-radius:10px; font-size:14px; }}
            .re-search button {{ background:#0f4c81; color:#fff; border:0; border-radius:10px; padding:0 20px; font-weight:700; cursor:pointer; }}
            .tabs {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:12px; }}
            .tab {{ padding:7px 14px; border-radius:20px; background:#e2e8f0; color:#334155; text-decoration:none; font-size:13px; font-weight:700; }}
            .tab b {{ background:rgba(0,0,0,.08); border-radius:10px; padding:1px 8px; margin-left:4px; font-size:12px; }}
            .tab.active {{ background:#0f4c81; color:#fff; }}
            .tab.active b {{ background:rgba(255,255,255,.25); }}
            .pt-list {{ border:1px solid #e2e8f0; border-radius:12px; overflow:hidden; }}
            .pt-row {{ display:flex; justify-content:space-between; align-items:center; gap:12px; padding:13px 16px; border-bottom:1px solid #eef2f7; text-decoration:none; color:inherit; background:#fff; }}
            .pt-row:last-child {{ border-bottom:0; }}
            .pt-row:hover {{ background:#f1f6ff; }}
            .pt-name {{ font-size:15.5px; font-weight:700; color:#0f172a; }}
            .pt-ref {{ color:#0f4c81; font-size:12px; margin-left:6px; }}
            .pt-meta {{ font-size:12.5px; color:#64748b; margin-top:3px; }}
            .pt-chips {{ margin-top:6px; display:flex; gap:5px; flex-wrap:wrap; }}
            .chip {{ background:#fee2e2; color:#b91c1c; border-radius:6px; padding:2px 8px; font-size:11.5px; font-weight:700; }}
            .chip.ok {{ background:#dcfce7; color:#15803d; }}
            .pt-side {{ display:flex; flex-direction:column; align-items:flex-end; gap:6px; flex-shrink:0; }}
            .pt-badge {{ color:#fff; border-radius:20px; padding:4px 12px; font-size:12px; font-weight:700; white-space:nowrap; }}
            .pt-go {{ color:#0f4c81; font-size:12.5px; font-weight:700; }}
            @media (max-width:640px) {{ .pt-row {{ flex-direction:column; align-items:flex-start; }} .pt-side {{ flex-direction:row; align-items:center; }} }}
        </style>
    </head>
    <body>
        <div class="re-wrap"><div class="re-card">
            <h2>Result Entry</h2>
            <div class="re-sub">Tap a patient to enter results, then save and print. Status updates automatically from the saved results.</div>
            <form class="re-search" method="get" action="/select-patient">
                <input type="hidden" name="status" value="{status}">
                <input type="text" name="search" value="{html.escape(search or '')}" placeholder="Search name, phone, ref no or bill no..." autofocus>
                <button type="submit">Search</button>
            </form>
            <div class="tabs">
                {_tab('all', 'All')}{_tab('pending', 'Pending')}{_tab('partial', 'Partial')}{_tab('done', 'Completed')}
            </div>
            <div class="pt-list">{''.join(cards) if cards else empty}</div>
            <div style="font-size:12px;color:#94a3b8;margin-top:10px;">Showing the latest {counts['all']} matching patients (max 40 per tab).</div>
        </div></div>
    </body>
    </html>
    """


@app.get("/enter-results", response_class=HTMLResponse)
def enter_results_compat(patient_id: Optional[int] = None, test_id: Optional[int] = None):
    """Compatibility entry point used by older buttons/links."""
    if patient_id is None:
        return RedirectResponse(url="/patients-dashboard", status_code=303)
    if test_id is not None:
        return RedirectResponse(url=f"/test-entry/{patient_id}/{test_id}", status_code=303)
    return RedirectResponse(url=f"/patient-results/{patient_id}", status_code=303)



# -------------------------------------------------------------
# 2. DEDICATED TEST ENTRY & PRINT PAGE (With Lock & Reset Unlock Mechanism)
# -------------------------------------------------------------
@app.post("/reset-test-results/{patient_id}/{test_id}")
async def reset_test_results(patient_id: int, test_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # ඩේටාබේස් එකෙන් අදාළ ටෙස්ට් එකේ පරාමිතීන් සහ රිසාල්ට් මකා දමා අන්ලොක් කිරීම
    cursor.execute("DELETE FROM patient_parameter_results WHERE patient_id = ? AND test_id = ?", (patient_id, test_id))
    cursor.execute("UPDATE patient_assigned_tests SET result = NULL WHERE patient_id = ? AND test_id = ?", (patient_id, test_id))
    
    conn.commit()
    conn.close()
    
    # නැවතත් ඒ පේජ් එකටම රීඩිරෙක්ට් කිරීම
    return RedirectResponse(url=f"/test-entry/{patient_id}/{test_id}", status_code=303)

@app.get("/test-entry/{patient_id}/{test_id}", response_class=HTMLResponse)
def test_entry_page(patient_id: int, test_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Fetch patient details
    cursor.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
    p_row = cursor.fetchone()
    if not p_row:
        conn.close()
        return "<h3>Patient not found!</h3>"
        
    p_cols = [desc[0] for desc in cursor.description]
    p_dict = dict(zip(p_cols, p_row))

    if bool(p_dict.get("is_cancelled")):
        conn.close()
        manual_bill_no = str(p_dict.get("manual_bill_no") or "").strip()
        ref_no = f"Med-{patient_id:04d}"
        display_ref_no = f"{ref_no} / {manual_bill_no}" if manual_bill_no else ref_no
        return render_cancelled_bill_page(display_ref_no)

    p_title = p_dict.get("title", "")
    p_name = p_dict.get("name", "")
    p_gender = p_dict.get("gender") or "Male"
    # Age is stored as three separate numeric columns. Surface all three so
    # infant/child ages entered as months or days round-trip correctly
    # through the edit form instead of collapsing to a single "years" box.
    def _age_part(key):
        try:
            value = p_dict.get(key)
            return max(0, int(float(value))) if value not in (None, "") else 0
        except (TypeError, ValueError):
            return 0

    p_age_years = _age_part("age_years")
    p_age_months = _age_part("age_months")
    p_age_days = _age_part("age_days")
    if p_age_years == 0 and p_age_months == 0 and p_age_days == 0:
        p_age_years = _age_part("age")
    p_age_display = format_age(p_age_years, p_age_months, p_age_days)
    p_doctor = p_dict.get("doctor") or ""
    p_center_display = p_dict.get("center") or p_dict.get("collecting_center") or ""
    
    # Fetch Test Name
    t_name = "Unknown Test"
    for test_tbl in ["tests", "test_types", "lab_tests", "available_tests"]:
        for test_col in ["test_name", "name", "title"]:
            try:
                cursor.execute(f"SELECT {test_col} FROM {test_tbl} WHERE id = ?", (test_id,))
                t_res = cursor.fetchone()
                if t_res and t_res[0]:
                    t_name = str(t_res[0])
                    break
            except:
                continue
        if t_name != "Unknown Test":
            break
            
    # Fetch existing main result if any
    cursor.execute("SELECT result FROM patient_assigned_tests WHERE patient_id = ? AND test_id = ?", (patient_id, test_id))
    assigned_res = cursor.fetchone()
    main_result_val = assigned_res["result"] if assigned_res and assigned_res["result"] else ""

    # Check if results exist (To Lock or Unlock inputs)
    has_results = False
    if main_result_val and str(main_result_val).strip() != "":
        has_results = True
    else:
        try:
            cursor.execute("SELECT COUNT(*) FROM patient_parameter_results WHERE patient_id = ? AND test_id = ?", (patient_id, test_id))
            if cursor.fetchone()[0] > 0:
                has_results = True
        except:
            pass

    # Fetch parameters from the real test_parameters table.
    # The fallback keeps compatibility with older databases that may not yet
    # have the calculation metadata columns.
    params = []
    try:
        cursor.execute("""
            SELECT id, param_name AS p_name, unit, ref_range,
                   COALESCE(display_order, 0) AS display_order,
                   COALESCE(default_result, '') AS default_result,
                   COALESCE(input_type, 'numeric') AS input_type,
                   COALESCE(is_calculated, 0) AS is_calculated,
                   calculation_key
            FROM test_parameters
            WHERE test_id = ?
            ORDER BY display_order ASC, id ASC
        """, (test_id,))
        params = cursor.fetchall()
    except sqlite3.Error:
        cursor.execute("""
            SELECT id, param_name AS p_name, unit, ref_range,
                   COALESCE(display_order, 0) AS display_order,
                   COALESCE(default_result, '') AS default_result,
                   COALESCE(input_type, 'numeric') AS input_type
            FROM test_parameters
            WHERE test_id = ?
            ORDER BY display_order ASC, id ASC
        """, (test_id,))
        params = cursor.fetchall()

    patient_age_days = patient_age_to_days(p_row)
    patient_gender = p_dict.get("gender") or ""

    param_form_html = ""
    
    # Input field attributes: If already saved (has_results), make them disabled (Locked)
    if has_results:
        input_attr = 'disabled style="flex: 3; padding: 3px 8px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; background: #f8fafc; color: #64748b; cursor: not-allowed;"'
    else:
        input_attr = 'style="flex: 3; padding: 3px 8px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; outline: none; transition: border-color 0.2s;"'

    if params:
        param_form_html += """
        <div style="display:grid; grid-template-columns: minmax(170px,2fr) minmax(110px,2.4fr) 58px 80px minmax(110px,1.6fr); gap:6px; padding-bottom:5px; margin-bottom:6px; border-bottom:2px solid #e2e8f0; font-size:11px; font-weight:700; color:#64748b; text-transform:uppercase; letter-spacing:0.3px;">
            <span>Parameter</span>
            <span>Result</span>
            <span style="text-align:center;">Bold</span>
            <span>Unit</span>
            <span>Reference Range</span>
        </div>
        """
        for p in params:
            p_id_param = p["id"]
            p_name_val = p["p_name"]
            # Structural spacer parameters are intentionally preserved in the
            # database and final report, but hidden from Result Entry.
            if str(p_name_val or "").strip() in {"", ".", "-", "_"}:
                continue
            unit_val = p["unit"] or ""
            is_calculated = bool(p["is_calculated"]) if "is_calculated" in p.keys() else False

            # Patient-specific reference range wins over the parameter default.
            selected_ref = None
            try:
                selected_ref = select_best_ref_range(cursor, p_id_param, patient_gender, patient_age_days)
            except Exception:
                selected_ref = None
            if not selected_ref:
                selected_ref = p["ref_range"] or ""

            p_val = ""
            p_is_bold = 0
            try:
                cursor.execute(
                    "SELECT result_value, COALESCE(is_bold, 0) AS is_bold FROM patient_parameter_results "
                    "WHERE patient_id = ? AND test_id = ? AND parameter_id = ?",
                    (patient_id, test_id, p_id_param)
                )
                exist_res = cursor.fetchone()
                if exist_res and exist_res["result_value"] is not None:
                    p_val = str(exist_res["result_value"])
                if exist_res:
                    p_is_bold = int(exist_res["is_bold"] or 0)
            except Exception:
                # Older database without the is_bold column - fall back to the
                # value-only query so Result Entry still works.
                try:
                    cursor.execute("SELECT result_value FROM patient_parameter_results WHERE patient_id = ? AND test_id = ? AND parameter_id = ?", (patient_id, test_id, p_id_param))
                    exist_res = cursor.fetchone()
                    if exist_res and exist_res["result_value"] is not None:
                        p_val = str(exist_res["result_value"])
                except Exception:
                    pass

            default_val = str(p["default_result"] or "").strip()
            # Existing entered value always wins. If no value exists, show the
            # test parameter's configured default immediately in Result Entry.
            final_val = p_val.strip() if str(p_val).strip() != "" else default_val

            if is_calculated:
                calc_attr = 'readonly style="flex: 3; padding: 3px 8px; border: 1px solid #93c5fd; border-radius: 6px; font-size: 14px; background: #eff6ff; color: #1d4ed8; font-weight: 700;"'
                badge = '<span style="background:#dbeafe;color:#1d4ed8;padding:3px 7px;border-radius:10px;font-size:10px;font-weight:700;margin-left:6px;">AUTO</span>'
            else:
                calc_attr = input_attr
                badge = ''

            # Reference range now gets its own right-hand helper column so the
            # operator can verify limits while typing, instead of being tucked
            # under the parameter name on the left.
            ref_html = (
                f'<span style="font-size:11.5px;color:#475569;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="{html.escape(str(selected_ref))}">{html.escape(str(selected_ref))}</span>'
                if selected_ref else '<span></span>'
            )
            unit_html = f'<span style="font-size:12px;color:#64748b;">{html.escape(str(unit_val))}</span>' if unit_val else '<span></span>'

            # Per-result Bold toggle. Calculated parameters are excluded -
            # their value is derived, and the entry input is already readonly.
            if is_calculated:
                bold_html = '<span></span>'
            else:
                bold_disabled = ' disabled' if has_results else ''
                bold_checked = ' checked' if p_is_bold else ''
                bold_html = (
                    f'<label style="display:flex;align-items:center;gap:4px;font-size:11px;color:#64748b;cursor:{"not-allowed" if has_results else "pointer"};white-space:nowrap;" title="Print this result in bold on the report">'
                    f'<input type="checkbox" name="bold_{test_id}_{p_id_param}" value="1"{bold_checked}{bold_disabled} style="width:13px;height:13px;margin:0;">Bold</label>'
                )

            param_form_html += f"""
            <div style="display:grid; grid-template-columns: minmax(170px,2fr) minmax(110px,2.4fr) 58px 80px minmax(110px,1.6fr); margin-bottom: 2px; align-items:center; gap:6px;">
                <label style="font-weight:600;color:#334155;font-size:14px;">{html.escape(str(p_name_val))}{badge}</label>
                <input type="text" name="param_{test_id}_{p_id_param}" value="{html.escape(final_val)}" placeholder="{'Auto calculated' if is_calculated else 'Enter result...'}" class="param-input" onkeydown="handleParamKeyNav(event, this)" {calc_attr}>
                {bold_html}
                {unit_html}
                {ref_html}
            </div>
            """
    else:
        main_input_attr = 'disabled style="width: 100%; padding: 5px 8px; box-sizing: border-box; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; background: #f8fafc; color: #64748b; cursor: not-allowed;"' if has_results else 'style="width: 100%; padding: 5px 8px; box-sizing: border-box; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; outline: none;"'
        param_form_html += f"""
        <div style="margin-bottom: 15px;">
            <input type="text" name="result_{test_id}" value="{main_result_val}" placeholder="Enter test result..." {main_input_attr}>
        </div>
        """
        
    # ---- Culture & Sensitivity: "Hide ABST" toggle ----
    # Only surfaced for culture/sensitivity tests, identified by test name
    # (this database has no separate test-type flag to key off).
    _t_name_lower = str(t_name or "").lower()
    is_culture_test = any(k in _t_name_lower for k in ("culture", "sensitivity", "abst", "c/s", "c & s"))
    abst_toggle_html = ""
    if is_culture_test:
        current_hide_abst = 0
        try:
            cursor.execute(
                "SELECT COALESCE(hide_abst, 0) AS hide_abst FROM patient_assigned_tests WHERE patient_id = ? AND test_id = ?",
                (patient_id, test_id)
            )
            _abst_row = cursor.fetchone()
            if _abst_row:
                current_hide_abst = int(_abst_row["hide_abst"] or 0)
        except Exception:
            current_hide_abst = 0

        abst_toggle_html = f"""
        <div style="background:#fff7ed; border:1px solid #fed7aa; border-radius:8px; padding:12px 16px; margin-bottom:16px;">
            <label style="display:flex; align-items:center; gap:10px; cursor:{"not-allowed" if has_results else "pointer"}; font-size:13.5px; font-weight:600; color:#9a3412;">
                <input type="checkbox" name="hide_abst" value="1"{" checked" if current_hide_abst else ""}{" disabled" if has_results else ""} style="width:17px; height:17px; margin:0;">
                <span><i class="fa-solid fa-flask-vial"></i> Hide ABST Section (No Growth / Not Applicable)</span>
            </label>
            <div style="font-size:11.5px; color:#b45309; margin-top:6px; padding-left:27px;">
                When ticked, the antibiotic susceptibility grid is omitted from the printed report, keeping &ldquo;No Growth&rdquo; reports clean.
            </div>
        </div>
        """

    # Save button OR Locked Warning Message
    if has_results:
        save_action_html = """
        <div class="locked-banner">
            🔒 This test result is saved & locked. To edit, click the Reset button below.
        </div>
        """
    else:
        save_action_html = """
        <div style="text-align: center; margin-top: 20px;">
            <button type="submit" class="btn-save no-print">💾 Save Results Permanently</button>
        </div>
        """

    # Render Reset Button HTML only if results exist (This acts as the Unlock button)
    reset_section_html = ""
    if has_results:
        reset_section_html = f"""
        <form action="/reset-test-results/{patient_id}/{test_id}" method="post" onsubmit="return confirm('Are you sure you want to reset/unlock this test to edit?');" style="margin-top: 15px; text-align: center;">
            <button type="submit" class="btn-reset no-print">🔄 Reset & Unlock Results</button>
        </form>
        """

    doctor_field_html, center_field_html = build_doctor_center_fields(
        cursor, p_doctor, p_center_display,
        "patient_doctor", "patient_doctor_manual", "patient_center",
        input_style="width:100%; padding:8px 10px; border:1px solid #cbd5e1; border-radius:6px; font-size:13px; box-sizing:border-box;"
    )
    conn.close()

    patient_edit_html = f"""
    <div style="background:#f8fafc; border:1px solid #e2e8f0; border-radius:8px; padding:15px 18px; margin-bottom:20px;">
        <div style="font-size:12.5px; font-weight:700; color:#0f4c81; margin-bottom:10px; text-transform:uppercase; letter-spacing:0.4px;">
            <i class="fa-solid fa-user-pen"></i> Patient Details
        </div>
        <form action="/update-patient-info/{patient_id}" method="post">
            <input type="hidden" name="test_id" value="{test_id}">
            <div style="display:flex; flex-wrap:wrap; gap:12px; margin-bottom:12px;">
                <div style="flex:2; min-width:180px;">
                    <label style="display:block; font-size:12px; font-weight:600; color:#475569; margin-bottom:4px;">Patient Name</label>
                    <input type="text" name="patient_name" value="{p_name}" required style="width:100%; padding:8px 10px; border:1px solid #cbd5e1; border-radius:6px; font-size:13px; box-sizing:border-box;">
                </div>
                <div style="flex:1; min-width:100px;">
                    <label style="display:block; font-size:12px; font-weight:600; color:#475569; margin-bottom:4px;">Title</label>
                    <select name="patient_title" style="width:100%; padding:8px 10px; border:1px solid #cbd5e1; border-radius:6px; font-size:13px;">
                        <option value="Mr." {"selected" if p_title == "Mr." else ""}>Mr.</option>
                        <option value="Mrs." {"selected" if p_title == "Mrs." else ""}>Mrs.</option>
                        <option value="Ms." {"selected" if p_title == "Ms." else ""}>Ms.</option>
                        <option value="Miss" {"selected" if p_title == "Miss" else ""}>Miss</option>
                        <option value="Rev." {"selected" if p_title == "Rev." else ""}>Rev.</option>
                        <option value="Dr." {"selected" if p_title == "Dr." else ""}>Dr.</option>
                        <option value="Master" {"selected" if p_title == "Master" else ""}>Master</option>
                        <option value="Baby" {"selected" if p_title == "Baby" else ""}>Baby</option>
                    </select>
                </div>
                <div style="flex:1; min-width:110px;">
                    <label style="display:block; font-size:12px; font-weight:600; color:#475569; margin-bottom:4px;">Gender</label>
                    <select name="patient_gender" style="width:100%; padding:8px 10px; border:1px solid #cbd5e1; border-radius:6px; font-size:13px;">
                        <option value="Male" {"selected" if p_gender == "Male" else ""}>Male</option>
                        <option value="Female" {"selected" if p_gender == "Female" else ""}>Female</option>
                    </select>
                </div>
                <div style="flex:1.4; min-width:210px;">
                    <label style="display:block; font-size:12px; font-weight:600; color:#475569; margin-bottom:4px;">Age (Years / Months / Days) &mdash; currently: <b>{html.escape(p_age_display)}</b></label>
                    <div style="display:flex; gap:6px;">
                        <input type="number" name="patient_age_years" min="0" value="{p_age_years}" title="Years" placeholder="Y" style="width:100%; padding:8px 6px; border:1px solid #cbd5e1; border-radius:6px; font-size:13px; box-sizing:border-box; text-align:center;">
                        <input type="number" name="patient_age_months" min="0" max="11" value="{p_age_months}" title="Months" placeholder="M" style="width:100%; padding:8px 6px; border:1px solid #cbd5e1; border-radius:6px; font-size:13px; box-sizing:border-box; text-align:center;">
                        <input type="number" name="patient_age_days" min="0" max="30" value="{p_age_days}" title="Days" placeholder="D" style="width:100%; padding:8px 6px; border:1px solid #cbd5e1; border-radius:6px; font-size:13px; box-sizing:border-box; text-align:center;">
                    </div>
                </div>
                <div style="flex:1; min-width:150px;">
                    <label style="display:block; font-size:12px; font-weight:600; color:#475569; margin-bottom:4px;">Doctor</label>
                    {doctor_field_html}
                </div>
                <div style="flex:1; min-width:150px;">
                    <label style="display:block; font-size:12px; font-weight:600; color:#475569; margin-bottom:4px;">Center</label>
                    {center_field_html}
                </div>
            </div>
            <button type="submit" style="background:#0f4c81; color:white; border:none; padding:8px 18px; border-radius:6px; font-weight:600; font-size:13px; cursor:pointer;">
                <i class="fa-solid fa-floppy-disk"></i> Update Patient Details
            </button>
        </form>
    </div>
    """

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Enter Results - {t_name}</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f8fafc; color: #1e293b; padding: 30px; }}
            .container {{ max-width: 800px; margin: auto; background: white; padding: 30px; border-radius: 12px; box-shadow: 0 10px 25px -5px rgba(0,0,0,0.05), 0 8px 10px -6px rgba(0,0,0,0.05); }}
            h2 {{ color: #0f172a; margin-top: 0; font-size: 22px; font-weight: 700; border-bottom: 2px solid #f1f5f9; padding-bottom: 12px; }}
            .back-link {{ display: inline-flex; align-items: center; gap: 6px; color: #3b82f6; text-decoration: none; font-weight: 600; font-size: 13px; transition: color 0.2s; }}
            .back-link:hover {{ color: #1d4ed8; }}
            
            /* Compact, Centered & Modern Smart Buttons */
            .btn-save {{ background: linear-gradient(135deg, #10b981 0%, #059669 100%); color: white; border: none; padding: 12px 28px; font-size: 14px; border-radius: 6px; cursor: pointer; font-weight: 600; display: inline-block; min-width: 240px; box-shadow: 0 4px 6px -1px rgba(16, 185, 129, 0.2); transition: all 0.2s ease; }}
            .btn-save:hover {{ background: linear-gradient(135deg, #059669 0%, #047857 100%); transform: translateY(-1px); box-shadow: 0 6px 8px -1px rgba(16, 185, 129, 0.3); }}
            
            .btn-reset {{ background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); color: white; border: none; padding: 12px 28px; font-size: 14px; border-radius: 6px; cursor: pointer; font-weight: 600; display: inline-block; min-width: 240px; box-shadow: 0 4px 6px -1px rgba(239, 68, 68, 0.2); transition: all 0.2s ease; }}
            .btn-reset:hover {{ background: linear-gradient(135deg, #dc2626 100%, #b91c1c 100%); transform: translateY(-1px); box-shadow: 0 6px 8px -1px rgba(239, 68, 68, 0.3); }}

            .btn-print {{ background: linear-gradient(135deg, #3b82f6 0%, #2563eb 100%); color: white; border: none; padding: 12px 28px; font-size: 14px; border-radius: 6px; cursor: pointer; font-weight: 600; display: inline-block; min-width: 240px; box-shadow: 0 4px 6px -1px rgba(59, 130, 246, 0.2); transition: all 0.2s ease; }}
            .btn-print:hover {{ background: linear-gradient(135deg, #2563eb 100%, #1d4ed8 100%); transform: translateY(-1px); box-shadow: 0 6px 8px -1px rgba(59, 130, 246, 0.3); }}

            .btn-report {{ background: linear-gradient(135deg, #0f4c81 0%, #0c3c68 100%); color: white; border: none; padding: 8px 16px; font-size: 13px; border-radius: 6px; cursor: pointer; font-weight: 600; text-decoration: none; display: inline-block; box-shadow: 0 2px 5px rgba(15, 76, 129, 0.2); transition: all 0.2s ease; }}
            .btn-report:hover {{ background: linear-gradient(135deg, #0c3c68 0%, #092c4e 100%); transform: translateY(-1px); }}

            /* Modern Alert Box */
            .locked-banner {{ background: #fffbeb; color: #b45309; padding: 14px 16px; border-radius: 6px; font-size: 13px; text-align: center; margin-top: 15px; border: 1px solid #fde68a; border-left: 4px solid #f59e0b; font-weight: 600; box-shadow: 0 1px 3px rgba(0,0,0,0.02); }}
            
            @media print {{
                body * {{ visibility: hidden; }}
                .printable-area, .printable-area * {{ visibility: visible; }}
                .printable-area {{ position: absolute; left: 0; top: 0; width: 100%; border: none !important; }}
                .no-print {{ display: none !important; }}
            }}
        </style>
        <script>
            // Preserve Result Entry position/context across save redirects and
            // report navigation so multi-test workflows never jump to top.
            const resultEntryScrollKey = "result-entry-scroll:{patient_id}:{test_id}";
            window.addEventListener("beforeunload", () => sessionStorage.setItem(resultEntryScrollKey, String(window.scrollY || 0)));
            window.addEventListener("DOMContentLoaded", () => {{
                const y = sessionStorage.getItem(resultEntryScrollKey);
                if (y !== null) requestAnimationFrame(() => window.scrollTo(0, Number(y) || 0));
            }});
            // Down Arrow / Enter -> next parameter field, Up Arrow -> previous.
            // Scoped to the enclosing <form>, and preventDefault() on Enter
            // stops the form from submitting prematurely.
            function handleParamKeyNav(event, inputEl) {{
                if (event.key !== "ArrowDown" && event.key !== "ArrowUp" && event.key !== "Enter") return;
                event.preventDefault();
                var scope = inputEl.closest('form') || document;
                var inputs = Array.prototype.slice.call(scope.querySelectorAll('.param-input'));
                var idx = inputs.indexOf(inputEl);
                if (idx === -1) return;
                var nextIdx = (event.key === "ArrowUp") ? idx - 1 : idx + 1;
                if (nextIdx >= 0 && nextIdx < inputs.length) {{
                    inputs[nextIdx].focus();
                    if (inputs[nextIdx].select) inputs[nextIdx].select();
                }}
            }}
        </script>
    </head>
    <body>
        <div class="container">
            <!-- Top Navigation Bar (Back Link & View Professional Report Button) -->
            <div class="no-print" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <a href="/patient-results/{patient_id}" class="back-link">&larr; Back to Patient Overview</a>
                <a href="/report-view/{patient_id}/{test_id}" target="_blank" class="btn-report" onclick="sessionStorage.setItem(resultEntryScrollKey, String(window.scrollY || 0));">
                    📄 View Professional Report
                </a>
            </div>
            
            <div class="no-print">
                {patient_edit_html}
            </div>

            <div class="printable-area">
                <h2>{t_name} - Report</h2>
                
                <form action="/save-specific-test/{patient_id}/{test_id}" method="post">
                    {abst_toggle_html}
                    {param_form_html}
                    {save_action_html}
                </form>
                
                {reset_section_html}
                
               <div style="text-align: center; margin-top: 12px;">
        <a href="/report-view/{patient_id}/{test_id}" target="_blank" class="btn-print no-print" onclick="sessionStorage.setItem(resultEntryScrollKey, String(window.scrollY || 0));" style="text-decoration: none; display: inline-block; line-height: normal;">
            📄 View & Print Professional Report
        </a>
    </div>
</div>
</div>
</body>
</html>
"""

# -------------------------------------------------------------
# 3. BACKEND ACTION ENDPOINTS (Saving & Updates)
# -------------------------------------------------------------
@app.post("/update-patient-info/{patient_id}")
def update_patient_info(
    patient_id: int,
    request: Request,
    patient_title: str = Form(...),
    patient_name: str = Form(...),
    patient_phone: str = Form(None),
    patient_doctor: str = Form(None),
    patient_doctor_manual: str = Form(None),
    patient_age: str = Form(None),
    patient_age_years: str = Form(None),
    patient_age_months: str = Form(None),
    patient_age_days: str = Form(None),
    patient_center: str = Form(None),
    patient_gender: str = Form(None),
    test_id: int = Form(None),
):
    """
    FIX: this handler previously accepted a single `patient_age` string and
    wrote it into age_years (and the legacy `age` column) only - age_months
    and age_days were never touched. Editing an infant's age as months/days
    on the Result Entry screen therefore appeared to save but silently
    discarded the months/days, and the report kept showing the old age.

    The form now submits three separate numeric fields; all three are
    persisted. `patient_age` is still accepted so any older/cached form
    that posts a single value keeps working (treated as years).
    """
    if not user_can(get_current_user(request), "can_edit_patients"):
        return render_locked_page("Update Patient Details")

    def _as_int(value, fallback=0):
        try:
            return max(0, int(float(str(value).strip())))
        except (TypeError, ValueError, AttributeError):
            return fallback

    # Prefer the explicit 3-field form; fall back to the legacy single field.
    if patient_age_years is None and patient_age_months is None and patient_age_days is None:
        years = _as_int(patient_age)
        months = 0
        days = 0
    else:
        years = _as_int(patient_age_years)
        months = _as_int(patient_age_months)
        days = _as_int(patient_age_days)

    patient_doctor = _resolve_doctor_value(patient_doctor, patient_doctor_manual)

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        # phone = COALESCE(?, phone): this form has no phone box, so a
        # missing value must keep the stored phone (it used to wipe it).
        cursor.execute("""
            UPDATE patients 
            SET title = ?, name = ?, phone = COALESCE(?, phone), doctor = ?,
                age_years = ?, age_months = ?, age_days = ?, age = ?,
                center = ?, collecting_center = ?, gender = ?
            WHERE id = ?
        """, (patient_title, patient_name, patient_phone, patient_doctor,
              years, months, days, years,
              patient_center, patient_center, patient_gender, patient_id))
        conn.commit()
    except Exception:
        try:
            cursor.execute("UPDATE patients SET name = ? WHERE id = ?", (patient_name, patient_id))
            conn.commit()
        except Exception:
            pass
    conn.close()
    if test_id:
        return RedirectResponse(url=f"/test-entry/{patient_id}/{test_id}", status_code=303)
    return RedirectResponse(url=f"/patient-results/{patient_id}", status_code=303)


@app.post("/save-specific-test/{patient_id}/{test_id}")
async def save_specific_test(patient_id: int, test_id: int, request: Request):
    if not user_can(get_current_user(request), "can_edit_results"):
        return render_locked_page("Enter / Modify Test Results")
    form_data = await request.form()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN saved_at TEXT")
        conn.commit()
    except Exception:
        pass
    save_timestamp = now_colombo().isoformat(timespec="seconds")
    
    for key, value in form_data.items():
        if key.startswith("param_"):
            parts = key.split("_")
            if len(parts) >= 3:
                p_id_param = parts[2]

                # An unchecked checkbox is simply absent from the POST body,
                # so the flag is derived from presence of bold_<test>_<param>.
                is_bold_flag = 1 if form_data.get(f"bold_{test_id}_{p_id_param}") else 0

                # Locking: only allow setting the parameter result if it isn't already saved.
                cursor.execute("""
                    SELECT result_value FROM patient_parameter_results 
                    WHERE patient_id = ? AND test_id = ? AND parameter_id = ?
                """, (patient_id, test_id, p_id_param))
                existing_param = cursor.fetchone()
                existing_param_value = existing_param["result_value"] if existing_param else None
                if not (existing_param_value and str(existing_param_value).strip()):
                    cursor.execute("""
                        INSERT INTO patient_parameter_results (patient_id, test_id, parameter_id, result_value, is_bold)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(patient_id, test_id, parameter_id) 
                        DO UPDATE SET result_value = ?, is_bold = ?
                    """, (patient_id, test_id, p_id_param, value, is_bold_flag, value, is_bold_flag))
        elif key.startswith("result_"):
            # Locking: only allow setting the result if it isn't already saved.
            cursor.execute("SELECT result FROM patient_assigned_tests WHERE patient_id = ? AND test_id = ?", (patient_id, test_id))
            existing_row = cursor.fetchone()
            existing_result = existing_row["result"] if existing_row else None
            if not (existing_result and str(existing_result).strip()):
                cursor.execute("""
                    UPDATE patient_assigned_tests 
                    SET result = ? 
                    WHERE patient_id = ? AND test_id = ?
                """, (value, patient_id, test_id))

    # Automatically calculate derived parameters (LDL/VLDL/ratio/eGFR).
    calculate_and_save_derived_results(cursor, patient_id, test_id)

    # Persist the "Hide ABST" preference for culture tests. The checkbox is
    # only rendered for culture/sensitivity tests, so for every other test
    # this simply writes 0 and changes nothing observable.
    hide_abst_flag = 1 if form_data.get("hide_abst") else 0
    try:
        cursor.execute("UPDATE patient_assigned_tests SET hide_abst = ? WHERE patient_id = ? AND test_id = ?",
                       (hide_abst_flag, patient_id, test_id))
    except Exception:
        pass

    # Persist the exact time this test's results were saved.
    cursor.execute("UPDATE patient_assigned_tests SET saved_at = ? WHERE patient_id = ? AND test_id = ?",
                   (save_timestamp, patient_id, test_id))

    conn.commit()
    conn.close()
    return RedirectResponse(url=f"/test-entry/{patient_id}/{test_id}", status_code=303)



from typing import Optional
from fastapi import Request, Query, Form
from fastapi.responses import HTMLResponse, RedirectResponse

# -------------------------------------------------------------
# 1. PATIENT RESULTS & EDIT PAGE (Split Screen UI with Formatting Toolbar)
# -------------------------------------------------------------
@app.get("/patient-results/{patient_id}", response_class=HTMLResponse)
def patient_results(request: Request, patient_id: int, updated: Optional[str] = Query(None)):
    conn = get_db_connection()
    cursor = conn.cursor()

    # Ensure required tables and 'comment' column exist safely
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS patient_assigned_tests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            patient_id INTEGER,
            test_id INTEGER,
            result TEXT,
            comment TEXT
        )
    """)
    conn.commit()
    
    try:
        cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN comment TEXT;")
        conn.commit()
    except:
        pass

    # 1. Fetch Patient Info safely with all possible column name variations
    cursor.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
    patient = cursor.fetchone()

    if not patient:
        conn.close()
        return HTMLResponse(content="<h3>Patient Not Found!</h3><a href='/patients-dashboard'>Back</a>", status_code=404)

    p = dict(patient)

    if bool(p.get("is_cancelled")):
        conn.close()
        manual_bill_no = str(p.get("manual_bill_no") or "").strip()
        ref_no = f"Med-{patient_id:04d}"
        display_ref_no = f"{ref_no} / {manual_bill_no}" if manual_bill_no else ref_no
        return render_cancelled_bill_page(display_ref_no)

    p_id = p.get("id")
    p_title = p.get("title") or p.get("salutation") or ""
    p_name = p.get("name") or p.get("patient_name") or p.get("full_name") or ""
    p_age = p.get("age") or p.get("age_years") or p.get("patient_age") or ""
    # Separate Years/Months/Days, mirroring test_entry_page()'s _age_part()
    # helper, so infant/child ages entered in months or days round-trip
    # correctly here too instead of collapsing into one "years" box.
    def _age_part(key):
        try:
            value = p.get(key)
            return max(0, int(float(value))) if value not in (None, "") else 0
        except (TypeError, ValueError):
            return 0
    p_age_years = _age_part("age_years")
    p_age_months = _age_part("age_months")
    p_age_days = _age_part("age_days")
    if p_age_years == 0 and p_age_months == 0 and p_age_days == 0:
        p_age_years = _age_part("age")
    p_gender = p.get("gender") or p.get("sex") or "Male"
    p_phone = p.get("phone") or p.get("telephone") or p.get("mobile") or ""
    p_doctor = p.get("doctor") or p.get("doctor_name") or p.get("ref_doctor") or ""
    p_center = p.get("center") or p.get("collecting_center") or p.get("branch") or ""

    # Needed for the same gender/age-aware reference-range lookup that
    # test_entry_page() already uses, so a parameter's correct range shows
    # up immediately here too instead of only after visiting report_view.
    patient_age_days = patient_age_to_days(p)
    patient_gender_val = p.get("gender") or ""

    # 2. Fetch Assigned Tests with Categories safely
    try:
        cursor.execute("""
            SELECT pat.id as assigned_id, pat.test_id, pat.result, pat.comment,
                   COALESCE(t.test_name, tt.test_name, 'Unknown Test') as test_name,
                   COALESCE(t.category, tt.category, 'General Tests') as category_name
            FROM patient_assigned_tests pat
            LEFT JOIN tests t ON pat.test_id = t.id
            LEFT JOIN test_types tt ON pat.test_id = tt.id
            WHERE pat.patient_id = ?
        """, (patient_id,))
        tests = cursor.fetchall()
    except:
        cursor.execute("""
            SELECT pat.id as assigned_id, pat.test_id, pat.result, pat.comment,
                   COALESCE(t.test_name, 'Unknown Test') as test_name, 
                   'General Tests' as category_name
            FROM patient_assigned_tests pat
            LEFT JOIN tests t ON pat.test_id = t.id
            WHERE pat.patient_id = ?
        """, (patient_id,))
        tests = cursor.fetchall()

    # Group tests by category
    tests_by_category = {}
    total_tests = len(tests)
    completed_count = 0

    for t_row in tests:
        cat_name = t_row["category_name"]
        if cat_name not in tests_by_category:
            tests_by_category[cat_name] = []
        tests_by_category[cat_name].append(t_row)
        
        if t_row["result"] and str(t_row["result"]).strip():
            completed_count += 1

    # 3. Build Categories, Parameters & Comment Boxes HTML with Formatting Toolbar
    categories_html = ""
    if tests:
        for category, cat_tests in tests_by_category.items():
            categories_html += f"""
            <div style="margin-bottom: 25px;">
                <h4 style="background: #e2e8f0; color: #0d47a1; padding: 10px 14px; border-radius: 8px; font-size: 14px; margin-bottom: 15px; font-weight: 700; border-left: 4px solid #0d47a1;">
                    <i class="fa-solid fa-layer-group"></i> {category}
                </h4>
            """
            
            for t in cat_tests:
                t_id = t["test_id"]
                t_name = t["test_name"]
                assigned_id = t["assigned_id"]
                main_result = t["result"] if t["result"] else ""
                test_comment = t["comment"] if "comment" in t.keys() and t["comment"] else ""
                
                # Fetch parameters straight from test_parameters, respecting
                # the saved custom display order and pulling unit/ref_range
                # too - same query test_entry_page() uses, so both Result
                # Entry screens show identical reference ranges immediately
                # on load instead of one of them needing a report_view visit
                # or a Reset first to "discover" this data.
                params = []
                try:
                    cursor.execute("""
                        SELECT id, param_name AS p_name, unit, ref_range,
                               COALESCE(display_order, 0) AS display_order,
                               COALESCE(default_result, '') AS default_ref_range
                        FROM test_parameters
                        WHERE test_id = ?
                        ORDER BY display_order ASC, id ASC
                    """, (t_id,))
                    params = cursor.fetchall()
                except sqlite3.Error:
                    params = []
                
                # Pre-fetch existing parameter values, bold flag & lock status
                param_values = []
                has_saved_param_value = False
                for p_item in params:
                    p_id_param = p_item["id"]
                    p_name_val = p_item["p_name"]
                    # Structural spacer parameters (blank, ".", "-", "_")
                    # are intentionally preserved in the database and on
                    # the final report, but hidden here on Result Entry -
                    # there's nothing meaningful to type into a separator.
                    if str(p_name_val or "").strip() in {"", ".", "-", "_"}:
                        continue
                    unit_val = p_item["unit"] or ""
                    default_val = p_item["default_ref_range"] if "default_ref_range" in p_item.keys() and p_item["default_ref_range"] else ""

                    # Patient-specific reference range wins over the
                    # parameter's own default, exactly like test_entry_page.
                    selected_ref = None
                    try:
                        selected_ref = select_best_ref_range(cursor, p_id_param, patient_gender_val, patient_age_days)
                    except Exception:
                        selected_ref = None
                    if not selected_ref:
                        selected_ref = p_item["ref_range"] or ""

                    p_val = ""
                    p_is_bold = 0
                    try:
                        cursor.execute(
                            "SELECT result_value, COALESCE(is_bold, 0) AS is_bold FROM patient_parameter_results "
                            "WHERE patient_id = ? AND test_id = ? AND parameter_id = ?",
                            (patient_id, t_id, p_id_param)
                        )
                        exist_res = cursor.fetchone()
                        if exist_res:
                            if exist_res["result_value"] is not None:
                                p_val = exist_res["result_value"]
                            p_is_bold = int(exist_res["is_bold"] or 0)
                    except Exception:
                        # Older database without the is_bold column - fall
                        # back to the value-only query.
                        try:
                            cursor.execute("SELECT result_value FROM patient_parameter_results WHERE patient_id = ? AND test_id = ? AND parameter_id = ?", (patient_id, t_id, p_id_param))
                            exist_res = cursor.fetchone()
                            if exist_res: p_val = exist_res["result_value"]
                        except: pass
                    if p_val and str(p_val).strip():
                        has_saved_param_value = True
                    param_values.append((p_id_param, p_name_val, default_val, p_val, unit_val, selected_ref, p_is_bold))

                has_results = bool(main_result and str(main_result).strip()) or has_saved_param_value

                if has_results:
                    value_input_attr = 'disabled style="flex: 2; padding: 5px 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; outline: none; background: #f1f5f9; color: #64748b; cursor: not-allowed;"'
                else:
                    value_input_attr = 'style="flex: 2; padding: 5px 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; outline: none;"'

                lock_badge_html = '<span style="background:#fef3c7; color:#b45309; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:700;"><i class="fa-solid fa-lock"></i> Locked</span>' if has_results else ""

                reset_button_html = f"""
                <form action="/reset-test-results/{p_id}/{t_id}" method="post" onsubmit="return confirm('Are you sure you want to reset/unlock this test to edit?');" style="margin: 8px 0 0 0; text-align: right;">
                    <button type="submit" style="background: #ef4444; color: white; border: none; padding: 6px 14px; border-radius: 6px; font-weight: 600; font-size: 12px; cursor: pointer;">
                        <i class="fa-solid fa-rotate-left"></i> Reset & Unlock
                    </button>
                </form>
                """ if has_results else ""

                categories_html += f"""
                <div style="background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 12px 14px; margin-bottom: 10px; box-shadow: 0 2px 5px rgba(0,0,0,0.03);">
                    <form action="/save-test-results" method="post" style="margin: 0;">
                        <input type="hidden" name="patient_id" value="{p_id}">
                        <input type="hidden" name="test_id" value="{t_id}">
                        <input type="hidden" name="assigned_id" value="{assigned_id}">
                        
                        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #f1f5f9; padding-bottom: 8px; margin-bottom: 10px;">
                            <div style="display: flex; align-items: center; gap: 10px;">
                                <strong style="color: #0f172a; font-size: 15px;"><i class="fa-solid fa-vial"></i> {t_name}</strong>
                                {lock_badge_html}
                            </div>
                            
                            <div style="display: flex; gap: 8px;">
                                <button type="submit" style="background: #16a34a; color: white; border: none; padding: 6px 14px; border-radius: 6px; font-weight: 600; font-size: 12px; cursor: pointer; display: flex; align-items: center; gap: 5px;">
                                    <i class="fa-solid fa-floppy-disk"></i> Save
                                </button>
                                
                                <a href="/print-report/{p_id}/{t_id}" target="_blank" style="background: #0284c7; color: white; border: none; padding: 6px 14px; border-radius: 6px; font-weight: 600; font-size: 12px; cursor: pointer; text-decoration: none; display: flex; align-items: center; gap: 5px;">
                                    <i class="fa-solid fa-print"></i> Print
                                </a>
                            </div>
                        </div>
                """
                
                if params:
                    categories_html += f"""
                    <div style="display: grid; grid-template-columns: minmax(140px,1.6fr) minmax(90px,1.8fr) 50px 60px minmax(90px,1.3fr); gap:8px; padding-bottom:4px; margin-bottom:4px; border-bottom:1px solid #e2e8f0; font-size:10px; font-weight:700; color:#94a3b8; text-transform:uppercase; letter-spacing:0.3px;">
                        <span>Parameter</span><span>Result</span><span style="text-align:center;">Bold</span><span>Unit</span><span>Ref. Range</span>
                    </div>
                    <div style="display: grid; gap: 4px; margin-bottom: 8px;">"""
                    for p_id_param, p_name_val, default_val, p_val, unit_val, selected_ref, p_is_bold in param_values:
                        final_val = p_val if p_val != "" else default_val

                        bold_disabled = ' disabled' if has_results else ''
                        bold_checked = ' checked' if p_is_bold else ''
                        ref_html = (
                            f'<span style="font-size:11px;color:#475569;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;" title="{html.escape(str(selected_ref))}">{html.escape(str(selected_ref))}</span>'
                            if selected_ref else '<span></span>'
                        )
                        unit_html = f'<span style="font-size:11.5px;color:#64748b;">{html.escape(str(unit_val))}</span>' if unit_val else '<span></span>'

                        categories_html += f"""
                        <div style="display: grid; grid-template-columns: minmax(140px,1.6fr) minmax(90px,1.8fr) 50px 60px minmax(90px,1.3fr); align-items: center; gap: 8px; padding: 2px 0;">
                            <label style="font-size: 13px; font-weight: 600; color: #475569;">{html.escape(str(p_name_val))}</label>
                            <input type="text" name="param_{t_id}_{p_id_param}" value="{html.escape(str(final_val))}" placeholder="Result..." class="param-input" onkeydown="handleParamKeyNav(event, this)" {value_input_attr}>
                            <label style="display:flex;align-items:center;gap:3px;font-size:10.5px;color:#64748b;cursor:{'not-allowed' if has_results else 'pointer'};white-space:nowrap;" title="Print this result in bold on the report">
                                <input type="checkbox" name="bold_{t_id}_{p_id_param}" value="1"{bold_checked}{bold_disabled} style="width:12px;height:12px;margin:0;">Bold
                            </label>
                            {unit_html}
                            {ref_html}
                        </div>
                        """
                    categories_html += "</div>"
                else:
                    categories_html += f"""
                    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 12px;">
                        <label style="flex: 1; font-size: 13px; font-weight: 600; color: #475569;">Main Result</label>
                        <input type="text" name="result_{assigned_id}" value="{main_result}" placeholder="Enter value..." {value_input_attr}>
                    </div>
                    """
                
                # --- TEST COMMENT / REMARK BOX WITH FORMATTING TOOLBAR ---
                categories_html += f"""
                <div style="margin-top: 12px; border-top: 1px dashed #cbd5e1; padding-top: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 4px;">
                        <label style="font-weight: 600; color: #0d47a1; font-size: 12.5px;"><i class="fa-solid fa-comment-medical"></i> Test Comment / Remark:</label>
                        <!-- Mini Formatting Toolbar -->
                        <div style="display: flex; gap: 4px;">
                            <button type="button" onclick="formatText('comment_{assigned_id}', '<b>', '</b>')" style="padding: 2px 7px; font-weight: bold; background: #e2e8f0; border: 1px solid #cbd5e1; border-radius: 4px; cursor: pointer; font-size: 11px;" title="Bold">B</button>
                            <button type="button" onclick="formatText('comment_{assigned_id}', '<u>', '</u>')" style="padding: 2px 7px; text-decoration: underline; background: #e2e8f0; border: 1px solid #cbd5e1; border-radius: 4px; cursor: pointer; font-size: 11px;" title="Underline">U</button>
                            <button type="button" onclick="formatText('comment_{assigned_id}', '<span style=\\'font-size: 15px;\\'>', '</span>')" style="padding: 2px 6px; background: #e2e8f0; border: 1px solid #cbd5e1; border-radius: 4px; cursor: pointer; font-size: 10px;" title="Larger Text">A+</button>
                            <button type="button" onclick="formatText('comment_{assigned_id}', '<span style=\\'font-size: 11px;\\'>', '</span>')" style="padding: 2px 6px; background: #e2e8f0; border: 1px solid #cbd5e1; border-radius: 4px; cursor: pointer; font-size: 10px;" title="Smaller Text">A-</button>
                        </div>
                    </div>
                    <textarea id="comment_{assigned_id}" name="comment_{assigned_id}" placeholder="Enter specific comment or note..." style="width: 100%; padding: 8px 10px; box-sizing: border-box; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 12.5px; background: #f8fafc;" rows="2">{test_comment}</textarea>
                </div>
                </form>
                {reset_button_html}
                </div>
                """
            categories_html += "</div>"
    else:
        categories_html = '<div style="padding: 24px; text-align: center; color: #94a3b8; background: white; border-radius: 8px; border: 1px solid #e2e8f0;">No tests assigned for this patient.</div>'

    doctor_field_html, center_field_html = build_doctor_center_fields(
        cursor, p_doctor, p_center, "doctor", "doctor_manual", "center"
    )
    conn.close()

    is_verified = (total_tests > 0 and completed_count == total_tests)
    status_badge = """
    <span style="background: #22c55e; color: white; padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 700;">
        <i class="fa-solid fa-circle-check"></i> Verified
    </span>
    """ if is_verified else """
    <span style="background: #f59e0b; color: white; padding: 6px 14px; border-radius: 20px; font-size: 12px; font-weight: 700;">
        <i class="fa-solid fa-clock"></i> Pending Results
    </span>
    """

    alert_banner = ""
    if updated == "1":
        alert_banner = """
        <div style="background: #dcfce7; color: #15803d; border: 1px solid #86efac; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-weight: 600; font-size: 13px;">
            <i class="fa-solid fa-check-circle"></i> Patient details updated successfully!
        </div>
        """
    elif updated == "results_saved":
        alert_banner = """
        <div style="background: #dcfce7; color: #15803d; border: 1px solid #86efac; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-weight: 600; font-size: 13px;">
            <i class="fa-solid fa-check-circle"></i> Test results & comments saved successfully!
        </div>
        """
    elif updated == "cancelled":
        alert_banner = """
        <div style="background: #fee2e2; color: #991b1b; border: 1px solid #fca5a5; padding: 12px 16px; border-radius: 8px; margin-bottom: 20px; font-weight: 600; font-size: 13px;">
            <i class="fa-solid fa-ban"></i> This bill has been cancelled and is now excluded from all sales/revenue reports.
        </div>
        """

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Patient Result Management</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; }}
            body {{ background: #f4f7fe; color: #1b2559; padding: 24px; }}
            .container {{ max-width: 1400px; margin: auto; }}
            .top-bar {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }}
            .back-link {{ color: #0d47a1; text-decoration: none; font-weight: 700; font-size: 14px; display: flex; align-items: center; gap: 6px; }}
            .main-grid {{ display: grid; grid-template-columns: 360px 1fr; gap: 22px; }}
            @media (max-width: 992px) {{ .main-grid {{ grid-template-columns: 1fr; }} }}
            .card-box {{ background: white; padding: 22px; border-radius: 12px; box-shadow: 0px 8px 24px rgba(0,0,0,0.05); border: 1px solid #e2e8f0; }}
            .card-box h3 {{ font-size: 16px; color: #0d47a1; font-weight: 700; margin-bottom: 18px; border-bottom: 2px solid #f1f5f9; padding-bottom: 10px; display: flex; justify-content: space-between; align-items: center; }}
            .form-group {{ margin-bottom: 14px; }}
            .form-group label {{ display: block; font-size: 12px; font-weight: 700; color: #475569; margin-bottom: 5px; }}
            .form-group input, .form-group select {{ width: 100%; padding: 9px 12px; border: 1px solid #cbd5e1; border-radius: 8px; font-size: 13px; outline: none; background: #f8fafc; }}
            .form-group input:focus, .form-group select:focus {{ border-color: #0d47a1; background: white; }}
            .row-2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; }}
            .btn-save {{ background: #0d47a1; color: white; border: none; padding: 12px; border-radius: 8px; font-weight: 700; font-size: 14px; cursor: pointer; width: 100%; margin-top: 10px; }}
            .btn-save:hover {{ background: #0a3880; }}
        </style>
        <script>
            function formatText(fieldId, startTag, endTag) {{
                var field = document.getElementById(fieldId);
                if (!field) return;
                var start = field.selectionStart;
                var end = field.selectionEnd;
                var text = field.value;
                field.value = text.substring(0, start) + startTag + text.substring(start, end) + endTag + text.substring(end);
                field.focus();
                field.setSelectionRange(start + startTag.length, end + startTag.length);
            }}

            // Down Arrow / Enter -> next parameter field, Up Arrow -> previous.
            // Scoped to the enclosing <form> so navigation stays within one
            // test's group of parameters, and preventDefault() on Enter stops
            // the form from submitting prematurely.
            function handleParamKeyNav(event, inputEl) {{
                if (event.key !== "ArrowDown" && event.key !== "ArrowUp" && event.key !== "Enter") return;
                event.preventDefault();
                var scope = inputEl.closest('form') || document;
                var inputs = Array.prototype.slice.call(scope.querySelectorAll('.param-input'));
                var idx = inputs.indexOf(inputEl);
                if (idx === -1) return;
                var nextIdx = (event.key === "ArrowUp") ? idx - 1 : idx + 1;
                if (nextIdx >= 0 && nextIdx < inputs.length) {{
                    inputs[nextIdx].focus();
                    if (inputs[nextIdx].select) inputs[nextIdx].select();
                }}
            }}
        </script>
    </head>
    <body>
        <div class="container">
            <div class="top-bar">
                <a href="/patients-dashboard" class="back-link"><i class="fa-solid fa-arrow-left"></i> Back to Result Dashboard</a>
                <div>{status_badge}</div>
            </div>

            {alert_banner}

            <div class="main-grid">
                <!-- LEFT SIDE: Editable Patient Info Form -->
                <div class="card-box" style="height: fit-content;">
                    <h3><span><i class="fa-solid fa-user-pen"></i> Edit Patient Info</span> <span style="font-size: 12px; opacity: 0.7;">#{p_id}</span></h3>
                    <div style="font-size:15px; font-weight:700; color:#0f172a; margin:-10px 0 16px 0;">{p_title} {p_name}</div>
                    <form action="/update-patient-details" method="post">
                        <input type="hidden" name="patient_id" value="{p_id}">
                        <div class="row-2">
                            <div class="form-group">
                                <label>Title</label>
                                <select name="title">
                                    <option value="Mr." {"selected" if p_title == "Mr." else ""}>Mr.</option>
                                    <option value="Mrs." {"selected" if p_title == "Mrs." else ""}>Mrs.</option>
                                    <option value="Ms." {"selected" if p_title == "Ms." else ""}>Ms.</option>
                                    <option value="Miss" {"selected" if p_title == "Miss" else ""}>Miss</option>
                                    <option value="Rev." {"selected" if p_title == "Rev." else ""}>Rev.</option>
                                    <option value="Dr." {"selected" if p_title == "Dr." else ""}>Dr.</option>
                                    <option value="Master" {"selected" if p_title == "Master" else ""}>Master</option>
                                    <option value="Baby" {"selected" if p_title == "Baby" else ""}>Baby</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Age (Years / Months / Days)</label>
                                <div style="display:flex; gap:6px;">
                                    <input type="number" name="age_years" min="0" value="{p_age_years}" title="Years" placeholder="Y" style="width:100%; padding:9px 6px; border:1px solid #cbd5e1; border-radius:8px; font-size:13px; box-sizing:border-box; text-align:center; background:#f8fafc;">
                                    <input type="number" name="age_months" min="0" max="11" value="{p_age_months}" title="Months" placeholder="M" style="width:100%; padding:9px 6px; border:1px solid #cbd5e1; border-radius:8px; font-size:13px; box-sizing:border-box; text-align:center; background:#f8fafc;">
                                    <input type="number" name="age_days" min="0" max="30" value="{p_age_days}" title="Days" placeholder="D" style="width:100%; padding:9px 6px; border:1px solid #cbd5e1; border-radius:8px; font-size:13px; box-sizing:border-box; text-align:center; background:#f8fafc;">
                                </div>
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Full Name</label>
                            <input type="text" name="name" value="{p_name}" required>
                        </div>
                        <div class="row-2">
                            <div class="form-group">
                                <label>Gender</label>
                                <select name="gender">
                                    <option value="Male" {"selected" if p_gender == "Male" else ""}>Male</option>
                                    <option value="Female" {"selected" if p_gender == "Female" else ""}>Female</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Phone</label>
                                <input type="text" name="phone" value="{p_phone}">
                            </div>
                        </div>
                        <div class="form-group">
                            <label>Doctor</label>
                            {doctor_field_html}
                        </div>
                        <div class="form-group">
                            <label>Center / Branch</label>
                            {center_field_html}
                        </div>
                        <button type="submit" class="btn-save"><i class="fa-solid fa-floppy-disk"></i> Save Patient Info</button>
                    </form>
                </div>

                <!-- RIGHT SIDE: Assigned Tests, Results & Comments -->
                <div class="card-box">
                    <h3 style="margin-bottom: 25px;">
                        <span><i class="fa-solid fa-flask"></i> Assigned Tests, Results & Comments</span>
                    </h3>
                    {categories_html}
                </div>
            </div>
        </div>
    </body>
    </html>
    """

# -------------------------------------------------------------
# 2. UPDATE PATIENT DETAILS ROUTE (POST)
# -------------------------------------------------------------
@app.post("/update-patient-details")
async def update_patient_details(request: Request):
    """Persist demographic edits made from Result Entry / Patient Results.

    The form now submits direct age_years/age_months/age_days number
    fields (matching test_entry_page()'s "Patient Details" form), which
    map straight onto the normalized columns the report/reference-range
    logic uses. The legacy single free-text `age` field (e.g. "25 Y") is
    still accepted and parsed the same way as before, purely so any other
    caller still posting the old format keeps working.
    """
    if not user_can(get_current_user(request), "can_edit_patients"):
        return render_locked_page("Update Patient Details")
    conn = None
    try:
        form_data = await request.form()
        patient_id_raw = (form_data.get("patient_id") or "").strip()
        if not patient_id_raw:
            return HTMLResponse("<h3>Patient ID missing!</h3>", status_code=400)

        try:
            patient_id = int(patient_id_raw)
        except (TypeError, ValueError):
            return HTMLResponse("<h3>Invalid Patient ID!</h3>", status_code=400)

        title = (form_data.get("title") or "").strip()
        name = (form_data.get("name") or "").strip()
        age_raw = (form_data.get("age") or "").strip()
        age_years_raw = (form_data.get("age_years") or "").strip()
        age_months_raw = (form_data.get("age_months") or "").strip()
        age_days_raw = (form_data.get("age_days") or "").strip()
        gender = (form_data.get("gender") or "").strip()
        phone = (form_data.get("phone") or "").strip()
        doctor = _resolve_doctor_value(form_data.get("doctor"), form_data.get("doctor_manual"))
        center = (form_data.get("center") or "").strip()

        if not name:
            return HTMLResponse("<h3>Patient name is required!</h3>", status_code=400)

        age_years = 0
        age_months = 0
        age_days = 0
        age_db_value = None

        if age_years_raw != "" or age_months_raw != "" or age_days_raw != "":
            # Direct Years/Months/Days fields were submitted - use them
            # straight, clamped to sane ranges.
            try:
                age_years = max(0, int(float(age_years_raw))) if age_years_raw else 0
            except (TypeError, ValueError):
                age_years = 0
            try:
                age_months = max(0, min(11, int(float(age_months_raw)))) if age_months_raw else 0
            except (TypeError, ValueError):
                age_months = 0
            try:
                age_days = max(0, min(30, int(float(age_days_raw)))) if age_days_raw else 0
            except (TypeError, ValueError):
                age_days = 0
            age_db_value = age_years
        elif age_raw:
            # Legacy free-text fallback. Normalize into the columns used by
            # the dynamic reference-range and eGFR logic. Supports: `25`,
            # `25 Y`, `25Y 3M`, `25Y 3M 5D`, and infant forms like `3M`,
            # `5 D`, `8 months`, `15 days`.
            #
            # Parsing is delegated to parse_age_components(), which requires
            # an explicit unit suffix. The previous inline regex treated the
            # year suffix as optional, so "5 D" became 5 YEARS 5 days and
            # "8 months" became 8 years 8 months - silently corrupting every
            # infant record that came through this path.
            age_years, age_months, age_days, age_ok = parse_age_components(age_raw)
            if not age_ok:
                return HTMLResponse("<h3>Invalid age format!</h3><p>Use e.g. 25 Y, 25Y 3M, or 0Y 3M 5D.</p><a href='/patient-results/%s'>Go Back</a>" % patient_id, status_code=400)

            # Keep the legacy `age` field numeric for compatibility with the
            # existing schema and older code paths.
            age_db_value = age_years

        conn = get_db_connection()
        cursor = conn.cursor()

        # Update all demographic fields used by the existing Result Entry and
        # Report View routes. Update both center columns because older records
        # and current registration use collecting_center/center interchangeably.
        cursor.execute("""
            UPDATE patients
            SET title = ?,
                name = ?,
                age = ?,
                age_years = ?,
                age_months = ?,
                age_days = ?,
                gender = ?,
                phone = ?,
                doctor = ?,
                collecting_center = ?,
                center = ?
            WHERE id = ?
        """, (
            title, name, age_db_value, age_years, age_months, age_days,
            gender, phone, doctor, center, center, patient_id
        ))

        if cursor.rowcount == 0:
            conn.rollback()
            conn.close()
            return HTMLResponse("<h3>Patient not found!</h3>", status_code=404)

        conn.commit()
        conn.close()

        # The redirected page performs a fresh DB read, so the new details
        # are immediately visible and report_view will use the new age/gender.
        return RedirectResponse(url=f"/patient-results/{patient_id}?updated=1", status_code=303)
    except Exception as e:
        if conn is not None:
            try:
                conn.rollback()
                conn.close()
            except Exception:
                pass
        return HTMLResponse(content=f"<h3>Error updating patient details: {html.escape(str(e))}</h3>", status_code=500)

# =============================================================
# BILL / INVOICE CANCELLATION
# =============================================================
# A patient's registration/visit is this system's natural "invoice" -
# it covers all tests assigned to that one visit. Cancelling it excludes
# the whole bill from every sales/revenue report, and marks the printed
# report so it can never be mistaken for a valid test bill.
@app.post("/invoices/{invoice_id}/cancel")
def cancel_invoice(invoice_id: int, request: Request):
    current_user = get_current_user(request)
    # Bill cancellation is destructive and financially significant, so it
    # needs its own explicit grant - having general "reports" access is no
    # longer sufficient. user_can() re-reads the flag from the database
    # rather than trusting the (client-editable) permissions cookie.
    if not user_can(current_user, "can_cancel_bills"):
        return render_locked_page("Cancel Bill")

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, manual_bill_no FROM patients WHERE id = ?", (invoice_id,))
    row = cursor.fetchone()
    if not row:
        conn.close()
        return HTMLResponse("<h3>Patient/Bill not found!</h3>", status_code=404)

    cursor.execute("UPDATE patients SET is_cancelled = 1 WHERE id = ?", (invoice_id,))
    conn.commit()
    conn.close()

    ref_no = f"Med-{invoice_id:04d}"
    manual_bill_no = str(row["manual_bill_no"] or "").strip()
    display_ref_no = f"{ref_no} / {manual_bill_no}" if manual_bill_no else ref_no
    success_msg = f"Bill {display_ref_no} cancelled successfully."
    return RedirectResponse(
        url=f"/patients-dashboard?tab=cancel_bills&msg={quote(success_msg, safe='')}",
        status_code=303
    )

# =============================================================
# 2. SAVE TEST RESULTS ROUTE (Fixed with Comment Support)
# =============================================================
@app.post("/save-test-results")
async def save_test_results(request: Request):
    if not user_can(get_current_user(request), "can_edit_results"):
        return render_locked_page("Enter / Modify Test Results")
    try:
        form_data = await request.form()
        patient_id = form_data.get("patient_id")
        if not patient_id:
            return HTMLResponse("<h3>Patient ID missing!</h3>", status_code=400)
        patient_id = int(patient_id)
        
        conn = get_db_connection()
        cursor = conn.cursor()

        # Cancelled bills must never accept new/edited results.
        cursor.execute("SELECT is_cancelled FROM patients WHERE id = ?", (patient_id,))
        p_row = cursor.fetchone()
        if p_row and bool(p_row["is_cancelled"]):
            conn.close()
            return render_cancelled_bill_page(f"Med-{patient_id:04d}")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS patient_parameter_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                patient_id INTEGER,
                test_id INTEGER,
                parameter_id INTEGER,
                result_value TEXT,
                UNIQUE(patient_id, test_id, parameter_id)
            )
        """)
        
        try:
            cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN comment TEXT;")
        except:
            pass
        try:
            cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN saved_at TEXT")
            conn.commit()
        except:
            pass
        save_timestamp = now_colombo().isoformat(timespec="seconds")
        
        for key, value in form_data.items():
            if key.startswith("result_"):
                assigned_id = key.split("_")[1]

                # Locking: only allow setting the result if it isn't already saved.
                cursor.execute("SELECT result FROM patient_assigned_tests WHERE id = ?", (assigned_id,))
                existing_row = cursor.fetchone()
                existing_result = existing_row["result"] if existing_row else None
                if not (existing_result and str(existing_result).strip()):
                    cursor.execute("""
                        UPDATE patient_assigned_tests 
                        SET result = ? 
                        WHERE id = ?
                    """, (value, assigned_id))
                    
            elif key.startswith("comment_"):
                assigned_id = key.split("_")[1]
                cursor.execute("""
                    UPDATE patient_assigned_tests 
                    SET comment = ? 
                    WHERE id = ?
                """, (value, assigned_id))
                    
            elif key.startswith("param_"):
                parts = key.split("_")
                test_id = parts[1]
                param_id = parts[2]

                # An unchecked checkbox is simply absent from the POST
                # body, so the bold flag is derived from presence of
                # bold_<test>_<param> - same convention save_specific_test()
                # (test_entry_page's save handler) already uses.
                is_bold_flag = 1 if form_data.get(f"bold_{test_id}_{param_id}") else 0

                # Locking: only allow setting the parameter result if it isn't already saved.
                cursor.execute("""
                    SELECT result_value FROM patient_parameter_results 
                    WHERE patient_id = ? AND test_id = ? AND parameter_id = ?
                """, (patient_id, test_id, param_id))
                existing_param = cursor.fetchone()
                existing_param_value = existing_param["result_value"] if existing_param else None
                if not (existing_param_value and str(existing_param_value).strip()):
                    cursor.execute("""
                        INSERT INTO patient_parameter_results (patient_id, test_id, parameter_id, result_value, is_bold)
                        VALUES (?, ?, ?, ?, ?)
                        ON CONFLICT(patient_id, test_id, parameter_id) DO UPDATE SET result_value = excluded.result_value, is_bold = excluded.is_bold
                    """, (patient_id, test_id, param_id, value, is_bold_flag))

        # Calculate all derived parameters after the manual inputs are saved.
        # If this request contains several tests, calculate each affected test.
        affected_test_ids = set()
        for key in form_data.keys():
            if key.startswith("param_"):
                parts = key.split("_")
                if len(parts) >= 3:
                    try:
                        affected_test_ids.add(int(parts[1]))
                    except ValueError:
                        pass
        for affected_test_id in affected_test_ids:
            calculate_and_save_derived_results(cursor, patient_id, affected_test_id)

        for affected_test_id in affected_test_ids:
            cursor.execute("UPDATE patient_assigned_tests SET saved_at = ? WHERE patient_id = ? AND test_id = ?",
                           (save_timestamp, patient_id, affected_test_id))

        conn.commit()
        conn.close()
        
        return RedirectResponse(url=f"/patient-results/{patient_id}?updated=results_saved", status_code=303)
        
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error saving: {str(e)}</h3>", status_code=500)
    
# -------------------------------------------------------------
# PRINT REPORT ROUTE (Redirects to Report View)
# -------------------------------------------------------------
@app.get("/print-report/{patient_id}/{test_id}", response_class=HTMLResponse)
def print_report_with_test(patient_id: int, test_id: int):
    return RedirectResponse(url=f"/report-view/{patient_id}/{test_id}", status_code=303)
    
# -------------------------------------------------------------
# Compatibility route: old save buttons can open the first assigned test report.
@app.get("/print-report/{patient_id}", response_class=HTMLResponse)
def print_report(patient_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT test_id FROM patient_assigned_tests
        WHERE patient_id = ?
        ORDER BY id ASC
        LIMIT 1
    """, (patient_id,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return HTMLResponse("<h3>No tests assigned to this patient.</h3><a href='/patient-results/%s'>Back</a>" % patient_id, status_code=404)
    return RedirectResponse(url=f"/report-view/{patient_id}/{row[0]}", status_code=303)


# -------------------------------------------------------------
# DIRECT PDF DOWNLOAD ROUTE (QR + Download Button)
# -------------------------------------------------------------
@app.get("/report-download/{patient_id}/{test_id}")
def report_download(patient_id: int, test_id: int, request: Request):
    """Render the existing report HTML to a PDF for QR-code/download use.

    The report-view route remains the single source of truth for report data and
    styling, so this does not duplicate or change the existing report logic.
    """
    try:
        from weasyprint import HTML
    except Exception:
        # Keep the system usable on installations without WeasyPrint.
        return RedirectResponse(url=f"/report-view/{patient_id}/{test_id}", status_code=303)

    report_html = report_view(patient_id, test_id, request)
    if isinstance(report_html, HTMLResponse):
        html_bytes = report_html.body
        html_text = html_bytes.decode("utf-8")
    elif isinstance(report_html, str):
        html_text = report_html
    else:
        return report_html
    try:
        pdf_bytes = HTML(string=html_text, base_url=str(request.base_url)).write_pdf()
    except Exception as exc:
        return HTMLResponse(content=f"<h3>Unable to generate PDF: {html.escape(str(exc))}</h3>", status_code=500)

    safe_name = re.sub(r"[^A-Za-z0-9_-]+", "_", f"MEDISTAR_{patient_id}_{test_id}").strip("_") or "MEDISTAR_REPORT"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{safe_name}.pdf"'}
    )

# -------------------------------------------------------------
# PUBLIC (QR) REPORT ROUTES - token-gated, read-only, no login, no cookies
# -------------------------------------------------------------
_REPORT_QR_TABLE_READY = False
_QR_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{16,64}$")

# Widths per symbol value (0..105 data/start, 106 = stop), in modules,
# alternating bar/space starting with a bar.
_CODE128_WIDTHS = [
    "212222", "222122", "222221", "121223", "121322", "131222", "122213", "122312",
    "132212", "221213", "221312", "231212", "112232", "122132", "122231", "113222",
    "123122", "123221", "223211", "221132", "221231", "213212", "223112", "312131",
    "311222", "321122", "321221", "312212", "322112", "322211", "212123", "212321",
    "232121", "111323", "131123", "131321", "112313", "132113", "132311", "211313",
    "231113", "231311", "112133", "112331", "132131", "113123", "113321", "133121",
    "313121", "211331", "231131", "213113", "213311", "213131", "311123", "311321",
    "331121", "312113", "312311", "332111", "314111", "221411", "431111", "111224",
    "111422", "121124", "121421", "141122", "141221", "112214", "112412", "122114",
    "122411", "142112", "142211", "241211", "221114", "413111", "241112", "134111",
    "111242", "121142", "121241", "114212", "124112", "124211", "411212", "421112",
    "421211", "212141", "214121", "412121", "111143", "111341", "131141", "114113",
    "114311", "411113", "411311", "113141", "114131", "311141", "411131", "211412",
    "211214", "211232", "2331112",
]


def _code128b_data_uri(text: str):
    """SVG data: URI of a Code 128-B barcode for `text` (generated locally, no
    external service), or None if it cannot be encoded."""
    try:
        if not text or any(not (32 <= ord(ch) <= 126) for ch in text):
            return None
        values = [104] + [ord(ch) - 32 for ch in text]
        checksum = (104 + sum(i * v for i, v in enumerate(values[1:], start=1))) % 103
        values += [checksum, 106]
        quiet = 10
        x = quiet
        rects = []
        for val in values:
            is_bar = True
            for w in _CODE128_WIDTHS[val]:
                width = int(w)
                if is_bar:
                    rects.append(f'<rect x="{x}" y="0" width="{width}" height="30"/>')
                x += width
                is_bar = not is_bar
        total = x + quiet
        svg = (
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {total} 30" '
            f'preserveAspectRatio="none" shape-rendering="crispEdges">'
            f'<rect width="{total}" height="30" fill="#fff"/><g fill="#000">{"".join(rects)}</g></svg>'
        )
        return "data:image/svg+xml;base64," + base64.b64encode(svg.encode("ascii")).decode("ascii")
    except Exception:
        return None


def _ensure_report_qr_table(cursor) -> None:
    """Additive-only table: maps an unguessable token to ONE (patient, test)."""
    global _REPORT_QR_TABLE_READY
    if _REPORT_QR_TABLE_READY:
        return
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS report_qr_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            token TEXT UNIQUE NOT NULL,
            patient_id INTEGER NOT NULL,
            test_id INTEGER NOT NULL,
            created_at TEXT,
            UNIQUE(patient_id, test_id)
        )
    """)
    _REPORT_QR_TABLE_READY = True


def _get_or_create_report_qr_token(patient_id: int, test_id: int):
    """Stable QR token for a report (created on first use), or None on any
    problem (callers then keep the previous QR target)."""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        _ensure_report_qr_table(cursor)
        cursor.execute(
            "SELECT token FROM report_qr_tokens WHERE patient_id = ? AND test_id = ? LIMIT 1",
            (patient_id, test_id),
        )
        row = cursor.fetchone()
        if row:
            return row[0]

        # Only mint tokens for tests that really belong to this patient.
        cursor.execute(
            "SELECT 1 FROM patient_assigned_tests WHERE patient_id = ? AND test_id = ? LIMIT 1",
            (patient_id, test_id),
        )
        if not cursor.fetchone():
            return None

        cursor.execute(
            "INSERT OR IGNORE INTO report_qr_tokens (token, patient_id, test_id, created_at) VALUES (?, ?, ?, ?)",
            (secrets.token_urlsafe(24), patient_id, test_id, now_colombo().isoformat(timespec="seconds")),
        )
        conn.commit()
        cursor.execute(
            "SELECT token FROM report_qr_tokens WHERE patient_id = ? AND test_id = ? LIMIT 1",
            (patient_id, test_id),
        )
        row = cursor.fetchone()
        return row[0] if row else None
    except Exception:
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _resolve_report_qr_token(token: str):
    """token -> (patient_id, test_id) or None. Never raises."""
    if not token or not _QR_TOKEN_RE.match(token):
        return None
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        _ensure_report_qr_table(cursor)
        cursor.execute(
            "SELECT patient_id, test_id FROM report_qr_tokens WHERE token = ? LIMIT 1",
            (token,),
        )
        row = cursor.fetchone()
        return (row[0], row[1]) if row else None
    except Exception:
        return None
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def _public_message_page(title: str, message: str, status_code: int) -> HTMLResponse:
    """Neutral standalone page for public visitors: no staff UI, no login or
    dashboard links, no cookies."""
    return HTMLResponse(
        f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{html.escape(title)}</title></head>
<body style="font-family:Arial,sans-serif;background:#f4f7fe;color:#1b2559;margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;">
<div style="background:#fff;border:1px solid #e2e8f0;border-radius:14px;padding:40px 32px;max-width:440px;text-align:center;">
<h2 style="margin:0 0 12px 0;font-size:20px;">{html.escape(title)}</h2>
<p style="margin:0;color:#707eae;font-size:14px;line-height:1.6;">{html.escape(message)}</p>
</div></body></html>""",
        status_code=status_code,
        headers=dict(PUBLIC_REPORT_HEADERS),
    )


def _build_public_report_html(patient_id: int, test_id: int, request: Request):
    """Public report HTML = the official staff report layout (always with the
    lab letterhead, barcode and patient registration box), minus staff
    controls, with the barcode generated locally."""
    built = _build_report_html(patient_id, test_id, request, letterhead=1, public=True)
    if isinstance(built, str):
        ref_no = f"Med-{patient_id:04d}"
        remote = f"https://barcode.tec-it.com/barcode.ashx?data={ref_no}&code=Code128&dpi=96&hidehrt=true"
        local = _code128b_data_uri(ref_no)
        if local and remote in built:
            built = built.replace(remote, local, 1)
    return built


@app.get("/public-report/{token}", response_class=HTMLResponse)
def public_report_view(token: str, request: Request):
    """Public, unauthenticated, READ-ONLY view of exactly one report, reached
    from the QR code. Access = possession of the random token. It reads no
    cookies, sets none, and exposes no staff controls or other patient data."""
    target = _resolve_report_qr_token(token)
    if not target:
        return _public_message_page(
            "Report link invalid",
            "This report link is invalid or no longer available. Please contact the laboratory.",
            404,
        )
    patient_id, test_id = target

    built = _build_public_report_html(patient_id, test_id, request)
    if isinstance(built, HTMLResponse):
        built = built.body.decode("utf-8")
    if not isinstance(built, str) or "Patient not found" in built[:200]:
        return _public_message_page("Report unavailable", "This report is no longer available.", 404)

    # Fail closed: the official letterhead, barcode and patient registration box
    # must all be present before anything is served.
    if ("url('" not in built or 'class="top-barcode-container"' not in built
            or 'class="patient-box"' not in built or "/static/letterhead.png" not in built):
        return _public_message_page("Report unavailable", "This report cannot be displayed right now.", 500)

    # Fail closed: refuse to serve if any staff control survived.
    if 'class="action-bar"' in built or "/test-entry/" in built:
        return _public_message_page("Report unavailable", "This report cannot be displayed right now.", 500)

    safe_token = html.escape(token, quote=True)
    head_css = (
        "<style>.action-bar{display:none !important;}"
        "body{padding-bottom:76px !important;}"
        ".public-bar{position:fixed;left:0;right:0;bottom:0;z-index:50;background:#ffffff;"
        "border-top:1px solid #e2e8f0;box-shadow:0 -2px 8px rgba(0,0,0,0.08);padding:10px;"
        "text-align:center;font-family:Arial,sans-serif;}"
        "@media print{.public-bar{display:none !important;}body{padding-bottom:0 !important;}}</style>"
    )
    public_bar = f"""
    <div class="public-bar">
        <a href="/public-report/{safe_token}/download" style="display:inline-block;background:#0f4c81;color:#fff;padding:11px 24px;border-radius:8px;text-decoration:none;font-weight:bold;font-size:14px;margin:2px 4px;">&#128196; Download PDF</a>
        <button type="button" onclick="window.print()" style="display:inline-block;background:#0f172a;color:#fff;padding:11px 24px;border-radius:8px;border:none;font-weight:bold;font-size:14px;cursor:pointer;margin:2px 4px;">&#128424; Print</button>
    </div>
    """

    if "</head>" in built:
        built = built.replace("</head>", head_css + "</head>", 1)
    else:
        built = head_css + built
    if "</body>" in built:
        built = built.replace("</body>", public_bar + "</body>", 1)
    else:
        built = built + public_bar

    return HTMLResponse(built, headers=dict(PUBLIC_REPORT_HEADERS))


@app.get("/public-report/{token}/download")
def public_report_download(token: str, request: Request):
    """Public PDF download for the single report behind a QR token."""
    target = _resolve_report_qr_token(token)
    if not target:
        return _public_message_page(
            "Report link invalid",
            "This report link is invalid or no longer available. Please contact the laboratory.",
            404,
        )
    patient_id, test_id = target

    try:
        from weasyprint import HTML
    except Exception:
        # Keep the system usable on installations without WeasyPrint.
        return RedirectResponse(url=f"/public-report/{token}", status_code=303)

    report_html = _build_public_report_html(patient_id, test_id, request)
    if isinstance(report_html, HTMLResponse):
        if report_html.status_code != 200:
            return report_html
        html_text = report_html.body.decode("utf-8")
    elif isinstance(report_html, str):
        html_text = report_html
    else:
        return report_html
    try:
        pdf_bytes = HTML(string=html_text, base_url=str(request.base_url)).write_pdf()
    except Exception as exc:
        return _public_message_page("Unable to generate PDF", "The PDF could not be generated right now. Please try again.", 500)

    safe_name = re.sub(r"[^A-Za-z0-9_-]+", "_", f"MEDISTAR_{patient_id}_{test_id}").strip("_") or "MEDISTAR_REPORT"
    headers = {"Content-Disposition": f'attachment; filename="{safe_name}.pdf"'}
    headers.update(PUBLIC_REPORT_HEADERS)
    return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)

# -------------------------------------------------------------
# SHAREABLE REPORT LINKS (for WhatsApp / public sharing)
# -------------------------------------------------------------
# Uses the new, additive-only `share_links` table (see init_db). Does not
# alter report_view/report_download or any existing table - it only maps
# a random, unguessable token to an existing (patient_id, test_id) pair.

@app.get("/share-reports", response_class=HTMLResponse)
def share_reports_page(request: Request, q: str = ""):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "share_reports"):
        return render_locked_page("Share Reports")

    conn = get_db_connection()
    cursor = conn.cursor()

    search_results_html = ""
    if q.strip():
        like = f"%{q.strip()}%"
        cursor.execute("""
            SELECT p.id, p.name, p.phone, pat.test_id, t.test_name
            FROM patients p
            JOIN patient_assigned_tests pat ON pat.patient_id = p.id
            JOIN tests t ON t.id = pat.test_id
            WHERE (p.name LIKE ? OR p.phone LIKE ? OR CAST(p.id AS TEXT) = ?) AND (p.is_cancelled IS NULL OR p.is_cancelled = 0)
            ORDER BY p.id DESC, t.test_name ASC
            LIMIT 50
        """, (like, like, q.strip()))
        rows = cursor.fetchall()
        if rows:
            for r in rows:
                p_id, p_name, p_phone, t_id, t_name = r[0], r[1], r[2], r[3], r[4]
                search_results_html += f"""
                <tr>
                    <td style="padding:10px; border-bottom:1px solid #eee;">#{p_id}</td>
                    <td style="padding:10px; border-bottom:1px solid #eee; font-weight:600;">{html.escape(p_name or "")}</td>
                    <td style="padding:10px; border-bottom:1px solid #eee;">{html.escape(p_phone or "")}</td>
                    <td style="padding:10px; border-bottom:1px solid #eee;">{html.escape(t_name or "")}</td>
                    <td style="padding:10px; border-bottom:1px solid #eee; text-align:right;">
                        <form action="/generate-share-link" method="post" style="display:inline;">
                            <input type="hidden" name="patient_id" value="{p_id}">
                            <input type="hidden" name="test_id" value="{t_id}">
                            <button type="submit" style="background:#25D366; color:white; border:none; padding:8px 14px; border-radius:6px; font-weight:bold; cursor:pointer; font-size:12px;">
                                <i class="fa-brands fa-whatsapp"></i> Generate Link
                            </button>
                        </form>
                    </td>
                </tr>
                """
        else:
            search_results_html = '<tr><td colspan="5" style="padding:16px; text-align:center; color:#94a3b8;">No matching patients/tests found.</td></tr>'

    cursor.execute("""
        SELECT sl.token, sl.patient_id, sl.test_id, sl.created_at, p.name, t.test_name
        FROM share_links sl
        JOIN patients p ON p.id = sl.patient_id
        JOIN tests t ON t.id = sl.test_id
        ORDER BY sl.id DESC
        LIMIT 20
    """)
    recent = cursor.fetchall()
    conn.close()

    base_url = str(request.base_url).rstrip("/")
    recent_rows_html = ""
    for token, p_id, t_id, created_at, p_name, t_name in recent:
        share_url = f"{base_url}/shared-report/{token}"
        wa_message = (
            f"Hello {p_name},\n"
            f"Your test report from Medistar Medical Laboratory is now ready.\n"
            f"You can view and download your report in PDF or Image format using this secure link:\n"
            f"🔗 {share_url}\n\n"
            f"Thank you!"
        )
        wa_text = quote(wa_message)
        # data-message carries the raw (unescaped-for-URL) template for the
        # "Copy Message & Link" button's clipboard action.
        copy_payload = html.escape(wa_message, quote=True)
        recent_rows_html += f"""
        <tr>
            <td style="padding:10px; border-bottom:1px solid #eee; font-weight:600;">{html.escape(p_name or "")}</td>
            <td style="padding:10px; border-bottom:1px solid #eee;">{html.escape(t_name or "")}</td>
            <td style="padding:10px; border-bottom:1px solid #eee;">
                <input type="text" readonly value="{share_url}" onclick="this.select();"
                       style="width:100%; padding:6px; border:1px solid #cbd5e1; border-radius:4px; font-size:12px;">
            </td>
            <td style="padding:10px; border-bottom:1px solid #eee; text-align:right; white-space:nowrap;">
                <a href="https://api.whatsapp.com/send?text={wa_text}" target="_blank"
                   style="background:#25D366; color:white; padding:6px 10px; text-decoration:none; border-radius:4px; font-size:12px; font-weight:bold; margin-right:5px;">
                    📲 Share via WhatsApp
                </a>
                <button type="button" onclick="copyShareMessage(this)" data-message="{copy_payload}"
                   style="background:#64748b; color:white; padding:6px 10px; border:none; border-radius:4px; font-size:12px; font-weight:bold; cursor:pointer; margin-right:5px;">
                    📋 Copy Message &amp; Link
                </button>
                <a href="{share_url}" target="_blank"
                   style="background:#0f4c81; color:white; padding:6px 10px; text-decoration:none; border-radius:4px; font-size:12px; font-weight:bold;">
                    Open
                </a>
            </td>
        </tr>
        """
    if not recent_rows_html:
        recent_rows_html = '<tr><td colspan="4" style="padding:16px; text-align:center; color:#94a3b8;">No share links generated yet.</td></tr>'

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Share Reports</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 30px; }}
            .container {{ max-width: 1000px; margin: auto; }}
            .card {{ background: white; padding: 24px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); margin-bottom: 20px; }}
            h2 {{ color: #0f4c81; margin-top: 0; }}
            .back-link {{ display: inline-block; margin-bottom: 15px; color: #0f4c81; text-decoration: none; font-weight: bold; }}
            .search-box {{ display:flex; gap:10px; margin-bottom: 15px; }}
            .search-box input {{ flex:1; padding: 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; }}
            .search-box button {{ background: #0f4c81; color: white; border: none; padding: 10px 20px; border-radius: 6px; font-weight: bold; cursor: pointer; }}
            table {{ width: 100%; border-collapse: collapse; }}
            th {{ text-align: left; padding: 10px; background: #f1f5f9; font-size: 13px; color: #334155; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/dashboard" class="back-link">&larr; Back to Dashboard</a>
            <div class="card">
                <h2><i class="fa-brands fa-whatsapp"></i> Share Reports</h2>
                <p style="color:#64748b; font-size:13px;">Search for a patient by name, phone, or ID to generate a secure, shareable report link you can send via WhatsApp.</p>
                <form class="search-box" method="get" action="/share-reports">
                    <input type="text" name="q" value="{html.escape(q)}" placeholder="Search by patient name, phone, or ID...">
                    <button type="submit"><i class="fa-solid fa-magnifying-glass"></i> Search</button>
                </form>
                {"<table><tr><th>ID</th><th>Name</th><th>Phone</th><th>Test</th><th style='text-align:right;'>Action</th></tr>" + search_results_html + "</table>" if q.strip() else ""}
            </div>
            <div class="card">
                <h2 style="font-size:18px;">Recently Generated Links</h2>
                <table>
                    <tr><th>Patient</th><th>Test</th><th>Link</th><th style="text-align:right;">Share</th></tr>
                    {recent_rows_html}
                </table>
            </div>
        </div>
        <script>
            function copyShareMessage(btn) {{
                const msg = btn.getAttribute("data-message");
                navigator.clipboard.writeText(msg).then(function() {{
                    const original = btn.textContent;
                    btn.textContent = "✅ Copied!";
                    setTimeout(function() {{ btn.textContent = original; }}, 1800);
                }}).catch(function() {{
                    alert("Could not copy automatically. Message:\\n\\n" + msg);
                }});
            }}
        </script>
    </body>
    </html>
    """


@app.post("/generate-share-link")
async def generate_share_link(request: Request):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "share_reports"):
        return render_locked_page("Share Reports")

    form_data = await request.form()
    try:
        patient_id = int(form_data.get("patient_id"))
        test_id = int(form_data.get("test_id"))
    except (TypeError, ValueError):
        return RedirectResponse(url="/share-reports", status_code=303)

    token = secrets.token_urlsafe(24)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO share_links (token, patient_id, test_id, created_at, created_by) VALUES (?, ?, ?, ?, ?)",
        (token, patient_id, test_id, now_colombo().isoformat(timespec="seconds"), current_user.get("username", ""))
    )
    conn.commit()
    conn.close()

    return RedirectResponse(url="/share-reports", status_code=303)


@app.get("/shared-report/{token}", response_class=HTMLResponse)
def shared_report_view(token: str, request: Request):
    """
    Public-facing report page - intentionally requires NO login, since this
    is the link a patient opens directly from WhatsApp. Access is gated
    entirely by possession of the random, unguessable token rather than a
    session, exactly like the pattern already used by the existing QR-code
    download link on the printed report.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT patient_id, test_id FROM share_links WHERE token = ?", (token,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return HTMLResponse("<h2 style='font-family:Arial; text-align:center; margin-top:80px; color:#e74c3c;'>This report link is invalid or has expired.</h2>", status_code=404)

    patient_id, test_id = row[0], row[1]
    lab_no = f"Med-{patient_id:04d}"
    inner_report = report_view(patient_id, test_id, request)
    if isinstance(inner_report, HTMLResponse):
        inner_html = inner_report.body.decode("utf-8")
    elif isinstance(inner_report, str):
        inner_html = inner_report
    else:
        return inner_report

    # Hide every internal/admin control on this public page (the "Back to
    # Edit" link and the internal print toggle in .action-bar) without
    # needing to string-surgically remove exact HTML - a CSS override is
    # robust regardless of how that markup changes in the future.
    hide_admin_css = "<style>.action-bar { display: none !important; }</style>"

    patient_banner = """
    <div style="max-width:900px; margin:16px auto 0 auto; background:#eff6ff; border:1px solid #bfdbfe; border-radius:10px; padding:16px 20px; text-align:center; font-family:Arial, sans-serif; color:#1e3a5f;">
        <strong>Your laboratory test report is ready.</strong><br>
        You can view it online or download it directly to your device.
    </div>
    """

    download_bar = f"""
    <div style="max-width:900px; margin:14px auto 0 auto; text-align:center; font-family:Arial, sans-serif;">
        <button onclick="downloadReportAsPdf()"
           style="display:inline-block; background:#0f4c81; color:white; padding:12px 26px; border-radius:8px; text-decoration:none; font-weight:bold; border:none; font-size:14px; cursor:pointer; margin:4px;">
            📄 Download PDF
        </button>
        <button onclick="downloadReportAsJpg()"
           style="display:inline-block; background:#0f172a; color:white; padding:12px 26px; border-radius:8px; text-decoration:none; font-weight:bold; border:none; font-size:14px; cursor:pointer; margin:4px;">
            🖼️ Download as JPG
        </button>
    </div>
    <div id="shared-report-status" style="text-align:center; font-family:Arial, sans-serif; font-size:12px; color:#64748b; margin-top:6px;"></div>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2canvas/1.4.1/html2canvas.min.js"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/html2pdf.js/0.10.1/html2pdf.bundle.min.js"></script>
    <script>
        function _setSharedStatus(msg) {{
            const el = document.getElementById("shared-report-status");
            if (el) el.textContent = msg;
        }}
        function downloadReportAsPdf() {{
            const el = document.querySelector(".report-page");
            if (!el) return;
            _setSharedStatus("Preparing PDF...");
            html2pdf().set({{
                margin: 0,
                filename: "Report_{lab_no}.pdf",
                image: {{ type: "jpeg", quality: 0.98 }},
                html2canvas: {{ scale: 2, useCORS: true }},
                jsPDF: {{ unit: "mm", format: "a4", orientation: "portrait" }}
            }}).from(el).save().then(() => _setSharedStatus("")).catch(() => _setSharedStatus("Could not generate PDF - please try again."));
        }}
        function downloadReportAsJpg() {{
            const el = document.querySelector(".report-page");
            if (!el) return;
            _setSharedStatus("Preparing image...");
            html2canvas(el, {{ scale: 2, useCORS: true }}).then(function(canvas) {{
                const link = document.createElement("a");
                link.download = "Report_{lab_no}.jpg";
                link.href = canvas.toDataURL("image/jpeg", 0.95);
                link.click();
                _setSharedStatus("");
            }}).catch(() => _setSharedStatus("Could not generate image - please try again."));
        }}
    </script>
    """

    if "</head>" in inner_html:
        inner_html = inner_html.replace("</head>", hide_admin_css + "</head>")
    else:
        inner_html = hide_admin_css + inner_html

    if "</body>" in inner_html:
        inner_html = inner_html.replace("<body>", "<body>" + patient_banner)
        inner_html = inner_html.replace("</body>", download_bar + "</body>")
    else:
        inner_html = patient_banner + inner_html + download_bar

    return HTMLResponse(inner_html)


@app.get("/shared-report/{token}/download")
def shared_report_download(token: str, request: Request):
    """Public PDF download counterpart to /shared-report/{token}."""
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT patient_id, test_id FROM share_links WHERE token = ?", (token,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        return HTMLResponse("<h2 style='font-family:Arial; text-align:center; margin-top:80px; color:#e74c3c;'>This report link is invalid or has expired.</h2>", status_code=404)

    patient_id, test_id = row[0], row[1]
    return report_download(patient_id, test_id, request)


# -------------------------------------------------------------
# PRINT LAYOUT SETTINGS (dashboard-configurable report styling)
# -------------------------------------------------------------
@app.get("/print-settings", response_class=HTMLResponse)
def print_settings_page(request: Request, saved: int = 0):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "print_settings"):
        return render_locked_page("Print Layout Settings")

    s = get_print_settings()
    success_banner = (
        '<div style="background:#dcfce7; color:#166534; padding:10px 16px; border-radius:8px; margin-bottom:18px; font-weight:600; font-size:14px;">'
        '<i class="fa-solid fa-circle-check"></i> Print settings saved. New reports will use these values immediately.'
        '</div>'
    ) if saved else ""

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Print Layout Settings</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; padding: 30px; margin: 0; }}
            .container {{ max-width: 700px; margin: auto; }}
            .card {{ background: white; padding: 28px; border-radius: 12px; box-shadow: 0 4px 15px rgba(0,0,0,0.08); }}
            h2 {{ color: #0f4c81; margin-top: 0; }}
            .back-link {{ display: inline-block; margin-bottom: 15px; color: #0f4c81; text-decoration: none; font-weight: bold; }}
            .field-row {{ display: flex; gap: 18px; margin-bottom: 18px; }}
            .field {{ flex: 1; }}
            .field label {{ display: block; font-size: 13px; font-weight: 700; color: #334155; margin-bottom: 6px; }}
            .field .hint {{ font-size: 11px; color: #94a3b8; font-weight: 400; display: block; margin-top: 3px; }}
            .field input[type="number"] {{ width: 100%; padding: 9px 10px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; box-sizing: border-box; }}
            .toggle-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 20px; padding: 12px; background: #f8fafc; border-radius: 8px; }}
            .save-btn {{ background: #0f4c81; color: white; border: none; padding: 11px 26px; border-radius: 8px; font-weight: 700; cursor: pointer; font-size: 14px; }}
            .reset-link {{ margin-left: 14px; color: #64748b; font-size: 13px; text-decoration: none; }}
        </style>
    </head>
    <body>
        <div class="container">
            <a href="/dashboard" class="back-link">&larr; Back to Dashboard</a>
            <div class="card">
                <h2><i class="fa-solid fa-sliders"></i> Print Layout Settings</h2>
                <p style="color:#64748b; font-size:13px; margin-top:-8px;">
                    Adjust how printed/PDF lab reports look, without touching any code. Changes apply to every report immediately.
                </p>
                {success_banner}
                <form action="/print-settings" method="post">
                    <div class="field-row">
                        <div class="field">
                            <label>Table Row Padding (px)</label>
                            <input type="number" name="row_padding_px" min="0" max="15" step="1" value="{s['row_padding_px']}">
                            <span class="hint">Vertical spacing inside each result row. Higher = less squeezed.</span>
                        </div>
                        <div class="field">
                            <label>Line Height</label>
                            <input type="number" name="line_height" min="1.0" max="2.0" step="0.05" value="{s['line_height']}">
                            <span class="hint">Space between wrapped lines of text within a row.</span>
                        </div>
                    </div>
                    <div class="field-row">
                        <div class="field">
                            <label>Base Font Size (px)</label>
                            <input type="number" name="base_font_size_px" min="7" max="16" step="1" value="{s['base_font_size_px']}">
                            <span class="hint">Test parameter & result text size.</span>
                        </div>
                        <div class="field">
                            <label>Header Font Size (px)</label>
                            <input type="number" name="header_font_size_px" min="7" max="16" step="1" value="{s['header_font_size_px']}">
                            <span class="hint">Column header text size (Investigation, Result, etc).</span>
                        </div>
                    </div>
                    <div class="field-row">
                        <div class="field">
                            <label>Footer Bottom Gap (px)</label>
                            <input type="number" name="footer_gap_px" min="0" max="60" step="1" value="{s['footer_gap_px']}">
                            <span class="hint">Space above the QR/signature footer block.</span>
                        </div>
                        <div class="field">
                            <label>Page Side Margins (mm)</label>
                            <input type="number" name="page_side_margin_mm" min="5" max="30" step="1" value="{s['page_side_margin_mm']}">
                            <span class="hint">Left/right printable margin (top space is fixed for the letterhead zone).</span>
                        </div>
                    </div>
                    <div class="field-row">
                        <div class="field">
                            <label>Patient Box Font Size (px)</label>
                            <input type="number" name="patient_box_font_size_px" min="7" max="16" step="1" value="{s['patient_box_font_size_px']}">
                            <span class="hint">Text size for Name, Age, Reference No, etc.</span>
                        </div>
                        <div class="field">
                            <label>Patient Box Padding (px)</label>
                            <input type="number" name="patient_box_padding_px" min="0" max="15" step="1" value="{s['patient_box_padding_px']}">
                            <span class="hint">Vertical spacing inside the patient details box.</span>
                        </div>
                    </div>
                    <div class="field-row">
                        <div class="field">
                            <label>MLT Signature Font Size (px)</label>
                            <input type="number" name="mlt_signature_font_size_px" min="6" max="20" step="1" value="{s['mlt_signature_font_size_px']}">
                            <span class="hint">Size of the signed technologist's name under the signature image.</span>
                        </div>
                        <div class="field">
                            <label>MLT Details Font Size (px)</label>
                            <input type="number" name="mlt_details_font_size_px" min="6" max="20" step="1" value="{s['mlt_details_font_size_px']}">
                            <span class="hint">Size of the designation and registration number lines below the name.</span>
                        </div>
                    </div>
                    <div class="field-row">
                        <div class="field">
                            <label>Test Category Note / Interpretation Font Size (px)</label>
                            <input type="number" name="category_note_font_size" min="6" max="20" step="1" value="{s['category_note_font_size']}">
                            <span class="hint">Size of Test Category Notes and interpretation/guideline text on reports.</span>
                        </div>
                        <div class="field"></div>
                    </div>
                    <div class="toggle-row">
                        <input type="checkbox" id="show_printed_on" name="show_printed_on" value="1" {"checked" if s.get('show_printed_on', 1) else ""} style="width:18px; height:18px;">
                        <label for="show_printed_on" style="margin:0; font-size:14px;">Show “Printed on” date/time on reports</label>
                    </div>
                    <div class="toggle-row">
                        <input type="checkbox" id="default_letterhead" name="default_letterhead" value="1" {"checked" if s['default_letterhead'] else ""} style="width:18px; height:18px;">
                        <label for="default_letterhead" style="margin:0; font-size:14px;">Show digital letterhead by default when opening a report</label>
                    </div>

                    <h3 style="color:#0f4c81; font-size:15px; margin:26px 0 4px 0; border-top:1px solid #e2e8f0; padding-top:18px;">
                        ✍️ MLT Signature Fine-Tuning
                    </h3>
                    <p style="color:#64748b; font-size:12px; margin-top:-2px;">
                        Fine-tune the signature image's position and size on the report - no CSS editing needed. Negative values are allowed (e.g. -50 to +50).
                    </p>
                    <div class="field-row">
                        <div class="field">
                            <label>Signature Margin Top (px)</label>
                            <input type="number" name="sig_margin_top_px" min="-50" max="50" step="1" value="{s['sig_margin_top_px']}">
                            <span class="hint">Positive = nudge down, negative = nudge up.</span>
                        </div>
                        <div class="field">
                            <label>Signature Margin Bottom (px)</label>
                            <input type="number" name="sig_margin_bottom_px" min="-50" max="50" step="1" value="{s['sig_margin_bottom_px']}">
                            <span class="hint">Use negative values like -30px to reduce the gap between the signature image and the name/details text below it.</span>
                        </div>
                    </div>
                    <div class="field-row">
                        <div class="field">
                            <label>Signature Margin Left (px)</label>
                            <input type="number" name="sig_margin_left_px" min="-50" max="50" step="1" value="{s['sig_margin_left_px']}">
                            <span class="hint">Positive = nudge right, negative = nudge left.</span>
                        </div>
                        <div class="field">
                            <label>Signature Margin Right (px)</label>
                            <input type="number" name="sig_margin_right_px" min="-50" max="50" step="1" value="{s['sig_margin_right_px']}">
                            <span class="hint">Extra space reserved to the right of the signature image.</span>
                        </div>
                    </div>
                    <div class="field-row">
                        <div class="field">
                            <label>Signature Height (px)</label>
                            <input type="number" name="sig_img_height_px" min="20" max="200" step="1" value="{s['sig_img_height_px']}">
                            <span class="hint">Scales the signature image's rendered height (width adjusts proportionally via object-fit: contain).</span>
                        </div>
                        <div class="field"></div>
                    </div>

                    <h3 style="color:#0f4c81; font-size:15px; margin:26px 0 4px 0; border-top:1px solid #e2e8f0; padding-top:18px;">
                        <i class="fa-solid fa-arrows-up-down-left-right"></i> FIA Graph Box Position
                    </h3>
                    <p style="color:#64748b; font-size:12px; margin-top:-2px;">
                        Fine-tune nudges (in px) for the HbA1c/FIA gauge box on the report - no CSS editing needed. All default to 0 (no change from the current position).
                    </p>
                    <div class="field-row">
                        <div class="field">
                            <label>Margin Top (px)</label>
                            <input type="number" name="fia_margin_top_px" min="-50" max="100" step="1" value="{s['fia_margin_top_px']}">
                            <span class="hint">Positive = nudge down, negative = nudge up.</span>
                        </div>
                        <div class="field">
                            <label>Margin Bottom (px)</label>
                            <input type="number" name="fia_margin_bottom_px" min="-50" max="100" step="1" value="{s['fia_margin_bottom_px']}">
                            <span class="hint">Extra space reserved below the graph box.</span>
                        </div>
                    </div>
                    <div class="field-row">
                        <div class="field">
                            <label>Margin Left (px)</label>
                            <input type="number" name="fia_margin_left_px" min="-100" max="100" step="1" value="{s['fia_margin_left_px']}">
                            <span class="hint">Positive = nudge right, negative = nudge left.</span>
                        </div>
                        <div class="field">
                            <label>Margin Right (px)</label>
                            <input type="number" name="fia_margin_right_px" min="-50" max="100" step="1" value="{s['fia_margin_right_px']}">
                            <span class="hint">Extra space reserved to the right of the graph box (pulls it left from the page edge).</span>
                        </div>
                    </div>

                    <button type="submit" class="save-btn"><i class="fa-solid fa-check"></i> Save Settings</button>
                    <a href="/print-settings-reset" class="reset-link" onclick="return confirm('Reset all print settings to defaults?');">Reset to defaults</a>
                </form>
            </div>
        </div>
    </body>
    </html>
    """


@app.post("/print-settings")
async def print_settings_save(request: Request):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "print_settings"):
        return render_locked_page("Print Layout Settings")

    form_data = await request.form()

    # Every value is clamped to a safe range server-side (not just via the
    # HTML min/max attributes, which a user could bypass) so a bad/garbled
    # submission can never produce a broken or unreadable report layout.
    row_padding_px = int(_clamp(form_data.get("row_padding_px"), 0, 15, DEFAULT_PRINT_SETTINGS["row_padding_px"]))
    base_font_size_px = int(_clamp(form_data.get("base_font_size_px"), 7, 16, DEFAULT_PRINT_SETTINGS["base_font_size_px"]))
    header_font_size_px = int(_clamp(form_data.get("header_font_size_px"), 7, 16, DEFAULT_PRINT_SETTINGS["header_font_size_px"]))
    line_height = _clamp(form_data.get("line_height"), 1.0, 2.0, DEFAULT_PRINT_SETTINGS["line_height"])
    footer_gap_px = int(_clamp(form_data.get("footer_gap_px"), 0, 60, DEFAULT_PRINT_SETTINGS["footer_gap_px"]))
    page_side_margin_mm = int(_clamp(form_data.get("page_side_margin_mm"), 5, 30, DEFAULT_PRINT_SETTINGS["page_side_margin_mm"]))
    default_letterhead = 1 if form_data.get("default_letterhead") else 0
    show_printed_on = 1 if form_data.get("show_printed_on") else 0
    patient_box_font_size_px = int(_clamp(form_data.get("patient_box_font_size_px"), 7, 16, DEFAULT_PRINT_SETTINGS["patient_box_font_size_px"]))
    patient_box_padding_px = int(_clamp(form_data.get("patient_box_padding_px"), 0, 15, DEFAULT_PRINT_SETTINGS["patient_box_padding_px"]))
    mlt_signature_font_size_px = int(_clamp(form_data.get("mlt_signature_font_size_px"), 6, 20, DEFAULT_PRINT_SETTINGS["mlt_signature_font_size_px"]))
    mlt_details_font_size_px = int(_clamp(form_data.get("mlt_details_font_size_px"), 6, 20, DEFAULT_PRINT_SETTINGS["mlt_details_font_size_px"]))
    fia_margin_top_px = int(_clamp(form_data.get("fia_margin_top_px"), -50, 100, DEFAULT_PRINT_SETTINGS["fia_margin_top_px"]))
    fia_margin_bottom_px = int(_clamp(form_data.get("fia_margin_bottom_px"), -50, 100, DEFAULT_PRINT_SETTINGS["fia_margin_bottom_px"]))
    fia_margin_left_px = int(_clamp(form_data.get("fia_margin_left_px"), -100, 100, DEFAULT_PRINT_SETTINGS["fia_margin_left_px"]))
    fia_margin_right_px = int(_clamp(form_data.get("fia_margin_right_px"), -50, 100, DEFAULT_PRINT_SETTINGS["fia_margin_right_px"]))
    category_note_font_size = int(_clamp(form_data.get("category_note_font_size"), 6, 20, DEFAULT_PRINT_SETTINGS["category_note_font_size"]))
    sig_margin_top_px = int(_clamp(form_data.get("sig_margin_top_px"), -50, 50, DEFAULT_PRINT_SETTINGS["sig_margin_top_px"]))
    sig_margin_bottom_px = int(_clamp(form_data.get("sig_margin_bottom_px"), -50, 50, DEFAULT_PRINT_SETTINGS["sig_margin_bottom_px"]))
    sig_margin_left_px = int(_clamp(form_data.get("sig_margin_left_px"), -50, 50, DEFAULT_PRINT_SETTINGS["sig_margin_left_px"]))
    sig_margin_right_px = int(_clamp(form_data.get("sig_margin_right_px"), -50, 50, DEFAULT_PRINT_SETTINGS["sig_margin_right_px"]))
    sig_img_height_px = int(_clamp(form_data.get("sig_img_height_px"), 20, 200, DEFAULT_PRINT_SETTINGS["sig_img_height_px"]))

    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE system_print_settings
        SET row_padding_px = ?, base_font_size_px = ?, header_font_size_px = ?,
            line_height = ?, footer_gap_px = ?, page_side_margin_mm = ?,
            default_letterhead = ?, show_printed_on = ?, patient_box_font_size_px = ?, patient_box_padding_px = ?,
            mlt_signature_font_size_px = ?, mlt_details_font_size_px = ?,
            fia_margin_top_px = ?, fia_margin_bottom_px = ?, fia_margin_left_px = ?, fia_margin_right_px = ?,
            category_note_font_size = ?,
            sig_margin_top_px = ?, sig_margin_bottom_px = ?, sig_margin_left_px = ?, sig_margin_right_px = ?, sig_img_height_px = ?,
            updated_at = ?
        WHERE id = 1
    """, (row_padding_px, base_font_size_px, header_font_size_px, line_height,
          footer_gap_px, page_side_margin_mm, default_letterhead, show_printed_on,
          patient_box_font_size_px, patient_box_padding_px,
          mlt_signature_font_size_px, mlt_details_font_size_px,
          fia_margin_top_px, fia_margin_bottom_px, fia_margin_left_px, fia_margin_right_px,
          category_note_font_size,
          sig_margin_top_px, sig_margin_bottom_px, sig_margin_left_px, sig_margin_right_px, sig_img_height_px,
          now_colombo().isoformat(timespec="seconds")))
    conn.commit()
    conn.close()

    return RedirectResponse(url="/print-settings?saved=1", status_code=303)


@app.get("/print-settings-reset")
def print_settings_reset(request: Request):
    current_user = get_current_user(request)
    if not user_has_access(current_user, "print_settings"):
        return render_locked_page("Print Layout Settings")

    d = DEFAULT_PRINT_SETTINGS
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE system_print_settings
        SET row_padding_px = ?, base_font_size_px = ?, header_font_size_px = ?,
            line_height = ?, footer_gap_px = ?, page_side_margin_mm = ?,
            default_letterhead = ?, show_printed_on = ?, patient_box_font_size_px = ?, patient_box_padding_px = ?,
            mlt_signature_font_size_px = ?, mlt_details_font_size_px = ?,
            fia_margin_top_px = ?, fia_margin_bottom_px = ?, fia_margin_left_px = ?, fia_margin_right_px = ?,
            category_note_font_size = ?,
            sig_margin_top_px = ?, sig_margin_bottom_px = ?, sig_margin_left_px = ?, sig_margin_right_px = ?, sig_img_height_px = ?,
            updated_at = ?
        WHERE id = 1
    """, (d["row_padding_px"], d["base_font_size_px"], d["header_font_size_px"],
          d["line_height"], d["footer_gap_px"], d["page_side_margin_mm"],
          d["default_letterhead"], d["show_printed_on"], d["patient_box_font_size_px"], d["patient_box_padding_px"],
          d["mlt_signature_font_size_px"], d["mlt_details_font_size_px"],
          d["fia_margin_top_px"], d["fia_margin_bottom_px"], d["fia_margin_left_px"], d["fia_margin_right_px"],
          d["category_note_font_size"],
          d["sig_margin_top_px"], d["sig_margin_bottom_px"], d["sig_margin_left_px"], d["sig_margin_right_px"], d["sig_img_height_px"],
          now_colombo().isoformat(timespec="seconds")))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/print-settings?saved=1", status_code=303)

# -------------------------------------------------------------
# PROFESSIONAL LAB REPORT VIEW (Letterhead Background, QR, Sig, Comment Box)
# -------------------------------------------------------------
@app.get("/report-letterhead-preview/{patient_id}/{test_id}", response_class=HTMLResponse)
def report_letterhead_preview(patient_id: int, test_id: int, request: Request):
    """Letterhead Print view."""
    return report_view(patient_id, test_id, request, letterhead=1)


@app.get("/report-view/{patient_id}/{test_id}", response_class=HTMLResponse)
def report_view(patient_id: int, test_id: int, request: Request, letterhead: Optional[int] = None):
    # Staff route: behaviour unchanged.
    return _build_report_html(patient_id, test_id, request, letterhead=letterhead, public=False)


# ---- ABST (antibiotic sensitivity) section detection for culture reports ----
_ABST_MARKER_RE = re.compile(r"\b(abst|antibiotic|antibiotics|antibiogram|sensitivity|susceptibility)\b", re.I)
_ABST_DRUG_RE = re.compile(
    r"\b(amoxicillin|amoxycillin|ampicillin|augmentin|amoxiclav|co-?amoxiclav|cefalexin|cephalexin|cefuroxime|"
    r"cefixime|ceftriaxone|ceftazidime|cefotaxime|cefepime|cefazolin|cefoxitin|ciprofloxacin|levofloxacin|"
    r"norfloxacin|ofloxacin|gentamicin|gentamycin|amikacin|tobramycin|nitrofurantoin|cotrimoxazole|"
    r"co-trimoxazole|trimethoprim|sulfamethoxazole|meropenem|imipenem|ertapenem|piperacillin|tazobactam|"
    r"azithromycin|erythromycin|clarithromycin|clindamycin|doxycycline|tetracycline|vancomycin|linezolid|"
    r"teicoplanin|colistin|polymyxin|fosfomycin|chloramphenicol|cloxacillin|flucloxacillin|penicillin|"
    r"oxacillin|aztreonam)\b",
    re.I,
)


def _abst_param_ids_to_skip(cursor, params, name_col, patient_id, test_id, hide_abst, test_name):
    """Ids of the parameter rows that make up the ABST section of a culture
    report and must be left out of the printed table. Returns an empty set
    (nothing hidden) whenever in doubt, so a report is never emptied.

    The ABST section is: every row from the first row whose name looks like an
    ABST heading (ABST / Antibiotic / Sensitivity / Susceptibility) to the end;
    or, when there is no such heading row, the rows named after common
    antibiotics. It is hidden when the "Hide ABST" toggle is ticked, and also
    automatically when no ABST result has been entered at all.
    """
    try:
        if not params:
            return set()
        tn = str(test_name or "").lower()
        if not any(k in tn for k in ("culture", "sensitivity", "abst", "c/s", "c & s")):
            return set()

        rows = []  # (id, name, is_spacer)
        for p in params:
            d = dict(p)
            nm = str(d.get(name_col) or "").strip()
            rows.append((d.get("id"), nm, nm in ("", ".", "-", "_")))

        marker_idx = next((i for i, r in enumerate(rows) if not r[2] and _ABST_MARKER_RE.search(r[1])), None)
        if marker_idx is not None:
            abst_rows = rows[marker_idx:]
        else:
            first_drug = next((i for i, r in enumerate(rows) if not r[2] and _ABST_DRUG_RE.search(r[1])), None)
            if first_drug is None:
                return set()
            abst_rows = [r for i, r in enumerate(rows)
                         if i >= first_drug and (r[2] or _ABST_DRUG_RE.search(r[1]))]

        abst_ids = {r[0] for r in abst_rows if r[0] is not None}
        real_ids = [r[0] for r in abst_rows if not r[2] and r[0] is not None]
        if not real_ids:
            return set()

        if not hide_abst:
            # Toggle left on "show": still omit the section when it is entirely empty.
            for pid in real_ids:
                cursor.execute(
                    "SELECT result_value FROM patient_parameter_results WHERE patient_id=? AND test_id=? AND parameter_id=? LIMIT 1",
                    (patient_id, test_id, pid),
                )
                rr = cursor.fetchone()
                if rr and rr[0] is not None and str(rr[0]).strip():
                    return set()

        # Never hide every visible row.
        if not [r for r in rows if r[0] not in abst_ids and not r[2]]:
            return set()
        return abst_ids
    except Exception:
        return set()


def _strip_staff_controls(report_html: str) -> str:
    """Removes the staff action bar ("Back to Edit", print-mode links) so it
    can never be shown on a public page."""
    return re.sub(
        r'<div class="action-bar">.*?</div>\s*</div>',
        "",
        report_html,
        count=1,
        flags=re.S,
    )


def _build_report_html(patient_id: int, test_id: int, request: Request,
                       letterhead: Optional[int] = None, public: bool = False):
    """public=True is only ever passed by the token-validated /public-report
    routes (it is a function argument, never a request parameter)."""
    result = _report_html_impl(patient_id, test_id, request, letterhead, public)
    if public and isinstance(result, str):
        result = _strip_staff_controls(result)
    return result


def _report_html_impl(patient_id: int, test_id: int, request: Request,
                      letterhead: Optional[int] = None, public: bool = False):
    # Opaque, unguessable token that the printed QR code points to.
    qr_token = _get_or_create_report_qr_token(patient_id, test_id)

    # Resolve letterhead state: an explicit query param (?letterhead=0/1)
    # always wins (preserves the existing toggle/link behavior exactly);
    # only when no explicit value is given do we fall back to the
    # admin-configured default from Print Layout Settings.
    print_settings = get_print_settings()
    if letterhead is None:
        letterhead = print_settings["default_letterhead"]

    # Computed once here as plain, literal inline pixel values (no calc(),
    # no CSS var()) and written directly onto the signature <img> tag. An
    # inline style is required rather than a class/variable because print
    # and PDF rendering does not reliably resolve CSS custom properties.
    # Defaults mirror the original hardcoded .sig-img-new rule, so output
    # is unchanged until an admin edits these in Print Settings.
    sig_img_inline_style = (
        f"margin-top: {print_settings['sig_margin_top_px']}px !important; "
        f"margin-bottom: {print_settings['sig_margin_bottom_px']}px !important; "
        f"margin-left: {print_settings['sig_margin_left_px']}px !important; "
        f"margin-right: {print_settings['sig_margin_right_px']}px !important; "
        f"height: {print_settings['sig_img_height_px']}px !important; "
        f"position: relative;"
    )

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT COALESCE(show_fia_graph, 0) FROM tests WHERE id = ?", (test_id,))
        _fia_row = cursor.fetchone()
        show_fia_graph = bool(_fia_row[0]) if _fia_row else False
    except Exception:
        show_fia_graph = False

    # Base URL for static images (Fixes 404 Not Found error for letterhead & signature)
    base_url_str = str(request.base_url).rstrip("/")
    letterhead_img_url = f"{base_url_str}/static/letterhead.png"
    signature_img_url = f"{base_url_str}/static/mlt_signature.png"

    # 1. Fetch Patient Details
    cursor.execute("SELECT * FROM patients WHERE id = ?", (patient_id,))
    p_row = cursor.fetchone()
    if not p_row:
        conn.close()
        return "<h3>Patient not found!</h3>"
    
    p_cols = [desc[0] for desc in cursor.description]
    patient = dict(zip(p_cols, p_row))

    title = patient.get("title", "")
    name = patient.get("name", "")
    patient_name = f"{title} {name}".strip()
    gender = patient.get("gender", "N/A")
    ay=int(patient.get("age_years",0) or 0); am=int(patient.get("age_months",0) or 0); ad=int(patient.get("age_days",0) or 0)
    
    if ay < 5:
        if ay or am or ad:
            gender_age=f"{gender} / {ay}Y {am}M {ad}D"
        else:
            legacy_age=patient.get("age","N/A")
            gender_age=f"{gender} / {legacy_age}Y" if legacy_age not in (None,"","N/A") else gender
    else:
        gender_age=f"{gender} / {ay}Y" if ay else gender
    
    doctor_value = patient.get("doctor") or patient.get("doctor_name") or ""
    doctor = doctor_value or "Not Specified"
    if doctor_value:
        try:
            cursor.execute("SELECT name FROM doctors WHERE code = ? LIMIT 1", (doctor_value,))
            doctor_row = cursor.fetchone()
            if doctor_row and doctor_row["name"]:
                doctor = doctor_row["name"]
        except Exception:
            pass

    center = (
        patient.get("center")
        or patient.get("collecting_center")
        or patient.get("branch")
        or "Main Branch"
    )

    ref_no = f"Med-{patient.get('id', 0):04d}"
    manual_bill_no = str(patient.get("manual_bill_no") or "").strip()
    # Keep the existing reference number unchanged when no manual bill was
    # entered; otherwise append it exactly once using the requested slash.
    display_ref_no = f"{ref_no} / {manual_bill_no}" if manual_bill_no else ref_no

    is_cancelled_bill = bool(patient.get("is_cancelled"))
    cancelled_report_banner_html = """
    <div style="text-align:center; margin: 4px 0 10px 0;">
        <span style="display:inline-block; color:#b91c1c; border:2px solid #b91c1c; padding:4px 22px; font-size:16px; font-weight:900; letter-spacing:2px; transform: rotate(-3deg); border-radius:4px;">
            CANCELLED
        </span>
    </div>
    """ if is_cancelled_bill else ""

    def format_report_datetime(value):
        if not value or str(value).strip().lower() == "none":
            return None
        try:
            raw = str(value).strip().replace("Z", "")
            parsed = datetime.fromisoformat(raw)
        except Exception:
            parsed = None
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y %H:%M"):
                try:
                    parsed = datetime.strptime(str(value).strip(), fmt)
                    break
                except Exception:
                    continue
        return parsed.strftime("%d/%m/%Y %I:%M %p") if parsed else None

    # Received on — the patient's actual registration date/time from the
    # database. Check every plausible column name on the patients table, in
    # priority order, and only use that stored value. Never fall back to the
    # current print/system time; if nothing is found, show "N/A".
    recv_raw_value = None
    for recv_key in ["created_at", "registered_at", "timestamp", "date", "reg_date"]:
        if patient.get(recv_key):
            recv_raw_value = patient.get(recv_key)
            break

    recv_parsed = format_report_datetime(recv_raw_value) if recv_raw_value else None
    received_on = recv_parsed if recv_parsed else "N/A"

    department = "GENERAL"
    specimen = "N/A"

    # 2. Fetch Test Name, Category, Specimen & Test Notes / Description
    test_name = "LAB REPORT"
    test_notes_html = ""
    try:
        cursor.execute("SELECT * FROM tests WHERE id = ?", (test_id,))
        test_row = cursor.fetchone()
        if test_row:
            t_keys = test_row.keys()
            department = (
                test_row["department"]
                if "department" in t_keys and test_row["department"]
                else "GENERAL"
            )
            specimen = (
                str(test_row["specimen"]).strip()
                if "specimen" in t_keys and test_row["specimen"]
                else "N/A"
            )
            for key in ["name", "test_name", "category", "title"]:
                if key in t_keys and test_row[key]:
                    test_name = str(test_row[key]).upper()
                    break
            
            for n_key in ["notes", "description", "details", "info", "test_description"]:
                if n_key in t_keys and test_row[n_key]:
                    raw_note = str(test_row[n_key])
                    clean_note = html.unescape(raw_note)
                    test_notes_html = f"<div class='report-test-note test-category-note interpretation-note'>{clean_note}</div>"
                    break
    except Exception as e:
        pass

    raw_alignments = "left,center,center,left,left"
    try:
        if test_row and "col_alignments" in test_row.keys() and test_row["col_alignments"]:
            raw_alignments = str(test_row["col_alignments"])
    except Exception:
        pass

    raw_parts = [x.strip() for x in raw_alignments.split(",")]
    default_alignments = ["left", "center", "center", "left", "left"]
    valid_alignments = {"left", "center", "right", "none"}

    alignment_parts = raw_parts[:5]
    while len(alignment_parts) < 5:
        alignment_parts.append(default_alignments[len(alignment_parts)])

    align_parts = [
        value.lower() if value.lower() in valid_alignments else default_alignments[i]
        for i, value in enumerate(alignment_parts[:5])
    ]
    align_inv, align_res, align_flag, align_unit, align_ref = align_parts

    default_widths = [38.0, 13.0, 8.0, 14.0, 27.0]
    width_parts = []

    for i in range(5):
        try:
            raw_width = raw_parts[5 + i] if len(raw_parts) > 5 + i else default_widths[i]
            width_parts.append(max(1.0, min(100.0, float(raw_width))))
        except (TypeError, ValueError):
            width_parts.append(default_widths[i])

    col_align = [align_inv, align_res, align_flag, align_unit, align_ref]
    col_visible = [x != "none" for x in col_align]
    visible_width_sum = sum(width_parts[i] for i in range(5) if col_visible[i]) or 1.0
    col_widths = [(width_parts[i] / visible_width_sum * 100.0) if col_visible[i] else 0.0 for i in range(5)]

    # 3. Recalculate derived results
    try:
        calculate_and_save_derived_results(cursor, patient_id, test_id)
        conn.commit()
    except Exception:
        pass

    # 4. Fetch Assigned Test Results & Comments
    cursor.execute("SELECT * FROM patient_assigned_tests WHERE patient_id = ? AND test_id = ?", (patient_id, test_id))
    assigned_res = cursor.fetchone()
    
    main_result_val = ""
    comment_text = ""
    saved_at_value = None
    # Set from the "Hide ABST Section (No Growth / Not Applicable)" toggle on
    # the Result Entry screen. Use this to gate any antibiotic-susceptibility
    # block: `if not hide_abst: ...render ABST table...`
    hide_abst = False
    
    if assigned_res:
        assigned_keys = assigned_res.keys()
        if "hide_abst" in assigned_keys:
            hide_abst = bool(int(assigned_res["hide_abst"] or 0))
        if "result" in assigned_keys and assigned_res["result"]:
            main_result_val = str(assigned_res["result"])
            
        for c_key in ["comment", "comments", "note", "notes", "remark", "remarks"]:
            if c_key in assigned_keys and assigned_res[c_key]:
                raw_comment = str(assigned_res[c_key])
                comment_text = html.unescape(raw_comment)
                break
                
        # Check the assigned-test row for the actual save/update timestamp,
        # trying every plausible column name in priority order. This is the
        # real "Reported On" moment (when results were saved), not the time
        # the report happens to be printed/viewed.
        for ts_key in ["saved_at", "updated_at", "timestamp", "date", "created_at"]:
            if ts_key in assigned_keys and assigned_res[ts_key]:
                saved_at_value = assigned_res[ts_key]
                break

    rep_parsed = format_report_datetime(saved_at_value) if saved_at_value else None
    # Fallback: if no save timestamp exists on the assigned-test row, use the
    # patient's received_on timestamp. NEVER fall back to the current
    # print/system time (datetime.now()) for "Reported On".
    reported_on = rep_parsed if rep_parsed else received_on
    printed_on = now_colombo().strftime("%d/%m/%Y %I:%M %p")

    patient_age_days = patient_age_to_days(patient)
    patient_gender = normalize_patient_gender(patient.get("gender"))

    params = []
    possible_tables = ["test_parameters", "parameters", "sub_tests", "test_fields"]
    possible_cols = ["parameter_name", "name", "param_name"]
    name_col="name"; unit_col=None; range_col=None

    for tbl in possible_tables:
        try:
            cursor.execute(f"PRAGMA table_info({tbl});")
            cols=[c[1] for c in cursor.fetchall()]
            if not cols: continue
            n_col=next((c for c in possible_cols if c in cols), "param_name" if "param_name" in cols else cols[1])
            u_col=next((c for c in ["unit","units"] if c in cols),None)
            r_col=next((c for c in ["normal_range","reference_range","ref_range","range","normal","default_ref_range"] if c in cols),None)
            # Respect the custom display order saved on the "Manage
            # Parameters" screen (Save Parameter Order). Not every
            # possible_tables candidate has a display_order column (some
            # are legacy/alternate schemas), so only add it to the ORDER
            # BY when it actually exists - otherwise keep the previous
            # id-based fallback exactly as before.
            order_clause = "id ASC"
            if "display_order" in cols:
                order_clause = "display_order ASC, id ASC"
            cursor.execute(f"SELECT * FROM {tbl} WHERE test_id = ? ORDER BY {order_clause}",(test_id,))
            got=cursor.fetchall()
            if got:
                params=got; name_col=n_col; unit_col=u_col; range_col=r_col; break
        except (sqlite3.Error,TypeError,ValueError): continue

    rows_html = ""
    # For the FBC Absolute Differential Count sub-section (fix #2 below).
    # Populated from whatever gets displayed in the main table above, so
    # it always matches what the user actually entered - never a second
    # database read, never anything written back to the DB.
    total_wbc_value = None
    differential_percentages = {}  # e.g. "neutrophils" -> 62.0
    DIFFERENTIAL_NAMES = ["neutrophils", "lymphocytes", "monocytes", "eosinophils", "basophils"]

    # Numeric result used to place the pointer on the FIA reference-range
    # gauge below (when show_fia_graph is on for this test). Captured from
    # whichever parameter's result is the first to parse as a number -
    # correct for FIA-graph tests, which are single-parameter (e.g. HbA1c).
    fia_result_value = None

    def _try_float(value):
        try:
            return float(str(value).strip())
        except (TypeError, ValueError):
            return None

    visible_col_count = sum(col_visible) or 1

    # ABST (antibiotic sensitivity) rows left out of the printed table when the
    # "Hide ABST" toggle is ticked, or when no ABST result was entered.
    abst_skip_ids = _abst_param_ids_to_skip(cursor, params, name_col, patient_id, test_id, hide_abst, test_name)

    if params:
        for p in params:
            d=dict(p); p_id=d.get("id")
            if p_id in abst_skip_ids:
                continue

            # FIX #1: Some parameter rows are deliberately named "." (or
            # left blank) purely to create a visual gap between groups of
            # parameters on the report (e.g. separating RBC indices from
            # the differential count). Previously these rendered as a
            # literal "." with a normal border. Render them instead as a
            # clean, borderless spacer row - same vertical gap, nothing
            # visible.
            raw_name_val = d.get(name_col)
            raw_name_str = str(raw_name_val).strip() if raw_name_val is not None else ""
            if raw_name_str in ("", ".", "-", "_"):
                rows_html += (
                    f'<tr><td colspan="{visible_col_count}" '
                    'style="border:none;padding:0;height:10px;line-height:10px;">&nbsp;</td></tr>'
                )
                continue

            p_name=raw_name_str or "Parameter"
            unit=str(d.get(unit_col,"") or "").strip() if unit_col else ""
            default_ref=str(d.get(range_col,"") or "").strip() if range_col else ""
            matched=select_best_ref_range(cursor,int(p_id),patient_gender,patient_age_days) if p_id is not None else None
            ref_range=matched or default_ref
            res="-"
            result_marked_bold = False
            try:
                cursor.execute("SELECT result_value, COALESCE(is_bold, 0) AS is_bold FROM patient_parameter_results WHERE patient_id=? AND test_id=? AND parameter_id=? LIMIT 1",(patient_id,test_id,p_id))
                rr=cursor.fetchone()
                if rr and rr["result_value"] is not None and str(rr["result_value"]).strip(): res=str(rr["result_value"]).strip()
                if rr:
                    result_marked_bold = bool(int(rr["is_bold"] or 0))
            except sqlite3.Error:
                try:
                    cursor.execute("SELECT result_value FROM patient_parameter_results WHERE patient_id=? AND parameter_id=? LIMIT 1",(patient_id,p_id))
                    rr=cursor.fetchone()
                    if rr and rr["result_value"] is not None and str(rr["result_value"]).strip(): res=str(rr["result_value"]).strip()
                except sqlite3.Error: pass

            # Capture Total WBC / differential % values for the Absolute
            # Differential Count sub-section, purely in-memory for this
            # render - never written back to the database.
            p_name_lower = p_name.lower()
            if "wbc" in p_name_lower or "white blood cell" in p_name_lower:
                wbc_val = _try_float(res)
                if wbc_val is not None:
                    total_wbc_value = wbc_val
            else:
                for diff_name in DIFFERENTIAL_NAMES:
                    if diff_name in p_name_lower:
                        pct_val = _try_float(res)
                        if pct_val is not None:
                            differential_percentages[diff_name] = pct_val
                        break

            flag,is_abnormal=evaluate_result_flag(res,ref_range)
            if fia_result_value is None:
                fia_result_value = _try_float(res)
            # Bold the result value when it is out of range (existing
            # behaviour) OR when the operator explicitly ticked "Bold" for
            # this specific result on the Result Entry screen.
            result_weight="bold" if (is_abnormal or result_marked_bold) else "normal"
            investigation_weight="bold" if int(d.get("is_bold", 0) or 0) else "normal"
            cells = [
                (html.escape(p_name), align_inv, investigation_weight, "#000"),
                (html.escape(res), align_res, result_weight, "#000"),
                (flag, align_flag, "bold", "#000"),
                (html.escape(unit), align_unit, "normal", "#333"),
                (html.escape(ref_range or ""), align_ref, "normal", "#333"),
            ]
            row_cells = []
            for idx, (cell_value, cell_align, cell_weight, cell_color) in enumerate(cells):
                if cell_align == "none":
                    continue
                row_cells.append(
                    f'<td style="width:{col_widths[idx]:.2f}%;padding:var(--dynamic-row-padding) 7px;border-bottom:none;text-align:{cell_align};font-weight:{cell_weight};color:{cell_color};line-height:var(--dynamic-line-height);">{cell_value}</td>'
                )
            rows_html += "<tr>" + "".join(row_cells) + "</tr>"
    elif main_result_val:
        flag,is_abnormal=evaluate_result_flag(main_result_val,"")
        fia_result_value = _try_float(main_result_val)
        weight="bold" if is_abnormal else "normal"
        cells = [
            (html.escape(test_name), align_inv, "normal", "#000"),
            (html.escape(main_result_val), align_res, weight, "#000"),
            (flag, align_flag, "bold", "#000"),
            ("-", align_unit, "normal", "#000"),
            ("-", align_ref, "normal", "#000"),
        ]
        row_cells = []
        for idx, (cell_value, cell_align, cell_weight, cell_color) in enumerate(cells):
            if cell_align == "none":
                continue
            row_cells.append(
                f'<td style="width:{col_widths[idx]:.2f}%;padding:var(--dynamic-row-padding) 7px;text-align:{cell_align};font-weight:{cell_weight};color:{cell_color};line-height:var(--dynamic-line-height);">{cell_value}</td>'
            )
        rows_html = "<tr>" + "".join(row_cells) + "</tr>"
    else:
        rows_html='<tr><td colspan="5" style="text-align:center;padding:15px;color:#777;border-bottom:none;">No parameters or results found for this test.</td></tr>'

    # -----------------------------------------------------------------
    # FIX #2: Auto-calculated Absolute Differential Count for FBC.
    # Purely a render-time calculation from whatever Total WBC / % values
    # were already displayed above - nothing is written to the database,
    # and nothing changes for any test other than FBC.
    # -----------------------------------------------------------------
    test_code_val = ""
    try:
        if test_row and "test_code" in test_row.keys() and test_row["test_code"]:
            test_code_val = str(test_row["test_code"]).strip().upper()
    except Exception:
        pass
    is_fbc = test_code_val == "FBC" or "FULL BLOOD COUNT" in test_name.upper() or "FBC" in test_name.upper()

    absolute_diff_html = ""
    if is_fbc and total_wbc_value is not None and differential_percentages:
        diff_labels = {
            "neutrophils": "Absolute Neutrophils",
            "lymphocytes": "Absolute Lymphocytes",
            "monocytes": "Absolute Monocytes",
            "eosinophils": "Absolute Eosinophils",
            "basophils": "Absolute Basophils",
        }

        def _abs_diff_row(cells):
            row_cells = []
            for idx, (cell_value, cell_align, cell_weight, cell_color) in enumerate(cells):
                if cell_align == "none":
                    continue
                row_cells.append(
                    f'<td style="width:{col_widths[idx]:.2f}%;padding:var(--dynamic-row-padding) 7px;border-bottom:none;text-align:{cell_align};font-weight:{cell_weight};color:{cell_color};line-height:var(--dynamic-line-height);">{cell_value}</td>'
                )
            return "<tr>" + "".join(row_cells) + "</tr>"

        # Section heading rendered as an ordinary row in the SAME table -
        # same column widths/alignment as every other row, plain black
        # bold text (matching the existing "DIFFERENTIAL COUNT" heading
        # row style above), no separate table, no colored accent border.
        diff_section_html = _abs_diff_row([
            ("ABSOLUTE DIFFERENTIAL COUNT", align_inv, "bold", "#000"),
            ("-", align_res, "normal", "#000"),
            ("", align_flag, "normal", "#000"),
            ("", align_unit, "normal", "#333"),
            ("", align_ref, "normal", "#333"),
        ])

        # Fixed clinical order, regardless of the order parameters happen
        # to be entered/displayed in above.
        for key in DIFFERENTIAL_NAMES:
            if key not in differential_percentages:
                continue
            pct_value = differential_percentages[key]
            absolute_value = (total_wbc_value * pct_value) / 100.0
            diff_section_html += _abs_diff_row([
                (diff_labels[key], align_inv, "normal", "#000"),
                (f"{absolute_value:.2f}", align_res, "normal", "#000"),
                ("", align_flag, "normal", "#000"),
                ("&times;10&sup3;/&micro;L", align_unit, "normal", "#333"),
                ("", align_ref, "normal", "#333"),
            ])

        # Append directly into the main results table body, so these rows
        # share its exact column widths/alignment/borders instead of a
        # separate standalone table.
        rows_html += diff_section_html

    # Optional FIA graph is test-configurable, never hardcoded to HbA1c.
    # It renders INLINE, beside the results table itself (not as a
    # separate block below it) - the table + graph sit side by side as
    # one row. Notes/comments are not tied to this block and are
    # rendered normally in their usual place below the table, exactly as
    # when the FIA graph is off.
    #
    # Graph content: a Color-Banded Reference Range Gauge (replaces the
    # earlier signal/reaction-curve mockup). Bands follow standard HbA1c
    # interpretation - Green <5.6% (normal), Yellow 5.6-7.0%
    # (pre-diabetes), Red >10% (diabetes range) - with a pointer marking
    # the patient's own result. Scale is fixed at 4.0-10.0% so the three
    # bands stay proportioned and legible at this box's fixed size;
    # results outside that range clamp the pointer to the nearest edge
    # (they still land visibly in the green or red band, just at its
    # outer edge) rather than being drawn off the gauge.
    fia_graph_only_html = ""
    if show_fia_graph:
        # Computed here in plain Python and written as literal inline
        # pixel values (no calc(), no var(), no position:relative) - see
        # the long comment on .fia-graph-wrap in the <style> block above
        # for why the previous CSS-variable/calc() approach silently
        # failed specifically in print/PDF output. !important on each
        # guarantees these always win regardless of any other CSS rule.
        fia_margin_top_final = 28 + print_settings["fia_margin_top_px"]
        fia_margin_bottom_final = print_settings["fia_margin_bottom_px"]
        fia_margin_left_final = print_settings["fia_margin_left_px"]
        fia_margin_right_final = print_settings["fia_margin_right_px"]
        fia_graph_wrap_style = (
            f"margin-top: {fia_margin_top_final}px !important; "
            f"margin-bottom: {fia_margin_bottom_final}px !important; "
            f"margin-right: {fia_margin_right_final}px !important; "
            f"position: relative !important; "
            f"left: {fia_margin_left_final}px !important;"
        )

        GAUGE_MIN, GAUGE_MAX = 4.0, 10.0
        GAUGE_X0, GAUGE_X1 = 40, 400
        GREEN_YELLOW_CUT, YELLOW_RED_CUT = 5.6, 7.0
        BAR_Y, BAR_H = 70, 28

        def _gauge_x(value):
            v = max(GAUGE_MIN, min(GAUGE_MAX, value))
            frac = (v - GAUGE_MIN) / (GAUGE_MAX - GAUGE_MIN)
            return GAUGE_X0 + frac * (GAUGE_X1 - GAUGE_X0)

        green_end_x = _gauge_x(GREEN_YELLOW_CUT)
        yellow_end_x = _gauge_x(YELLOW_RED_CUT)

        pointer_x = _gauge_x(fia_result_value) if fia_result_value is not None else None
        result_label = f"{fia_result_value:.1f}%" if fia_result_value is not None else "N/A"

        pointer_svg = ""
        if pointer_x is not None:
            pointer_svg = f"""
                <line x1='{pointer_x:.1f}' y1='26' x2='{pointer_x:.1f}' y2='52' stroke='#111' stroke-width='2'/>
                <polygon points='{pointer_x-7:.1f},52 {pointer_x+7:.1f},52 {pointer_x:.1f},{BAR_Y}' fill='#111'/>
            """

        fia_graph_only_html = f"""
        <div class='fia-graph-wrap' style='{fia_graph_wrap_style}'>
            <div class='fia-graph-title'>FLUORESCENCE IMMUNOASSAY (FIA) - HbA1c GAUGE</div>
            <svg viewBox='0 0 420 180' class='fia-graph' role='img' aria-label='HbA1c color-banded reference range gauge'>
                <text x='210' y='16' font-size='15' font-weight='700' text-anchor='middle'>Result: {result_label}</text>
                {pointer_svg}
                <rect x='{GAUGE_X0}' y='{BAR_Y}' width='{green_end_x - GAUGE_X0:.1f}' height='{BAR_H}' fill='#4caf50'/>
                <rect x='{green_end_x:.1f}' y='{BAR_Y}' width='{yellow_end_x - green_end_x:.1f}' height='{BAR_H}' fill='#ffc107'/>
                <rect x='{yellow_end_x:.1f}' y='{BAR_Y}' width='{GAUGE_X1 - yellow_end_x:.1f}' height='{BAR_H}' fill='#f44336'/>
                <rect x='{GAUGE_X0}' y='{BAR_Y}' width='{GAUGE_X1 - GAUGE_X0}' height='{BAR_H}' fill='none' stroke='#111' stroke-width='1.5'/>
                <line x1='{green_end_x:.1f}' y1='{BAR_Y}' x2='{green_end_x:.1f}' y2='{BAR_Y + BAR_H}' stroke='#111' stroke-width='1'/>
                <line x1='{yellow_end_x:.1f}' y1='{BAR_Y}' x2='{yellow_end_x:.1f}' y2='{BAR_Y + BAR_H}' stroke='#111' stroke-width='1'/>
                <text x='{GAUGE_X0}' y='{BAR_Y + BAR_H + 14}' font-size='10' text-anchor='start'>&lt;{GAUGE_MIN:.1f}</text>
                <text x='{green_end_x:.1f}' y='{BAR_Y + BAR_H + 14}' font-size='10' text-anchor='middle'>{GREEN_YELLOW_CUT:.1f}</text>
                <text x='{yellow_end_x:.1f}' y='{BAR_Y + BAR_H + 14}' font-size='10' text-anchor='middle'>{YELLOW_RED_CUT:.1f}</text>
                <text x='{GAUGE_X1}' y='{BAR_Y + BAR_H + 14}' font-size='10' text-anchor='end'>&gt;{GAUGE_MAX:.1f}</text>
                <text x='210' y='170' font-size='9.5' text-anchor='middle'>Green: Normal &#160;&#160; Yellow: Pre-diabetes &#160;&#160; Red: Diabetes range</text>
            </svg>
        </div>
        """

    barcode_url = f"https://barcode.tec-it.com/barcode.ashx?data={ref_no}&code=Code128&dpi=96&hidehrt=true"
    if qr_token:
        # Dedicated, unauthenticated, read-only public page for this ONE report.
        download_url = str(request.base_url).rstrip("/") + f"/public-report/{qr_token}"
    else:
        # Token could not be created: keep the previous QR target (unchanged behaviour).
        download_url = str(request.base_url).rstrip("/") + f"/report-download/{patient_id}/{test_id}"
    qr_data = quote(download_url, safe="")
    qr_url = f"https://api.qrserver.com/v1/create-qr-code/?size=120x120&data={qr_data}"

    show_letterhead_bg = letterhead != 0

    if show_letterhead_bg:
        screen_bg_css = (
            f"background-image: url('{letterhead_img_url}');\n"
            "                    background-size: 210mm 297mm;\n"
            "                    background-repeat: no-repeat;\n"
            "                    background-position: top center;"
        )
        print_bg_css = (
            f"background-image: url('{letterhead_img_url}') !important;\n"
            "                         background-size: 210mm 297mm !important;\n"
            "                         background-repeat: no-repeat !important;\n"
            "                         background-position: top center !important;"
        )
        other_mode_link_html = f'<a href="/report-view/{patient_id}/{test_id}?letterhead=0" class="btn" style="background: #7c3aed; margin-right: 6px;">📄 Normal Print</a>'
        print_button_label = "🖨️ Letterhead Print"
    else:
        screen_bg_css = "background-image: none;"
        print_bg_css = "background-image: none !important;"
        other_mode_link_html = f'<a href="/report-letterhead-preview/{patient_id}/{test_id}" class="btn" style="background: #7c3aed; margin-right: 6px;">📄 Letterhead Print</a>'
        print_button_label = "🖨️ Normal Print"

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MEDISTAR MEDICAL LABORATORY - Lab Report - {patient_name}</title>
        <style>
            /* Print Layout Settings, admin-configurable at /print-settings.
               Every dynamic value in this stylesheet reads from these
               variables instead of a hardcoded literal, so a saved
               setting takes effect on every report immediately with no
               code changes. Falls back safely via get_print_settings()
               if the settings row is ever missing (see that function). */
            :root {{
                --dynamic-row-padding: {print_settings['row_padding_px']}px;
                --dynamic-font-size: {print_settings['base_font_size_px']}px;
                --dynamic-header-font-size: {print_settings['header_font_size_px']}px;
                --dynamic-line-height: {print_settings['line_height']};
                --dynamic-footer-gap: {print_settings['footer_gap_px']}px;
                --dynamic-side-margin: {print_settings['page_side_margin_mm']}mm;
                --dynamic-patient-font: {print_settings['patient_box_font_size_px']}px;
                --dynamic-patient-padding: {print_settings['patient_box_padding_px']}px;
                --dynamic-mlt-signature-font: {print_settings['mlt_signature_font_size_px']}px;
                --dynamic-mlt-details-font: {print_settings['mlt_details_font_size_px']}px;
                --dynamic-category-note-font: {print_settings['category_note_font_size']}px;
            }}
            body {{ font-family: Verdana, Geneva, sans-serif !important; font-size: var(--dynamic-font-size); background: #f0f2f5; margin: 0; padding: 20px; color: #000; }}
            .report-page, .report-page * {{ font-family: Verdana, Geneva, sans-serif !important; font-size: var(--dynamic-font-size) !important; }}
            .action-bar {{ max-width: 800px; margin: 0 auto 15px auto; background: white; padding: 10px 20px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            .btn {{ background: #333; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: bold; text-decoration: none; font-size: 13px; }}
            .btn:hover {{ background: #000; }}
            
            .report-page {{ 
                width: 210mm; 
                min-height: 297mm; 
                margin: 0 auto; 
                background: white; 
                {screen_bg_css}
                padding: 38mm var(--dynamic-side-margin) 15mm var(--dynamic-side-margin); 
                box-sizing: border-box; 
                box-shadow: 0 4px 15px rgba(0,0,0,0.15); 
                position: relative; 
            }}
            
            .top-barcode-container {{ text-align: right; margin-bottom: 8px; }}
            .top-barcode-container img {{ height: 30px; width: 155px; object-fit: fill; display: block; margin-left: auto; }}

            .patient-box {{ border: 1px solid #333; border-radius: 3px; padding: 10px 15px; margin-bottom: 12px; background: rgba(255,255,255,0.9); }}

            /* Patient Details Box: table-layout AUTO (not fixed) so the
               browser/WeasyPrint's standard table layout algorithm sizes
               each column to fit its actual content, borrowing space from
               columns that don't need it. This is what lets the box scale
               comfortably to 12-14px+ font sizes: a nowrap label like
               "Reference No" or "Gender / Age" will never be truncated or
               forced to wrap, because auto-layout always widens a column
               to fit non-wrapping content rather than clipping it - it
               only ever falls back to the <colgroup> percentages below as
               a starting proportion, then grows columns as needed. Colon
               alignment stays fully guaranteed either way: every row
               shares the exact same 6 column widths, since it's one
               table, so column 2's colon lines up down every row, and
               column 5's colon lines up down every row. */
            .header-table {{ 
                width: 100%; 
                border-collapse: collapse; 
                table-layout: auto; 
                font-size: var(--dynamic-patient-font) !important; 
            }}
            .header-table td {{ 
                padding: var(--dynamic-patient-padding) 6px; 
                vertical-align: middle; 
                font-size: var(--dynamic-patient-font) !important;
            }}
            /* Label cells: never wrap ("Gender / Age" must stay on one
               line) and always bold/black for consistent hierarchy. No
               overflow:hidden here - with table-layout:auto the column
               simply grows to fit this text instead of ever needing to
               clip it. */
            .header-table td.hlabel {{ 
                font-weight: bold; 
                color: #000; 
                white-space: nowrap; 
            }}
            /* Colon cells: sized to their content (just ":"), so they
               stay compact and centered - every colon in a column sits
               at the exact same horizontal position across all rows. */
            .header-table td.hcolon {{ 
                text-align: center; 
                white-space: nowrap; 
                width: 1%;
            }}
            /* Value cells: get all remaining space (auto-layout gives
               unclaimed width to the most flexible columns), and still
               wrap gracefully for unusually long text rather than
               overflowing the box. */
            .header-table td.hvalue {{ 
                overflow-wrap: break-word; 
                word-break: break-word; 
            }}
            
            .test-title-bar {{ text-align: center; font-weight: bold; font-size: var(--dynamic-header-font-size); margin: 8px 0 5px 0; color: #000; text-transform: uppercase; letter-spacing: 0.5px; }}

            .report-table {{ width: 100%; border-collapse: collapse; margin-top: 3px; font-size: var(--dynamic-font-size); table-layout: fixed; }}
            .report-table th {{ background: none; color: #000; border-top: 1px solid #000; border-bottom: 1px solid #000; padding: var(--dynamic-row-padding) 7px; font-size: var(--dynamic-header-font-size) !important; font-weight: bold; box-sizing: border-box; line-height: var(--dynamic-line-height); }}
            .report-table td {{ box-sizing: border-box; overflow-wrap: anywhere; word-break: normal; line-height: var(--dynamic-line-height); }}
            
            .report-note, .report-test-note, .test-category-note, .interpretation-note {{ margin-top: 10px; padding: 0; font-size: var(--dynamic-category-note-font) !important; color: #000; background: transparent; border: none; line-height: 1.4; }}
            /* When a FIA gauge is present, the row's height is driven by
               the (taller) gauge box rather than a typically much
               shorter single-parameter table, which otherwise leaves an
               awkward blank gap before the notes/guidelines text below.
               This tightens the gap specifically in that case only -
               every other test's note spacing above is untouched. */
            .fia-inline-row + .report-note, .fia-inline-row + .report-test-note, .fia-inline-row + .test-category-note, .fia-inline-row + .interpretation-note {{ margin-top: -5px; }}

            /* Tables typed into a Test Category's Notes / Description box
               (e.g. reference ranges). The page-wide reset gives bare
               <table>/<td> no borders or padding, so they printed as
               unreadable jammed-together text. These scoped rules give
               them a clean bordered grid in screen view AND print view.
               Only affects tables inside the notes block. */
            .report-test-note table, .test-category-note table, .interpretation-note table {{ display: table !important; width: 100%; border-collapse: collapse; margin: 6px 0; table-layout: auto; border: 1px solid #000; break-inside: avoid; page-break-inside: avoid; }}
            .report-test-note thead, .test-category-note thead {{ display: table-header-group; }}
            .report-test-note tbody, .test-category-note tbody {{ display: table-row-group; }}
            .report-test-note tr, .test-category-note tr {{ display: table-row; break-inside: avoid; page-break-inside: avoid; }}
            .report-test-note th, .report-test-note td, .test-category-note th, .test-category-note td {{ display: table-cell; border: 1px solid #000; padding: 3px 6px; text-align: left; vertical-align: top; color: #000; line-height: 1.3; overflow-wrap: anywhere; }}
            .report-test-note th, .test-category-note th {{ font-weight: bold; background: #f2f2f2; }}

            .end-report-text {{ text-align: center; font-size: 7px !important; font-weight: bold; color: #000; margin: 4px 0; letter-spacing: 0.7px; }}
            .section-divider {{ border: none; border-top: 1px solid #999; margin: 5px 0 3px 0; }}

            /* Footer (QR + MLT/Signature + Printed On) now sits in plain,
               natural document flow directly below the "END OF REPORT"
               line - no forced bottom positioning, no sticky-footer flex
               trick, no fixed offset. A short report ends with a compact
               footer right after its short table; a long, multi-parameter
               report (e.g. FBC) simply flows the footer further down the
               page, exactly where the content naturally ends. This is
               what keeps long reports from overflowing or triggering
               awkward forced page breaks. */
            /* FIA graph is now rendered INLINE beside the results table
               itself (not as a separate block below it). .fia-inline-row
               is only applied when the graph is on for this test - when
               it's off, .report-table renders exactly as before, full
               width, completely unaffected. box-sizing:border-box on
               every box here is what guarantees the table column and the
               graph box sit cleanly side by side without colliding. */
            .fia-inline-row {{ 
                display: flex; 
                flex-wrap: nowrap; 
                justify-content: flex-end;
                gap: 15px; 
                align-items: flex-start; 
                box-sizing: border-box; 
                width: 100%; 
            }}
            .fia-table-col {{ 
                flex: 1 1 auto; 
                min-width: 0; 
                box-sizing: border-box; 
            }}
            /* Right side: a fixed-width box that hugs the SVG closely.
               Sized up slightly from the previous standalone version
               (190px -> 230px) for better legibility now that it sits
               directly beside the result row instead of underneath a
               long block of text. align-items:flex-start on
               .fia-inline-row (above) stops it from being stretched to
               match the table's full height, so there's no leftover
               empty white space inside the box. margin-left:auto plus
               flex-wrap:nowrap/justify-content:flex-end on the row above
               are three independent guarantees that this box always sits
               flush against the far-right edge of the row, never
               wrapping under the table or drifting left.

               NOTE: the admin-configurable top/bottom/left/right offsets
               are intentionally NOT set here via CSS var()/calc(). That
               was the actual bug: calc(28px + var(--x)) combined with
               position:relative + a var()-driven `left` offset is not
               reliably supported by WeasyPrint (the PDF/print rendering
               engine used for /report-download and this page's browser
               print output) - it would resolve fine on-screen in a
               regular browser tab, but silently fail to apply in the
               actual printed/PDF output, which is exactly the reported
               symptom ("not moving the graph box in print mode"). The
               fix is to compute the final pixel values in Python (see
               fia_graph_only_html below) and write them as plain,
               literal inline styles - no calc(), no var(), no
               position:relative - which every rendering engine
               (browser screen, browser print, and WeasyPrint) handles
               identically and reliably. margin-left:auto (for the
               right-anchor) is the one exception kept here, since it's
               fixed layout behavior, not an admin-adjustable value. */
            .fia-graph-wrap {{ 
                flex: 0 0 230px; 
                max-width: 230px; 
                margin-left: auto;
                box-sizing: border-box; 
                padding: 6px 8px; 
                border: 1px solid #222; 
            }}
            .fia-graph-title {{ text-align:center; font-size:8.5px !important; font-weight:700; margin-bottom:3px; }}
            /* SVG itself is untouched (viewBox + width:100% already make
               it scale cleanly and responsively) - only its wrapper's
               box model and size were ever adjusted. */
            .fia-graph {{ width:100%; height:auto; display:block; }}
            @media print {{ .fia-inline-row {{ break-inside: avoid; page-break-inside: avoid; }} }}

            .report-bottom-fixed {{
                margin-top: var(--dynamic-footer-gap);
                width: 100%;
            }}
            .bottom-section {{ 
                display: flex; 
                justify-content: space-between; 
                align-items: flex-end; 
                width: 100%; 
            }}
            .qr-container img {{ width: 75px; height: 75px; }}
            
            .sig-wrapper-new {{ 
                text-align: center; 
                min-width: 300px; 
                /* Shifted further toward the right margin. Capped at the
                   page's own printable width (A4, 15mm side padding) -
                   pushing it further would cut the signature block off
                   the printed page, so this is the maximum safe rightward
                   offset that still prints in full. */
                margin-right: -10mm; 
                display: flex;
                flex-direction: column;
                align-items: center;
                line-height: 1.15; 
            }}
            .sig-img-new {{ 
                width: 420px; 
                height: 135px; 
                object-fit: contain; 
                display: block; 
                margin-top: -45px; 
                margin-bottom: -32px; 
                margin-left: 10px; 
            }}
            /* MLT Signature: the technologist's typed name under the
               signature image. Independently adjustable at
               /print-settings so it can be made larger/smaller without
               touching the "MLT Details" lines below it. */
            .mlt-name {{
                font-size: var(--dynamic-mlt-signature-font) !important;
                margin-bottom: 1px;
                display: block;
            }}
            /* MLT Details: designation ("Medical Laboratory Technologist
               (MLT)") and registration number lines. Independently
               adjustable at /print-settings, separate from the name. */
            .mlt-details {{
                font-size: var(--dynamic-mlt-details-font) !important;
                display: block;
            }}

            /* "Printed on" now sits directly under the MLT/signature
               block (not centered under the whole page), with a
               one-line gap, and no divider line above it. */
            .printed-on-line {{
                margin-top: 14px;
                text-align: center;
                font-size: 8.5px !important;
                font-weight: 700;
                color: #000;
            }}

            @media print {{
                body {{ background: none; padding: 0; margin: 0; }}
                .action-bar {{ display: none !important; }}
                .report-page {{ 
                    box-shadow: none; margin: 0; width: 100%; height: auto; min-height: 297mm; 
                    padding: 38mm 15mm 15mm 15mm; border: none; 
                    -webkit-print-color-adjust: exact; print-color-adjust: exact; 
                    {print_bg_css}
                }}
                @page {{ size: A4; margin: 0; }}
            }}
        </style>
    </head>
    <body>

        <!-- Top Action Bar -->
        <div class="action-bar">
            <a href="/test-entry/{patient_id}/{test_id}" class="btn" style="background: #475569;">&larr; Back to Edit</a>
            <div>
                {other_mode_link_html}
                <button onclick="window.print()" class="btn" style="background: #0f172a;">{print_button_label}</button>
            </div>
        </div>

        <!-- A4 Report Sheet -->
        <div class="report-page">
            <div class="top-barcode-container">
                <img src="{barcode_url}" alt="Barcode">
            </div>

            {cancelled_report_banner_html}

            <div class="patient-box">
                <table class="header-table">
                    <colgroup>
                        <col style="width:12%;">
                        <col style="width:1%;">
                        <col style="width:40%;">
                        <col style="width:12%;">
                        <col style="width:1%;">
                        <col style="width:34%;">
                    </colgroup>
                    <tr>
                        <td class="hlabel">Patient Name</td>
                        <td class="hcolon">:</td>
                        <td class="hvalue" style="font-weight: bold;">{patient_name}</td>
                        <td class="hlabel">Reference No</td>
                        <td class="hcolon">:</td>
                        <td class="hvalue" style="font-weight: bold;">{display_ref_no}</td>
                    </tr>
                    <tr>
                        <td class="hlabel">Gender / Age</td>
                        <td class="hcolon">:</td>
                        <td class="hvalue">{gender_age}</td>
                        <td class="hlabel">Received On</td>
                        <td class="hcolon">:</td>
                        <td class="hvalue">{received_on}</td>
                    </tr>
                    <tr>
                        <td class="hlabel">Referred By</td>
                        <td class="hcolon">:</td>
                        <td class="hvalue">{doctor}</td>
                        <td class="hlabel">Reported On</td>
                        <td class="hcolon">:</td>
                        <td class="hvalue">{reported_on}</td>
                    </tr>
                    <tr>
                        <td class="hlabel">Center</td>
                        <td class="hcolon">:</td>
                        <td class="hvalue">{center}</td>
                        <td class="hlabel">Department</td>
                        <td class="hcolon">:</td>
                        <td class="hvalue">{department}</td>
                    </tr>
                    <tr>
                        <td></td>
                        <td></td>
                        <td></td>
                        <td class="hlabel">Specimen</td>
                        <td class="hcolon">:</td>
                        <td class="hvalue">{specimen}</td>
                    </tr>
                </table>
            </div>

            <div class="test-title-bar">{test_name}</div>

            <div class="{'fia-inline-row' if show_fia_graph else ''}">
                <div class="{'fia-table-col' if show_fia_graph else ''}">
                    <table class="report-table">
                        <thead>
                            <tr>
                                {f'<th style="width:{col_widths[0]:.2f}%;text-align:{align_inv};">Investigation</th>' if align_inv != "none" else ""}
                                {f'<th style="width:{col_widths[1]:.2f}%;text-align:{align_res};">Result</th>' if align_res != "none" else ""}
                                {f'<th style="width:{col_widths[2]:.2f}%;text-align:{align_flag};">Flag</th>' if align_flag != "none" else ""}
                                {f'<th style="width:{col_widths[3]:.2f}%;text-align:{align_unit};">Unit</th>' if align_unit != "none" else ""}
                                {f'<th style="width:{col_widths[4]:.2f}%;text-align:{align_ref};">Reference Range</th>' if align_ref != "none" else ""}
                            </tr>
                        </thead>
                        <tbody>
                            {rows_html}
                        </tbody>
                    </table>
                    {absolute_diff_html}
                </div>
                {fia_graph_only_html}
            </div>

            {("<div class='report-note'><b>Note:</b> " + comment_text + "</div>") if comment_text else ""}
            {test_notes_html}
            <hr class="section-divider">
            <div class="end-report-text">*** END OF REPORT ***</div>

            <!-- Footer: QR Left, MLT/Signature + Printed-on Right. Sits
                 directly below "END OF REPORT" in normal document flow. -->
            <div class="report-bottom-fixed">
                <div class="bottom-section">
                    <div class="qr-container">
                        <img src="{qr_url}" alt="QR Code">
                    </div>
                    <div class="sig-wrapper-new">
                        <img src="{signature_img_url}" alt="MLT Signature" class="sig-img-new" style="{sig_img_inline_style}" onerror="this.style.display='none';">
                        <b class="mlt-name">S.P.Jananga</b>
                        <span class="mlt-details" style="color: #222;">Medical Laboratory Technologist (MLT)</span>
                        <span class="mlt-details" style="color: #444;">SLMC No 2867</span>
                        {"<div class=\"printed-on-line\">Printed on: " + printed_on + "</div>" if print_settings.get("show_printed_on", 1) else ""}
                    </div>
                </div>
            </div>
        </div>

    </body>
    </html>
    """

# =================================================================
# SALES & FINANCIAL ANALYTICS MODULE (new, additive-only feature)
# =================================================================
# Reads from the existing patients / patient_assigned_tests / tests /
# doctors / collecting_centers tables exactly as they already are -
# no existing table is altered except the new, additive
# `doctors.commission_rate` column (see init_db() migration above,
# default 0 so every existing doctor's behavior is unchanged until a
# rate is actually set). No existing route's logic is touched; this is
# a brand-new route reached via a new link on the /reports page.

def _sales_analytics_date_range(preset: str, start_date: str, end_date: str):
    """Resolves the (start_date, end_date) SQL-ready date strings for
    the chosen preset. Returns (start_date, end_date, resolved_start,
    resolved_end) where the last two are always concrete dates (used
    for the on-screen "Date Range" label), while the first two mirror
    exactly what should be echoed back into the date <input> fields."""
    today = now_colombo().date()
    if preset == "today":
        d = today.isoformat()
        return d, d, d, d
    if preset == "this_month":
        first_of_month = today.replace(day=1).isoformat()
        d_end = today.isoformat()
        return first_of_month, d_end, first_of_month, d_end
    # "custom" (or anything else): use whatever was actually submitted.
    return start_date, end_date, (start_date or "All Time"), (end_date or "Present")


@app.get("/reports/sales-analytics", response_class=HTMLResponse)
def sales_analytics_page(
    request: Request,
    preset: str = "this_month",
    start_date: str = "",
    end_date: str = "",
    doctor: str = "all",
    center: str = "all",
    view: str = "table",
):
    current_user = get_current_user(request)
    if not user_can_or_legacy(current_user, "can_view_reports", "reports"):
        return render_locked_page("Sales & Financial Analytics")

    start_date, end_date, label_start, label_end = _sales_analytics_date_range(preset, start_date, end_date)

    conn = get_db_connection()
    cursor = conn.cursor()

    # ---- Shared date/doctor/center filters, built safely with
    # parameterized ? placeholders. The cancellation condition is kept
    # separate (see where_sql / cancelled_where_sql below) so the exact
    # same date/doctor/center filters apply consistently whether looking
    # at active sales or the Cancelled Invoices tab.
    common_where_sql = ""
    common_where_params = []

    if start_date and end_date:
        common_where_sql += " AND date(p.created_at) BETWEEN ? AND ?"
        common_where_params.extend([start_date, end_date])

    if doctor and doctor != "all":
        common_where_sql += " AND p.doctor = ?"
        common_where_params.append(doctor)

    if center and center != "all":
        common_where_sql += " AND COALESCE(p.center, p.collecting_center) = ?"
        common_where_params.append(center)

    # CRITICAL: this one clause feeds all three "active" queries below
    # (detailed sales rows, doctor-wise summary, center-wise summary), so
    # excluding cancelled bills here automatically keeps every revenue
    # total across this whole page accurate - a cancelled bill is never
    # double-excluded or missed in one view but not another.
    where_sql = "WHERE (p.is_cancelled IS NULL OR p.is_cancelled = 0)" + common_where_sql
    where_params = list(common_where_params)

    # Mirror image of where_sql: same date/doctor/center filters, but only
    # the cancelled bills - powers the dedicated Cancelled Invoices tab.
    cancelled_where_sql = "WHERE p.is_cancelled = 1" + common_where_sql
    cancelled_where_params = list(common_where_params)

    # ---- Dropdown option sources ----
    cursor.execute("SELECT code, name FROM doctors ORDER BY name")
    doctor_options_rows = cursor.fetchall()

    cursor.execute("""
        SELECT DISTINCT COALESCE(p.center, p.collecting_center) as c
        FROM patients p
        WHERE COALESCE(p.center, p.collecting_center) IS NOT NULL
        UNION
        SELECT center_name FROM collecting_centers WHERE center_name IS NOT NULL
        ORDER BY c
    """)
    center_options_rows = [r["c"] for r in cursor.fetchall() if r["c"]]

    # ---- Detailed sales rows (one row per patient, tests combined) ----
    sales_rows = []
    grand_total = 0.0
    try:
        cursor.execute(f"""
            SELECT p.id as patient_id, p.title, p.name, p.created_at, p.manual_bill_no,
                   p.doctor as doctor_code, COALESCE(d.name, p.doctor, 'Not Specified') as doctor_name,
                   COALESCE(p.center, p.collecting_center, 'Main Branch') as center_name,
                   GROUP_CONCAT(COALESCE(NULLIF(t.test_code, ''), t.test_name), ', ') as tests_performed,
                   SUM(COALESCE(t.price, 0)) as amount
            FROM patients p
            JOIN patient_assigned_tests pat ON pat.patient_id = p.id
            JOIN tests t ON t.id = pat.test_id
            LEFT JOIN doctors d ON d.code = p.doctor
            {where_sql}
            GROUP BY p.id
            ORDER BY p.id DESC
        """, where_params)
        sales_rows = cursor.fetchall()
        grand_total = sum((r["amount"] or 0) for r in sales_rows)
    except Exception as e:
        sales_rows = []
        sales_error = str(e)
    else:
        sales_error = ""

    # ---- Doctor-wise summary ----
    doctor_summary_rows = []
    try:
        cursor.execute(f"""
            SELECT p.doctor as doctor_code, COALESCE(d.name, p.doctor, 'Not Specified') as doctor_name,
                   COUNT(DISTINCT p.id) as patient_count,
                   SUM(COALESCE(t.price, 0)) as revenue,
                   COALESCE(d.commission_rate, 0) as commission_rate
            FROM patients p
            JOIN patient_assigned_tests pat ON pat.patient_id = p.id
            JOIN tests t ON t.id = pat.test_id
            LEFT JOIN doctors d ON d.code = p.doctor
            {where_sql}
            GROUP BY p.doctor
            ORDER BY revenue DESC
        """, where_params)
        doctor_summary_rows = cursor.fetchall()
    except Exception:
        doctor_summary_rows = []

    # ---- Center-wise summary ----
    center_summary_rows = []
    try:
        cursor.execute(f"""
            SELECT COALESCE(p.center, p.collecting_center, 'Main Branch') as center_name,
                   COUNT(DISTINCT p.id) as patient_count,
                   COUNT(pat.id) as tests_dispatched,
                   SUM(COALESCE(t.price, 0)) as billing
            FROM patients p
            JOIN patient_assigned_tests pat ON pat.patient_id = p.id
            JOIN tests t ON t.id = pat.test_id
            {where_sql}
            GROUP BY center_name
            ORDER BY billing DESC
        """, where_params)
        center_summary_rows = cursor.fetchall()
    except Exception:
        center_summary_rows = []

    # ---- Test-wise counts (overall, per doctor, per center) ----
    test_summary_rows = []
    tests_by_doctor = {}
    tests_by_center = {}
    test_doc_split = {}
    test_center_split = {}
    try:
        _label = "COALESCE(NULLIF(t.test_code, ''), t.test_name)"
        cursor.execute(f"""
            SELECT t.id as test_id, t.test_name, COALESCE(t.test_code, '') as test_code,
                   COALESCE(t.price, 0) as unit_price,
                   COUNT(pat.id) as cnt, SUM(COALESCE(t.price, 0)) as amount
            FROM patients p
            JOIN patient_assigned_tests pat ON pat.patient_id = p.id
            JOIN tests t ON t.id = pat.test_id
            {where_sql}
            GROUP BY t.id
            ORDER BY cnt DESC, t.test_name
        """, where_params)
        test_summary_rows = cursor.fetchall()

        cursor.execute(f"""
            SELECT p.doctor as doctor_code, {_label} as tlabel, COUNT(pat.id) as cnt
            FROM patients p
            JOIN patient_assigned_tests pat ON pat.patient_id = p.id
            JOIN tests t ON t.id = pat.test_id
            {where_sql}
            GROUP BY p.doctor, t.id
            ORDER BY cnt DESC
        """, where_params)
        for r in cursor.fetchall():
            tests_by_doctor.setdefault(r["doctor_code"], []).append((r["tlabel"], r["cnt"]))

        cursor.execute(f"""
            SELECT COALESCE(p.center, p.collecting_center, 'Main Branch') as cname,
                   {_label} as tlabel, COUNT(pat.id) as cnt
            FROM patients p
            JOIN patient_assigned_tests pat ON pat.patient_id = p.id
            JOIN tests t ON t.id = pat.test_id
            {where_sql}
            GROUP BY cname, t.id
            ORDER BY cnt DESC
        """, where_params)
        for r in cursor.fetchall():
            tests_by_center.setdefault(r["cname"], []).append((r["tlabel"], r["cnt"]))

        cursor.execute(f"""
            SELECT t.id as test_id, COALESCE(d.name, p.doctor, 'Not Specified') as dname, COUNT(pat.id) as cnt
            FROM patients p
            JOIN patient_assigned_tests pat ON pat.patient_id = p.id
            JOIN tests t ON t.id = pat.test_id
            LEFT JOIN doctors d ON d.code = p.doctor
            {where_sql}
            GROUP BY t.id, p.doctor
            ORDER BY cnt DESC
        """, where_params)
        for r in cursor.fetchall():
            test_doc_split.setdefault(r["test_id"], []).append((r["dname"], r["cnt"]))

        cursor.execute(f"""
            SELECT t.id as test_id, COALESCE(p.center, p.collecting_center, 'Main Branch') as cname,
                   COUNT(pat.id) as cnt
            FROM patients p
            JOIN patient_assigned_tests pat ON pat.patient_id = p.id
            JOIN tests t ON t.id = pat.test_id
            {where_sql}
            GROUP BY t.id, cname
            ORDER BY cnt DESC
        """, where_params)
        for r in cursor.fetchall():
            test_center_split.setdefault(r["test_id"], []).append((r["cname"], r["cnt"]))
    except Exception:
        pass

    # ---- Cancelled bills (dedicated audit tab) ----
    cancelled_rows = []
    try:
        cursor.execute(f"""
            SELECT p.id as patient_id, p.title, p.name, p.created_at, p.manual_bill_no,
                   p.doctor as doctor_code, COALESCE(d.name, p.doctor, 'Not Specified') as doctor_name,
                   COALESCE(p.center, p.collecting_center, 'Main Branch') as center_name,
                   SUM(COALESCE(t.price, 0)) as amount
            FROM patients p
            LEFT JOIN patient_assigned_tests pat ON pat.patient_id = p.id
            LEFT JOIN tests t ON t.id = pat.test_id
            LEFT JOIN doctors d ON d.code = p.doctor
            {cancelled_where_sql}
            GROUP BY p.id
            ORDER BY p.id DESC
        """, cancelled_where_params)
        cancelled_rows = cursor.fetchall()
    except Exception:
        cancelled_rows = []
    cancelled_count = len(cancelled_rows)
    cancelled_total = sum((r["amount"] or 0) for r in cancelled_rows)

    conn.close()

    # ---- Build option HTML ----
    doctor_opts_html = '<option value="all">All Doctors</option>' + "".join(
        f'<option value="{d["code"]}" {"selected" if doctor == d["code"] else ""}>{d["name"]} ({d["code"]})</option>'
        for d in doctor_options_rows
    )
    center_opts_html = '<option value="all">All Centers</option>' + "".join(
        f'<option value="{html.escape(c)}" {"selected" if center == c else ""}>{html.escape(c)}</option>'
        for c in center_options_rows
    )

    # ---- Build the active view's table ----
    # Shared helper for the detailed doctor-wise / center-wise views: renders one
    # bill row using the exact same 7-column structure as the main sales table.
    def _detail_bill_row_html(r):
        ref_no = f"PRI-{r['patient_id']:04d}"
        display_ref_no = f"{ref_no} / {r['manual_bill_no']}" if r["manual_bill_no"] else ref_no
        date_str = str(r["created_at"] or "").split(" ")[0]
        patient_name = f"{r['title'] or ''} {r['name'] or ''}".strip()
        return f"""
        <tr>
            <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{date_str}</td>
            <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{display_ref_no}</td>
            <td style="padding:8px 10px; border-bottom:1px solid var(--border-color); font-weight:bold;">{html.escape(patient_name)}</td>
            <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{html.escape(r['tests_performed'] or '')}</td>
            <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{html.escape(r['doctor_name'] or 'Not Specified')}</td>
            <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{html.escape(r['center_name'] or 'Main Branch')}</td>
            <td style="padding:8px 10px; border-bottom:1px solid var(--border-color); text-align:right;">{(r['amount'] or 0):,.2f}</td>
        </tr>
        """

    def _test_count_row_html(items):
        if not items:
            return ""
        total_cnt = sum(c for _, c in items)
        chips = " &middot; ".join(f"{html.escape(str(n))} &times; <b>{c}</b>" for n, c in items)
        return f"""
        <tr style="background: rgba(39,174,96,0.07);">
            <td colspan="7" style="padding:7px 10px; border-bottom:1px solid var(--border-color); font-size:12.5px;">
                <b>Test-wise count ({total_cnt} total):</b> {chips}
            </td>
        </tr>
        """

    def _split_text(items):
        return " &middot; ".join(f"{html.escape(str(n))} &times; <b>{c}</b>" for n, c in items) or "-"

    # Group the already-fetched (cancelled-excluded, filtered) bill rows so each
    # doctor / center section lists its own bills.
    bills_by_doctor = {}
    bills_by_center = {}
    for _r in sales_rows:
        bills_by_doctor.setdefault(_r["doctor_code"], []).append(_r)
        bills_by_center.setdefault(_r["center_name"] or "Main Branch", []).append(_r)

    if view == "doctor":
        table_title = "Doctor-wise Detailed Sales & Commission"
        table_header_html = "<th>Date</th><th>Invoice/Lab No</th><th>Patient Name</th><th>Test(s) Performed</th><th>Doctor</th><th>Center</th><th style='text-align:right;'>Amount (LKR)</th>"
        body_rows = ""
        total_revenue = 0.0
        total_commission = 0.0
        for r in doctor_summary_rows:
            revenue = r["revenue"] or 0
            rate = r["commission_rate"] or 0
            commission = revenue * (rate / 100.0)
            total_revenue += revenue
            total_commission += commission
            group_bills = bills_by_doctor.get(r["doctor_code"], [])
            doc_label = html.escape(r["doctor_name"] or "Not Specified")
            doc_code = html.escape(r["doctor_code"] or "-")
            body_rows += f"""
            <tr style="background: rgba(15,76,129,0.10);">
                <td colspan="7" style="padding:10px; border-bottom:1px solid var(--border-color); font-weight:bold; color:#0f4c81;">
                    {doc_label} ({doc_code}) &mdash; {r['patient_count']} patient(s) &middot; Revenue: LKR {revenue:,.2f} &middot; Commission {rate:.1f}%: LKR {commission:,.2f}
                </td>
            </tr>
            """
            body_rows += _test_count_row_html(tests_by_doctor.get(r["doctor_code"], []))
            for b in group_bills:
                body_rows += _detail_bill_row_html(b)
            body_rows += f"""
            <tr style="font-weight:bold; background: rgba(15,76,129,0.04);">
                <td colspan="6" style="padding:8px 10px; text-align:right; border-bottom:2px solid var(--border-color);">Subtotal &mdash; {doc_label}</td>
                <td style="padding:8px 10px; text-align:right; border-bottom:2px solid var(--border-color);">{revenue:,.2f}</td>
            </tr>
            """
        if not body_rows:
            body_rows = '<tr><td colspan="7" style="padding:20px; text-align:center; color: var(--text-muted);">No data for the selected filters.</td></tr>'
        footer_html = f"""
        <tr style="font-weight:bold; background: rgba(15,76,129,0.06);">
            <td colspan="6" style="padding:10px; text-align:right;">TOTAL REVENUE (LKR)</td>
            <td style="padding:10px; text-align:right;">{total_revenue:,.2f}</td>
        </tr>
        <tr style="font-weight:bold; background: rgba(15,76,129,0.06);">
            <td colspan="6" style="padding:10px; text-align:right;">TOTAL COMMISSION (LKR)</td>
            <td style="padding:10px; text-align:right;">{total_commission:,.2f}</td>
        </tr>
        """

    elif view == "center":
        table_title = "Center-wise Detailed Sales & Billing"
        table_header_html = "<th>Date</th><th>Invoice/Lab No</th><th>Patient Name</th><th>Test(s) Performed</th><th>Doctor</th><th>Center</th><th style='text-align:right;'>Amount (LKR)</th>"
        body_rows = ""
        total_billing = 0.0
        for r in center_summary_rows:
            billing = r["billing"] or 0
            total_billing += billing
            c_name = r["center_name"] or "Main Branch"
            group_bills = bills_by_center.get(c_name, [])
            c_label = html.escape(c_name)
            body_rows += f"""
            <tr style="background: rgba(15,76,129,0.10);">
                <td colspan="7" style="padding:10px; border-bottom:1px solid var(--border-color); font-weight:bold; color:#0f4c81;">
                    {c_label} &mdash; {r['patient_count']} patient(s) &middot; {r['tests_dispatched']} test(s) dispatched &middot; Billing: LKR {billing:,.2f}
                </td>
            </tr>
            """
            body_rows += _test_count_row_html(tests_by_center.get(c_name, []))
            for b in group_bills:
                body_rows += _detail_bill_row_html(b)
            body_rows += f"""
            <tr style="font-weight:bold; background: rgba(15,76,129,0.04);">
                <td colspan="6" style="padding:8px 10px; text-align:right; border-bottom:2px solid var(--border-color);">Subtotal &mdash; {c_label}</td>
                <td style="padding:8px 10px; text-align:right; border-bottom:2px solid var(--border-color);">{billing:,.2f}</td>
            </tr>
            """
        if not body_rows:
            body_rows = '<tr><td colspan="7" style="padding:20px; text-align:center; color: var(--text-muted);">No data for the selected filters.</td></tr>'
        footer_html = f"""
        <tr style="font-weight:bold; background: rgba(15,76,129,0.06);">
            <td colspan="6" style="padding:10px; text-align:right;">TOTAL BILLING (LKR)</td>
            <td style="padding:10px; text-align:right;">{total_billing:,.2f}</td>
        </tr>
        """

    elif view == "tests":
        table_title = "Test-wise Count & Revenue"
        table_header_html = "<th>#</th><th>Test</th><th>Code</th><th style='text-align:right;'>Count</th><th style='text-align:right;'>Unit Price</th><th style='text-align:right;'>Revenue (LKR)</th><th>Doctor-wise count</th><th>Center-wise count</th>"
        body_rows = ""
        total_count = 0
        total_amount = 0.0
        for idx, r in enumerate(test_summary_rows, 1):
            total_count += r["cnt"] or 0
            total_amount += r["amount"] or 0
            body_rows += f"""
            <tr>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{idx}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color); font-weight:bold;">{html.escape(r['test_name'] or '')}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{html.escape(r['test_code'] or '')}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color); text-align:right; font-weight:bold;">{r['cnt']}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color); text-align:right;">{(r['unit_price'] or 0):,.2f}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color); text-align:right;">{(r['amount'] or 0):,.2f}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color); font-size:12px;">{_split_text(test_doc_split.get(r['test_id'], []))}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color); font-size:12px;">{_split_text(test_center_split.get(r['test_id'], []))}</td>
            </tr>
            """
        if not body_rows:
            body_rows = '<tr><td colspan="8" style="padding:20px; text-align:center; color: var(--text-muted);">No data for the selected filters.</td></tr>'
        footer_html = f"""
        <tr style="font-weight:bold; background: rgba(15,76,129,0.06);">
            <td colspan="3" style="padding:10px; text-align:right;">TOTAL TESTS / REVENUE</td>
            <td style="padding:10px; text-align:right;">{total_count}</td>
            <td></td>
            <td style="padding:10px; text-align:right;">{total_amount:,.2f}</td>
            <td colspan="2"></td>
        </tr>
        """

    elif view == "cancelled":
        table_title = "Cancelled Invoices (Audit)"
        table_header_html = "<th>Date / Time</th><th>Invoice / Lab No</th><th>Patient Name</th><th>Doctor Name</th><th>Collecting Center</th><th style='text-align:right;'>Cancelled Bill Amount (LKR)</th>"
        body_rows = ""
        for r in cancelled_rows:
            ref_no = f"Med-{r['patient_id']:04d}"
            display_ref_no = f"{ref_no} / {r['manual_bill_no']}" if r["manual_bill_no"] else ref_no
            date_str = str(r["created_at"] or "")
            patient_name = f"{r['title'] or ''} {r['name'] or ''}".strip()
            body_rows += f"""
            <tr>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{html.escape(date_str)}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{display_ref_no}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color); font-weight:bold;">{html.escape(patient_name)}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{html.escape(r['doctor_name'] or 'Not Specified')}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{html.escape(r['center_name'] or 'Main Branch')}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color); text-align:right; color:#c0392b; font-weight:bold;">{(r['amount'] or 0):,.2f}</td>
            </tr>
            """
        if not body_rows:
            body_rows = '<tr><td colspan="6" style="padding:20px; text-align:center; color: var(--text-muted);">No cancelled bills for the selected filters.</td></tr>'
        footer_html = f"""
        <tr style="font-weight:bold; background: rgba(192,57,43,0.06);">
            <td colspan="5" style="padding:10px; text-align:right;">TOTAL CANCELLED (LKR)</td>
            <td style="padding:10px; text-align:right; color:#c0392b;">{cancelled_total:,.2f}</td>
        </tr>
        """

    else:
        view = "table"
        table_title = "Detailed Sales Data"
        table_header_html = "<th>Date</th><th>Invoice/Lab No</th><th>Patient Name</th><th>Test(s) Performed</th><th>Doctor</th><th>Center</th><th style='text-align:right;'>Amount (LKR)</th>"
        body_rows = ""
        for r in sales_rows:
            ref_no = f"Med-{r['patient_id']:04d}"
            display_ref_no = f"{ref_no} / {r['manual_bill_no']}" if r["manual_bill_no"] else ref_no
            date_str = str(r["created_at"] or "").split(" ")[0]
            patient_name = f"{r['title'] or ''} {r['name'] or ''}".strip()
            body_rows += f"""
            <tr>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{date_str}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{display_ref_no}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color); font-weight:bold;">{html.escape(patient_name)}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{html.escape(r['tests_performed'] or '')}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{html.escape(r['doctor_name'] or 'Not Specified')}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color);">{html.escape(r['center_name'] or 'Main Branch')}</td>
                <td style="padding:8px 10px; border-bottom:1px solid var(--border-color); text-align:right;">{(r['amount'] or 0):,.2f}</td>
            </tr>
            """
        if not body_rows:
            body_rows = f'<tr><td colspan="7" style="padding:20px; text-align:center; color: var(--text-muted);">{"Error: " + html.escape(sales_error) if sales_error else "No matching sales records for the selected filters."}</td></tr>'
        footer_html = f"""
        <tr style="font-weight:bold; background: rgba(15,76,129,0.06);">
            <td colspan="6" style="padding:10px; text-align:right;">TOTAL AMOUNT (LKR)</td>
            <td style="padding:10px; text-align:right;">{grand_total:,.2f}</td>
        </tr>
        """

    def _view_link(v):
        return f"/reports/sales-analytics?preset={preset}&start_date={start_date}&end_date={end_date}&doctor={doctor}&center={center}&view={v}"

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Sales & Financial Analytics - MEDISTAR MEDICAL LABORATORY</title>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/xlsx/0.18.5/xlsx.full.min.js"></script>
        <style>
            :root {{
                --bg-color: #f4f7fb; --header-bg: #0f4c81; --card-bg: #ffffff;
                --text-main: #1e293b; --text-muted: #64748b; --border-color: #cbd5e1; --btn-color: #0f4c81;
            }}
            body {{ font-family: Arial, sans-serif; background: var(--bg-color); color: var(--text-main); margin: 0; padding: 0; }}
            .header {{ background: var(--header-bg); color: white; padding: 15px 30px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            .header h2 {{ margin: 0; font-size: 19px; }}
            .container {{ padding: 30px; max-width: 1300px; margin: auto; }}
            .btn-secondary {{ background: #64748b; color: white; border: none; padding: 9px 16px; border-radius: 5px; font-weight: bold; cursor: pointer; text-decoration: none; font-size: 13px; }}
            .btn-primary {{ background: var(--btn-color); color: white; border: none; padding: 9px 20px; border-radius: 5px; font-weight: bold; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 8px; font-size: 13px; }}
            .filter-box {{ background: var(--card-bg); padding: 20px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); border: 1px solid var(--border-color); margin-bottom: 18px; display: flex; gap: 14px; flex-wrap: wrap; align-items: flex-end; }}
            .filter-group {{ display: flex; flex-direction: column; gap: 5px; }}
            .filter-group label {{ font-size: 12px; font-weight: bold; color: var(--text-muted); }}
            .filter-group input, .filter-group select {{ padding: 8px 12px; border: 1px solid var(--border-color); border-radius: 5px; background: var(--card-bg); color: var(--text-main); outline: none; }}
            .tabs {{ display: flex; gap: 8px; margin-bottom: 18px; }}
            .tab-link {{ padding: 9px 18px; border-radius: 20px; text-decoration: none; font-size: 13px; font-weight: bold; background: #e2e8f0; color: #334155; }}
            .tab-link.active {{ background: var(--header-bg); color: white; }}
            .tab-link.cancelled-tab.active {{ background: #c0392b; }}
            .summary-cards {{ display: flex; gap: 16px; margin-bottom: 18px; }}
            .summary-card {{ background: var(--card-bg); border: 1px solid var(--border-color); border-left: 4px solid #c0392b; border-radius: 10px; padding: 16px 20px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); min-width: 220px; }}
            .summary-card-label {{ font-size: 12px; font-weight: bold; color: var(--text-muted); text-transform: uppercase; margin-bottom: 6px; }}
            .summary-card-value {{ font-size: 24px; font-weight: bold; color: var(--text-main); }}
            .report-card {{ background: var(--card-bg); padding: 25px; border-radius: 10px; box-shadow: 0 2px 8px rgba(0,0,0,0.05); border: 1px solid var(--border-color); }}
            .report-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 18px; border-bottom: 2px solid var(--border-color); padding-bottom: 12px; }}
            table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
            th {{ padding: 10px; font-size: 12.5px; color: white; background: var(--header-bg); text-align: left; }}
            @media print {{
                .no-print {{ display: none !important; }}
                body {{ background: white; color: black; }}
                .report-card {{ border: none; box-shadow: none; padding: 0; }}
            }}
        </style>
    </head>
    <body>
        <div class="header no-print">
            <h2><i class="fa-solid fa-sack-dollar"></i> Sales & Financial Analytics</h2>
            <a href="/reports" class="btn-secondary">&larr; Back to Reports</a>
        </div>

        <div class="container">
            <form method="GET" action="/reports/sales-analytics" class="filter-box no-print">
                <div class="filter-group">
                    <label>Date Preset</label>
                    <select name="preset" onchange="this.form.submit()">
                        <option value="today" {"selected" if preset == "today" else ""}>Today</option>
                        <option value="this_month" {"selected" if preset == "this_month" else ""}>This Month</option>
                        <option value="custom" {"selected" if preset == "custom" else ""}>Custom Range</option>
                    </select>
                </div>
                <div class="filter-group">
                    <label>Start Date</label>
                    <input type="date" name="start_date" value="{start_date}">
                </div>
                <div class="filter-group">
                    <label>End Date</label>
                    <input type="date" name="end_date" value="{end_date}">
                </div>
                <div class="filter-group">
                    <label>Doctor</label>
                    <select name="doctor">{doctor_opts_html}</select>
                </div>
                <div class="filter-group">
                    <label>Collecting Center</label>
                    <select name="center">{center_opts_html}</select>
                </div>
                <input type="hidden" name="view" value="{view}">
                <div class="filter-group">
                    <button type="submit" class="btn-primary">Apply Filter</button>
                </div>
                <div class="filter-group" style="margin-left:auto; flex-direction:row; gap:8px;">
                    <button type="button" onclick="window.print()" class="btn-primary" style="background:#27ae60;">🖨️ Print</button>
                    <button type="button" onclick="exportSalesTableToExcel()" class="btn-primary" style="background:#1d7a46;">📊 Export to Excel</button>
                </div>
            </form>

            <div class="tabs no-print">
                <a href="{_view_link('table')}" class="tab-link {'active' if view == 'table' else ''}">📋 Sales Table</a>
                <a href="{_view_link('doctor')}" class="tab-link {'active' if view == 'doctor' else ''}">👨‍⚕️ Doctor-wise Details</a>
                <a href="{_view_link('center')}" class="tab-link {'active' if view == 'center' else ''}">🏥 Center-wise Details</a>
                <a href="{_view_link('tests')}" class="tab-link {'active' if view == 'tests' else ''}">🧪 Test-wise Count</a>
                <a href="{_view_link('cancelled')}" class="tab-link cancelled-tab {'active' if view == 'cancelled' else ''}">🚫 Cancelled Invoices</a>
            </div>

            {f'''
            <div class="summary-cards no-print">
                <div class="summary-card">
                    <div class="summary-card-label">Total Cancelled Bills</div>
                    <div class="summary-card-value">{cancelled_count}</div>
                </div>
                <div class="summary-card">
                    <div class="summary-card-label">Total Cancelled Revenue Value</div>
                    <div class="summary-card-value" style="color:#c0392b;">LKR {cancelled_total:,.2f}</div>
                </div>
            </div>
            ''' if view == 'cancelled' else ''}

            <div class="report-card">
                <div class="report-header">
                    <div>
                        <h3 style="margin:0; font-size:17px;">{table_title}</h3>
                        <p style="margin:4px 0 0 0; font-size:12px; color: var(--text-muted);">Date Range: {label_start} to {label_end}</p>
                    </div>
                    <span style="font-size:12px; font-weight:bold; color: var(--text-muted);">MEDISTAR MEDICAL LABORATORY</span>
                </div>

                <table id="exportTable">
                    <thead><tr>{table_header_html}</tr></thead>
                    <tbody>
                        {body_rows}
                        {footer_html}
                    </tbody>
                </table>
        </div>

        <script>
            function exportSalesTableToExcel() {{
                const table = document.getElementById('exportTable');
                const wb = XLSX.utils.table_to_book(table, {{ sheet: "Report" }});
                const stamp = new Date().toISOString().slice(0, 10);
                XLSX.writeFile(wb, "Sales_Report_" + stamp + ".xlsx");
            }}
        </script>
    </body>
    </html>
    """