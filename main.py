import libsql_experimental as sqlite3
import os
import re
import html
from datetime import datetime
from urllib.parse import quote
from typing import Optional
from fastapi import FastAPI, Form, Request, Query, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.responses import Response as StarletteResponse
from contextlib import asynccontextmanager

# Turso Cloud Database Credentials
TURSO_DB_URL = os.getenv("TURSO_DB_URL", "libsql://lab-system-medilab310.aws-ap-south-1.turso.io")
TURSO_AUTH_TOKEN = os.getenv("TURSO_AUTH_TOKEN", "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJhIjoicnciLCJpYXQiOjE3ODc5NDM5NTksImlkIjoiMDFhMDQ5YzEtMzIwMS03ZmMxLWI3YzQtZTFmMWUyMjg3M2I4Iiwia2lkIjoiRXQtY2FBZ2lvdi1lVUFpek5OWm11QUhOUW84bk01Z25WdmF6MnZ3azNIcyIsInJpZCI6ImUwMDU5NWYyLTNkYjAtNGQ3Yi1hZjhjLTQ4ODNhNzUxYzc4MSJ9.Z2ThLbkhOxlDqEGEIGF0TDP7-fE8lpqsWRBh-WqPbSEAT788xlaExpQG2gRPhPCAJByGWJSapzR1O0Wfs6IYDw")

def get_db_connection():
    """Turso Cloud Database එකට Connection එක ලබා දෙන ශ්‍රිතය"""
    conn = sqlite3.connect(f"{TURSO_DB_URL}?auth_token={TURSO_AUTH_TOKEN}")
    conn.row_factory = sqlite3.Row
    return conn

@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    seed_standard_tests_and_parameters()
    yield

app = FastAPI(lifespan=lifespan)

# Static files folder configuration
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")

if not os.path.isdir(STATIC_DIR):
    try:
        os.makedirs(STATIC_DIR, exist_ok=True)
    except OSError:
        pass
if os.path.isdir(STATIC_DIR):
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    
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

@app.middleware("http")
async def inject_logout_sync(request: Request, call_next):
    response = await call_next(request)
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
    return response

# -------------------------------------------------------------
# 0. ROOT & LOGIN ROUTES
# -------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def root():
    return RedirectResponse(url="/login", status_code=303)

@app.get("/login", response_class=HTMLResponse)
def login_page(error: str = ""):
    error_html = f"<p style='color: #e74c3c; font-size: 13px; text-align: center; margin-bottom: 15px;'>{error}</p>" if error else ""
    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>MEDISTAR MEDICAL LABORATORY - Login</title>
        <style>
            body {{ font-family: Arial, sans-serif; background: #f4f7fb; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }}
            .login-card {{ background: white; padding: 30px; border-radius: 10px; box-shadow: 0 4px 12px rgba(0,0,0,0.1); width: 350px; border-top: 5px solid #0f4c81; }}
            h2 {{ color: #0f4c81; text-align: center; margin-bottom: 5px; font-size: 20px; }}
            p.sub {{ text-align: center; color: #64748b; font-size: 12px; margin-bottom: 20px; }}
            .form-group {{ margin-bottom: 15px; display: flex; flex-direction: column; gap: 5px; }}
            label {{ font-size: 12px; font-weight: bold; color: #64748b; }}
            input {{ padding: 10px; border: 1px solid #cbd5e1; border-radius: 5px; outline: none; font-size: 14px; }}
            .btn-login {{ background: #0f4c81; color: white; border: none; padding: 10px; border-radius: 5px; font-weight: bold; cursor: pointer; width: 100%; margin-top: 10px; font-size: 14px; }}
            .btn-login:hover {{ background: #0c3d6d; }}
        </style>
    </head>
    <body>
        <div class="login-card">
            <h2>MEDISTAR MEDICAL LABORATORY</h2>
            <p class="sub">Sign in to your account</p>
            {error_html}
            <form method="POST" action="/login">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" name="username" required placeholder="Enter username">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" name="password" required placeholder="Enter password">
                </div>
                <button type="submit" class="btn-login">Login</button>
            </form>
        </div>
    </body>
    </html>
    """

@app.post("/login")
async def login_post(request: Request):
    form_data = await request.form()
    username = form_data.get("username", "").strip()
    password = form_data.get("password", "").strip()
    
    # 1. Default Admin Check
    if username == "admin" and password == "1234":
        resp = RedirectResponse(url="/dashboard", status_code=303)
        resp.set_cookie(key="username", value="admin")
        resp.set_cookie(key="role", value="admin")
        return resp
    
    # 2. Database Check
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT, 
                username TEXT, 
                password TEXT, 
                role TEXT
            )
        """)
        
        cursor.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = cursor.fetchone()
        conn.close()
        
        if user:
            # Role එකක් නැත්නම් default 'staff' විදිහට ගන්නවා
            user_role = user["role"] if "role" in user.keys() and user["role"] else "staff"
            
            # හැමෝම Dashboard එකට යවනවා සහ Cookies සෙට් කරනවා
            resp = RedirectResponse(url="/dashboard", status_code=303)
            resp.set_cookie(key="username", value=username)
            resp.set_cookie(key="role", value=user_role)
            return resp
            
    except Exception as e:
        pass
    
    # වැරදි නම් එරර් එකක් සමඟ නැවත ලොගින් පේජ් එකටම යැවීම
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
    
    if username and password and role:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (username, password, role))
        conn.commit()
        conn.close()
        
    return RedirectResponse(url="/manage-users", status_code=303)

@app.get("/delete-user/{user_id}")
def delete_user(user_id: int):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return RedirectResponse(url="/manage-users", status_code=303)

# -----------------------------
# HELPER FUNCTIONS
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
            specimen TEXT
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

    # Compatibility migrations for databases created by older project versions.
    cursor.execute("PRAGMA table_info(patients)")
    patient_columns = {row[1] for row in cursor.fetchall()}
    if "center" not in patient_columns:
        cursor.execute("ALTER TABLE patients ADD COLUMN center TEXT DEFAULT 'Main Branch'")
    if "result_status" not in patient_columns:
        cursor.execute("ALTER TABLE patients ADD COLUMN result_status TEXT DEFAULT 'PENDING'")

    cursor.execute("PRAGMA table_info(patient_assigned_tests)")
    assigned_columns = {row[1] for row in cursor.fetchall()}
    if "verified" not in assigned_columns:
        cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN verified INTEGER DEFAULT 0")
    if "verified_at" not in assigned_columns:
        cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN verified_at TEXT")
    if "saved_at" not in assigned_columns:
        cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN saved_at TEXT")

    # Default admin user (username: admin, password: 1234)
    cursor.execute("INSERT OR IGNORE INTO users (username, password) VALUES ('admin', '1234')")

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

    conn.commit()
    conn.close()

# NOTE: `app` and `lifespan` were already created once at the top of this
# file (right after DB_PATH). They used to be redefined here as well, which
# silently wiped out every route registered above this point.

# -------------------------------------------------------------
# 1. MAIN DASHBOARD (Updated Big Action Buttons UI with User Management)
# -------------------------------------------------------------
@app.get("/dashboard", response_class=HTMLResponse)
def dashboard():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM patients")
    total_patients = cursor.fetchone()[0]
    
    try:
        cursor.execute("SELECT COUNT(DISTINCT patient_id) FROM patient_assigned_tests WHERE result IS NOT NULL AND result != ''")
        completed_reports = cursor.fetchone()[0]
    except:
        completed_reports = 0
    
    cursor.execute("SELECT COUNT(*) FROM tests")
    total_tests = cursor.fetchone()[0]
    
    cursor.execute("SELECT id, title, name, phone, doctor FROM patients ORDER BY id DESC LIMIT 5")
    recent_patients = cursor.fetchall()
    
    conn.close()

    recent_rows = ""
    if recent_patients:
        for p in recent_patients:
            p_id, title, name, phone, doctor = p
            p_phone = phone if phone else 'N/A'
            recent_rows += f"""
            <tr>
                <td style="padding: 10px 12px; font-weight: 700;">#{p_id}</td>
                <td style="padding: 10px 12px; font-weight: 600;">{title} {name}</td>
                <td style="padding: 10px 12px; opacity: 0.8;">{p_phone}</td>
                <td style="padding: 10px 12px;">{doctor}</td>
                <td style="padding: 10px 12px; text-align: center;">
                    <a href="/patient-results/{p_id}" class="view-btn"><i class="fa-solid fa-eye"></i> View</a>
                </td>
            </tr>
            """
    else:
        recent_rows = '<tr><td colspan="5" style="padding: 20px; text-align: center; color: var(--text-muted);">No patients registered yet.</td></tr>'

    return f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Lab System - Dashboard</title>
        <!-- FontAwesome Icons -->
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
        <style>
            :root {{
                --bg-color: #f4f7fe;
                --header-bg: #0d47a1;
                --card-bg: #ffffff;
                --text-main: #1b2559;
                --text-muted: #707eae;
                --border-color: #e2e8f0;
                --btn-bg: #ffffff;
                --btn-color: #0d47a1;
                --btn-hover-bg: #0d47a1;
                --btn-hover-color: #ffffff;
                --accent-green: #2e7d32;
                --shadow: 0px 8px 24px rgba(0, 0, 0, 0.05);
                --table-header: #0d47a1;
            }}

            [data-theme="dark"] {{
                --bg-color: #0b1437;
                --header-bg: #111c44;
                --card-bg: #111c44;
                --text-main: #ffffff;
                --text-muted: #8f9bba;
                --border-color: #1b254b;
                --btn-bg: #1b254b;
                --btn-color: #38bdf8;
                --btn-hover-bg: #38bdf8;
                --btn-hover-color: #0b1437;
                --accent-green: #4ade80;
                --shadow: 0px 8px 24px rgba(0, 0, 0, 0.3);
                --table-header: #1b254b;
            }}

            [data-theme="emerald"] {{
                --bg-color: #f0fdf4;
                --header-bg: #065f46;
                --card-bg: #ffffff;
                --text-main: #064e3b;
                --text-muted: #047857;
                --border-color: #a7f3d0;
                --btn-bg: #ffffff;
                --btn-color: #065f46;
                --btn-hover-bg: #065f46;
                --btn-hover-color: #ffffff;
                --accent-green: #10b981;
                --shadow: 0px 8px 24px rgba(6, 95, 70, 0.08);
                --table-header: #065f46;
            }}

            * {{ box-sizing: border-box; margin: 0; padding: 0; font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; transition: background 0.3s, color 0.3s; }}
            body {{ background: var(--bg-color); color: var(--text-main); }}

            /* Smart Top Navbar */
            .header {{
                background: var(--header-bg);
                color: white;
                padding: 14px 28px;
                display: flex;
                justify-content: space-between;
                align-items: center;
                box-shadow: 0 4px 12px rgba(0,0,0,0.1);
            }}
            .header h2 {{ margin: 0; font-size: 20px; font-weight: 700; letter-spacing: 0.5px; display: flex; align-items: center; gap: 10px; }}
            .header p {{ margin: 2px 0 0 0; font-size: 12px; opacity: 0.8; }}

            .header-right {{ display: flex; align-items: center; gap: 15px; }}
            .live-clock {{
                font-size: 13px;
                font-weight: 600;
                background: rgba(255, 255, 255, 0.15);
                padding: 6px 14px;
                border-radius: 20px;
                color: #ffffff;
                display: flex;
                align-items: center;
                gap: 6px;
            }}

            .theme-select {{
                background: rgba(255, 255, 255, 0.2);
                color: white;
                border: 1px solid rgba(255, 255, 255, 0.3);
                padding: 6px 12px;
                border-radius: 20px;
                cursor: pointer;
                font-weight: 600;
                font-size: 13px;
                outline: none;
            }}
            .theme-select option {{ background: #111c44; color: white; }}

            .logout-btn {{
                background: #e53e3e;
                color: white;
                border: none;
                padding: 7px 16px;
                border-radius: 8px;
                font-weight: 600;
                font-size: 13px;
                cursor: pointer;
                text-decoration: none;
                transition: 0.2s;
            }}
            .logout-btn:hover {{ background: #c53030; }}

            .container {{ padding: 22px 28px; max-width: 1440px; margin: auto; }}

            /* Stat Cards Grid */
            .cards-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 16px; margin-bottom: 22px; }}
            .card {{
                background: var(--card-bg);
                padding: 18px;
                border-radius: 12px;
                box-shadow: var(--shadow);
                border-left: 5px solid var(--btn-color);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .card.status-card {{ border-left-color: var(--accent-green); }}
            .card-content h3 {{ margin: 0 0 4px 0; font-size: 11px; color: var(--text-muted); text-transform: uppercase; font-weight: 700; letter-spacing: 0.5px; }}
            .card-content .number {{ font-size: 24px; font-weight: 700; color: var(--text-main); margin: 0; }}
            .card-icon {{ font-size: 28px; opacity: 0.25; color: var(--text-main); }}

            /* Big Prominent Action Tabs */
            .btn-grid {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
                gap: 16px;
                margin-bottom: 26px;
            }}
            .action-btn {{
                background: var(--card-bg);
                border: 2px solid var(--border-color);
                padding: 16px 20px;
                border-radius: 14px;
                text-decoration: none;
                color: var(--btn-color);
                font-weight: 700;
                font-size: 15px;
                box-shadow: var(--shadow);
                transition: all 0.25s cubic-bezier(0.4, 0, 0.2, 1);
                display: flex;
                align-items: center;
                justify-content: flex-start;
                gap: 14px;
            }}
            .action-btn i {{
                font-size: 22px;
            }}
            .action-btn:hover {{
                background: var(--btn-hover-bg);
                color: var(--btn-hover-color);
                border-color: var(--btn-hover-bg);
                transform: translateY(-4px);
                box-shadow: 0px 12px 28px rgba(0, 0, 0, 0.12);
            }}

            /* Primary Highlight Tabs */
            .action-btn.primary-highlight {{
                background: var(--header-bg);
                color: #ffffff;
                border-color: var(--header-bg);
            }}
            .action-btn.primary-highlight:hover {{
                opacity: 0.92;
                transform: translateY(-4px);
            }}

            /* Bottom Layout: Table + Calendar */
            .bottom-grid {{ display: grid; grid-template-columns: 2.8fr 1.2fr; gap: 20px; }}
            @media (max-width: 992px) {{ .bottom-grid {{ grid-template-columns: 1fr; }} }}

            .section-box {{
                background: var(--card-bg);
                padding: 18px 22px;
                border-radius: 14px;
                box-shadow: var(--shadow);
                border: 1px solid var(--border-color);
            }}
            .section-box h3 {{
                margin-top: 0;
                margin-bottom: 14px;
                font-size: 15px;
                font-weight: 700;
                color: var(--text-main);
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}

            /* Compact Table */
            .compact-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
            .compact-table th {{
                background: var(--table-header);
                color: white;
                text-align: left;
                padding: 10px 12px;
                font-weight: 600;
            }}
            .compact-table td {{ padding: 10px 12px; border-bottom: 1px solid var(--border-color); }}
            .compact-table tr:hover {{ background-color: rgba(0,0,0,0.02); }}

            .view-btn {{
                color: var(--btn-color);
                text-decoration: none;
                font-size: 12px;
                font-weight: 700;
                background: rgba(13, 71, 161, 0.1);
                padding: 6px 12px;
                border-radius: 6px;
                transition: 0.2s;
            }}
            .view-btn:hover {{ background: var(--btn-color); color: white; }}

            /* Mini Calendar Widget */
            .calendar {{ text-align: center; }}
            .calendar-header {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; font-weight: 700; font-size: 14px; color: var(--text-main); }}
            .calendar-weekdays {{ display: grid; grid-template-columns: repeat(7, 1fr); font-size: 12px; font-weight: 700; color: var(--text-muted); margin-bottom: 8px; }}
            .calendar-days {{ display: grid; grid-template-columns: repeat(7, 1fr); gap: 4px; }}
            .calendar-day {{ padding: 7px 0; font-size: 12px; border-radius: 6px; color: var(--text-main); background: rgba(0,0,0,0.02); }}
            .calendar-day.today {{ background: var(--btn-color) !important; color: white !important; font-weight: 700; }}
        </style>
    </head>
    <body>
        <!-- Modern Header -->
        <div class="header">
            <div>
                <h2><i class="fa-solid fa-flask-vial"></i> MEDISTAR MEDICAL LABORATORY</h2>
                <p>Patient & Laboratory Report Management System</p>
            </div>
            <div class="header-right">
                <div class="live-clock">
                    <i class="fa-regular fa-clock"></i> <span id="liveClock">00:00:00 AM</span>
                </div>
                <select id="themeSwitcher" class="theme-select" onchange="changeTheme(this.value)">
                    <option value="light">☀️ Classic Blue</option>
                    <option value="dark">🌙 Dark Mode</option>
                    <option value="emerald">🌿 Emerald Green</option>
                </select>
                <a href="/logout" class="logout-btn"><i class="fa-solid fa-right-from-bracket"></i> Logout</a>
            </div>
        </div>

        <div class="container">
            
            <!-- Cards Section -->
            <div class="cards-grid">
                <div class="card">
                    <div class="card-content">
                        <h3>Total Patients</h3>
                        <p class="number">{total_patients}</p>
                    </div>
                    <div class="card-icon"><i class="fa-solid fa-users"></i></div>
                </div>

                <div class="card">
                    <div class="card-content">
                        <h3>Completed Reports</h3>
                        <p class="number">{completed_reports}</p>
                    </div>
                    <div class="card-icon"><i class="fa-solid fa-file-medical"></i></div>
                </div>

                <div class="card">
                    <div class="card-content">
                        <h3>Available Tests</h3>
                        <p class="number">{total_tests}</p>
                    </div>
                    <div class="card-icon"><i class="fa-solid fa-vials"></i></div>
                </div>

                <div class="card status-card">
                    <div class="card-content">
                        <h3>Status</h3>
                        <p class="number" style="color: var(--accent-green); font-size: 18px;">Active</p>
                    </div>
                    <div class="card-icon" style="color: var(--accent-green);"><i class="fa-solid fa-circle-check"></i></div>
                </div>
            </div>

            <!-- Big Prominent Action Tabs -->
            <div class="btn-grid">
                <a href="/add-patient" class="action-btn primary-highlight">
                    <i class="fa-solid fa-user-plus"></i> Register Patient
                </a>
                <a href="/patients-dashboard" class="action-btn primary-highlight">
                    <i class="fa-solid fa-print"></i> Test Results & Print
                </a>
                <a href="/reports" class="action-btn">
                    <i class="fa-solid fa-chart-line"></i> Reports & Analytics
                </a>
                <a href="/manage-tests" class="action-btn">
                    <i class="fa-solid fa-microscope"></i> Manage Tests
                </a>
                <a href="/manage-doctors" class="action-btn">
                    <i class="fa-solid fa-user-doctor"></i> Manage Doctors
                </a>
                <a href="/manage-centers" class="action-btn">
                    <i class="fa-solid fa-hospital"></i> Centers
                </a>
                <!-- User Management Button Added Here -->
                <a href="/manage-users" class="action-btn">
                    <i class="fa-solid fa-user-gear"></i> Manage Users
                </a>
            </div>

            <!-- Bottom Section: Table + Calendar -->
            <div class="bottom-grid">
                
                <!-- Compact Table -->
                <div class="section-box">
                    <h3>
                        <span>Recent Patient Registrations</span>
                        <i class="fa-solid fa-list-check" style="opacity: 0.5;"></i>
                    </h3>
                    <table class="compact-table">
                        <thead>
                            <tr>
                                <th>Ref</th>
                                <th>Name</th>
                                <th>Phone</th>
                                <th>Doctor</th>
                                <th style="text-align: center;">Action</th>
                            </tr>
                        </thead>
                        <tbody>
                            {recent_rows}
                        </tbody>
                    </table>
                </div>

                <!-- Mini Calendar -->
                <div class="section-box calendar">
                    <div class="calendar-header">
                        <span id="monthYear">Month Year</span>
                        <i class="fa-solid fa-calendar-days" style="color: var(--btn-color);"></i>
                    </div>
                    <div class="calendar-weekdays">
                        <div>Su</div><div>Mo</div><div>Tu</div><div>We</div><div>Th</div><div>Fr</div><div>Sa</div>
                    </div>
                    <div class="calendar-days" id="calendarDays"></div>
                </div>

            </div>
        </div>

        <script>
            // Realtime Live Clock
            function updateClock() {{
                const now = new Date();
                let hours = now.getHours();
                const minutes = String(now.getMinutes()).padStart(2, '0');
                const seconds = String(now.getSeconds()).padStart(2, '0');
                const ampm = hours >= 12 ? 'PM' : 'AM';
                hours = hours % 12 || 12;
                document.getElementById('liveClock').innerText = `${{String(hours).padStart(2, '0')}}:${{minutes}}:${{seconds}} ${{ampm}}`;
            }}
            setInterval(updateClock, 1000);
            updateClock();

            // Dynamic Mini Calendar Render
            function renderCalendar() {{
                const now = new Date();
                const year = now.getFullYear();
                const month = now.getMonth();
                const months = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"];
                document.getElementById('monthYear').innerText = `${{months[month]}} ${{year}}`;

                const firstDayIndex = new Date(year, month, 1).getDay();
                const totalDays = new Date(year, month + 1, 0).getDate();
                const currentDay = now.getDate();

                let daysHTML = '';
                for (let i = 0; i < firstDayIndex; i++) daysHTML += `<div></div>`;
                for (let i = 1; i <= totalDays; i++) {{
                    let className = (i === currentDay) ? 'calendar-day today' : 'calendar-day';
                    daysHTML += `<div class="${{className}}">${{i}}</div>`;
                }}
                document.getElementById('calendarDays').innerHTML = daysHTML;
            }}
            renderCalendar();

            // Theme Switcher Logic
            function changeTheme(theme) {{
                if (theme === 'light') {{
                    document.documentElement.removeAttribute('data-theme');
                    localStorage.setItem('lab_theme', 'light');
                }} else {{
                    document.documentElement.setAttribute('data-theme', theme);
                    localStorage.setItem('lab_theme', theme);
                }}
            }}

            window.onload = function() {{
                const savedTheme = localStorage.getItem('lab_theme');
                if (savedTheme && savedTheme !== 'light') {{
                    document.documentElement.setAttribute('data-theme', savedTheme);
                    document.getElementById('themeSwitcher').value = savedTheme;
                }}
            }}
        </script>
    </body>
    </html>
    """

# -------------------------------------------------------------
# 2. MANAGE USERS ROUTE (100% Crash-Proof & Error-Free)
# -------------------------------------------------------------
@app.get("/manage-users", response_class=HTMLResponse)
def manage_users():
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
        
    cursor.execute("SELECT * FROM users")
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
                u_role = u["role"] if "role" in u.keys() and u["role"] else "admin"
            except Exception:
                u_role = "admin"

            users_rows += f"""
            <tr>
                <td style="padding: 12px; font-weight: 700;">#{u_id}</td>
                <td style="padding: 12px; font-weight: 600;">{u_name}</td>
                <td style="padding: 12px;">
                    <span style="background: rgba(13, 71, 161, 0.1); color: var(--btn-color); padding: 4px 10px; border-radius: 6px; font-size: 12px; font-weight: 700; text-transform: uppercase;">
                        {u_role}
                    </span>
                </td>
                <td style="padding: 12px; text-align: center;">
                    <a href="/delete-user/{u_id}" onclick="return confirm('Are you sure you want to delete this user?');" style="color: #e53e3e; text-decoration: none; font-weight: 700; font-size: 12px; background: rgba(229, 62, 62, 0.1); padding: 6px 12px; border-radius: 6px;">
                        <i class="fa-solid fa-trash"></i> Delete
                    </a>
                </td>
            </tr>
            """
    else:
        users_rows = '<tr><td colspan="4" style="padding: 20px; text-align: center; color: var(--text-muted);">No users found. Create a new user below.</td></tr>'

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
                            <option value="admin">Admin</option>
                            <option value="staff">Staff / Lab Assistant</option>
                        </select>
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
                            <th style="text-align: center;">Action</th>
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
def reports_page(start_date: str = "", end_date: str = "", report_type: str = "sales"):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    table_headers = ""
    table_rows = ""
    report_title = ""

    date_filter_sql = "1=1"
    params = []
    
    if start_date and end_date:
        date_filter_sql = "date(created_at) BETWEEN ? AND ?"
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
                        <p style="margin: 4px 0 0 0; font-size: 12px; color: var(--text-muted);">Date Range: {start_date if start_date else 'All Time'} to {end_date if end_date else 'Present'}</p>
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
@app.get("/patients-dashboard", response_class=HTMLResponse)
def patients_dashboard(
    request: Request,
    search: Optional[str] = Query(None),
    start_date: Optional[str] = Query(None),
    end_date: Optional[str] = Query(None)
):
    import re
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Tables check
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

    query = "SELECT id, title, name, created_at FROM patients WHERE 1=1"
    params = []

    if search and search.strip():
        search_term = f"%{search.strip()}%"
        query += " AND (CAST(id AS TEXT) LIKE ? OR name LIKE ?)"
        params.extend([search_term, search_term])

    if start_date and start_date.strip():
        query += " AND DATE(created_at) >= ?"
        params.append(start_date.strip())

    if end_date and end_date.strip():
        query += " AND DATE(created_at) <= ?"
        params.append(end_date.strip())

    query += " ORDER BY id DESC LIMIT 100"
    cursor.execute(query, params)
    patients = cursor.fetchall()

    table_rows_html = ""
    for pat in patients:
        p_id = pat["id"]
        ref_no = f"#{p_id}"
        
        title_val = pat["title"] if "title" in pat.keys() and pat["title"] else ""
        name_val = pat["name"] if "name" in pat.keys() and pat["name"] else ""
        patient_name = f"{title_val} {name_val}".strip()
        
        created_at_raw = pat["created_at"] if "created_at" in pat.keys() and pat["created_at"] else ""
        date_str = str(created_at_raw).split()[0] if created_at_raw else "N/A"

        # Assigned tests
        cursor.execute(f"SELECT t.{test_code_col} as test_code FROM patient_assigned_tests pat LEFT JOIN tests t ON pat.test_id = t.id WHERE pat.patient_id = ?", (p_id,))
        test_codes_list = [str(t_row["test_code"]) for t_row in cursor.fetchall() if t_row["test_code"]]
        tests_display = ", ".join(test_codes_list) if test_codes_list else '<span style="color: #94a3b8; font-style: italic;">No tests</span>'

        has_any_result = False
        
        # Check Assigned Tests table
        cursor.execute("SELECT result FROM patient_assigned_tests WHERE patient_id = ?", (p_id,))
        for r_row in cursor.fetchall():
            res_val = str(r_row["result"] or "")
            clean_text = re.sub(r'<[^>]*>', '', res_val).replace('&nbsp;', '').strip()
            if clean_text and clean_text.lower() != "none" and clean_text not in ["", "<p></p>", "<p><br></p>"]:
                has_any_result = True
                break
        
        # Check Parameter Results table
        if not has_any_result:
            cursor.execute("SELECT count(*) FROM patient_parameter_results WHERE patient_id = ? AND result_value IS NOT NULL AND TRIM(result_value) != ''", (p_id,))
            if cursor.fetchone()[0] > 0:
                has_any_result = True

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
        </div>
    </body>
    </html>"""

# -------------------------------------------------------------
# 1. REGISTER PATIENT FORM (GET) - Dynamic Doctors & Centers Dropdowns
# -------------------------------------------------------------
@app.get("/add-patient", response_class=HTMLResponse)
def add_patient_page(saved_id: int = None):
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # 1. Fetch Tests (name වෙනුවට test_name දාලා ඇත)
    cursor.execute("SELECT id, test_name FROM tests")
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

    # Generate Collecting Centers Options dynamically
    center_options = '<option value="">-- Select Center --</option>'
    for c in centers:
        # c[0] = center_name
        center_options += f'<option value="{c[0]}">{c[0]}</option>'
    
    if not centers:
        center_options = '<option value="Main Branch">Main Branch</option>'

    test_checkboxes = "".join([f"""
        <label class="test-item" data-name="{t[1].lower()}" style="display: flex; align-items: center; gap: 10px; margin-bottom: 6px; font-weight: normal; cursor: pointer; font-size: 14px;">
            <input type="checkbox" name="test_ids" value="{t[0]}" style="width: 16px; height: 16px; accent-color: #0f4c81;"> {t[1]}
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
            .test-box {{ border: 1px solid #cbd5e1; padding: 10px; max-height: 120px; overflow-y: auto; border-radius: 5px; background: #fafafa; }}
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
            <form action="/add-patient" method="post">
                <div class="form-group row-group">
                    <div class="col-title">
                        <label>Title:</label>
                        <select name="title" id="titleSelect" onchange="autoSelectGender()">
                            <option value="Mr.">Mr.</option>
                            <option value="Mrs.">Mrs.</option>
                            <option value="Miss">Miss</option>
                            <option value="Rev.">Rev.</option>
                            <option value="Dr.">Dr.</option>
                            <option value="Master">Master</option>
                            <option value="Baby">Baby</option>
                        </select>
                    </div>
                    <div class="col-name">
                        <label>Patient Name:</label>
                        <input type="text" name="name" required placeholder="Ex: A.B. Perera">
                    </div>
                </div>

                <div class="form-group">
                    <label>Age (Y / M / D):</label>
                    <div class="age-row">
                        <input type="number" name="age_years" min="0" value="0" placeholder="Years">
                        <input type="number" name="age_months" min="0" max="11" value="0" placeholder="Months">
                        <input type="number" name="age_days" min="0" max="30" value="0" placeholder="Days">
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
                        <input type="text" name="phone" placeholder="0771234567">
                    </div>
                </div>

                <div class="form-group row-group">
                    <div style="flex: 1;">
                        <label>Referred Doctor:</label>
                        <select name="doctor" required>
                            {doctor_options}
                        </select>
                    </div>
                    <div style="flex: 1;">
                        <label>Collecting Center:</label>
                        <select name="collecting_center" required>
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
                }} else if (title === "Mrs." || title === "Miss") {{
                    gender.value = "Female";
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

            window.onload = autoSelectGender;
        </script>
    </body>
    </html>
    """ 

# -------------------------------------------------------------
# 2. REGISTER PATIENT (POST) - Redirects with Reference ID
# -------------------------------------------------------------
@app.post("/add-patient")
async def add_patient_post(request: Request):
    try:
        form_data = await request.form()
        selected_tests = form_data.getlist("test_ids")

        conn = get_db_connection()
        cursor = conn.cursor()

        # Use the server's actual local date/time (not SQLite's built-in
        # CURRENT_TIMESTAMP default, which is UTC) so "Received On" reflects
        # correct local registration time.
        registration_timestamp = datetime.now().isoformat(timespec="seconds")

        cursor.execute("""
            INSERT INTO patients (title, name, age_years, age_months, age_days, gender, phone, doctor, collecting_center, center, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            form_data.get("title"),
            form_data.get("name"),
            form_data.get("age_years", 0),
            form_data.get("age_months", 0),
            form_data.get("age_days", 0),
            form_data.get("gender"),
            form_data.get("phone"),
            form_data.get("doctor", "None"),
            form_data.get("collecting_center", "Main Branch"),
            form_data.get("collecting_center", "Main Branch"),
            registration_timestamp
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
def manage_doctors():
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
        </tr>
    """ for d in doctors])

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Manage Doctors</title>
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
                <button type="submit" class="btn">Add Doctor</button>
            </form>

            <h3 style="margin-top: 25px; color: #333;">Existing Doctors</h3>
            <table>
                <tr>
                    <th>Code</th>
                    <th>Name</th>
                    <th>Specialization</th>
                    <th>Phone</th>
                </tr>
                {rows if rows else '<tr><td colspan="4" style="text-align:center;">No doctors added yet.</td></tr>'}
            </table>
        </div>
    </body>
    </html>
    """

@app.post("/add-doctor")
def add_doctor(code: str = Form(...), name: str = Form(...), specialization: str = Form(None), phone: str = Form(None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO doctors (code, name, specialization, phone) VALUES (?, ?, ?, ?)", 
                       (code, name, specialization, phone))
        conn.commit()
    except sqlite3.IntegrityError:
        pass # Code එක කලින් තිබුණොත් ignore කරයි
    conn.close()
    return RedirectResponse(url="/manage-doctors", status_code=303)

# --- COLLECTING CENTERS MANAGEMENT ---
@app.get("/manage-centers", response_class=HTMLResponse)
def manage_centers():
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
        </tr>
    """ for c in centers])

    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Manage Collecting Centers</title>
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
                </tr>
                {rows if rows else '<tr><td colspan="3" style="text-align:center;">No collecting centers added yet.</td></tr>'}
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


# -------------------------------------------------------------
# 3. SELECT PATIENT LIST (Step 1)
# -------------------------------------------------------------
@app.get("/add-test-entry", response_class=HTMLResponse)
def add_test_entry(search: str = "", selected_patient_id: int = None):
    conn = get_db_connection()
    cursor = conn.cursor()

    if search:
        search_term = f"%{search}%"
        cursor.execute("""
            SELECT p.id, p.title, p.name, p.age_years, p.age_months, p.age_days, p.gender, p.phone
            FROM patients p
            WHERE p.name LIKE ? OR p.phone LIKE ?
            ORDER BY p.id DESC
        """, (search_term, search_term))
    else:
        cursor.execute("""
            SELECT p.id, p.title, p.name, p.age_years, p.age_months, p.age_days, p.gender, p.phone
            FROM patients p
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
def manage_tests(dept: str = ""):
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

    test_list_html = ""
    for test_id, test_name, price, department, specimen, test_code in tests:
        cursor.execute("SELECT COUNT(*) FROM test_parameters WHERE test_id = ?", (test_id,))
        param_count = cursor.fetchone()[0]

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

    try:
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN default_result TEXT")
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN input_type TEXT DEFAULT 'numeric'")
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN is_bold INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass

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

    # Work out which test this parameter belongs to so we can redirect back to it.
    cursor.execute("SELECT test_id FROM test_parameters WHERE id = ?", (param_id,))
    row = cursor.fetchone()
    test_id = row[0] if row else None

    if row:
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
    test_id = form_data.get("test_id")

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute("ALTER TABLE test_parameters ADD COLUMN is_bold INTEGER DEFAULT 0")
        conn.commit()
    except sqlite3.OperationalError:
        pass

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

    # Safety checks for columns
    try:
        cursor.execute("ALTER TABLE tests ADD COLUMN notes TEXT")
        cursor.execute("ALTER TABLE tests ADD COLUMN col_alignments TEXT")
        cursor.execute("ALTER TABLE tests ADD COLUMN test_code TEXT")
        conn.commit()
    except sqlite3.OperationalError:
        pass

    try:
        cursor.execute("""
            INSERT INTO tests (test_code, test_name, price, department, specimen, notes, col_alignments) 
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (test_code.upper(), test_name.upper(), price, department, specimen, notes, alignments))
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
    cursor.execute("SELECT test_name, price, department, specimen, notes, col_alignments, test_code FROM tests WHERE id = ?", (test_id,))
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
                        <input type="text" name="test_code" value="{test[6] if test[6] else ''}">
                    </div>
                    <div style="flex: 2;">
                        <label>Test Category Name:</label>
                        <input type="text" name="test_name" value="{test[0]}" required>
                    </div>
                </div>
                <div class="row">
                    <div>
                        <label>Price (Rs):</label>
                        <input type="number" step="0.01" name="price" value="{test[1]}">
                    </div>
                    <div>
                        <label>Department:</label>
                        <input type="text" name="department" value="{test[2]}">
                    </div>
                    <div>
                        <label>Specimen:</label>
                        <input type="text" name="specimen" value="{test[3]}">
                    </div>
                </div>
                <div class="form-group">
                    <label>Notes / Details (Appears below print results):</label>
                    <textarea name="notes">{test[4]}</textarea>
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
    align_inv: str = Form("left"), align_res: str = Form("center"),
    align_flag: str = Form("center"), align_unit: str = Form("left"), align_ref: str = Form("left"),
    width_inv: float = Form(38), width_res: float = Form(13), width_flag: float = Form(8),
    width_unit: float = Form(14), width_ref: float = Form(27)
):
    alignments = f"{align_inv},{align_res},{align_flag},{align_unit},{align_ref},{width_inv},{width_res},{width_flag},{width_unit},{width_ref}"
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE tests 
        SET test_code = ?, test_name = ?, price = ?, department = ?, specimen = ?, notes = ?, col_alignments = ?
        WHERE id = ?
    """, (test_code.upper(), test_name.upper(), price, department, specimen, notes, alignments, test_id))
    conn.commit()
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
def select_patient(search: str = "", selected_patient_id: int = None):
    conn = get_db_connection()
    cursor = conn.cursor()

    if search:
        search_term = f"%{search}%"
        cursor.execute("""
            SELECT p.id, p.title, p.name, p.age_years, p.age_months, p.age_days, p.gender, p.phone,
                   CASE WHEN r.id IS NULL THEN 'Pending' ELSE 'Verified' END as status,
                   r.id as report_id
            FROM patients p
            LEFT JOIN reports r ON p.id = r.patient_id
            WHERE p.name LIKE ? OR p.phone LIKE ?
            ORDER BY p.id DESC
        """, (search_term, search_term))
    else:
        cursor.execute("""
            SELECT p.id, p.title, p.name, p.age_years, p.age_months, p.age_days, p.gender, p.phone,
                   CASE WHEN r.id IS NULL THEN 'Pending' ELSE 'Verified' END as status,
                   r.id as report_id
            FROM patients p
            LEFT JOIN reports r ON p.id = r.patient_id
            ORDER BY p.id DESC
            LIMIT 20
        """)
    
    patients = cursor.fetchall()
    conn.close()

    patient_cards = ""
    for row in patients:
        age_str = f"{row['age_years']}Y {row['age_months']}M {row['age_days']}D"
        checked = "checked" if selected_patient_id and row["id"] == selected_patient_id else ""
        
        badge_bg = "#27ae60" if row["status"] == "Verified" else "#e74c3c"
        status_text = row["status"]

        patient_cards += f"""
            <label style="display: flex; align-items: center; justify-content: space-between; padding: 12px 15px; border-bottom: 1px solid #eee; cursor: pointer;">
                <div style="display: flex; align-items: center; gap: 12px;">
                    <input type="radio" name="selected_patient_id" value="{row["id"]}" {checked} onclick="document.getElementById('patient_id_input').value = '{row["id"]}'" style="width: 18px; height: 18px; accent-color: #0f4c81;">
                    <div>
                        <div style="font-size: 16px; font-weight: bold; color: #333;">{row["title"]} {row["name"]}</div>
                        <div style="font-size: 13px; color: #666; margin-top: 3px;">Age: {age_str} | Gender: {row["gender"]} | Ph: {row["phone"] if row["phone"] else "N/A"}</div>
                    </div>
                </div>
                <div>
                    <span style="background-color: {badge_bg}; color: white; padding: 5px 12px; border-radius: 20px; font-size: 12px; font-weight: bold;">
                        {status_text}
                    </span>
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

            <form action="/select-patient" method="get" style="margin-bottom: 15px;">
                <div style="display: flex; gap: 8px;">
                    <input type="text" name="search" value="{search}" placeholder="Search name or phone..." style="flex: 1; padding: 10px; border: 1px solid #ccc; border-radius: 6px;">
                    <button type="submit" class="btn-search">Search</button>
                </div>
            </form>

            <form onsubmit="event.preventDefault(); var pid = document.getElementById('patient_id_input').value; if(pid) {{ window.location.href='/patient-results/' + pid; }} else {{ alert('Please select a patient first.'); }}">
                <input type="hidden" id="patient_id_input" value="{selected_patient_id if selected_patient_id else ''}">
                <div class="patient-list-container">
                    {patient_cards}
                </div>
                <button type="submit" class="btn-next">Next: View Patient Tests</button>
            </form>
        </div>
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
    p_title = p_dict.get("title", "")
    p_name = p_dict.get("name", "")
    p_gender = p_dict.get("gender") or "Male"
    p_age_display = p_dict.get("age_years") or p_dict.get("age") or ""
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
        input_attr = 'disabled style="flex: 3; padding: 10px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; background: #f8fafc; color: #64748b; cursor: not-allowed;"'
    else:
        input_attr = 'style="flex: 3; padding: 10px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; outline: none; transition: border-color 0.2s;"'

    if params:
        for p in params:
            p_id_param = p["id"]
            p_name_val = p["p_name"]
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
                calc_attr = 'readonly style="flex: 3; padding: 10px 12px; border: 1px solid #93c5fd; border-radius: 6px; font-size: 14px; background: #eff6ff; color: #1d4ed8; font-weight: 700;"'
                badge = '<span style="background:#dbeafe;color:#1d4ed8;padding:3px 7px;border-radius:10px;font-size:10px;font-weight:700;margin-left:6px;">AUTO</span>'
            else:
                calc_attr = input_attr
                badge = ''

            ref_html = f'<div style="font-size:11px;color:#64748b;margin-top:3px;">Ref: {html.escape(str(selected_ref))}</div>' if selected_ref else ''
            unit_html = f'<span style="min-width:90px;font-size:12px;color:#64748b;">{html.escape(str(unit_val))}</span>' if unit_val else '<span style="min-width:90px;"></span>'

            param_form_html += f"""
            <div style="display:grid; grid-template-columns: minmax(180px,2fr) minmax(120px,3fr) 100px; margin-bottom: 12px; align-items:center; gap:12px;">
                <label style="font-weight:600;color:#334155;font-size:14px;">{html.escape(str(p_name_val))}{badge}{ref_html}</label>
                <input type="text" name="param_{test_id}_{p_id_param}" value="{html.escape(final_val)}" placeholder="{'Auto calculated' if is_calculated else 'Enter result...'}" {calc_attr}>
                {unit_html}
            </div>
            """
    else:
        main_input_attr = 'disabled style="width: 100%; padding: 10px 12px; box-sizing: border-box; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; background: #f8fafc; color: #64748b; cursor: not-allowed;"' if has_results else 'style="width: 100%; padding: 10px 12px; box-sizing: border-box; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 14px; outline: none;"'
        param_form_html += f"""
        <div style="margin-bottom: 15px;">
            <input type="text" name="result_{test_id}" value="{main_result_val}" placeholder="Enter test result..." {main_input_attr}>
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
                <div style="flex:1; min-width:90px;">
                    <label style="display:block; font-size:12px; font-weight:600; color:#475569; margin-bottom:4px;">Age</label>
                    <input type="text" name="patient_age" value="{p_age_display}" style="width:100%; padding:8px 10px; border:1px solid #cbd5e1; border-radius:6px; font-size:13px; box-sizing:border-box;">
                </div>
                <div style="flex:1; min-width:150px;">
                    <label style="display:block; font-size:12px; font-weight:600; color:#475569; margin-bottom:4px;">Doctor</label>
                    <input type="text" name="patient_doctor" value="{p_doctor}" style="width:100%; padding:8px 10px; border:1px solid #cbd5e1; border-radius:6px; font-size:13px; box-sizing:border-box;">
                </div>
                <div style="flex:1; min-width:150px;">
                    <label style="display:block; font-size:12px; font-weight:600; color:#475569; margin-bottom:4px;">Center</label>
                    <input type="text" name="patient_center" value="{p_center_display}" style="width:100%; padding:8px 10px; border:1px solid #cbd5e1; border-radius:6px; font-size:13px; box-sizing:border-box;">
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
    </head>
    <body>
        <div class="container">
            <!-- Top Navigation Bar (Back Link & View Professional Report Button) -->
            <div class="no-print" style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px;">
                <a href="/patient-results/{patient_id}" class="back-link">&larr; Back to Patient Overview</a>
                <a href="/report-view/{patient_id}/{test_id}" target="_blank" class="btn-report">
                    📄 View Professional Report
                </a>
            </div>
            
            <div class="no-print">
                {patient_edit_html}
            </div>

            <div class="printable-area">
                <h2>{t_name} - Report</h2>
                
                <form action="/save-specific-test/{patient_id}/{test_id}" method="post">
                    {param_form_html}
                    {save_action_html}
                </form>
                
                {reset_section_html}
                
               <div style="text-align: center; margin-top: 12px;">
        <a href="/report-view/{patient_id}/{test_id}" target="_blank" class="btn-print no-print" style="text-decoration: none; display: inline-block; line-height: normal;">
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
def update_patient_info(patient_id: int, patient_title: str = Form(...), patient_name: str = Form(...), patient_phone: str = Form(None), patient_doctor: str = Form(None), patient_age: str = Form(None), patient_center: str = Form(None), patient_gender: str = Form(None), test_id: int = Form(None)):
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("""
            UPDATE patients 
            SET title = ?, name = ?, phone = ?, doctor = ?, age_years = ?, center = ?, gender = ?
            WHERE id = ?
        """, (patient_title, patient_name, patient_phone, patient_doctor, patient_age, patient_center, patient_gender, patient_id))
        conn.commit()
    except Exception as e:
        try:
            cursor.execute("UPDATE patients SET name = ? WHERE id = ?", (patient_name, patient_id))
            conn.commit()
        except:
            pass
    conn.close()
    if test_id:
        return RedirectResponse(url=f"/test-entry/{patient_id}/{test_id}", status_code=303)
    return RedirectResponse(url=f"/patient-results/{patient_id}", status_code=303)


@app.post("/save-specific-test/{patient_id}/{test_id}")
async def save_specific_test(patient_id: int, test_id: int, request: Request):
    form_data = await request.form()
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute("ALTER TABLE patient_assigned_tests ADD COLUMN saved_at TEXT")
        conn.commit()
    except Exception:
        pass
    save_timestamp = datetime.now().isoformat(timespec="seconds")
    
    for key, value in form_data.items():
        if key.startswith("param_"):
            parts = key.split("_")
            if len(parts) >= 3:
                p_id_param = parts[2]

                # Locking: only allow setting the parameter result if it isn't already saved.
                cursor.execute("""
                    SELECT result_value FROM patient_parameter_results 
                    WHERE patient_id = ? AND test_id = ? AND parameter_id = ?
                """, (patient_id, test_id, p_id_param))
                existing_param = cursor.fetchone()
                existing_param_value = existing_param["result_value"] if existing_param else None
                if not (existing_param_value and str(existing_param_value).strip()):
                    cursor.execute("""
                        INSERT INTO patient_parameter_results (patient_id, test_id, parameter_id, result_value)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(patient_id, test_id, parameter_id) 
                        DO UPDATE SET result_value = ?
                    """, (patient_id, test_id, p_id_param, value, value))
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
    p_id = p.get("id")
    p_title = p.get("title") or p.get("salutation") or ""
    p_name = p.get("name") or p.get("patient_name") or p.get("full_name") or ""
    p_age = p.get("age") or p.get("age_years") or p.get("patient_age") or ""
    p_gender = p.get("gender") or p.get("sex") or "Male"
    p_phone = p.get("phone") or p.get("telephone") or p.get("mobile") or ""
    p_doctor = p.get("doctor") or p.get("doctor_name") or p.get("ref_doctor") or ""
    p_center = p.get("center") or p.get("branch") or ""

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
                
                # Fetch parameters dynamically
                params = []
                for tbl in ["test_parameters", "parameters", "sub_tests", "test_fields"]:
                    for col in ["parameter_name", "name", "param_name"]:
                        try:
                            cursor.execute(f"SELECT id, {col} as p_name, default_ref_range FROM {tbl} WHERE test_id = ? ORDER BY id ASC", (t_id,))
                            params = cursor.fetchall()
                            if params: break
                        except:
                            try:
                                cursor.execute(f"SELECT id, {col} as p_name FROM {tbl} WHERE test_id = ? ORDER BY id ASC", (t_id,))
                                params = cursor.fetchall()
                                if params: break
                            except:
                                continue
                    if params: break
                
                # Pre-fetch existing parameter values & determine lock status
                param_values = []
                has_saved_param_value = False
                for p_item in params:
                    p_id_param = p_item["id"]
                    p_name_val = p_item["p_name"]
                    default_val = p_item["default_ref_range"] if "default_ref_range" in p_item.keys() and p_item["default_ref_range"] else ""
                    p_val = ""
                    try:
                        cursor.execute("SELECT result_value FROM patient_parameter_results WHERE patient_id = ? AND test_id = ? AND parameter_id = ?", (patient_id, t_id, p_id_param))
                        exist_res = cursor.fetchone()
                        if exist_res: p_val = exist_res["result_value"]
                    except: pass
                    if p_val and str(p_val).strip():
                        has_saved_param_value = True
                    param_values.append((p_id_param, p_name_val, default_val, p_val))

                has_results = bool(main_result and str(main_result).strip()) or has_saved_param_value

                if has_results:
                    value_input_attr = 'disabled style="flex: 2; padding: 8px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; outline: none; background: #f1f5f9; color: #64748b; cursor: not-allowed;"'
                else:
                    value_input_attr = 'style="flex: 2; padding: 8px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; outline: none;"'

                lock_badge_html = '<span style="background:#fef3c7; color:#b45309; padding:3px 10px; border-radius:12px; font-size:11px; font-weight:700;"><i class="fa-solid fa-lock"></i> Locked</span>' if has_results else ""

                reset_button_html = f"""
                <form action="/reset-test-results/{p_id}/{t_id}" method="post" onsubmit="return confirm('Are you sure you want to reset/unlock this test to edit?');" style="margin: 8px 0 0 0; text-align: right;">
                    <button type="submit" style="background: #ef4444; color: white; border: none; padding: 6px 14px; border-radius: 6px; font-weight: 600; font-size: 12px; cursor: pointer;">
                        <i class="fa-solid fa-rotate-left"></i> Reset & Unlock
                    </button>
                </form>
                """ if has_results else ""

                categories_html += f"""
                <div style="background: #ffffff; border: 1px solid #cbd5e1; border-radius: 8px; padding: 16px; margin-bottom: 15px; box-shadow: 0 2px 5px rgba(0,0,0,0.03);">
                    <form action="/save-test-results" method="post" style="margin: 0;">
                        <input type="hidden" name="patient_id" value="{p_id}">
                        <input type="hidden" name="test_id" value="{t_id}">
                        <input type="hidden" name="assigned_id" value="{assigned_id}">
                        
                        <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 2px solid #f1f5f9; padding-bottom: 12px; margin-bottom: 15px;">
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
                    categories_html += f"""<div style="display: grid; gap: 10px; margin-bottom: 12px;">"""
                    for p_id_param, p_name_val, default_val, p_val in param_values:
                        final_val = p_val if p_val != "" else default_val
                        
                        categories_html += f"""
                        <div style="display: flex; align-items: center; gap: 12px;">
                            <label style="flex: 1; font-size: 13px; font-weight: 600; color: #475569;">{p_name_val}</label>
                            <input type="text" name="param_{t_id}_{p_id_param}" value="{final_val}" placeholder="Result..." {value_input_attr}>
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
                    <form action="/update-patient-details" method="post">
                        <input type="hidden" name="patient_id" value="{p_id}">
                        <div class="row-2">
                            <div class="form-group">
                                <label>Title</label>
                                <select name="title">
                                    <option value="Mr." {"selected" if p_title == "Mr." else ""}>Mr.</option>
                                    <option value="Mrs." {"selected" if p_title == "Mrs." else ""}>Mrs.</option>
                                    <option value="Miss." {"selected" if p_title == "Miss." else ""}>Miss.</option>
                                    <option value="Baby." {"selected" if p_title == "Baby." else ""}>Baby.</option>
                                    <option value="Dr." {"selected" if p_title == "Dr." else ""}>Dr.</option>
                                </select>
                            </div>
                            <div class="form-group">
                                <label>Age</label>
                                <input type="text" name="age" value="{p_age}" placeholder="e.g. 25 Y">
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
                            <input type="text" name="doctor" value="{p_doctor}" placeholder="Doctor name">
                        </div>
                        <div class="form-group">
                            <label>Center / Branch</label>
                            <input type="text" name="center" value="{p_center}" placeholder="Center name">
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
    try:
        form_data = await request.form()
        patient_id = form_data.get("patient_id")
        if not patient_id:
            return HTMLResponse("<h3>Patient ID missing!</h3>", status_code=400)
            
        title = form_data.get("title")
        name = form_data.get("name")
        age = form_data.get("age")
        gender = form_data.get("gender")
        phone = form_data.get("phone")
        doctor = form_data.get("doctor")
        center = form_data.get("center")
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Update patients table based on standard column names
        cursor.execute("""
            UPDATE patients 
            SET title = ?, name = ?, age = ?, gender = ?, phone = ?, doctor = ?, center = ?
            WHERE id = ?
        """, (title, name, age, gender, phone, doctor, center, patient_id))
        
        conn.commit()
        conn.close()
        
        return RedirectResponse(url=f"/patient-results/{patient_id}?updated=1", status_code=303)
    except Exception as e:
        return HTMLResponse(content=f"<h3>Error updating patient details: {str(e)}</h3>", status_code=500)

# =============================================================
# 2. SAVE TEST RESULTS ROUTE (Fixed with Comment Support)
# =============================================================
@app.post("/save-test-results")
async def save_test_results(request: Request):
    try:
        form_data = await request.form()
        patient_id = form_data.get("patient_id")
        if not patient_id:
            return HTMLResponse("<h3>Patient ID missing!</h3>", status_code=400)
        patient_id = int(patient_id)
        
        conn = get_db_connection()
        cursor = conn.cursor()
        
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
        save_timestamp = datetime.now().isoformat(timespec="seconds")
        
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

                # Locking: only allow setting the parameter result if it isn't already saved.
                cursor.execute("""
                    SELECT result_value FROM patient_parameter_results 
                    WHERE patient_id = ? AND test_id = ? AND parameter_id = ?
                """, (patient_id, test_id, param_id))
                existing_param = cursor.fetchone()
                existing_param_value = existing_param["result_value"] if existing_param else None
                if not (existing_param_value and str(existing_param_value).strip()):
                    cursor.execute("""
                        INSERT INTO patient_parameter_results (patient_id, test_id, parameter_id, result_value)
                        VALUES (?, ?, ?, ?)
                        ON CONFLICT(patient_id, test_id, parameter_id) DO UPDATE SET result_value = excluded.result_value
                    """, (patient_id, test_id, param_id, value))

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
# PROFESSIONAL LAB REPORT VIEW (Letterhead Background, QR, Sig, Comment Box)
# -------------------------------------------------------------
@app.get("/report-letterhead-preview/{patient_id}/{test_id}", response_class=HTMLResponse)
def report_letterhead_preview(patient_id: int, test_id: int, request: Request):
    """Letterhead Print view."""
    return report_view(patient_id, test_id, request, letterhead=1)


@app.get("/report-view/{patient_id}/{test_id}", response_class=HTMLResponse)
def report_view(patient_id: int, test_id: int, request: Request, letterhead: int = 1):
    conn = get_db_connection()
    cursor = conn.cursor()

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
                    test_notes_html = f"<div class='report-test-note'>{clean_note}</div>"
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
    
    if assigned_res:
        assigned_keys = assigned_res.keys()
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
    printed_on = datetime.now().strftime("%d/%m/%Y %I:%M %p")

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
            cursor.execute(f"SELECT * FROM {tbl} WHERE test_id = ? ORDER BY id ASC",(test_id,))
            got=cursor.fetchall()
            if got:
                params=got; name_col=n_col; unit_col=u_col; range_col=r_col; break
        except (sqlite3.Error,TypeError,ValueError): continue

    rows_html=""
    if params:
        for p in params:
            d=dict(p); p_id=d.get("id")
            p_name=str(d.get(name_col,"Parameter") or "Parameter").strip()
            unit=str(d.get(unit_col,"") or "").strip() if unit_col else ""
            default_ref=str(d.get(range_col,"") or "").strip() if range_col else ""
            matched=select_best_ref_range(cursor,int(p_id),patient_gender,patient_age_days) if p_id is not None else None
            ref_range=matched or default_ref
            res="-"
            try:
                cursor.execute("SELECT result_value FROM patient_parameter_results WHERE patient_id=? AND test_id=? AND parameter_id=? LIMIT 1",(patient_id,test_id,p_id))
                rr=cursor.fetchone()
                if rr and rr["result_value"] is not None and str(rr["result_value"]).strip(): res=str(rr["result_value"]).strip()
            except sqlite3.Error:
                try:
                    cursor.execute("SELECT result_value FROM patient_parameter_results WHERE patient_id=? AND parameter_id=? LIMIT 1",(patient_id,p_id))
                    rr=cursor.fetchone()
                    if rr and rr["result_value"] is not None and str(rr["result_value"]).strip(): res=str(rr["result_value"]).strip()
                except sqlite3.Error: pass
            flag,is_abnormal=evaluate_result_flag(res,ref_range)
            result_weight="bold" if is_abnormal else "normal"
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
                    f'<td style="width:{col_widths[idx]:.2f}%;padding:4px 7px;border-bottom:none;text-align:{cell_align};font-weight:{cell_weight};color:{cell_color};line-height:1.15;">{cell_value}</td>'
                )
            rows_html += "<tr>" + "".join(row_cells) + "</tr>"
    elif main_result_val:
        flag,is_abnormal=evaluate_result_flag(main_result_val,"")
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
                f'<td style="width:{col_widths[idx]:.2f}%;padding:4px 7px;text-align:{cell_align};font-weight:{cell_weight};color:{cell_color};line-height:1.15;">{cell_value}</td>'
            )
        rows_html = "<tr>" + "".join(row_cells) + "</tr>"
    else:
        rows_html='<tr><td colspan="5" style="text-align:center;padding:15px;color:#777;border-bottom:none;">No parameters or results found for this test.</td></tr>'

    barcode_url = f"https://barcode.tec-it.com/barcode.ashx?data={ref_no}&code=Code128&dpi=96&hidehrt=true"
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
            body {{ font-family: Verdana, Geneva, sans-serif !important; font-size: 10px; background: #f0f2f5; margin: 0; padding: 20px; color: #000; }}
            .report-page, .report-page * {{ font-family: Verdana, Geneva, sans-serif !important; font-size: 10px !important; }}
            .action-bar {{ max-width: 800px; margin: 0 auto 15px auto; background: white; padding: 10px 20px; border-radius: 6px; display: flex; justify-content: space-between; align-items: center; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }}
            .btn {{ background: #333; color: white; border: none; padding: 8px 16px; border-radius: 4px; cursor: pointer; font-weight: bold; text-decoration: none; font-size: 13px; }}
            .btn:hover {{ background: #000; }}
            
            .report-page {{ 
                width: 210mm; 
                min-height: 297mm; 
                margin: 0 auto; 
                background: white; 
                {screen_bg_css}
                padding: 38mm 15mm 15mm 15mm; 
                box-sizing: border-box; 
                box-shadow: 0 4px 15px rgba(0,0,0,0.15); 
                position: relative; 
            }}
            
            .top-barcode-container {{ text-align: right; margin-bottom: 8px; }}
            .top-barcode-container img {{ height: 30px; width: 155px; object-fit: fill; display: block; margin-left: auto; }}

            .patient-box {{ border: 1px solid #333; border-radius: 3px; padding: 10px 15px; margin-bottom: 12px; background: rgba(255,255,255,0.9); }}
            .header-table {{ width: 100%; border-collapse: collapse; font-size: 10px; }}
            .header-table td {{ padding: 3px 4px; vertical-align: middle; }}
            
            .test-title-bar {{ text-align: center; font-weight: bold; font-size: 10px; margin: 8px 0 5px 0; color: #000; text-transform: uppercase; letter-spacing: 0.5px; }}

            .report-table {{ width: 100%; border-collapse: collapse; margin-top: 3px; font-size: 10px; table-layout: fixed; }}
            .report-table th {{ background: none; color: #000; border-top: 1px solid #000; border-bottom: 1px solid #000; padding: 4px 7px; font-size: 10px !important; font-weight: bold; box-sizing: border-box; line-height: 1.15; }}
            .report-table td {{ box-sizing: border-box; overflow-wrap: anywhere; word-break: normal; line-height: 1.15; }}
            
            .report-note, .report-test-note {{ margin-top: 10px; padding: 0; font-size: 10px !important; color: #000; background: transparent; border: none; line-height: 1.4; }}

            .end-report-text {{ text-align: center; font-size: 7px !important; font-weight: bold; color: #000; margin: 12px 0 8px 0; letter-spacing: 0.7px; }}

            /* SHIFTED ENTIRE BLOCK FURTHER RIGHT */
            .bottom-section {{ 
                display: flex; 
                justify-content: space-between; 
                align-items: flex-end; 
                margin-top: 6px; 
                width: 100%; 
            }}
            .qr-container img {{ width: 75px; height: 75px; }}
            
            .sig-wrapper-new {{ 
                text-align: center; 
                font-size: 10px !important; 
                min-width: 350px; 
                margin-right: -12px; 
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

            .report-footer {{ margin-top: 12px; text-align: center; font-size: 10px !important; font-weight: 700; color: #000; border-top: 1px solid #000; padding-top: 5px; }}

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

            <div class="patient-box">
                <table class="header-table">
                    <tr>
                        <td style="width: 14%; font-weight: bold; color: #000;">Patient Name</td>
                        <td style="width: 2%;">:</td>
                        <td style="width: 34%; font-weight: bold;">{patient_name}</td>
                        <td style="width: 14%; font-weight: bold; color: #000;">Reference No</td>
                        <td style="width: 2%;">:</td>
                        <td style="width: 34%; font-weight: bold;">{ref_no}</td>
                    </tr>
                    <tr>
                        <td style="font-weight: bold; color: #000;">Gender / Age</td>
                        <td>:</td>
                        <td>{gender_age}</td>
                        <td style="font-weight: bold; color: #000;">Received On</td>
                        <td>:</td>
                        <td>{received_on}</td>
                    </tr>
                    <tr>
                        <td style="font-weight: bold; color: #000;">Referred By</td>
                        <td>:</td>
                        <td>{doctor}</td>
                        <td style="font-weight: bold; color: #000;">Reported On</td>
                        <td>:</td>
                        <td>{reported_on}</td>
                    </tr>
                    <tr>
                        <td style="font-weight: bold; color: #000;">Center</td>
                        <td>:</td>
                        <td>{center}</td>
                        <td style="font-weight: bold; color: #000;">Department</td>
                        <td>:</td>
                        <td>{department}</td>
                    </tr>
                    <tr>
                        <td></td>
                        <td></td>
                        <td></td>
                        <td style="font-weight: bold; color: #000;">Specimen</td>
                        <td>:</td>
                        <td>{specimen}</td>
                    </tr>
                </table>
            </div>

            <div class="test-title-bar">{test_name}</div>

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

            {"<div class='report-note'><b>Note:</b> " + comment_text + "</div>" if comment_text else ""}
            {test_notes_html}
            <div class="end-report-text">*** END OF REPORT ***</div>

            <!-- Bottom Section: QR Left, Signature Right -->
            <div class="bottom-section">
                <div class="qr-container">
                    <img src="{qr_url}" alt="QR Code">
                </div>
                <div class="sig-wrapper-new">
                    <img src="{signature_img_url}" alt="MLT Signature" class="sig-img-new" onerror="this.style.display='none';">
                    <b style="margin-bottom: 1px;">S.P.Jananga</b>
                    <span style="font-size: 10px; color: #222; margin-bottom: 1px; display: block;">Medical Laboratory Technologist (MLT)</span>
                    <span style="font-size: 10px; color: #444; display: block;">SLMC No 2867</span>
                </div>
            </div>

            <div class="report-footer">
                Printed on: {printed_on}
            </div>
        </div>

    </body>
    </html>
    """