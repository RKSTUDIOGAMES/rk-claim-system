from flask import Flask, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
from flask_wtf.csrf import CSRFProtect, generate_csrf
import requests
import csv
from datetime import datetime, timedelta
import os
import re
import threading
import time
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# =========================
# 🔐 ENV VARIABLES
# =========================

SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
YOUTUBE_API_KEY = os.environ.get("YOUTUBE_API_KEY")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
ADMIN_KEY = os.environ.get("ADMIN_KEY")

if not SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY missing")
if not GOOGLE_CLIENT_ID or not GOOGLE_CLIENT_SECRET:
    raise RuntimeError("Google OAuth credentials missing")
if not ADMIN_KEY:
    raise RuntimeError("ADMIN_KEY missing")
if not YOUTUBE_API_KEY:
    raise RuntimeError("YOUTUBE_API_KEY missing")

app.secret_key = SECRET_KEY

# ✅ CSRF Protection
csrf = CSRFProtect(app)

# ✅ HTTPS Proxy Fix
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# ✅ Session Security
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PREFERRED_URL_SCHEME="https"
)

# ✅ Admin session timeout
app.permanent_session_lifetime = timedelta(minutes=30)

# =========================
# 🛡️ SECURITY HEADERS
# =========================

@app.after_request
def secure_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'"
    return response

# =========================
# 📁 DATA STORAGE
# =========================

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

WINNER_FILE = os.path.join(DATA_DIR, "winner.txt")
CLAIMS_FILE = os.path.join(DATA_DIR, "claims.csv")
PROGRESS_FILE = os.path.join(DATA_DIR, "progress.csv")

lock = threading.Lock()

# =========================
# 💾 WINNER STORAGE
# =========================

def load_winner():
    if os.path.exists(WINNER_FILE):
        with open(WINNER_FILE, "r", encoding="utf-8") as f:
            return f.read().strip()
    return None

def save_winner(cid):
    with open(WINNER_FILE, "w", encoding="utf-8") as f:
        f.write(cid)

# =========================
# ⭐ STEP LOGGING
# =========================

def log_step(channel_id, step):
    with lock:
        with open(PROGRESS_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([datetime.now().isoformat(), channel_id, step])

# =========================
# 🔐 GOOGLE OAUTH
# =========================

oauth = OAuth(app)

google = oauth.register(
    name="google",
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url="https://accounts.google.com/.well-known/openid-configuration",
    client_kwargs={
        "scope": "openid email profile https://www.googleapis.com/auth/youtube.readonly"
    }
)

# =========================
# 🎨 PREMIUM TEMPLATE (UI ONLY CHANGED)
# =========================

def premium_page(title, content):
    return f"""
    <html>
    <head>
        <title>{title}</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <style>
            body {{
                margin:0;
                font-family: 'Segoe UI', Arial, sans-serif;
                background: linear-gradient(135deg,#0f2027,#203a43,#2c5364);
                min-height:100vh;
                display:flex;
                align-items:center;
                justify-content:center;
                color:white;
            }}

            .card {{
                background: rgba(255,255,255,0.08);
                backdrop-filter: blur(18px);
                border-radius: 18px;
                padding: 30px 25px;
                width: 92%;
                max-width: 420px;
                box-shadow: 0 10px 40px rgba(0,0,0,0.6);
                animation: fadeIn 0.6s ease;
            }}

            h1 {{ margin-top:0; }}

            input {{
                width: 100%;
                padding: 12px;
                margin-top: 10px;
                border-radius: 10px;
                border: none;
                outline: none;
                font-size: 15px;
            }}

            button {{
                width: 100%;
                padding: 13px;
                margin-top: 16px;
                border: none;
                border-radius: 12px;
                background: linear-gradient(90deg,#00c6ff,#0072ff);
                color: white;
                font-size: 16px;
                font-weight: bold;
                cursor: pointer;
                transition: 0.25s;
            }}

            button:hover {{
                transform: translateY(-2px);
                box-shadow: 0 8px 20px rgba(0,0,0,0.4);
            }}

            a {{ text-decoration:none; }}

            @keyframes fadeIn {{
                from {{opacity:0; transform:translateY(20px);}}
                to {{opacity:1; transform:translateY(0);}}
            }}
        </style>
    </head>

    <body>
        <div class="card">
            {content}
        </div>
    </body>
    </html>
    """

# =========================
# 🏠 HOME
# =========================

@app.route("/")
def home():
    return premium_page("RK Studio Claims",
        "<h1>🏆 RK Studio Claims</h1>"

        "<p>This application is used to verify YouTube channel "
        "ownership for prize distribution from RK Studio giveaways.</p>"

        "<p>Users sign in with Google to confirm their YouTube channel ID.</p>"

        "<p>No personal data is sold or shared.</p>"

        "<a href='/login'><button>🔐 Continue with Google</button></a>"

        "<hr style='margin:20px 0'>"

        "<p style='font-size:14px'>"
        "<a href='/privacy'>Privacy Policy</a> | "
        "<a href='/terms'>Terms of Service</a>"
        "</p>"
    )
# =========================
# 🔑 LOGIN
# =========================

@app.route("/login")
def login():
    redirect_uri = url_for("auth", _external=True, _scheme="https")
    return google.authorize_redirect(redirect_uri)

# =========================
# 🔐 AUTH CALLBACK
# =========================

@app.route("/auth")
def auth():
    try:
        token = google.authorize_access_token()
    except Exception:
        return premium_page("Error", "<h2>Login Failed</h2>")

    yt = requests.get(
        "https://www.googleapis.com/youtube/v3/channels?part=id&mine=true",
        headers={"Authorization": "Bearer " + token["access_token"]}
    ).json()

    if not yt.get("items"):
        return premium_page("Error", "<h2>YouTube access failed</h2>")

    session.clear()
    session["channel_id"] = yt["items"][0]["id"]

    log_step(session["channel_id"], "logged_in")

    return redirect(url_for("verify"))

# =========================
# ✅ VERIFY
# =========================

@app.route("/verify")
def verify():
    if "channel_id" not in session:
        return redirect("/")

    winner_channel_id = load_winner()

    if not winner_channel_id:
        return premium_page("Pending", "<h2>Winner not announced yet</h2>")

    if session["channel_id"] == winner_channel_id:
        return redirect("/claim")
    else:
        return premium_page("Denied", "<h2>Access Denied — Not Winner</h2>")

# =========================
# 📝 CLAIM
# =========================

def sanitize(value):
    if value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value[:100]

upi_pattern = r"^[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}$"

@app.route("/claim", methods=["GET", "POST"])
def claim():
    if "channel_id" not in session:
        return redirect("/")

    if request.method == "POST":

        name = sanitize(request.form.get("name", "").strip())
        upi = sanitize(request.form.get("upi", "").strip())
        phone = sanitize(request.form.get("phone", "").strip())

        if not name or not upi or not phone:
            return premium_page("Error", "<h2>All fields required</h2>")

        if not re.match(upi_pattern, upi):
            return premium_page("Error", "<h2>Invalid UPI ID</h2>")

        if not re.match(r"^[6-9]\d{9}$", phone):
            return premium_page("Error", "<h2>Invalid phone number</h2>")

        with lock:
            with open(CLAIMS_FILE, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([
                    datetime.now().isoformat(),
                    session["channel_id"],
                    name,
                    upi,
                    phone
                ])

        return premium_page("Success", "<h2>✅ Claim Submitted Successfully</h2>")

    token = generate_csrf()

    return premium_page("Claim",
        f"<h1>🎁 Prize Claim Form</h1>"
        f"<form method='post'>"
        f"<input type='hidden' name='csrf_token' value='{token}'>"
        f"<input name='name' placeholder='Full Name' required>"
        f"<input name='upi' placeholder='UPI ID' required>"
        f"<input name='phone' placeholder='Phone Number' required>"
        f"<button type='submit'>Submit Claim</button>"
        f"</form>"
    )

# =========================
# 🔐 ADMIN LOGIN
# =========================

@app.route("/admin", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":
        if request.form.get("key") == ADMIN_KEY:

            session.clear()
            session.permanent = True
            session["admin"] = True

            return redirect("/admin_panel")
        else:
            time.sleep(2)
            return premium_page("Error", "<h2>Wrong Admin Key</h2>")

    token = generate_csrf()

    return premium_page("Admin Login",
        f"<h1>🔐 Admin Login</h1>"
        f"<form method='post'>"
        f"<input type='hidden' name='csrf_token' value='{token}'>"
        f"<input type='password' name='key' placeholder='Admin Key' required>"
        f"<button>Login</button>"
        f"</form>"
    )

# =========================
# ⚙️ ADMIN PANEL
# =========================

@app.route("/admin_panel")
def admin_panel():
    if not session.get("admin"):
        return redirect("/admin")

    winner = load_winner() or "Not announced yet"
    token = generate_csrf()

    return premium_page("Admin Panel",
        f"<h1>⚙️ Admin Panel</h1>"
        f"<h3>🏆 Current Winner</h3><p>{winner}</p>"
        f"<form method='post' action='/set_winner'>"
        f"<input type='hidden' name='csrf_token' value='{token}'>"
        f"<input name='handle' placeholder='@ChannelHandle' required>"
        f"<button>Set Winner</button>"
        f"</form>"

        "<hr style='margin:20px 0'>"

        "<a href='/view_claims'><button>📊 View Claims</button></a>"
        "<a href='/progress'><button>📈 View Activity</button></a>"
        "<a href='/logout'><button style='background:#ff5252'>🚪 Logout</button></a>"
    )

# =========================
# 🏆 SET WINNER
# =========================

@app.route("/set_winner", methods=["POST"])
def set_winner():
    if not session.get("admin"):
        return premium_page("Error", "<h2>Unauthorized</h2>")

    handle = request.form.get("handle", "").replace("@", "")

    r = requests.get(
        f"https://www.googleapis.com/youtube/v3/channels?part=id&forHandle={handle}&key={YOUTUBE_API_KEY}"
    ).json()

    if not r.get("items"):
        return premium_page("Error", "<h2>Channel not found</h2>")

    winner_channel_id = r["items"][0]["id"]
    save_winner(winner_channel_id)

    return premium_page("Success",
        f"<h2>Winner set</h2><p>{winner_channel_id}</p>")

# =========================
# 📊 VIEW CLAIMS
# =========================

@app.route("/view_claims")
def view_claims():
    if not session.get("admin"):
        return redirect("/admin")

    if not os.path.exists(CLAIMS_FILE):
        return premium_page("Claims", "<h2>No claims yet</h2>")

    with open(CLAIMS_FILE, "r", encoding="utf-8") as f:
        data = f.read()

    return premium_page("Claims",
        f"<h1>📊 Claim Submissions</h1>"
        f"<pre style='text-align:left'>{data}</pre>"
        "<a href='/admin_panel'><button>⬅ Back</button></a>"
    )

# =========================
# 📈 VIEW PROGRESS
# =========================

@app.route("/progress")
def view_progress():
    if not session.get("admin"):
        return redirect("/admin")

    if not os.path.exists(PROGRESS_FILE):
        return premium_page("Progress", "<h2>No activity yet</h2>")

    with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
        data = f.read()

    return premium_page("Progress",
        f"<h1>📈 User Activity</h1>"
        f"<pre style='text-align:left'>{data}</pre>"
        "<a href='/admin_panel'><button>⬅ Back</button></a>"
    )
# =========================
# 🚪 PRIVACY
# =========================
@app.route("/privacy")
def privacy():
    return premium_page("Privacy Policy",
        "<h1>Privacy Policy</h1>"
        "<p>This app only accesses your basic Google profile "
        "and YouTube channel ID for verification purposes.</p>"
        "<p>No data is sold or shared.</p>"
    )
 # =========================
# 🚪 TERMS
# =========================  
@app.route("/terms")
def terms():
    return premium_page("Terms",
        "<h1>Terms of Service</h1>"
        "<p>This tool is used only for prize claim verification.</p>"
    )

# =========================
# 🚪 LOGOUT
# =========================

@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# =========================
# 🚀 RUN
# =========================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7000))
    app.run(host="0.0.0.0", port=port)




