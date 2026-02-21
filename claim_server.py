from flask import Flask, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
from flask_wtf.csrf import CSRFProtect
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
# 🎨 TEMPLATE
# =========================

def premium_page(title, content):
    return f"""
    <html>
    <head>
        <title>{title}</title>
        <meta name='viewport' content='width=device-width, initial-scale=1'>
    </head>
    <body style="font-family:Arial; background:#0f2027; color:white; text-align:center; padding:30px;">
        {content}
    </body>
    </html>
    """

# =========================
# 🏠 HOME
# =========================

@app.route("/")
def home():
    return premium_page("Prize Portal",
        "<h1>🏆 Prize Claim Portal</h1>"
        "<a href='/login'><button>🔐 Continue with Google</button></a>"
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

    # ✅ Session fixation protection
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
    return value[:100]  # limit length

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

    return premium_page("Claim",
        "<h1>🎁 Prize Claim Form</h1>"
        "<form method='post'>"
        "<input name='name' placeholder='Full Name' required><br><br>"
        "<input name='upi' placeholder='UPI ID' required><br><br>"
        "<input name='phone' placeholder='Phone Number' required><br><br>"
        "<button type='submit'>Submit Claim</button>"
        "</form>"
    )

# =========================
# 🔐 ADMIN LOGIN
# =========================

@app.route("/admin", methods=["GET", "POST"])
def admin_login():

    if request.method == "POST":
        if request.form.get("key") == ADMIN_KEY:

            session.clear()  # fixation protection
            session.permanent = True
            session["admin"] = True

            return redirect("/admin_panel")
        else:
            time.sleep(2)
            return premium_page("Error", "<h2>Wrong Admin Key</h2>")

    return premium_page("Admin Login",
        "<h1>🔐 Admin Login</h1>"
        "<form method='post'>"
        "<input type='password' name='key' required><br><br>"
        "<button>Login</button>"
        "</form>"
    )

# =========================
# ⚙️ ADMIN PANEL
# =========================

@app.route("/admin_panel")
def admin_panel():
    if not session.get("admin"):
        return redirect("/admin")

    winner = load_winner() or "Not announced yet"

    return premium_page("Admin Panel",
        f"<h1>⚙️ Admin Panel</h1>"
        f"<h3>🏆 Current Winner</h3><p>{winner}</p>"
        "<form method='post' action='/set_winner'>"
        "<input name='handle' placeholder='@ChannelHandle' required><br><br>"
        "<button>Set Winner</button>"
        "</form>"
        "<br><a href='/logout'><button>Logout</button></a>"
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

    return premium_page("Success", f"<h2>Winner set</h2><p>{winner_channel_id}</p>")

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
