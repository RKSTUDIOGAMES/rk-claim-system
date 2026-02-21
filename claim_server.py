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
            csv.writer(f).writerow([datetime.now().isoformat(), channel_id, step])

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
# 🎨 PREMIUM TEMPLATE
# =========================

def premium_page(title, content):
    return f"""
    <html>
    <head>
        <title>{title}</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ margin:0;font-family:Arial;background:#f4f4f4;color:#222; }}
            .container {{ max-width:480px;margin:60px auto;background:#fff;padding:24px;border-radius:8px;box-shadow:0 2px 8px rgba(0,0,0,0.08); }}
            input,button {{ width:100%;padding:12px;margin-top:12px;border-radius:6px;border:1px solid #ccc;font-size:14px; }}
            button {{ background:#1976d2;color:#fff;border:none;cursor:pointer; }}
            button:hover {{ background:#155fa0; }}
        </style>
    </head>
    <body><div class="container">{content}</div></body></html>
    """

# =========================
# 🏠 HOME (PUBLIC)
# =========================

@app.route("/")
def home():
    return premium_page("RK Studio Claims",
        "<h1>RK Studio Claims</h1>"
        "<p><strong>Official web application operated by RK Studio (India).</strong></p>"
        "<p>This page is publicly accessible and does not require login.</p>"
        "<p>This application verifies ownership of a YouTube channel for giveaway prize claims.</p>"
        "<a href='/login'><button>Continue to Sign-In</button></a>"
        "<hr>"
        "<p><a href='/privacy'>Privacy Policy</a> | <a href='/terms'>Terms</a></p>"
    )

# =========================
# 🔑 LOGIN PAGE (NO AUTO REDIRECT)
# =========================

@app.route("/login")
def login_page():
    return premium_page("Sign In",
        "<h1>Sign In Required</h1>"
        "<p>Please sign in with your Google account to verify your YouTube channel.</p>"
        "<a href='/google_login'><button>Continue with Google</button></a>"
    )

# =========================
# 🔐 GOOGLE LOGIN REDIRECT
# =========================

@app.route("/google_login")
def google_login():
    redirect_uri = url_for("auth", _external=True, _scheme="https")
    return google.authorize_redirect(redirect_uri)

# =========================
# 🔐 AUTH CALLBACK
# =========================

@app.route("/auth")
def auth():
    token = google.authorize_access_token()

    yt = requests.get(
        "https://www.googleapis.com/youtube/v3/channels?part=id&mine=true",
        headers={"Authorization": "Bearer " + token["access_token"]}
    ).json()

    session.clear()
    session["channel_id"] = yt["items"][0]["id"]

    log_step(session["channel_id"], "logged_in")

    return redirect("/verify")

# =========================
# (BAKI CODE SAME — VERIFY, CLAIM, ADMIN, PRIVACY, TERMS, ETC.)
# =========================

# 🚀 RUN
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7000))
    app.run(host="0.0.0.0", port=port)
