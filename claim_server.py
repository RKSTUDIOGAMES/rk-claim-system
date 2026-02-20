from flask import Flask, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
import requests
import csv
from datetime import datetime
import os
import re
import threading
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
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PREFERRED_URL_SCHEME="https"
)

# =========================
# 📁 DATA STORAGE
# =========================

DATA_DIR = "data"
os.makedirs(DATA_DIR, exist_ok=True)

WINNER_FILE = os.path.join(DATA_DIR, "winner.txt")
CLAIMS_FILE = os.path.join(DATA_DIR, "claims.csv")
PROGRESS_FILE = os.path.join(DATA_DIR, "progress.csv")  # ⭐ NEW

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
# ⭐ STEP LOGGING FUNCTION
# =========================

def log_step(channel_id, step):
    with lock:
        with open(PROGRESS_FILE, "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                channel_id,
                step
            ])

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
        <meta name='viewport' content='width=device-width, initial-scale=1'>
        <style>
            body {{
                margin:0;
                height:100vh;
                display:flex;
                align-items:center;
                justify-content:center;
                font-family:Arial, sans-serif;
                background: linear-gradient(135deg,#0f2027,#203a43,#2c5364);
                color:white;
            }}

            .card {{
                background: rgba(255,255,255,0.08);
                backdrop-filter: blur(20px);
                border-radius:20px;
                padding:35px;
                width:90%;
                max-width:420px;
                text-align:center;
                box-shadow:0 0 40px rgba(0,0,0,0.6);
            }}

            input {{
                width:100%;
                padding:14px;
                margin:8px 0;
                border-radius:10px;
                border:none;
                font-size:16px;
            }}

            button {{
                width:100%;
                padding:15px;
                margin-top:15px;
                font-size:18px;
                border:none;
                border-radius:12px;
                background:#00c853;
                color:white;
                cursor:pointer;
                font-weight:bold;
            }}

            .google {{background:#4285F4;}}
            .error {{color:#ff5252;}}
            .success {{color:#00e676;}}
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
    return premium_page("Prize Portal", """
        <h1>🏆 Prize Claim Portal</h1>
        <a href="/login">
            <button class="google">🔐 Continue with Google</button>
        </a>
    """)

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
    except Exception as e:
        return premium_page("Error", f"<h2 class='error'>Login Failed</h2><p>{e}</p>")

    yt = requests.get(
        "https://www.googleapis.com/youtube/v3/channels?part=id&mine=true",
        headers={"Authorization": "Bearer " + token["access_token"]}
    ).json()

    if "items" not in yt or not yt["items"]:
        return premium_page("Error", "<h2 class='error'>YouTube access failed</h2>")

    session["channel_id"] = yt["items"][0]["id"]

    log_step(session["channel_id"], "logged_in")  # ⭐ NEW

    return redirect(url_for("verify"))

# =========================
# ✅ VERIFY WINNER
# =========================

@app.route("/verify")
def verify():
    if "channel_id" not in session:
        return redirect(url_for("home"))

    log_step(session["channel_id"], "verify_page")  # ⭐ NEW

    winner_channel_id = load_winner()

    if not winner_channel_id:
        return premium_page("Pending", "<h2>Winner not announced yet</h2>")

    if session["channel_id"] == winner_channel_id:
        log_step(session["channel_id"], "winner_verified")  # ⭐ NEW
        return redirect(url_for("claim"))
    else:
        log_step(session["channel_id"], "not_winner")  # ⭐ NEW
        return premium_page("Denied", "<h2 class='error'>Access Denied — Not Winner</h2>")

# =========================
# 📝 CLAIM FORM
# =========================

def sanitize(value):
    if value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value

upi_pattern = r"^[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}$"

@app.route("/claim", methods=["GET", "POST"])
def claim():
    if "channel_id" not in session:
        return redirect(url_for("home"))

    if request.method == "POST":

        name = sanitize(request.form.get("name", "").strip())
        upi = sanitize(request.form.get("upi", "").strip())
        phone = sanitize(request.form.get("phone", "").strip())

        if not name or not upi or not phone:
            return premium_page("Error", "<h2 class='error'>All fields required</h2>")

        if not re.match(upi_pattern, upi):
            return premium_page("Error", "<h2 class='error'>Invalid UPI ID</h2>")

        if not re.match(r"^[6-9]\d{9}$", phone):
            return premium_page("Error", "<h2 class='error'>Invalid phone number</h2>")

        if os.path.exists(CLAIMS_FILE):
            with open(CLAIMS_FILE, "r", encoding="utf-8") as f:
                if session["channel_id"] in f.read():
                    return premium_page("Error", "<h2 class='error'>Already submitted</h2>")

        with lock:
            with open(CLAIMS_FILE, "a", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow([
                    datetime.now().isoformat(),
                    session["channel_id"],
                    name,
                    upi,
                    phone
                ])

        log_step(session["channel_id"], "claim_submitted")  # ⭐ NEW

        return premium_page("Success", "<h2 class='success'>✅ Claim Submitted Successfully</h2>")

    log_step(session["channel_id"], "form_opened")  # ⭐ NEW

    return premium_page("Claim Prize", """
        <h1>🎁 Prize Claim Form</h1>
        <form method="post">
            <input name="name" placeholder="Full Name" required>
            <input name="upi" placeholder="UPI ID" required>
            <input name="phone" placeholder="Phone Number" required>
            <button type="submit">Submit Claim</button>
        </form>
    """)

# =========================
# 🏆 SET WINNER (ADMIN)
# =========================

@app.route("/set_winner", methods=["POST"])
def set_winner():
    if request.form.get("admin_key") != ADMIN_KEY:
        return "Unauthorized"

    handle = request.form.get("handle", "").replace("@", "")

    r = requests.get(
        f"https://www.googleapis.com/youtube/v3/channels?part=id&forHandle={handle}&key={YOUTUBE_API_KEY}"
    ).json()

    if not r.get("items"):
        return "Channel not found"

    winner_channel_id = r["items"][0]["id"]
    save_winner(winner_channel_id)

    return f"Winner set successfully: {winner_channel_id}"

# =========================
# 📊 VIEW PROGRESS (ADMIN)
# =========================

@app.route("/progress")
def view_progress():
    if request.args.get("key") != ADMIN_KEY:
        return "Unauthorized"

    if not os.path.exists(PROGRESS_FILE):
        return "No data"

    with open(PROGRESS_FILE, "r", encoding="utf-8") as f:
        data = f.read()

    return "<pre>" + data + "</pre>"

# =========================
# 🚪 LOGOUT
# =========================

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("home"))

# =========================
# 🚀 RUN
# =========================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7000))
    app.run(host="0.0.0.0", port=port)
