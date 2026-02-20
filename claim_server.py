from flask import Flask, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
from werkzeug.middleware.proxy_fix import ProxyFix
import requests, csv, os, re, threading, time
from datetime import datetime, timedelta

app = Flask(__name__)

# =========================
# 🔐 ENV VARIABLES
# =========================

SECRET_KEY = os.environ["FLASK_SECRET_KEY"]
GOOGLE_CLIENT_ID = os.environ["GOOGLE_CLIENT_ID"]
GOOGLE_CLIENT_SECRET = os.environ["GOOGLE_CLIENT_SECRET"]
YOUTUBE_API_KEY = os.environ["YOUTUBE_API_KEY"]
ADMIN_KEY = os.environ["ADMIN_KEY"]

app.secret_key = SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# Secure cookies
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=1)
)

# =========================
# 🛡 SECURITY HEADERS
# =========================

@app.after_request
def secure_headers(response):
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self' https://accounts.google.com"
    return response

# =========================
# 📁 STORAGE
# =========================

DATA = "data"
os.makedirs(DATA, exist_ok=True)

WINNER_FILE = f"{DATA}/winner.txt"
CLAIMS_FILE = f"{DATA}/claims.csv"
PROGRESS_FILE = f"{DATA}/progress.csv"
LOCK_FILE = f"{DATA}/claim.lock"

lock = threading.Lock()

# =========================
# 🚦 RATE LIMIT
# =========================

rate_limit = {}

def limited(ip, limit=30, window=60):
    now = time.time()
    logs = rate_limit.get(ip, [])
    logs = [t for t in logs if now - t < window]
    logs.append(now)
    rate_limit[ip] = logs
    return len(logs) > limit

# =========================
# 💾 WINNER
# =========================

def get_winner():
    if os.path.exists(WINNER_FILE):
        return open(WINNER_FILE).read().strip()
    return None

def set_winner(cid):
    with lock:
        with open(WINNER_FILE, "w") as f:
            f.write(cid)

# =========================
# 🧾 LOG
# =========================

def log(channel, step):
    with lock:
        with open(PROGRESS_FILE, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([
                datetime.now().isoformat(),
                channel,
                step,
                request.remote_addr,
                request.headers.get("User-Agent")
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
# 🏠 HOME
# =========================

@app.route("/")
def home():
    return """
    <h1>🏆 Prize Claim Portal</h1>
    <a href='/login'><button>Continue with Google</button></a>
    """

# =========================
# 🔑 LOGIN
# =========================

@app.route("/login")
def login():
    return google.authorize_redirect(
        url_for("auth", _external=True, _scheme="https")
    )

# =========================
# 🔐 AUTH CALLBACK
# =========================

@app.route("/auth")
def auth():

    ip = request.remote_addr
    if limited(ip):
        return "Too many requests"

    token = google.authorize_access_token()
    access_token = token.get("access_token")

    yt = requests.get(
        "https://www.googleapis.com/youtube/v3/channels?part=id&mine=true",
        headers={"Authorization": "Bearer " + access_token}
    ).json()

    if not yt.get("items"):
        return "YouTube access failed"

    cid = yt["items"][0]["id"]
    session["channel_id"] = cid
    log(cid, "login")

    return redirect("/verify")

# =========================
# ✅ VERIFY
# =========================

@app.route("/verify")
def verify():

    cid = session.get("channel_id")
    if not cid:
        return redirect("/")

    winner = get_winner()

    if not winner:
        return "Winner not announced"

    if cid != winner:
        return "❌ Not Winner"

    log(cid, "verified")
    return redirect("/claim")

# =========================
# 📝 CLAIM
# =========================

upi_regex = r"^[a-zA-Z0-9._-]{2,}@[a-zA-Z]{2,}$"

def clean(v):
    if v.lstrip().startswith(("=", "+", "-", "@")):
        return "'" + v
    return v

@app.route("/claim", methods=["GET", "POST"])
def claim():

    cid = session.get("channel_id")
    if not cid:
        return redirect("/")

    if os.path.exists(LOCK_FILE):
        return "Claim already completed"

    if request.method == "POST":

        name = clean(request.form["name"].strip())
        upi = clean(request.form["upi"].strip())
        phone = clean(request.form["phone"].strip())

        if not re.match(upi_regex, upi):
            return "Invalid UPI"

        if not re.match(r"^[6-9]\d{9}$", phone):
            return "Invalid phone"

        # duplicate check
        if os.path.exists(CLAIMS_FILE):
            for row in csv.reader(open(CLAIMS_FILE)):
                if row and row[1] == cid:
                    return "Already claimed"

        with lock:
            with open(CLAIMS_FILE, "a", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow([
                    datetime.now().isoformat(),
                    cid, name, upi, phone
                ])

            open(LOCK_FILE, "w").write("done")

        log(cid, "claimed")
        return "✅ Prize Claim Submitted"

    return """
    <h2>Claim Prize</h2>
    <form method='post'>
    <input name='name' placeholder='Full Name' required>
    <input name='upi' placeholder='UPI ID' required>
    <input name='phone' placeholder='Phone' required>
    <button>Submit</button>
    </form>
    """

# =========================
# 🏆 ADMIN SET WINNER
# =========================

@app.route("/set_winner", methods=["POST"])
def admin_set():

    if request.headers.get("X-ADMIN-KEY") != ADMIN_KEY:
        return "Unauthorized", 403

    handle = request.form["handle"].replace("@", "")

    r = requests.get(
        f"https://www.googleapis.com/youtube/v3/channels?part=id&forHandle={handle}&key={YOUTUBE_API_KEY}"
    ).json()

    if not r.get("items"):
        return "Channel not found"

    cid = r["items"][0]["id"]
    set_winner(cid)

    return f"Winner set: {cid}"

# =========================
# 📊 ADMIN CLAIM VIEW
# =========================

@app.route("/claims")
def claims():

    if request.args.get("key") != ADMIN_KEY:
        return "Unauthorized"

    if not os.path.exists(CLAIMS_FILE):
        return "No claims"

    return "<pre>" + open(CLAIMS_FILE).read() + "</pre>"

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
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 7000)))
