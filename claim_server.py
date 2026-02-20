from flask import Flask, redirect, url_for, session, request
from authlib.integrations.flask_client import OAuth
import requests
import csv
from datetime import datetime
import os

# ✅ IMPORTANT — Render HTTPS fix
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)

# =========================
# 🔐 REQUIRED ENV VARIABLES
# =========================

SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
YOUTUBE_API_KEY = os.environ.get("YOUTUBE_API_KEY")
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET")
ADMIN_KEY = os.environ.get("ADMIN_KEY")

if not SECRET_KEY:
    raise RuntimeError("FLASK_SECRET_KEY missing")

app.secret_key = SECRET_KEY

# ✅ Render proxy fix (VERY IMPORTANT)
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)

# =========================
# 🔐 SESSION SECURITY
# =========================

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

# =========================
# 💾 WINNER STORAGE
# =========================

def load_winner():
    if os.path.exists("winner.txt"):
        with open("winner.txt", "r", encoding="utf-8") as f:
            return f.read().strip()
    return None

def save_winner(cid):
    with open("winner.txt", "w", encoding="utf-8") as f:
        f.write(cid)

winner_channel_id = load_winner()

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
    return "<h1>Prize Claim Portal</h1><a href='/login'>Login with Google</a>"

# =========================
# 🔑 LOGIN
# =========================

@app.route("/login")
def login():
    # ✅ Force HTTPS redirect (IMPORTANT)
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
        return f"Login Failed: {e}"

    yt = requests.get(
        "https://www.googleapis.com/youtube/v3/channels?part=id&mine=true",
        headers={"Authorization": "Bearer " + token["access_token"]}
    ).json()

    if not yt.get("items"):
        return "No YouTube channel found"

    session["channel_id"] = yt["items"][0]["id"]
    return redirect("/verify")

# =========================
# ✅ VERIFY WINNER
# =========================

@app.route("/verify")
def verify():
    if "channel_id" not in session:
        return redirect("/")

    if not winner_channel_id:
        return "Winner not set yet"

    if session["channel_id"] == winner_channel_id:
        return redirect("/claim")
    else:
        return "<h2>Access Denied — Not Winner</h2>"

# =========================
# 📝 CLAIM FORM
# =========================

def sanitize(value):
    if value.startswith(("=", "+", "-", "@")):
        return "'" + value
    return value

@app.route("/claim", methods=["GET", "POST"])
def claim():
    if "channel_id" not in session:
        return redirect("/")

    if request.method == "POST":

        name = sanitize(request.form.get("name", "").strip())
        upi = sanitize(request.form.get("upi", "").strip())
        phone = sanitize(request.form.get("phone", "").strip())

        if not name or not upi or not phone:
            return "All fields required"

        with open("claims.csv", "a", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                datetime.now().isoformat(),
                session["channel_id"],
                name,
                upi,
                phone
            ])

        return "<h2>Claim Submitted Successfully ✅</h2>"

    return """
    <h2>Prize Claim Form</h2>
    <form method='post'>
        Name:<br><input name='name' required><br><br>
        UPI ID:<br><input name='upi' required><br><br>
        Phone:<br><input name='phone' required><br><br>
        <button type='submit'>Submit</button>
    </form>
    """

# =========================
# 🏆 SET WINNER (ADMIN)
# =========================

@app.route("/set_winner", methods=["POST"])
def set_winner():

    if request.form.get("admin_key") != ADMIN_KEY:
        return "Unauthorized"

    if not YOUTUBE_API_KEY:
        return "API key missing"

    handle = request.form.get("handle")

    if not handle:
        return "Handle required"

    r = requests.get(
        f"https://www.googleapis.com/youtube/v3/channels?part=id&forHandle={handle}&key={YOUTUBE_API_KEY}"
    ).json()

    if not r.get("items"):
        return "Channel not found"

    global winner_channel_id
    winner_channel_id = r["items"][0]["id"]
    save_winner(winner_channel_id)

    return f"Winner set successfully: {winner_channel_id}"

# =========================
# 🚀 RUN (Render Compatible)
# =========================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 7000))
    app.run(host="0.0.0.0", port=port)
