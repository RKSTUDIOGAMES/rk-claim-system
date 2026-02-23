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
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{
                margin: 0;
                font-family: Arial, sans-serif;
                background: #f4f4f4;
                color: #222;
            }}

            .container {{
                max-width: 480px;
                margin: 60px auto;
                background: #fff;
                padding: 24px;
                border-radius: 8px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.08);
            }}

            h1, h2, h3 {{
                margin-top: 0;
            }}

            p {{
                line-height: 1.5;
            }}

            ul {{
                padding-left: 18px;
            }}

            input {{
                width: 100%;
                padding: 10px;
                margin-top: 8px;
                border: 1px solid #ccc;
                border-radius: 6px;
                font-size: 14px;
            }}

            button {{
                width: 100%;
                padding: 12px;
                margin-top: 14px;
                border: none;
                border-radius: 6px;
                background: #1976d2;
                color: white;
                font-size: 15px;
                cursor: pointer;
            }}

            button:hover {{
                background: #155fa0;
            }}

            a {{
                color: #1976d2;
                text-decoration: none;
            }}

            hr {{
                margin: 20px 0;
            }}
        </style>
    </head>

    <body>
        <div class="container">
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
        "<h1>RK Studio Claims</h1>"

        "<p><strong>Official web application operated by RK Studio (India).</strong></p>"

        "<p>This page is publicly accessible and does not require login.</p>"

        "<h3>About This Application</h3>"
        "<p>This application is used by participants of RK Studio giveaways "
        "to verify ownership of their YouTube channel before receiving prizes.</p>"

        "<p>The app securely retrieves the user's YouTube Channel ID via Google Sign-In "
"and confirms eligibility for prize claims.</p>"

"<p><strong>Google user data is used solely for channel ownership verification "
"and not for any other purpose.</strong></p>"

        "<h3>Application Identity</h3>"
        "<ul>"
        "<li>Application Name: RK Studio Claims</li>"
        "<li>Operator: RK Studio</li>"
        "<li>Website: https://rkclaims.in</li>"
        "<li>Country: India</li>"
        "<li>Contact Email: rajjain2218@gmail.com</li>"
        "</ul>"

        "<h3>Data Usage</h3>"
        "<ul>"
        "<li>Google basic profile information</li>"
        "<li>YouTube Channel ID</li>"
        "<li>Claim details for prize delivery</li>"
        "</ul>"

        "<p>This application is independent and not affiliated with Google or YouTube.</p>"

        "<a href='/login'><button>Continue with Google Sign-In</button></a>"

        "<hr>"

        "<p><a href='/privacy'>Privacy Policy</a> | "
        "<a href='/terms'>Terms of Service</a></p>"
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
    return google.authorize_redirect(
        redirect_uri,
        include_granted_scopes="true"
    )

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
# ✅ VERIFY (UPDATED UI ADDED)
# =========================

@app.route("/verify")
def verify():
    if "channel_id" not in session:
        return redirect("/")

    winner_channel_id = load_winner()

    if not winner_channel_id:
        return premium_page("Pending",
            "<h2>⏳ Winner not announced yet</h2>"
        )

    # ✅ WINNER MATCH
    if session["channel_id"] == winner_channel_id:
        return premium_page("Verified",
            "<h2>✅ Verification Successful</h2>"
            "<p><strong>Channel ID matched with winner record.</strong></p>"
            "<p>Access granted. You may now proceed to claim your prize.</p>"
            "<a href='/claim'><button>Continue to Claim</button></a>"
        )

    # ❌ NOT WINNER
    else:
        return premium_page("Access Denied",
            "<h2>❌ Verification Failed</h2>"
            "<p><strong>Channel ID did not match the winner record.</strong></p>"
            "<p>Access denied. Only the verified winner can claim the prize.</p>"
        )

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
# 🚪 PRIVACY POLICY
# =========================
@app.route("/privacy")
def privacy():
    return premium_page("Privacy Policy",
        "<h1>Privacy Policy</h1>"

        "<p>RK Studio operates this web application to verify the ownership "
        "of YouTube channels for giveaway prize distribution purposes only.</p>"

        "<p>This application is independent and is not affiliated with, endorsed by, "
        "or sponsored by Google LLC or YouTube.</p>"

        "<h3>Information We Collect</h3>"
        "<p>When you use this application, we may collect the following information:</p>"
        "<ul>"
        "<li>Your Google basic profile information (name and email)</li>"
        "<li>Your YouTube Channel ID obtained via Google Sign-In</li>"
        "<li>Name submitted during prize claim</li>"
        "<li>UPI ID for payment delivery</li>"
        "<li>Phone number for verification purposes</li>"
        "</ul>"

        "<h3>How We Use Information</h3>"
        "<ul>"
        "<li>To verify ownership of the YouTube channel</li>"
        "<li>To confirm eligibility for giveaways</li>"
        "<li>To deliver prizes to verified winners</li>"
        "<li>To prevent fraud, impersonation, or duplicate claims</li>"
        "<li>To maintain records required for dispute resolution</li>"
        "</ul>"

        "<h3>Use of Google User Data</h3>"
        "<p>This application accesses Google user data only to retrieve the "
        "YouTube Channel ID associated with your account.</p>"
        "<p>We do not access, read, or store your YouTube content, videos, "
        "subscribers, or private data.</p>"

        "<h3>YouTube API Services</h3>"
        "<p>This application uses YouTube API Services. By using this application, "
        "you agree to be bound by the "
        "<a href='https://www.youtube.com/t/terms'>YouTube Terms of Service</a>.</p>"

        "<h3>Data Sharing</h3>"
        "<p>We do not sell, rent, or trade your personal data to any third parties.</p>"
        "<p>Your information may be shared only when required by law or for "
        "fraud prevention.</p>"

        "<h3>Data Retention</h3>"
        "<p>Personal information is retained only as long as necessary to "
        "complete prize distribution and resolve disputes.</p>"

        "<h3>Data Security</h3>"
        "<p>We implement reasonable administrative and technical measures to "
        "protect your information from unauthorized access, disclosure, or misuse.</p>"

        "<h3>User Rights</h3>"
        "<p>You may request access to or deletion of your personal data at any time.</p>"

        "<h3>Data Deletion Requests</h3>"
        "<p>To request deletion of your data, contact us at the email below. "
        "We will process valid requests within a reasonable timeframe.</p>"

        "<h3>Children's Privacy</h3>"
        "<p>This application is not intended for use by children under 13 years of age.</p>"

        "<h3>Changes to This Policy</h3>"
        "<p>We may update this Privacy Policy from time to time. "
        "Updated versions will be posted on this page.</p>"

        "<h3>Contact Information</h3>"
        "<p>Email: rajjain2218@gmail.com</p>"
        "<p>Operator: RK Studio, India</p>"
                        "<p><a href='/'>Home</a> | "
        "<a href='/terms'>Terms of Service</a></p>"
    )
# =========================
# 🚪 TERMS OF SERVICE
# =========================
@app.route("/terms")
def terms():
    return premium_page("Terms of Service",
        "<h1>Terms of Service</h1>"

        "<p>These Terms govern your use of the RK Studio Claims application.</p>"

        "<h3>Purpose of the Application</h3>"
        "<p>This tool is designed solely to verify the ownership of a YouTube "
        "channel for giveaway prize claims conducted by RK Studio.</p>"

        "<h3>Eligibility</h3>"
        "<p>You must be the legitimate owner of the YouTube channel used to log in.</p>"

        "<h3>User Responsibilities</h3>"
        "<ul>"
        "<li>You agree to provide accurate information during the claim process</li>"
        "<li>You must not impersonate another person or channel</li>"
        "<li>You must not attempt to bypass verification mechanisms</li>"
        "</ul>"

        "<h3>Prize Claims</h3>"
        "<p>Submission of a claim does not guarantee prize delivery unless "
        "verified as the official winner.</p>"

        "<h3>Fraud Prevention</h3>"
        "<p>RK Studio reserves the right to reject claims suspected of fraud "
        "or policy violations.</p>"

        "<h3>Limitation of Liability</h3>"
        "<p>RK Studio shall not be liable for any indirect or consequential "
        "loss arising from the use of this application.</p>"

        "<h3>Termination</h3>"
        "<p>Access may be restricted or terminated for misuse or violation of terms.</p>"

        "<h3>Governing Law</h3>"
        "<p>These Terms shall be governed by the laws of India.</p>"

        "<h3>Contact</h3>"
        "<p>Email: rajjain2218@gmail.com</p>"
                        "<p><a href='/privacy'>Privacy Policy</a> | "
        "<a href='/'>Home</a></p>"
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
