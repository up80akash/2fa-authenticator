from flask import Flask, render_template, request, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import pyotp
import qrcode
import os

# -------------------------------
# App Configuration
# -------------------------------
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
DB_NAME = os.path.join(BASE_DIR, "database.db")

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.secret_key = "change-this-secret-key"

# -------------------------------
# Safe SQLite Connection
# -------------------------------
def get_db():
    return sqlite3.connect(DB_NAME, timeout=10, check_same_thread=False)

# -------------------------------
# Database Initialization
# -------------------------------
def init_db():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            otp_secret TEXT,
            is_2fa_enabled INTEGER DEFAULT 0
        )
        """)
        conn.commit()

init_db()

# -------------------------------
# Home
# -------------------------------
@app.route("/")
def home():
    if "user_id" in session:
        return redirect("/dashboard")
    return redirect("/login")

# -------------------------------
# Register (Step 1)
# -------------------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username or not password:
            return "Username and password required"

        password_hash = generate_password_hash(password)

        try:
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, password_hash)
                )
                user_id = cursor.lastrowid

            # Temporary session ONLY for 2FA setup
            session.clear()
            session["setup_user_id"] = user_id
            return redirect("/setup-2fa")

        except sqlite3.IntegrityError:
            return "Username already exists"

    return render_template("register.html")

# -------------------------------
# Setup 2FA (Step 2 - Mandatory)
# -------------------------------
@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    if "setup_user_id" not in session:
        return redirect("/register")

    user_id = session["setup_user_id"]

    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT otp_secret, is_2fa_enabled FROM users WHERE id=?",
            (user_id,)
        )
        row = cursor.fetchone()

        if not row:
            return "Invalid session. Please register again."

        otp_secret, is_2fa_enabled = row

        if is_2fa_enabled == 1:
            session.pop("setup_user_id")
            return redirect("/login")

        if not otp_secret:
            otp_secret = pyotp.random_base32()
            cursor.execute(
                "UPDATE users SET otp_secret=? WHERE id=?",
                (otp_secret, user_id)
            )
            conn.commit()

    totp = pyotp.TOTP(otp_secret)
    uri = totp.provisioning_uri(
        name=f"user{user_id}",
        issuer_name="Secure2FA App"
    )

    if not os.path.exists(STATIC_DIR):
        os.mkdir(STATIC_DIR)

    qrcode.make(uri).save(os.path.join(STATIC_DIR, "qrcode.png"))

    if request.method == "POST":
        otp = request.form.get("otp")
        if otp and totp.verify(otp):
            with get_db() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "UPDATE users SET is_2fa_enabled=1 WHERE id=?",
                    (user_id,)
                )
                conn.commit()

            session.pop("setup_user_id")
            return redirect("/login")

        return "Invalid OTP"

    return render_template("setup_2fa.html")

# -------------------------------
# Login (Step 3)
# -------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, password_hash, is_2fa_enabled FROM users WHERE username=?",
                (username,)
            )
            user = cursor.fetchone()

        if not user or not check_password_hash(user[1], password):
            return "Invalid username or password"

        if user[2] == 0:
            return "Please complete 2FA setup before login"

        session.clear()
        session["temp_user_id"] = user[0]
        return redirect("/verify-otp")

    return render_template("login.html")

# -------------------------------
# Verify OTP (Step 4)
# -------------------------------
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if "temp_user_id" not in session:
        return redirect("/login")

    user_id = session["temp_user_id"]

    if request.method == "POST":
        otp = request.form.get("otp")

        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT otp_secret FROM users WHERE id=?",
                (user_id,)
            )
            row = cursor.fetchone()

        if not row:
            return "Invalid session"

        totp = pyotp.TOTP(row[0])

        if totp.verify(otp):
            session.clear()
            session["user_id"] = user_id
            return redirect("/dashboard")

        return "Invalid OTP"

    return render_template("verify_otp.html")

# -------------------------------
# Dashboard (Protected)
# -------------------------------
@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect("/login")
    return render_template("dashboard.html")

# -------------------------------
# Logout
# -------------------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login")

# -------------------------------
# Run Server
# -------------------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True, use_reloader=False)

