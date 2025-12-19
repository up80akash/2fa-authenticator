from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import pyotp
from functools import wraps

DB_NAME = "DB_NAME.db"

app = Flask(__name__)
app.secret_key = "supersecretkey"

# ----------------- Helper functions -----------------
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT is_admin FROM users WHERE id=?", (session["user_id"],))
        user = cursor.fetchone()
        conn.close()
        if not user or user[0] != 1:
            flash("Access denied: Admins only")
            return redirect("/")
        return f(*args, **kwargs)
    return decorated_function

def get_user_by_username(username):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username=?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def get_user_by_id(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()
    conn.close()
    return user

# ----------------- Routes -----------------
@app.route("/")
def index():
    if "user_id" in session:
        user = get_user_by_id(session["user_id"])
        return render_template("index.html", user=user)
    return render_template("index.html", user=None)

# ----------------- Register -----------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = generate_password_hash(request.form["password"])
        otp_secret = pyotp.random_base32()

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        # First user is Admin with username "Admin"
        cursor.execute("SELECT COUNT(*) FROM users")
        user_count = cursor.fetchone()[0]
        is_admin = 1 if user_count == 0 else 0
        if user_count == 0:
            username = "Admin"  # Force first user to Admin

        try:
            cursor.execute(
                "INSERT INTO users (username, password, otp_secret, is_admin) VALUES (?, ?, ?, ?)",
                (username, password, otp_secret, is_admin)
            )
            conn.commit()
        except sqlite3.IntegrityError:
            conn.close()
            flash("Username already exists")
            return redirect("/register")

        cursor.execute("SELECT id FROM users WHERE username=?", (username,))
        session["setup_user_id"] = cursor.fetchone()[0]
        conn.close()
        flash(f"User registered successfully! { 'You are admin.' if is_admin else '' }")
        return redirect("/setup-2fa")

    return render_template("register.html")

# ----------------- Login -----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = get_user_by_username(username)
        if user and check_password_hash(user[2], password):
            session["user_id"] = user[0]
            if user[4] == 1:  # is_2fa_enabled
                return redirect("/verify-2fa")
            flash("Logged in successfully!")
            return redirect("/")
        flash("Invalid username or password")
        return redirect("/login")
    return render_template("login.html")

# ----------------- Setup 2FA -----------------
@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    if "setup_user_id" not in session:
        flash("No user to setup 2FA for")
        return redirect("/register")

    user_id = session["setup_user_id"]
    user = get_user_by_id(user_id)

    if request.method == "POST":
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET is_2fa_enabled=1 WHERE id=?", (user_id,))
        conn.commit()
        conn.close()
        session.pop("setup_user_id")
        flash("2FA enabled successfully! Please login")
        return redirect("/login")

    otp_uri = pyotp.totp.TOTP(user[3]).provisioning_uri(name=user[1], issuer_name="2FA-App")
    return render_template("setup_2fa.html", otp_uri=otp_uri)

# ----------------- Verify 2FA -----------------
@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if "user_id" not in session:
        flash("Login required")
        return redirect("/login")

    user = get_user_by_id(session["user_id"])
    if request.method == "POST":
        token = request.form["token"]
        totp = pyotp.TOTP(user[3])
        if totp.verify(token):
            flash("2FA verified! You are logged in")
            return redirect("/")
        flash("Invalid OTP. Try again")
        return redirect("/verify-2fa")

    return render_template("verify_2fa.html")

# ----------------- Logout -----------------
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully")
    return redirect("/")

# ----------------- Admin Panel -----------------
@app.route("/admin")
@admin_required
def admin_panel():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, username, is_admin FROM users")
    users = cursor.fetchall()
    conn.close()
    return render_template("admin.html", users=users)

@app.route("/promote/<int:user_id>", methods=["POST"])
@admin_required
def promote_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash("User not found")
        conn.close()
        return redirect("/admin")
    cursor.execute("UPDATE users SET is_admin=1 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    flash("User promoted to admin successfully")
    return redirect("/admin")

@app.route("/demote/<int:user_id>", methods=["POST"])
@admin_required
def demote_user(user_id):
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE id=?", (user_id,))
    user = cursor.fetchone()
    if not user:
        flash("User not found")
        conn.close()
        return redirect("/admin")
    # Prevent demoting the main Admin
    if user_id == 1:
        flash("Cannot demote main Admin")
        conn.close()
        return redirect("/admin")
    cursor.execute("UPDATE users SET is_admin=0 WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    flash("User demoted to normal user successfully")
    return redirect("/admin")

# ----------------- Initialize DB -----------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            otp_secret TEXT NOT NULL,
            is_2fa_enabled INTEGER DEFAULT 0,
            is_admin INTEGER DEFAULT 0
        )
    ''')
    conn.commit()
    conn.close()

# ----------------- Run App -----------------
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=True)

