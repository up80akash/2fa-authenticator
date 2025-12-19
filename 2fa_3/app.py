from flask import Flask, render_template, request, redirect, session, url_for, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3, pyotp, secrets, time
from functools import wraps

DB_NAME = "DB_NAME.db"

app = Flask(__name__)
app.secret_key = "supersecretkey"

# -------------------- DATABASE INIT --------------------
def init_db():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        otp_secret TEXT,
        is_2fa_enabled INTEGER DEFAULT 0,
        is_admin INTEGER DEFAULT 0,
        reset_token TEXT,
        reset_expiry INTEGER
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER,
        action TEXT,
        target_user INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    conn.commit()
    conn.close()

# -------------------- HELPERS --------------------
def get_user_by_id(uid):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id=?", (uid,))
    user = c.fetchone()
    conn.close()
    return user

def get_user_by_username(username):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()
    return user

def log_action(admin_id, action, target_user):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute(
        "INSERT INTO audit_logs (admin_id, action, target_user) VALUES (?,?,?)",
        (admin_id, action, target_user)
    )
    conn.commit()
    conn.close()

# -------------------- DECORATORS --------------------
def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if "user_id" not in session:
            return redirect("/login")

        user = get_user_by_id(session["user_id"])
        if not user or user[5] != 1:
            flash("Admin access required")
            return redirect("/")

        return f(*args, **kwargs)
    return wrap

# -------------------- ROUTES --------------------
@app.route("/")
def index():
    user = get_user_by_id(session["user_id"]) if "user_id" in session else None
    return render_template("index.html", user=user)

# -------------------- REGISTER --------------------
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("SELECT COUNT(*) FROM users")
        count = c.fetchone()[0]

        username = "Admin" if count == 0 else request.form["username"]
        password = generate_password_hash(request.form["password"])
        otp_secret = pyotp.random_base32()
        is_admin = 1 if count == 0 else 0

        try:
            c.execute("""
                INSERT INTO users (username, password, otp_secret, is_admin)
                VALUES (?,?,?,?)
            """, (username, password, otp_secret, is_admin))
            conn.commit()
        except:
            conn.close()
            flash("Username already exists")
            return redirect("/register")

        c.execute("SELECT id FROM users WHERE username=?", (username,))
        session["setup_user_id"] = c.fetchone()[0]
        conn.close()

        flash("Registration successful")
        return redirect("/setup-2fa")

    return render_template("register.html")

# -------------------- LOGIN --------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = get_user_by_username(request.form["username"])
        if user and check_password_hash(user[2], request.form["password"]):
            session["user_id"] = user[0]
            if user[4] == 1:
                return redirect("/verify-2fa")
            return redirect("/")
        flash("Invalid credentials")
    return render_template("login.html")

# -------------------- 2FA SETUP --------------------
@app.route("/setup-2fa", methods=["GET", "POST"])
def setup_2fa():
    if "setup_user_id" not in session:
        return redirect("/register")

    user = get_user_by_id(session["setup_user_id"])

    if request.method == "POST":
        conn = sqlite3.connect(DB_NAME)
        c = conn.cursor()
        c.execute("UPDATE users SET is_2fa_enabled=1 WHERE id=?", (user[0],))
        conn.commit()
        conn.close()

        session.pop("setup_user_id")
        return redirect("/login")

    uri = pyotp.TOTP(user[3]).provisioning_uri(
        name=user[1],
        issuer_name="2FA-App"
    )
    return render_template("setup_2fa.html", otp_uri=uri)

# -------------------- VERIFY 2FA --------------------
@app.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    if "user_id" not in session:
        return redirect("/login")

    user = get_user_by_id(session["user_id"])

    if request.method == "POST":
        if pyotp.TOTP(user[3]).verify(request.form["token"]):
            return redirect("/")
        flash("Invalid OTP")

    return render_template("verify_2fa.html")

# -------------------- LOGOUT --------------------
@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

# -------------------- ADMIN PANEL --------------------
@app.route("/admin")
@admin_required
def admin():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, username, is_admin FROM users")
    users = c.fetchall()
    conn.close()
    return render_template("admin.html", users=users)

# -------------------- ROLE MANAGEMENT --------------------
@app.route("/make-admin/<int:uid>", methods=["POST"])
@admin_required
def make_admin(uid):
    current_user = get_user_by_id(session["user_id"])

    # Nobody can change main admin
    if uid == 1:
        flash("Main Admin cannot be changed")
        return redirect("/admin")

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE users SET is_admin=1 WHERE id=?", (uid,))
    conn.commit()
    conn.close()

    log_action(current_user[0], "MAKE_ADMIN", uid)
    return redirect("/admin")


@app.route("/make-normal/<int:uid>", methods=["POST"])
@admin_required
def make_normal(uid):
    current_user = get_user_by_id(session["user_id"])

    # Cannot demote main admin
    if uid == 1:
        flash("Main Admin cannot be demoted")
        return redirect("/admin")

    # Promoted admin cannot demote itself
    if current_user[0] == uid:
        flash("You cannot demote yourself")
        return redirect("/admin")

    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("UPDATE users SET is_admin=0 WHERE id=?", (uid,))
    conn.commit()
    conn.close()

    log_action(current_user[0], "MAKE_NORMAL", uid)
    return redirect("/admin")

# -------------------- AUDIT LOGS --------------------
@app.route("/admin/logs")
@admin_required
def admin_logs():
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("""
        SELECT a.timestamp, u.username, a.action, a.target_user
        FROM audit_logs a
        JOIN users u ON a.admin_id = u.id
        ORDER BY a.timestamp DESC
    """)
    logs = c.fetchall()
    conn.close()
    return render_template("admin_logs.html", logs=logs)

# -------------------- PASSWORD RESET --------------------
@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        user = get_user_by_username(request.form["username"])
        if user:
            token = secrets.token_urlsafe(32)
            expiry = int(time.time()) + 900

            conn = sqlite3.connect(DB_NAME)
            c = conn.cursor()
            c.execute("""
                UPDATE users SET reset_token=?, reset_expiry=? WHERE id=?
            """, (token, expiry, user[0]))
            conn.commit()
            conn.close()

            print("RESET LINK:", url_for("reset_password", token=token, _external=True))

        flash("If user exists, reset link generated (check console)")
    return render_template("forgot_password.html")


@app.route("/reset/<token>", methods=["GET", "POST"])
def reset_password(token):
    conn = sqlite3.connect(DB_NAME)
    c = conn.cursor()
    c.execute("SELECT id, reset_expiry FROM users WHERE reset_token=?", (token,))
    user = c.fetchone()

    if not user or user[1] < int(time.time()):
        conn.close()
        return "Invalid or expired token"

    if request.method == "POST":
        new_pass = generate_password_hash(request.form["password"])
        c.execute("""
            UPDATE users
            SET password=?, reset_token=NULL, reset_expiry=NULL
            WHERE id=?
        """, (new_pass, user[0]))
        conn.commit()
        conn.close()
        return redirect("/login")

    conn.close()
    return render_template("reset_password.html")

# -------------------- RUN --------------------
if __name__ == "__main__":
    init_db()
    app.run(debug=True)

