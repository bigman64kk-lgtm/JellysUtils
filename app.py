from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from functools import wraps
import secrets
import string
import hashlib
import os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-production-please")

database_url = os.environ.get("DATABASE_URL", "")
if database_url.startswith("postgres://"):
    database_url = database_url.replace("postgres://", "postgresql://", 1)

app.config["SQLALCHEMY_DATABASE_URI"] = database_url
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = hashlib.sha256(
    os.environ.get("ADMIN_PASSWORD", "changeme123").encode()
).hexdigest()


class LicenseKey(db.Model):
    id         = db.Column(db.Integer, primary_key=True)
    key        = db.Column(db.String(64), unique=True, nullable=False)
    label      = db.Column(db.String(128), default="")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    locked_ip  = db.Column(db.String(64), nullable=True)
    is_revoked = db.Column(db.Boolean, default=False)
    last_used  = db.Column(db.DateTime, nullable=True)

    @property
    def is_expired(self):
        return datetime.utcnow() > self.expires_at

    @property
    def status(self):
        if self.is_revoked:
            return "revoked"
        if self.is_expired:
            return "expired"
        return "active"


def generate_key(prefix="RBX"):
    chars = string.ascii_uppercase + string.digits
    random_part = "".join(secrets.choice(chars) for _ in range(20))
    chunks = [random_part[i:i+5] for i in range(0, 20, 5)]
    return f"{prefix}-" + "-".join(chunks)


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


def get_real_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


@app.route("/")
def index():
    if session.get("logged_in"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        pw_hash = hashlib.sha256(password.encode()).hexdigest()
        if username == ADMIN_USERNAME and pw_hash == ADMIN_PASSWORD_HASH:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    keys    = LicenseKey.query.order_by(LicenseKey.created_at.desc()).all()
    active  = [k for k in keys if k.status == "active"]
    expired = [k for k in keys if k.status == "expired"]
    revoked = [k for k in keys if k.status == "revoked"]
    return render_template("dashboard.html", active=active, expired=expired, revoked=revoked)


@app.route("/create-key", methods=["POST"])
@login_required
def create_key():
    label    = request.form.get("label", "")
    days     = int(request.form.get("days", 30))
    quantity = min(int(request.form.get("quantity", 1)), 50)
    for _ in range(quantity):
        db.session.add(LicenseKey(
            key=generate_key(),
            label=label,
            expires_at=datetime.utcnow() + timedelta(days=days),
        ))
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/revoke-key/<int:key_id>", methods=["POST"])
@login_required
def revoke_key(key_id):
    k = LicenseKey.query.get_or_404(key_id)
    k.is_revoked = True
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/delete-key/<int:key_id>", methods=["POST"])
@login_required
def delete_key(key_id):
    k = LicenseKey.query.get_or_404(key_id)
    db.session.delete(k)
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/unlock-ip/<int:key_id>", methods=["POST"])
@login_required
def unlock_ip(key_id):
    k = LicenseKey.query.get_or_404(key_id)
    k.locked_ip = None
    db.session.commit()
    return redirect(url_for("dashboard"))


@app.route("/api/verify", methods=["POST"])
def api_verify():
    data      = request.get_json(silent=True) or {}
    key_str   = data.get("key", "").strip()
    client_ip = get_real_ip()

    if not key_str:
        return jsonify({"valid": False, "reason": "No key provided."}), 400

    k = LicenseKey.query.filter_by(key=key_str).first()

    if not k:
        return jsonify({"valid": False, "reason": "Invalid key."}), 403
    if k.is_revoked:
        return jsonify({"valid": False, "reason": "This key has been revoked."}), 403
    if k.is_expired:
        return jsonify({"valid": False, "reason": f"Key expired on {k.expires_at.strftime('%Y-%m-%d')}."}), 403

    if k.locked_ip is None:
        k.locked_ip = client_ip
    elif k.locked_ip != client_ip:
        return jsonify({"valid": False, "reason": "Key is locked to a different IP address. Contact support if you changed networks."}), 403

    k.last_used = datetime.utcnow()
    db.session.commit()

    days_left = (k.expires_at - datetime.utcnow()).days
    return jsonify({
        "valid":          True,
        "label":          k.label,
        "expires_at":     k.expires_at.strftime("%Y-%m-%d"),
        "days_remaining": days_left,
    }), 200


with app.app_context():
    db.create_all()

if __name__ == "__main__":
    app.run(debug=False)
