from flask import Flask, request, jsonify, render_template, redirect, url_for, session
from datetime import datetime, timedelta
from functools import wraps
import secrets
import string
import hashlib
import os
import json

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-production-please")

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD_HASH = hashlib.sha256(
    os.environ.get("ADMIN_PASSWORD", "changeme123").encode()
).hexdigest()

KEYS_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "keys.json")


def load_keys():
    if os.path.exists(KEYS_FILE):
        try:
            with open(KEYS_FILE, "r") as f:
                return json.load(f)
        except Exception:
            pass
    return []


def save_keys(keys):
    with open(KEYS_FILE, "w") as f:
        json.dump(keys, f, indent=2)


def get_real_ip():
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def generate_key(prefix="RBX"):
    chars = string.ascii_uppercase + string.digits
    random_part = "".join(secrets.choice(chars) for _ in range(20))
    chunks = [random_part[i:i+5] for i in range(0, 20, 5)]
    return f"{prefix}-" + "-".join(chunks)


def key_status(k):
    if k.get("is_revoked"):
        return "revoked"
    if datetime.utcnow() > datetime.fromisoformat(k["expires_at"]):
        return "expired"
    return "active"


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated


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
    keys = load_keys()
    for k in keys:
        k["_status"] = key_status(k)
    active  = [k for k in keys if k["_status"] == "active"]
    expired = [k for k in keys if k["_status"] == "expired"]
    revoked = [k for k in keys if k["_status"] == "revoked"]
    return render_template("dashboard.html", active=active, expired=expired, revoked=revoked)


@app.route("/create-key", methods=["POST"])
@login_required
def create_key():
    label    = request.form.get("label", "")
    days     = int(request.form.get("days", 30))
    quantity = min(int(request.form.get("quantity", 1)), 50)
    keys     = load_keys()

    for _ in range(quantity):
        keys.append({
            "id":         secrets.token_hex(8),
            "key":        generate_key(),
            "label":      label,
            "created_at": datetime.utcnow().isoformat(),
            "expires_at": (datetime.utcnow() + timedelta(days=days)).isoformat(),
            "locked_ip":  None,
            "is_revoked": False,
            "last_used":  None,
        })

    save_keys(keys)
    return redirect(url_for("dashboard"))


@app.route("/revoke-key/<key_id>", methods=["POST"])
@login_required
def revoke_key(key_id):
    keys = load_keys()
    for k in keys:
        if k["id"] == key_id:
            k["is_revoked"] = True
            break
    save_keys(keys)
    return redirect(url_for("dashboard"))


@app.route("/delete-key/<key_id>", methods=["POST"])
@login_required
def delete_key(key_id):
    keys = load_keys()
    keys = [k for k in keys if k["id"] != key_id]
    save_keys(keys)
    return redirect(url_for("dashboard"))


@app.route("/unlock-ip/<key_id>", methods=["POST"])
@login_required
def unlock_ip(key_id):
    keys = load_keys()
    for k in keys:
        if k["id"] == key_id:
            k["locked_ip"] = None
            break
    save_keys(keys)
    return redirect(url_for("dashboard"))


@app.route("/api/verify", methods=["POST"])
def api_verify():
    data      = request.get_json(silent=True) or {}
    key_str   = data.get("key", "").strip()
    client_ip = get_real_ip()

    if not key_str:
        return jsonify({"valid": False, "reason": "No key provided."}), 400

    keys = load_keys()
    k    = next((x for x in keys if x["key"] == key_str), None)

    if not k:
        return jsonify({"valid": False, "reason": "Invalid key."}), 403

    if k.get("is_revoked"):
        return jsonify({"valid": False, "reason": "This key has been revoked."}), 403

    expires_at = datetime.fromisoformat(k["expires_at"])
    if datetime.utcnow() > expires_at:
        return jsonify({"valid": False, "reason": f"Key expired on {expires_at.strftime('%Y-%m-%d')}."}), 403

    if k["locked_ip"] is None:
        k["locked_ip"] = client_ip
    elif k["locked_ip"] != client_ip:
        return jsonify({"valid": False, "reason": "Key is locked to a different IP address. Contact support if you changed networks."}), 403

    k["last_used"] = datetime.utcnow().isoformat()
    save_keys(keys)

    days_left = (expires_at - datetime.utcnow()).days
    return jsonify({
        "valid":          True,
        "label":          k.get("label", ""),
        "expires_at":     expires_at.strftime("%Y-%m-%d"),
        "days_remaining": days_left,
    }), 200


if __name__ == "__main__":
    app.run(debug=False)
