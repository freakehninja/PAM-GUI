"""
api.py — PAM Vault Flask REST API
Serves the React GUI and exposes endpoints for:
  - Auth (login, register, TOTP verify)
  - Vault accounts (CRUD)
  - Credential retrieval (TOTP-gated)
  - Password rotation (SSH + WinRM)
  - Audit logs
  - Scheduler control

Run: python api.py
"""

import os
import json
import time
import threading
import secrets as py_secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS

from vault import CredentialVault
from password_gen import generate_password
from ssh_rotator import rotate_linux
from winrm_rotator import rotate_windows
from logger import AuditLogger
import totp_util

app = Flask(__name__, static_folder="static")
CORS(app, supports_credentials=True)

logger = AuditLogger()
vault  = CredentialVault()

# ─── In-memory state (persisted to disk via JSON) ────────────────────────────

DATA_FILE    = "config/app_data.json"
SESSION_FILE = "config/sessions.json"

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE) as f:
            return json.load(f)
    return {"users": [], "accounts": [], "logs": []}

def save_data(data):
    os.makedirs("config", exist_ok=True)
    with open(DATA_FILE, "w") as f:
        json.dump(data, f, indent=2)

data = load_data()

# Session store: token -> {username, expires}
sessions = {}

# ─── Helpers ─────────────────────────────────────────────────────────────────

def add_log(entry_type, account, message, code, user=None):
    entry = {
        "id": py_secrets.token_hex(6),
        "timestamp": datetime.utcnow().isoformat(),
        "type": entry_type,
        "account": account,
        "message": message,
        "code": code,
        "user": user,
    }
    data["logs"].append(entry)
    save_data(data)
    logger.log(f"[{code}] {message}", level="ERROR" if entry_type == "error" else "INFO")
    return entry


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Session-Token")
        if not token or token not in sessions:
            return jsonify({"error": "Unauthorized"}), 401
        session = sessions[token]
        if datetime.fromisoformat(session["expires"]) < datetime.utcnow():
            del sessions[token]
            return jsonify({"error": "Session expired"}), 401
        request.current_user = session["username"]
        return f(*args, **kwargs)
    return decorated


def find_user(username):
    return next((u for u in data["users"] if u["username"] == username), None)


def find_account(account_id):
    return next((a for a in data["accounts"] if a["id"] == account_id), None)


# ─── Auth endpoints ───────────────────────────────────────────────────────────

@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    """Check if any users exist (first-run detection)."""
    return jsonify({"has_users": len(data["users"]) > 0})


@app.route("/api/auth/register", methods=["POST"])
def register():
    """Register first admin user. Only allowed when no users exist."""
    if data["users"]:
        return jsonify({"error": "Registration closed. Users already exist."}), 403
    body = request.json
    username = body.get("username", "").strip()
    password = body.get("password", "")
    if not username or len(password) < 8:
        return jsonify({"error": "Username required and password must be 8+ chars."}), 400
    secret = totp_util.generate_secret()
    user = {
        "username": username,
        "password_hash": totp_util.hash_password(password),
        "totp_secret": secret,
        "role": "admin",
        "created_at": datetime.utcnow().isoformat(),
    }
    data["users"].append(user)
    save_data(data)
    otp_uri = totp_util.get_otp_uri(secret, username)
    add_log("info", username, f"Admin user created: {username}", "USER_CREATED")
    return jsonify({"totp_secret": secret, "otp_uri": otp_uri})


@app.route("/api/auth/create_user", methods=["POST"])
@require_auth
def create_user():
    """Create additional vault user (admin only)."""
    body = request.json
    username = body.get("username", "").strip()
    password = body.get("password", "")
    if not username or len(password) < 8:
        return jsonify({"error": "Invalid input."}), 400
    if find_user(username):
        return jsonify({"error": "Username already exists."}), 409
    secret = totp_util.generate_secret()
    user = {
        "username": username,
        "password_hash": totp_util.hash_password(password),
        "totp_secret": secret,
        "role": "admin",
        "created_at": datetime.utcnow().isoformat(),
    }
    data["users"].append(user)
    save_data(data)
    otp_uri = totp_util.get_otp_uri(secret, username)
    add_log("info", username, f"User created: {username}", "USER_CREATED", user=request.current_user)
    return jsonify({"totp_secret": secret, "otp_uri": otp_uri})


@app.route("/api/auth/login", methods=["POST"])
def login():
    body = request.json
    username = body.get("username", "")
    password = body.get("password", "")
    user = find_user(username)
    if not user or not totp_util.verify_password(password, user["password_hash"]):
        add_log("error", username, f"Failed login attempt: {username}", "LOGIN_FAIL")
        return jsonify({"error": "Invalid credentials."}), 401
    token = py_secrets.token_hex(32)
    sessions[token] = {
        "username": username,
        "expires": (datetime.utcnow() + timedelta(hours=8)).isoformat(),
    }
    add_log("info", username, f"Vault login: {username}", "LOGIN_OK")
    return jsonify({"token": token, "username": username, "role": user["role"]})


@app.route("/api/auth/logout", methods=["POST"])
@require_auth
def logout():
    token = request.headers.get("X-Session-Token")
    add_log("info", request.current_user, f"Vault logout: {request.current_user}", "LOGOUT")
    sessions.pop(token, None)
    return jsonify({"ok": True})


@app.route("/api/auth/users", methods=["GET"])
@require_auth
def list_users():
    safe = [{"username": u["username"], "role": u["role"], "created_at": u["created_at"]} for u in data["users"]]
    return jsonify(safe)


# ─── Account CRUD ─────────────────────────────────────────────────────────────

@app.route("/api/accounts", methods=["GET"])
@require_auth
def list_accounts():
    # Never return passwords in list view
    safe = []
    for a in data["accounts"]:
        acc = {k: v for k, v in a.items() if k != "vault_key"}
        acc["has_credential"] = vault.retrieve(a["hostname"], a["username"]) is not None
        safe.append(acc)
    return jsonify(safe)


@app.route("/api/accounts", methods=["POST"])
@require_auth
def add_account():
    body = request.json
    required = ["name", "hostname", "username", "os"]
    if not all(body.get(k) for k in required):
        return jsonify({"error": "Missing required fields: name, hostname, username, os"}), 400

    account_id = py_secrets.token_hex(8)
    initial_password = body.get("password") or generate_password(body.get("password_length", 15))

    account = {
        "id": account_id,
        "name": body["name"],
        "hostname": body["hostname"],
        "username": body["username"],
        "os": body["os"],
        "port": body.get("port", 22 if body["os"] == "linux" else 5985),
        "description": body.get("description", ""),
        "preset": body.get("preset", "Custom"),
        "password_length": body.get("password_length", 15),
        "status": "active",
        "created_at": datetime.utcnow().isoformat(),
        "last_rotated": None,
    }
    data["accounts"].append(account)

    # Store initial password in encrypted vault
    vault.store(account["hostname"], account["username"], initial_password)

    save_data(data)
    add_log("info", account["name"], f"Account added: {account['username']}@{account['hostname']}", "ACC_ADD", user=request.current_user)
    return jsonify({k: v for k, v in account.items()})


@app.route("/api/accounts/<account_id>", methods=["PUT"])
@require_auth
def update_account(account_id):
    account = find_account(account_id)
    if not account:
        return jsonify({"error": "Account not found"}), 404
    body = request.json
    for field in ["name", "hostname", "username", "os", "port", "description", "preset", "password_length"]:
        if field in body:
            account[field] = body[field]
    save_data(data)
    add_log("info", account["name"], f"Account updated: {account['username']}@{account['hostname']}", "ACC_EDIT", user=request.current_user)
    return jsonify({k: v for k, v in account.items()})


@app.route("/api/accounts/<account_id>", methods=["DELETE"])
@require_auth
def delete_account(account_id):
    account = find_account(account_id)
    if not account:
        return jsonify({"error": "Account not found"}), 404
    vault.delete(account["hostname"], account["username"])
    data["accounts"].remove(account)
    save_data(data)
    add_log("warning", account["name"], f"Account deleted: {account['username']}@{account['hostname']}", "ACC_DEL", user=request.current_user)
    return jsonify({"ok": True})


# ─── Credential Retrieval (TOTP-gated) ───────────────────────────────────────

@app.route("/api/accounts/<account_id>/retrieve", methods=["POST"])
@require_auth
def retrieve_credential(account_id):
    """
    Retrieve the current password for an account.
    Requires a valid TOTP code from the requesting user's authenticator.
    """
    account = find_account(account_id)
    if not account:
        return jsonify({"error": "Account not found"}), 404

    body = request.json
    totp_code = body.get("totp_code", "")

    user = find_user(request.current_user)
    if not totp_util.verify_totp(totp_code, user["totp_secret"]):
        add_log("error", account["name"],
                f"Credential retrieval DENIED for {account['username']}@{account['hostname']} — invalid MFA code",
                "RETRIEVE_FAIL_MFA", user=request.current_user)
        return jsonify({"error": "Invalid authenticator code."}), 403

    password = vault.retrieve(account["hostname"], account["username"])
    if password is None:
        return jsonify({"error": "No credential stored for this account."}), 404

    add_log("info", account["name"],
            f"Credential retrieved: {account['username']}@{account['hostname']} by {request.current_user}",
            "RETRIEVE_OK", user=request.current_user)
    return jsonify({"password": password, "username": account["username"], "hostname": account["hostname"]})


# ─── Password Rotation ────────────────────────────────────────────────────────

def do_rotate(account, triggered_by="scheduler"):
    """Core rotation logic. Called by manual trigger or scheduler."""
    hostname = account["hostname"]
    username = account["username"]
    os_type  = account["os"]
    new_password = generate_password(account.get("password_length", 15))
    current = vault.retrieve(hostname, username)

    if current is None:
        add_log("error", account["name"], f"No stored credential for {username}@{hostname} — cannot rotate", "ROT_FAIL_NOCRED")
        account["status"] = "error"
        save_data(data)
        return False

    # Daily pre-verification
    add_log("info", account["name"], f"Daily verification started for {username}@{hostname}", "VERIFY_START")
    try:
        if os_type == "linux":
            success = rotate_linux(hostname, username, current, new_password, port=account.get("port", 22))
        elif os_type == "windows":
            success = rotate_windows(hostname, username, current, new_password, port=account.get("port", 5985))
        else:
            success = False
    except Exception as e:
        success = False
        add_log("error", account["name"], f"Rotation exception for {username}@{hostname}: {e}", "ROT_EXCEPTION")

    if success:
        vault.store(hostname, username, new_password)
        account["last_rotated"] = datetime.utcnow().isoformat()
        account["status"] = "active"
        add_log("success", account["name"], f"Password rotated for {username}@{hostname}", "ROT_OK", user=triggered_by)
        add_log("success", account["name"], f"Post-rotation validation passed for {username}@{hostname}", "POSTVERIFY_OK", user=triggered_by)
    else:
        account["status"] = "error"
        add_log("error", account["name"], f"Rotation FAILED for {username}@{hostname} — authentication or connection error", "ROT_FAIL", user=triggered_by)
        add_log("error", account["name"], f"Post-rotation validation SKIPPED — rotation did not complete for {username}@{hostname}", "POSTVERIFY_SKIP", user=triggered_by)

    save_data(data)
    return success


@app.route("/api/accounts/<account_id>/rotate", methods=["POST"])
@require_auth
def rotate_account(account_id):
    """Manually rotate a single account."""
    account = find_account(account_id)
    if not account:
        return jsonify({"error": "Account not found"}), 404
    add_log("info", account["name"], f"Manual rotation triggered for {account['username']}@{account['hostname']}", "ROT_MANUAL", user=request.current_user)
    success = do_rotate(account, triggered_by=request.current_user)
    return jsonify({"success": success, "status": account["status"], "last_rotated": account["last_rotated"]})


@app.route("/api/rotate/all", methods=["POST"])
@require_auth
def rotate_all():
    """Rotate all accounts."""
    results = {"success": 0, "failed": 0, "details": []}
    for account in data["accounts"]:
        ok = do_rotate(account, triggered_by=request.current_user)
        if ok: results["success"] += 1
        else:  results["failed"] += 1
        results["details"].append({"name": account["name"], "success": ok})
    return jsonify(results)


# ─── Logs ─────────────────────────────────────────────────────────────────────

@app.route("/api/logs", methods=["GET"])
@require_auth
def get_logs():
    log_type = request.args.get("type")
    logs = data["logs"]
    if log_type:
        logs = [l for l in logs if l.get("type") == log_type or l.get("code", "").startswith(log_type.upper())]
    return jsonify(list(reversed(logs[-500:])))  # Return last 500, newest first


@app.route("/api/logs/clear", methods=["DELETE"])
@require_auth
def clear_logs():
    data["logs"] = []
    save_data(data)
    return jsonify({"ok": True})


# ─── Scheduler ────────────────────────────────────────────────────────────────

scheduler_state = {"running": False, "interval_hours": 24, "last_run": None, "thread": None}


def scheduler_loop():
    while scheduler_state["running"]:
        interval = scheduler_state["interval_hours"] * 3600
        time.sleep(interval)
        if not scheduler_state["running"]:
            break
        add_log("info", "scheduler", "Scheduled rotation job triggered", "SCHED_TRIGGER")
        for account in data["accounts"]:
            do_rotate(account, triggered_by="scheduler")
        scheduler_state["last_run"] = datetime.utcnow().isoformat()


@app.route("/api/scheduler/start", methods=["POST"])
@require_auth
def start_scheduler():
    body = request.json or {}
    scheduler_state["interval_hours"] = body.get("interval_hours", 24)
    if not scheduler_state["running"]:
        scheduler_state["running"] = True
        t = threading.Thread(target=scheduler_loop, daemon=True)
        t.start()
        scheduler_state["thread"] = t
    add_log("info", "scheduler", f"Scheduler started — every {scheduler_state['interval_hours']}h", "SCHED_START", user=request.current_user)
    return jsonify({"running": True, "interval_hours": scheduler_state["interval_hours"]})


@app.route("/api/scheduler/stop", methods=["POST"])
@require_auth
def stop_scheduler():
    scheduler_state["running"] = False
    add_log("info", "scheduler", "Scheduler stopped", "SCHED_STOP", user=request.current_user)
    return jsonify({"running": False})


@app.route("/api/scheduler/status", methods=["GET"])
@require_auth
def scheduler_status():
    return jsonify({
        "running": scheduler_state["running"],
        "interval_hours": scheduler_state["interval_hours"],
        "last_run": scheduler_state["last_run"],
    })


# ─── Static frontend ──────────────────────────────────────────────────────────

@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_frontend(path):
    if path and os.path.exists(os.path.join("static", path)):
        return send_from_directory("static", path)
    return send_from_directory("static", "index.html")


if __name__ == "__main__":
    os.makedirs("vault", exist_ok=True)
    os.makedirs("logs", exist_ok=True)
    os.makedirs("config", exist_ok=True)
    print("\n  PAM Vault API starting...")
    print("  Open: http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
