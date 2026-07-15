"""
api.py — PAM Vault Flask REST API v3
Changes:
  - Auto-trigger pre-verify + rotate + post-verify when last_verified > 24h (scheduler only, not on deposit)
  - New accounts: status = "never_verified", no auto rotation on creation
  - PSM: /api/accounts/<id>/psm/connect — returns session token + credential for SSH/RDP
  - Bulk verify/rotate on selected account IDs
  - Report generation endpoint (CSV)
  - All existing features preserved
"""

import os, json, time, threading, io, csv
import secrets as py_secrets
from datetime import datetime, timedelta
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, Response
from flask_cors import CORS
from vault import CredentialVault
from password_gen import generate_password
from ssh_rotator import rotate_linux
from winrm_rotator import rotate_windows
from logger import AuditLogger
import totp_util

app    = Flask(__name__, static_folder="static")
CORS(app, supports_credentials=True)
logger = AuditLogger()
vault  = CredentialVault()

DATA_FILE = "config/app_data.json"

def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE) as f:
            return json.load(f)
    return {"users": [], "accounts": [], "logs": []}

def save_data(d):
    os.makedirs("config", exist_ok=True)
    with open(DATA_FILE, "w") as f:
        json.dump(d, f, indent=2)

data     = load_data()
sessions = {}
lockouts = {}

# ─── Helpers ──────────────────────────────────────────────────────────────────

def add_log(entry_type, account_name, message, code, user=None, account_id=None):
    entry = {
        "id":         py_secrets.token_hex(6),
        "timestamp":  datetime.utcnow().isoformat(),
        "type":       entry_type,
        "account":    account_name,
        "account_id": account_id,
        "message":    message,
        "code":       code,
        "user":       user,
    }
    data["logs"].append(entry)
    if len(data["logs"]) > 2000:
        data["logs"] = data["logs"][-2000:]
    save_data(data)
    logger.log(f"[{code}] {message}", level="ERROR" if entry_type == "error" else "INFO")
    return entry

SESSION_INACTIVITY_MINUTES = 10

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Session-Token")
        if not token or token not in sessions:
            return jsonify({"error": "Unauthorized"}), 401
        s   = sessions[token]
        now = datetime.utcnow()
        # Check hard expiry (kept as safety net)
        if datetime.fromisoformat(s["expires"]) < now:
            del sessions[token]
            return jsonify({"error": "Session expired", "reason": "expired"}), 401
        # Check inactivity timeout
        last = s.get("last_activity")
        if last:
            idle = now - datetime.fromisoformat(last)
            if idle > timedelta(minutes=SESSION_INACTIVITY_MINUTES):
                del sessions[token]
                add_log("info", s["username"], f"Session timed out after {SESSION_INACTIVITY_MINUTES} min inactivity: {s['username']}", "SESSION_TIMEOUT")
                return jsonify({"error": "Session timed out due to inactivity. Please log in again.", "reason": "timeout"}), 401
        # Refresh last activity on every valid request
        s["last_activity"] = now.isoformat()
        request.current_user = s["username"]
        request.current_role = s["role"]
        return f(*args, **kwargs)
    return decorated

def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Session-Token")
        if not token or token not in sessions:
            return jsonify({"error": "Unauthorized"}), 401
        s   = sessions[token]
        now = datetime.utcnow()
        # Check hard expiry
        if datetime.fromisoformat(s["expires"]) < now:
            del sessions[token]
            return jsonify({"error": "Session expired", "reason": "expired"}), 401
        # Check inactivity timeout
        last = s.get("last_activity")
        if last:
            idle = now - datetime.fromisoformat(last)
            if idle > timedelta(minutes=SESSION_INACTIVITY_MINUTES):
                del sessions[token]
                add_log("info", s["username"], f"Session timed out after {SESSION_INACTIVITY_MINUTES} min inactivity: {s['username']}", "SESSION_TIMEOUT")
                return jsonify({"error": "Session timed out due to inactivity. Please log in again.", "reason": "timeout"}), 401
        if s.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
        # Refresh last activity
        s["last_activity"] = now.isoformat()
        request.current_user = s["username"]
        request.current_role = s["role"]
        return f(*args, **kwargs)
    return decorated

def find_user(username):
    return next((u for u in data["users"] if u["username"] == username), None)

def find_account(account_id):
    return next((a for a in data["accounts"] if a["id"] == account_id), None)

def is_locked(username):
    lo = lockouts.get(username)
    if not lo: return False
    lu = lo.get("locked_until")
    if lu and datetime.utcnow() < datetime.fromisoformat(lu): return True
    if lu: lockouts[username] = {"fails": 0, "locked_until": None}
    return False

def record_fail(username):
    lo = lockouts.get(username, {"fails": 0, "locked_until": None})
    lo["fails"] = lo.get("fails", 0) + 1
    if lo["fails"] >= 3:
        lo["locked_until"] = (datetime.utcnow() + timedelta(minutes=30)).isoformat()
        add_log("error", username, f"Account locked after 3 failed attempts: {username}", "LOGIN_LOCKED")
    lockouts[username] = lo

def clear_fails(username):
    lockouts[username] = {"fails": 0, "locked_until": None}

def password_expired(user):
    changed = user.get("password_changed_at") or user.get("created_at")
    if not changed: return False
    return datetime.utcnow() > datetime.fromisoformat(changed) + timedelta(days=30)

def needs_auto_cycle(account):
    """Return True if account hasn't been verified in >24h and auto_management is on."""
    if not account.get("auto_management", True):
        return False
    if account.get("status") == "never_verified":
        return False  # Never auto-trigger on fresh deposit
    lv = account.get("last_verified")
    if not lv:
        return False  # Never verified manually yet — don't auto-trigger
    try:
        age = datetime.utcnow() - datetime.fromisoformat(lv)
        return age > timedelta(hours=24)
    except:
        return False

# ─── Auth ──────────────────────────────────────────────────────────────────────

@app.route("/api/auth/status", methods=["GET"])
def auth_status():
    return jsonify({"has_users": len(data["users"]) > 0})

@app.route("/api/auth/register", methods=["POST"])
def register():
    if data["users"]:
        return jsonify({"error": "Registration closed."}), 403
    body = request.json or {}
    username = body.get("username","").strip()
    password = body.get("password","")
    if not username or len(password) < 8:
        return jsonify({"error": "Username required and password must be 8+ chars."}), 400
    secret = totp_util.generate_secret()
    user = {
        "username": username,
        "password_hash": totp_util.hash_password(password),
        "totp_secret": secret, "role": "admin",
        "created_at": datetime.utcnow().isoformat(),
        "password_changed_at": datetime.utcnow().isoformat()
    }
    data["users"].append(user)
    save_data(data)
    add_log("info", username, f"Admin user created: {username}", "USER_CREATED")
    return jsonify({"totp_secret": secret, "otp_uri": totp_util.get_otp_uri(secret, username)})

@app.route("/api/auth/create_user", methods=["POST"])
@require_admin
def create_user():
    body = request.json or {}
    username = body.get("username","").strip()
    password = body.get("password","")
    role     = body.get("role","readonly")
    if not username or len(password) < 8:
        return jsonify({"error": "Invalid input."}), 400
    if find_user(username):
        return jsonify({"error": "Username already exists."}), 409
    secret = totp_util.generate_secret()
    user = {
        "username": username, "password_hash": totp_util.hash_password(password),
        "totp_secret": secret, "role": role,
        "created_at": datetime.utcnow().isoformat(),
        "password_changed_at": datetime.utcnow().isoformat()
    }
    data["users"].append(user)
    save_data(data)
    add_log("info", username, f"User created: {username} ({role})", "USER_CREATED", user=request.current_user)
    return jsonify({"totp_secret": secret, "otp_uri": totp_util.get_otp_uri(secret, username)})

@app.route("/api/auth/users/<username>", methods=["DELETE"])
@require_admin
def delete_user(username):
    if username == request.current_user:
        return jsonify({"error": "Cannot delete your own account."}), 400
    user = find_user(username)
    if not user:
        return jsonify({"error": "User not found."}), 404
    data["users"].remove(user)
    for token in list(sessions.keys()):
        if sessions[token]["username"] == username:
            del sessions[token]
    save_data(data)
    add_log("warning", username, f"User deleted: {username}", "USER_DELETED", user=request.current_user)
    return jsonify({"ok": True})

@app.route("/api/auth/login", methods=["POST"])
def login():
    body = request.json or {}
    username  = body.get("username","")
    password  = body.get("password","")
    totp_code = body.get("totp_code","")
    if is_locked(username):
        lo = lockouts.get(username,{})
        return jsonify({"error": "Account locked after 3 failed attempts.", "locked": True, "locked_until": lo.get("locked_until")}), 423
    user = find_user(username)
    if not user or not totp_util.verify_password(password, user["password_hash"]):
        record_fail(username)
        fails = lockouts.get(username,{}).get("fails",0)
        remaining = max(0,3-fails)
        add_log("error", username, f"Failed login: {username} ({fails}/3)", "LOGIN_FAIL")
        return jsonify({"error": f"Invalid credentials. {remaining} attempt(s) remaining before lockout."}), 401
    # MFA check — verify TOTP after password is confirmed correct
    if not totp_util.verify_totp(totp_code, user["totp_secret"]):
        record_fail(username)
        fails = lockouts.get(username,{}).get("fails",0)
        remaining = max(0,3-fails)
        add_log("error", username, f"Failed login (invalid MFA): {username} ({fails}/3)", "LOGIN_FAIL_MFA")
        return jsonify({"error": f"Invalid authenticator code. {remaining} attempt(s) remaining before lockout."}), 401
    clear_fails(username)
    expired = password_expired(user)
    token = py_secrets.token_hex(32)
    now = datetime.utcnow()
    sessions[token] = {
        "username":      username,
        "role":          user["role"],
        "expires":       (now + timedelta(minutes=10)).isoformat(),
        "last_activity": now.isoformat(),
    }
    add_log("info", username, f"Vault login: {username}", "LOGIN_OK")
    return jsonify({"token": token, "username": username, "role": user["role"], "password_expired": expired})

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
    now = datetime.utcnow()
    result = []
    for u in data["users"]:
        changed = u.get("password_changed_at") or u.get("created_at","")
        days = (now - datetime.fromisoformat(changed)).days if changed else 0
        result.append({
            "username":   u["username"], "role": u["role"],
            "created_at": u["created_at"],
            "password_changed_at": u.get("password_changed_at"),
            "password_expired": password_expired(u),
            "days_since_change": days,
        })
    return jsonify(result)

@app.route("/api/auth/change_password", methods=["POST"])
@require_auth
def change_own_password():
    body = request.json or {}
    old_pass  = body.get("old_password","")
    new_pass  = body.get("new_password","")
    totp_code = body.get("totp_code","")
    user = find_user(request.current_user)
    if not user: return jsonify({"error": "User not found."}), 404
    if not totp_util.verify_totp(totp_code, user["totp_secret"]):
        return jsonify({"error": "Invalid authenticator code."}), 403
    if not totp_util.verify_password(old_pass, user["password_hash"]):
        return jsonify({"error": "Current password is incorrect."}), 401
    if len(new_pass) < 8:
        return jsonify({"error": "New password must be 8+ characters."}), 400
    if totp_util.verify_password(new_pass, user["password_hash"]):
        return jsonify({"error": "New password must differ from current."}), 400
    user["password_hash"] = totp_util.hash_password(new_pass)
    user["password_changed_at"] = datetime.utcnow().isoformat()
    save_data(data)
    add_log("info", request.current_user, f"Vault password changed: {request.current_user}", "USER_PASS_CHANGED", user=request.current_user)
    return jsonify({"ok": True})

@app.route("/api/auth/reset_password", methods=["POST"])
def reset_password():
    body = request.json or {}
    username  = body.get("username","")
    totp_code = body.get("totp_code","")
    new_pass  = body.get("new_password","")
    user = find_user(username)
    if not user: return jsonify({"error": "User not found."}), 404
    if not totp_util.verify_totp(totp_code, user["totp_secret"]):
        add_log("error", username, f"Password reset failed — invalid MFA: {username}", "RESET_FAIL_MFA")
        return jsonify({"error": "Invalid authenticator code."}), 403
    if len(new_pass) < 8:
        return jsonify({"error": "Password must be 8+ chars."}), 400
    if totp_util.verify_password(new_pass, user["password_hash"]):
        return jsonify({"error": "New password must differ."}), 400
    user["password_hash"] = totp_util.hash_password(new_pass)
    user["password_changed_at"] = datetime.utcnow().isoformat()
    lockouts[username] = {"fails": 0, "locked_until": None}
    save_data(data)
    add_log("info", username, f"Password reset via MFA: {username}", "RESET_OK")
    return jsonify({"ok": True})

# ─── Accounts ─────────────────────────────────────────────────────────────────

@app.route("/api/accounts", methods=["GET"])
@require_auth
def list_accounts():
    result = []
    for a in data["accounts"]:
        acc = dict(a)
        acc["has_credential"] = vault.retrieve(a["hostname"], a["username"]) is not None
        result.append(acc)
    return jsonify(result)

@app.route("/api/accounts", methods=["POST"])
@require_admin
def add_account():
    body = request.json or {}
    if not all(body.get(k) for k in ["name","hostname","username","os"]):
        return jsonify({"error": "Missing required fields."}), 400
    account_id       = py_secrets.token_hex(8)
    initial_password = body.get("password") or generate_password(body.get("password_length",15))
    account = {
        "id":                   account_id,
        "name":                 body["name"],
        "hostname":             body["hostname"],
        "username":             body["username"],
        "os":                   body["os"],
        "port":                 body.get("port", 22 if body["os"]=="linux" else 5985),
        "description":          body.get("description",""),
        "preset":               body.get("preset","Custom"),
        "password_length":      body.get("password_length",15),
        "status":               "never_verified",   # Fresh deposit — no auto trigger
        "auto_management":      True,
        "disable_reason":       "",
        "created_at":           datetime.utcnow().isoformat(),
        "last_rotated":         None,
        "last_verified":        None,
        "last_verified_status": None,
    }
    data["accounts"].append(account)
    vault.store(account["hostname"], account["username"], initial_password)
    save_data(data)
    add_log("info", account["name"], f"Account deposited: {account['username']}@{account['hostname']} — awaiting first manual verification", "ACC_ADD", user=request.current_user, account_id=account_id)
    return jsonify(account)

@app.route("/api/accounts/<account_id>", methods=["PUT"])
@require_admin
def update_account(account_id):
    account = find_account(account_id)
    if not account: return jsonify({"error": "Not found"}), 404
    body = request.json or {}
    for f in ["name","hostname","username","os","port","description","preset","password_length","auto_management","disable_reason"]:
        if f in body:
            account[f] = body[f]
    # Only set status=disabled if admin explicitly disabled management
    if not account.get("auto_management", True):
        account["status"] = "disabled"
    elif account.get("status") == "disabled":
        # Re-enabled — go back to never_verified if no history
        account["status"] = "active" if account.get("last_rotated") else "never_verified"
    save_data(data)
    add_log("info", account["name"], f"Account updated: {account['username']}@{account['hostname']}", "ACC_EDIT", user=request.current_user, account_id=account_id)
    return jsonify(account)

@app.route("/api/accounts/<account_id>", methods=["DELETE"])
@require_admin
def delete_account(account_id):
    account = find_account(account_id)
    if not account: return jsonify({"error": "Not found"}), 404
    vault.delete(account["hostname"], account["username"])
    data["accounts"].remove(account)
    save_data(data)
    add_log("warning", account["name"], f"Account deleted: {account['username']}@{account['hostname']}", "ACC_DEL", user=request.current_user, account_id=account_id)
    return jsonify({"ok": True})

# ─── Credential Retrieval ──────────────────────────────────────────────────────

@app.route("/api/accounts/<account_id>/retrieve", methods=["POST"])
@require_auth
def retrieve_credential(account_id):
    account = find_account(account_id)
    if not account: return jsonify({"error": "Not found"}), 404
    body      = request.json or {}
    totp_code = body.get("totp_code","")
    user      = find_user(request.current_user)
    if not totp_util.verify_totp(totp_code, user["totp_secret"]):
        add_log("error", account["name"], f"Credential retrieval DENIED — invalid MFA: {account['username']}@{account['hostname']}", "RETRIEVE_FAIL_MFA", user=request.current_user, account_id=account_id)
        return jsonify({"error": "Invalid authenticator code."}), 403
    password = vault.retrieve(account["hostname"], account["username"])
    if password is None:
        return jsonify({"error": "No credential stored."}), 404
    add_log("info", account["name"], f"Credential retrieved by {request.current_user}: {account['username']}@{account['hostname']}", "RETRIEVE_OK", user=request.current_user, account_id=account_id)
    return jsonify({"password": password, "username": account["username"], "hostname": account["hostname"]})

# ─── Verify ───────────────────────────────────────────────────────────────────

def _verify_connectivity(account):
    """Test stored credential works. Returns (success, error_message)."""
    password = vault.retrieve(account["hostname"], account["username"])
    if not password:
        return False, "No stored credential — VERIFY_FAIL_NOCRED"
    try:
        import paramiko
        if account["os"] == "linux":
            c = paramiko.SSHClient()
            c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            c.connect(account["hostname"], port=account.get("port",22),
                      username=account["username"], password=password,
                      timeout=10, look_for_keys=False, allow_agent=False)
            c.close()
            return True, ""
        elif account["os"] == "windows":
            import winrm
            s = winrm.Session(
                target=f"http://{account['hostname']}:{account.get('port',5985)}/wsman",
                auth=(account["username"], password), transport="ntlm",
                server_cert_validation="ignore", operation_timeout_sec=15)
            r = s.run_ps("Write-Output 'VERIFY_OK'")
            if b"VERIFY_OK" in r.std_out: return True, ""
            return False, "Remote command failed — VERIFY_FAIL_REMOTE"
        return False, "Unknown OS type"
    except Exception as e:
        return False, str(e)

@app.route("/api/accounts/<account_id>/verify", methods=["POST"])
@require_auth
def verify_account(account_id):
    account = find_account(account_id)
    if not account: return jsonify({"error": "Not found"}), 404
    add_log("info", account["name"], f"Verification started: {account['username']}@{account['hostname']}", "VERIFY_START", user=request.current_user, account_id=account_id)
    ok, err = _verify_connectivity(account)
    account["last_verified"]        = datetime.utcnow().isoformat()
    account["last_verified_status"] = "success" if ok else "failed"
    if ok:
        if account.get("status") == "never_verified":
            account["status"] = "active"
        add_log("success", account["name"], f"Verification SUCCESS: {account['username']}@{account['hostname']}", "VERIFY_OK", user=request.current_user, account_id=account_id)
    else:
        account["status"] = "error"
        add_log("error", account["name"], f"Verification FAILED: {account['username']}@{account['hostname']} — {err}", "VERIFY_FAIL", user=request.current_user, account_id=account_id)
    save_data(data)
    return jsonify({"success": ok, "error": err, "code": "VERIFY_OK" if ok else "VERIFY_FAIL"})

# ─── Password Rotation ─────────────────────────────────────────────────────────

def do_rotate(account, triggered_by="scheduler", pre_verify=True):
    """Full CPM cycle: pre-verify → change → post-verify."""
    if not account.get("auto_management", True):
        add_log("warning", account["name"], f"Rotation SKIPPED — auto management disabled: {account['username']}@{account['hostname']}", "ROT_SKIP_DISABLED", account_id=account["id"])
        return False, "Auto management disabled"

    hostname     = account["hostname"]
    username     = account["username"]
    new_password = generate_password(account.get("password_length",15))
    current      = vault.retrieve(hostname, username)
    if not current:
        add_log("error", account["name"], f"Change password FAILED — no stored credential: {username}@{hostname}", "ROT_FAIL_NOCRED", account_id=account["id"])
        account["status"] = "error"; save_data(data)
        return False, "No stored credential"

    # Pre-verify
    if pre_verify:
        add_log("info", account["name"], f"Pre-verification started: {username}@{hostname}", "PREVERIFY_START", user=triggered_by, account_id=account["id"])
        ok, err = _verify_connectivity(account)
        account["last_verified"]        = datetime.utcnow().isoformat()
        account["last_verified_status"] = "success" if ok else "failed"
        if not ok:
            account["status"] = "error"
            add_log("error", account["name"], f"Pre-verification FAILED: {username}@{hostname} — {err}", "PREVERIFY_FAIL", user=triggered_by, account_id=account["id"])
            save_data(data)
            return False, f"Pre-verification failed: {err}"
        add_log("success", account["name"], f"Pre-verification PASSED: {username}@{hostname}", "PREVERIFY_OK", user=triggered_by, account_id=account["id"])

    # Change password
    add_log("info", account["name"], f"Password change initiated: {username}@{hostname}", "ROT_START", user=triggered_by, account_id=account["id"])
    try:
        if account["os"] == "linux":
            success = rotate_linux(hostname, username, current, new_password, port=account.get("port",22))
        elif account["os"] == "windows":
            success = rotate_windows(hostname, username, current, new_password, port=account.get("port",5985))
        else:
            success = False
        err_detail = ""
    except Exception as e:
        success    = False
        err_detail = str(e)
        add_log("error", account["name"], f"Change password EXCEPTION: {username}@{hostname}: {err_detail}", "ROT_EXCEPTION", user=triggered_by, account_id=account["id"])

    if success:
        vault.store(hostname, username, new_password)
        account["last_rotated"] = datetime.utcnow().isoformat()
        account["status"]       = "active"
        add_log("success", account["name"], f"Password changed successfully: {username}@{hostname}", "ROT_OK", user=triggered_by, account_id=account["id"])
        # Post-verify
        add_log("info", account["name"], f"Post-verification started: {username}@{hostname}", "POSTVERIFY_START", user=triggered_by, account_id=account["id"])
        pok, perr = _verify_connectivity(account)
        account["last_verified"]        = datetime.utcnow().isoformat()
        account["last_verified_status"] = "success" if pok else "failed"
        if pok:
            add_log("success", account["name"], f"Post-verification PASSED: {username}@{hostname}", "POSTVERIFY_OK", user=triggered_by, account_id=account["id"])
        else:
            account["status"] = "error"
            add_log("error", account["name"], f"Post-verification FAILED: {username}@{hostname} — {perr}", "POSTVERIFY_FAIL", user=triggered_by, account_id=account["id"])
    else:
        account["status"] = "error"
        reason = err_detail or "Authentication or connection error"
        add_log("error", account["name"], f"Change password FAILED: {username}@{hostname} — {reason}", "ROT_FAIL", user=triggered_by, account_id=account["id"])

    save_data(data)
    return success, err_detail

@app.route("/api/accounts/<account_id>/rotate", methods=["POST"])
@require_admin
def rotate_account(account_id):
    account = find_account(account_id)
    if not account: return jsonify({"error": "Not found"}), 404
    success, err = do_rotate(account, triggered_by=request.current_user, pre_verify=True)
    return jsonify({"success": success, "error": err, "status": account["status"], "last_rotated": account.get("last_rotated")})

@app.route("/api/rotate/all", methods=["POST"])
@require_admin
def rotate_all():
    results = {"success":0,"failed":0,"details":[]}
    for account in data["accounts"]:
        ok, err = do_rotate(account, triggered_by=request.current_user, pre_verify=True)
        if ok: results["success"] += 1
        else:  results["failed"]  += 1
        results["details"].append({"name":account["name"],"success":ok,"error":err})
    return jsonify(results)

@app.route("/api/accounts/bulk/verify", methods=["POST"])
@require_auth
def bulk_verify():
    body = request.json or {}
    ids  = body.get("account_ids",[])
    results = []
    for aid in ids:
        acc = find_account(aid)
        if not acc: continue
        add_log("info", acc["name"], f"Bulk verify started: {acc['username']}@{acc['hostname']}", "VERIFY_START", user=request.current_user, account_id=aid)
        ok, err = _verify_connectivity(acc)
        acc["last_verified"]        = datetime.utcnow().isoformat()
        acc["last_verified_status"] = "success" if ok else "failed"
        if ok:
            if acc.get("status") == "never_verified": acc["status"] = "active"
            add_log("success", acc["name"], f"Bulk verify OK: {acc['username']}@{acc['hostname']}", "VERIFY_OK", user=request.current_user, account_id=aid)
        else:
            acc["status"] = "error"
            add_log("error", acc["name"], f"Bulk verify FAILED: {acc['username']}@{acc['hostname']} — {err}", "VERIFY_FAIL", user=request.current_user, account_id=aid)
        results.append({"id":aid,"name":acc["name"],"success":ok,"error":err})
    save_data(data)
    return jsonify(results)

@app.route("/api/accounts/bulk/rotate", methods=["POST"])
@require_admin
def bulk_rotate():
    body = request.json or {}
    ids  = body.get("account_ids",[])
    results = []
    for aid in ids:
        acc = find_account(aid)
        if not acc: continue
        ok, err = do_rotate(acc, triggered_by=request.current_user, pre_verify=True)
        results.append({"id":aid,"name":acc["name"],"success":ok,"error":err})
    return jsonify(results)

# ─── PSM Connect ───────────────────────────────────────────────────────────────

@app.route("/api/accounts/<account_id>/psm/connect", methods=["POST"])
@require_auth
def psm_connect(account_id):
    """
    Return connection details (credential) for PSM session.
    Frontend uses this to initiate SSH (via WebSSH proxy) or download RDP file.
    The password is returned so the frontend can auto-fill/inject it.
    """
    account = find_account(account_id)
    if not account: return jsonify({"error": "Not found"}), 404
    body      = request.json or {}
    totp_code = body.get("totp_code","")
    user      = find_user(request.current_user)
    if not totp_util.verify_totp(totp_code, user["totp_secret"]):
        add_log("error", account["name"], f"PSM connect DENIED — invalid MFA: {account['username']}@{account['hostname']}", "PSM_FAIL_MFA", user=request.current_user, account_id=account_id)
        return jsonify({"error": "Invalid authenticator code."}), 403
    password = vault.retrieve(account["hostname"], account["username"])
    if not password:
        return jsonify({"error": "No stored credential."}), 404
    add_log("info", account["name"], f"PSM session initiated by {request.current_user}: {account['username']}@{account['hostname']}", "PSM_CONNECT", user=request.current_user, account_id=account_id)
    # Generate RDP file content for Windows
    rdp_content = None
    if account["os"] == "windows":
        rdp_port = 3389  # Standard RDP port (WinRM port != RDP port)
        rdp_content = "\n".join([
            f"full address:s:{account['hostname']}:{rdp_port}",
            f"username:s:{account['username']}",
            "authentication level:i:2",
            "enablecredsspsupport:i:1",
            "prompt for credentials:i:0",
            "negotiate security layer:i:1",
        ])
    return jsonify({
        "hostname":    account["hostname"],
        "username":    account["username"],
        "password":    password,
        "os":          account["os"],
        "port":        account.get("port",22),
        "rdp_content": rdp_content,
        "ssh_command": f"ssh {account['username']}@{account['hostname']} -p {account.get('port',22)}" if account["os"]=="linux" else None,
    })

# ─── Logs ─────────────────────────────────────────────────────────────────────

@app.route("/api/logs", methods=["GET"])
@require_auth
def get_logs():
    account_id = request.args.get("account_id")
    log_type   = request.args.get("type")
    logs       = data["logs"]
    if account_id:
        logs = [l for l in logs if l.get("account_id") == account_id]
    if log_type and log_type != "all":
        logs = [l for l in logs if l.get("type") == log_type]
    return jsonify(list(reversed(logs[-500:])))

@app.route("/api/logs/clear", methods=["DELETE"])
@require_admin
def clear_logs():
    data["logs"] = []
    save_data(data)
    return jsonify({"ok": True})

# ─── Reports ──────────────────────────────────────────────────────────────────

@app.route("/api/reports/csv", methods=["GET"])
@require_auth
def generate_report():
    """
    Generate CSV report. Query params:
      filter = all | linux | windows | disabled | verified_only
    """
    filter_type = request.args.get("filter","all")
    accounts    = data["accounts"]

    if filter_type == "linux":
        accounts = [a for a in accounts if a.get("os")=="linux"]
    elif filter_type == "windows":
        accounts = [a for a in accounts if a.get("os")=="windows"]
    elif filter_type == "disabled":
        accounts = [a for a in accounts if not a.get("auto_management",True)]
    elif filter_type == "verified_only":
        accounts = [a for a in accounts if a.get("last_verified") and not a.get("last_rotated")]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Name","Hostname","Port","Username","OS","Status","Auto Management","Disable Reason","Last Verified","Last Changed","Created At","Description"])
    for a in accounts:
        writer.writerow([
            a.get("name",""), a.get("hostname",""), a.get("port",""),
            a.get("username",""), a.get("os",""),
            a.get("status",""), "Yes" if a.get("auto_management",True) else "No",
            a.get("disable_reason",""),
            a.get("last_verified","Never") or "Never",
            a.get("last_rotated","Never") or "Never",
            a.get("created_at",""), a.get("description",""),
        ])
    csv_content = output.getvalue()
    filename    = f"PAM_Report_{filter_type}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    add_log("info", "system", f"Report generated: {filter_type} by {request.current_user}", "REPORT_GEN", user=request.current_user)
    return Response(csv_content, mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})

# ─── Scheduler ────────────────────────────────────────────────────────────────

sched = {"running": False, "interval_hours": 24, "last_run": None}

def scheduler_loop():
    while sched["running"]:
        time.sleep(60)  # Check every minute
        if not sched["running"]: break
        for acc in data["accounts"]:
            if needs_auto_cycle(acc):
                add_log("info", acc["name"], f"Auto-cycle triggered (>24h since last verify): {acc['username']}@{acc['hostname']}", "SCHED_AUTO_TRIGGER", account_id=acc["id"])
                do_rotate(acc, triggered_by="scheduler", pre_verify=True)
        sched["last_run"] = datetime.utcnow().isoformat()

@app.route("/api/scheduler/start", methods=["POST"])
@require_admin
def start_scheduler():
    body = request.json or {}
    sched["interval_hours"] = body.get("interval_hours",24)
    if not sched["running"]:
        sched["running"] = True
        threading.Thread(target=scheduler_loop, daemon=True).start()
    add_log("info","scheduler",f"Scheduler started","SCHED_START",user=request.current_user)
    return jsonify({"running":True,"interval_hours":sched["interval_hours"]})

@app.route("/api/scheduler/stop", methods=["POST"])
@require_admin
def stop_scheduler():
    sched["running"] = False
    add_log("info","scheduler","Scheduler stopped","SCHED_STOP",user=request.current_user)
    return jsonify({"running":False})

@app.route("/api/scheduler/status", methods=["GET"])
@require_auth
def scheduler_status():
    return jsonify({**sched})

# ─── Static ────────────────────────────────────────────────────────────────────

@app.route("/", defaults={"path":""})
@app.route("/<path:path>")
def serve_frontend(path):
    if path and os.path.exists(os.path.join("static",path)):
        return send_from_directory("static",path)
    return send_from_directory("static","index.html")

if __name__ == "__main__":
    for d_ in ["vault","logs","config"]: os.makedirs(d_, exist_ok=True)
    print("\n  PAM Vault API v3 starting...\n  Open: http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
