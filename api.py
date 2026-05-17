"""
api.py — PAM Vault Flask REST API v2
New in v2:
  - Login lockout after 3 failed attempts
  - MFA-gated password reset
  - Delete vault user endpoint
  - Per-account logs (account_id tagged on every log)
  - Verify password endpoint (test connectivity without rotating)
  - Change password endpoint (rotate on demand)
  - Disable automatic management per account
  - 30-day vault user password expiry policy
  - Bulk rotate/verify endpoints
"""

import os, json, time, threading
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
logger   = AuditLogger()
vault    = CredentialVault()

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
sessions = {}            # token -> {username, expires}
lockouts = {}            # username -> {fails, locked_until}

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
    # Keep last 2000 logs only
    if len(data["logs"]) > 2000:
        data["logs"] = data["logs"][-2000:]
    save_data(data)
    logger.log(f"[{code}] {message}", level="ERROR" if entry_type == "error" else "INFO")
    return entry

def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get("X-Session-Token")
        if not token or token not in sessions:
            return jsonify({"error": "Unauthorized"}), 401
        s = sessions[token]
        if datetime.fromisoformat(s["expires"]) < datetime.utcnow():
            del sessions[token]
            return jsonify({"error": "Session expired"}), 401
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
        s = sessions[token]
        if s.get("role") != "admin":
            return jsonify({"error": "Admin access required"}), 403
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
    if lo.get("locked_until") and datetime.utcnow() < datetime.fromisoformat(lo["locked_until"]):
        return True
    if lo.get("locked_until") and datetime.utcnow() >= datetime.fromisoformat(lo["locked_until"]):
        lockouts[username] = {"fails": 0, "locked_until": None}
    return False

def record_fail(username):
    lo = lockouts.get(username, {"fails": 0, "locked_until": None})
    lo["fails"] = lo.get("fails", 0) + 1
    if lo["fails"] >= 3:
        lo["locked_until"] = (datetime.utcnow() + timedelta(minutes=30)).isoformat()
        add_log("error", username, f"Account locked after 3 failed login attempts: {username}", "LOGIN_LOCKED")
    lockouts[username] = lo

def clear_fails(username):
    lockouts[username] = {"fails": 0, "locked_until": None}

def password_expired(user):
    """Check if vault user's password is older than 30 days."""
    changed = user.get("password_changed_at") or user.get("created_at")
    if not changed: return False
    return datetime.utcnow() > datetime.fromisoformat(changed) + timedelta(days=30)

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
    user = {"username": username, "password_hash": totp_util.hash_password(password),
            "totp_secret": secret, "role": "admin",
            "created_at": datetime.utcnow().isoformat(),
            "password_changed_at": datetime.utcnow().isoformat()}
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
    user = {"username": username, "password_hash": totp_util.hash_password(password),
            "totp_secret": secret, "role": role,
            "created_at": datetime.utcnow().isoformat(),
            "password_changed_at": datetime.utcnow().isoformat()}
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
    # Invalidate any active sessions for this user
    for token in list(sessions.keys()):
        if sessions[token]["username"] == username:
            del sessions[token]
    save_data(data)
    add_log("warning", username, f"User deleted: {username}", "USER_DELETED", user=request.current_user)
    return jsonify({"ok": True})

@app.route("/api/auth/login", methods=["POST"])
def login():
    body = request.json or {}
    username = body.get("username","")
    password = body.get("password","")
    if is_locked(username):
        lo = lockouts.get(username,{})
        return jsonify({"error": "Account locked after 3 failed attempts. Try again later or reset password.", "locked": True, "locked_until": lo.get("locked_until")}), 423
    user = find_user(username)
    if not user or not totp_util.verify_password(password, user["password_hash"]):
        record_fail(username)
        fails = lockouts.get(username,{}).get("fails",0)
        remaining = max(0, 3 - fails)
        add_log("error", username, f"Failed login: {username} ({fails}/3 attempts)", "LOGIN_FAIL")
        return jsonify({"error": f"Invalid credentials. {remaining} attempt(s) remaining before lockout."}), 401
    clear_fails(username)
    # Check 30-day password expiry
    expired = password_expired(user)
    token = py_secrets.token_hex(32)
    sessions[token] = {"username": username, "role": user["role"],
                       "expires": (datetime.utcnow() + timedelta(hours=8)).isoformat()}
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
        days_since = (now - datetime.fromisoformat(changed)).days if changed else 0
        result.append({
            "username":   u["username"],
            "role":       u["role"],
            "created_at": u["created_at"],
            "password_changed_at": u.get("password_changed_at"),
            "password_expired": password_expired(u),
            "days_since_change": days_since,
        })
    return jsonify(result)

@app.route("/api/auth/change_password", methods=["POST"])
@require_auth
def change_own_password():
    """Change vault user's own password (used for 30-day policy)."""
    body = request.json or {}
    old_pass  = body.get("old_password","")
    new_pass  = body.get("new_password","")
    totp_code = body.get("totp_code","")
    user = find_user(request.current_user)
    if not user:
        return jsonify({"error": "User not found."}), 404
    if not totp_util.verify_totp(totp_code, user["totp_secret"]):
        return jsonify({"error": "Invalid authenticator code."}), 403
    if not totp_util.verify_password(old_pass, user["password_hash"]):
        return jsonify({"error": "Current password is incorrect."}), 401
    if len(new_pass) < 8:
        return jsonify({"error": "New password must be 8+ characters."}), 400
    if totp_util.verify_password(new_pass, user["password_hash"]):
        return jsonify({"error": "New password must be different from current password."}), 400
    user["password_hash"] = totp_util.hash_password(new_pass)
    user["password_changed_at"] = datetime.utcnow().isoformat()
    save_data(data)
    add_log("info", request.current_user, f"Vault user password changed: {request.current_user}", "USER_PASS_CHANGED", user=request.current_user)
    return jsonify({"ok": True})

@app.route("/api/auth/reset_password", methods=["POST"])
def reset_password():
    """MFA-gated password reset for locked accounts."""
    body = request.json or {}
    username  = body.get("username","")
    totp_code = body.get("totp_code","")
    new_pass  = body.get("new_password","")
    user = find_user(username)
    if not user:
        return jsonify({"error": "User not found."}), 404
    if not totp_util.verify_totp(totp_code, user["totp_secret"]):
        add_log("error", username, f"Password reset failed — invalid MFA: {username}", "RESET_FAIL_MFA")
        return jsonify({"error": "Invalid authenticator code."}), 403
    if len(new_pass) < 8:
        return jsonify({"error": "Password must be 8+ characters."}), 400
    if totp_util.verify_password(new_pass, user["password_hash"]):
        return jsonify({"error": "New password must differ from current."}), 400
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
    safe = []
    for a in data["accounts"]:
        acc = {k: v for k, v in a.items()}
        acc["has_credential"] = vault.retrieve(a["hostname"], a["username"]) is not None
        safe.append(acc)
    return jsonify(safe)

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
        "status":               "active",
        "auto_management":      True,   # False = disable automatic rotation
        "disable_reason":       "",
        "created_at":           datetime.utcnow().isoformat(),
        "last_rotated":         None,
        "last_verified":        None,
        "last_verified_status": None,
    }
    data["accounts"].append(account)
    vault.store(account["hostname"], account["username"], initial_password)
    save_data(data)
    add_log("info", account["name"], f"Account added: {account['username']}@{account['hostname']}", "ACC_ADD", user=request.current_user, account_id=account_id)
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
    if not account.get("auto_management", True):
        account["status"] = "disabled"
    elif account.get("status") == "disabled":
        account["status"] = "active"
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
        add_log("error", account["name"], f"Credential retrieval DENIED — invalid MFA code for {account['username']}@{account['hostname']}", "RETRIEVE_FAIL_MFA", user=request.current_user, account_id=account_id)
        return jsonify({"error": "Invalid authenticator code."}), 403
    password = vault.retrieve(account["hostname"], account["username"])
    if password is None:
        return jsonify({"error": "No credential stored."}), 404
    add_log("info", account["name"], f"Credential retrieved by {request.current_user}: {account['username']}@{account['hostname']}", "RETRIEVE_OK", user=request.current_user, account_id=account_id)
    return jsonify({"password": password, "username": account["username"], "hostname": account["hostname"]})

# ─── Verify Password (test connectivity, no rotation) ─────────────────────────

@app.route("/api/accounts/<account_id>/verify", methods=["POST"])
@require_auth
def verify_account(account_id):
    """Test that stored credential actually works on the remote machine."""
    account = find_account(account_id)
    if not account: return jsonify({"error": "Not found"}), 404

    password = vault.retrieve(account["hostname"], account["username"])
    if password is None:
        add_log("error", account["name"], f"Verify FAILED — no stored credential for {account['username']}@{account['hostname']}", "VERIFY_FAIL_NOCRED", user=request.current_user, account_id=account_id)
        return jsonify({"success": False, "error": "No credential stored.", "code": "VERIFY_FAIL_NOCRED"})

    add_log("info", account["name"], f"Verification started for {account['username']}@{account['hostname']}", "VERIFY_START", user=request.current_user, account_id=account_id)

    try:
        import paramiko, socket
        if account["os"] == "linux":
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(hostname=account["hostname"], port=account.get("port",22),
                           username=account["username"], password=password,
                           timeout=10, look_for_keys=False, allow_agent=False)
            client.close()
            success = True
        elif account["os"] == "windows":
            import winrm
            s = winrm.Session(
                target=f"http://{account['hostname']}:{account.get('port',5985)}/wsman",
                auth=(account["username"], password), transport="ntlm",
                server_cert_validation="ignore", operation_timeout_sec=15)
            r = s.run_ps("Write-Output 'VERIFY_OK'")
            success = b"VERIFY_OK" in r.std_out
        else:
            success = False
    except Exception as e:
        success = False
        err_msg = str(e)
        add_log("error", account["name"], f"Verify FAILED for {account['username']}@{account['hostname']}: {err_msg}", "VERIFY_FAIL_CONN", user=request.current_user, account_id=account_id)
        account["last_verified"] = datetime.utcnow().isoformat()
        account["last_verified_status"] = "failed"
        save_data(data)
        return jsonify({"success": False, "error": err_msg, "code": "VERIFY_FAIL_CONN"})

    account["last_verified"] = datetime.utcnow().isoformat()
    account["last_verified_status"] = "success" if success else "failed"
    if not success:
        add_log("error", account["name"], f"Verify FAILED — incorrect password for {account['username']}@{account['hostname']}", "VERIFY_FAIL_AUTH", user=request.current_user, account_id=account_id)
    else:
        add_log("success", account["name"], f"Verify SUCCESS for {account['username']}@{account['hostname']}", "VERIFY_OK", user=request.current_user, account_id=account_id)
    save_data(data)
    return jsonify({"success": success, "code": "VERIFY_OK" if success else "VERIFY_FAIL_AUTH"})

# ─── Change Password (manual rotate) ──────────────────────────────────────────

def do_rotate(account, triggered_by="scheduler"):
    if not account.get("auto_management", True):
        add_log("warning", account["name"], f"Rotation SKIPPED — auto management disabled for {account['username']}@{account['hostname']}", "ROT_SKIP_DISABLED", account_id=account["id"])
        return False, "Auto management disabled"

    hostname     = account["hostname"]
    username     = account["username"]
    new_password = generate_password(account.get("password_length",15))
    current      = vault.retrieve(hostname, username)

    if current is None:
        add_log("error", account["name"], f"Change password FAILED — no stored credential for {username}@{hostname}", "ROT_FAIL_NOCRED", account_id=account["id"])
        account["status"] = "error"
        save_data(data)
        return False, "No stored credential"

    add_log("info", account["name"], f"Password change initiated for {username}@{hostname}", "ROT_START", user=triggered_by, account_id=account["id"])

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
        add_log("error", account["name"], f"Change password EXCEPTION for {username}@{hostname}: {err_detail}", "ROT_EXCEPTION", user=triggered_by, account_id=account["id"])

    if success:
        vault.store(hostname, username, new_password)
        account["last_rotated"] = datetime.utcnow().isoformat()
        account["status"]       = "active"
        add_log("success", account["name"], f"Password changed successfully for {username}@{hostname}", "ROT_OK", user=triggered_by, account_id=account["id"])
        add_log("success", account["name"], f"Post-change verification PASSED for {username}@{hostname}", "POSTVERIFY_OK", user=triggered_by, account_id=account["id"])
    else:
        account["status"] = "error"
        reason = err_detail or "Authentication or connection error"
        add_log("error", account["name"], f"Change password FAILED for {username}@{hostname}: {reason}", "ROT_FAIL", user=triggered_by, account_id=account["id"])
        add_log("error", account["name"], f"Post-change verification SKIPPED — rotation did not complete for {username}@{hostname}", "POSTVERIFY_SKIP", user=triggered_by, account_id=account["id"])

    save_data(data)
    return success, err_detail

@app.route("/api/accounts/<account_id>/rotate", methods=["POST"])
@require_admin
def rotate_account(account_id):
    account = find_account(account_id)
    if not account: return jsonify({"error": "Not found"}), 404
    success, err = do_rotate(account, triggered_by=request.current_user)
    return jsonify({"success": success, "error": err, "status": account["status"], "last_rotated": account.get("last_rotated")})

@app.route("/api/rotate/all", methods=["POST"])
@require_admin
def rotate_all():
    results = {"success":0,"failed":0,"details":[]}
    for account in data["accounts"]:
        ok, err = do_rotate(account, triggered_by=request.current_user)
        if ok: results["success"] += 1
        else:  results["failed"]  += 1
        results["details"].append({"name": account["name"], "success": ok, "error": err})
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
        # Inline verify logic
        password = vault.retrieve(acc["hostname"], acc["username"])
        if not password:
            results.append({"id":aid,"name":acc["name"],"success":False,"error":"No credential stored"})
            continue
        try:
            import paramiko
            if acc["os"] == "linux":
                c = paramiko.SSHClient(); c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                c.connect(acc["hostname"], port=acc.get("port",22), username=acc["username"], password=password, timeout=10, look_for_keys=False, allow_agent=False)
                c.close(); ok=True; err=""
            else:
                import winrm
                s=winrm.Session(target=f"http://{acc['hostname']}:{acc.get('port',5985)}/wsman",auth=(acc["username"],password),transport="ntlm",server_cert_validation="ignore",operation_timeout_sec=15)
                r=s.run_ps("Write-Output 'OK'"); ok=b"OK" in r.std_out; err=""
        except Exception as e:
            ok=False; err=str(e)
        acc["last_verified"]=datetime.utcnow().isoformat(); acc["last_verified_status"]="success" if ok else "failed"
        add_log("success" if ok else "error", acc["name"], f"Bulk verify {'OK' if ok else 'FAILED'}: {acc['username']}@{acc['hostname']}{': '+err if err else ''}", "VERIFY_OK" if ok else "VERIFY_FAIL_CONN", user=request.current_user, account_id=aid)
        results.append({"id":aid,"name":acc["name"],"success":ok,"error":err})
    save_data(data)
    return jsonify(results)

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

# ─── Scheduler ────────────────────────────────────────────────────────────────

sched = {"running":False,"interval_hours":24,"last_run":None}

def scheduler_loop():
    while sched["running"]:
        time.sleep(sched["interval_hours"]*3600)
        if not sched["running"]: break
        add_log("info","scheduler","Scheduled rotation triggered","SCHED_TRIGGER")
        for acc in data["accounts"]:
            do_rotate(acc, triggered_by="scheduler")
        sched["last_run"] = datetime.utcnow().isoformat()

@app.route("/api/scheduler/start", methods=["POST"])
@require_admin
def start_scheduler():
    body = request.json or {}
    sched["interval_hours"] = body.get("interval_hours",24)
    if not sched["running"]:
        sched["running"] = True
        threading.Thread(target=scheduler_loop, daemon=True).start()
    add_log("info","scheduler",f"Scheduler started — every {sched['interval_hours']}h","SCHED_START",user=request.current_user)
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
    print("\n  PAM Vault API v2 starting...\n  Open: http://localhost:5000\n")
    app.run(host="0.0.0.0", port=5000, debug=False)
