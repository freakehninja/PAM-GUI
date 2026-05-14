# PAM Vault — Full System
Gilbert Andersen Sutanto · TP072352 · APU FYP

## Stack
- **Backend**: Python + Flask REST API
- **Frontend**: React SPA (served by Flask from `/static/index.html`)
- **Vault**: AES-encrypted credential store (Fernet + PBKDF2)
- **MFA**: Real TOTP (RFC 6238) — compatible with Microsoft Authenticator

---

## Setup on Controller VM

```bash
# 1. Clone / copy project
cd ~/Desktop
git clone https://github.com/freakehninja/PAM-Solution-Lightweight
cd PAM-Solution-Lightweight

# 2. Create venv
python3 -m venv venv --system-site-packages
source venv/bin/activate

# 3. Install dependencies
pip install cryptography paramiko pywinrm flask flask-cors

# 4. Make start script executable
chmod +x start.sh

# 5. Start the server
./start.sh
```

Enter a vault master password when prompted (this encrypts all stored credentials).

---

## Access the GUI

Open in browser on controller:
```
http://localhost:5000
```

From any VM on the same network:
```
http://192.168.1.10:5000
```

---

## First Run

1. On first visit, click **"Create admin account"**
2. Set username + password
3. **Scan the QR code** with Microsoft Authenticator — required to retrieve credentials later
4. Log in with your credentials

---

## How Credential Retrieval Works

1. Click 🔑 on any account in the vault
2. Open Microsoft Authenticator on your phone
3. Enter the 6-digit rotating code
4. The password is revealed — this is logged in the audit trail

The TOTP is verified server-side using RFC 6238 (same standard as Microsoft/Google Authenticator).

---

## Rotation Flow

Each rotation cycle runs three steps per account:
1. **Daily Verification** — confirms connectivity before rotating
2. **Password Change** — SSH (Linux) or WinRM (Windows) remote password update
3. **Post-Rotation Validation** — reconnects with new password to confirm success

All steps are logged with error codes under **Audit Logs**.

---

## Environment Variables

| Variable | Description |
|---|---|
| `VAULT_MASTER_PASSWORD` | Master password to decrypt the vault (required) |

---

## File Structure

```
PAM-Solution-Lightweight/
├── api.py                  ← Flask REST API (main entry point)
├── vault.py                ← Encrypted credential store
├── totp_util.py            ← RFC 6238 TOTP implementation
├── password_gen.py         ← Secure password generator
├── ssh_rotator.py          ← Linux SSH rotation
├── winrm_rotator.py        ← Windows WinRM rotation
├── logger.py               ← Audit logger
├── requirements.txt
├── start.sh                ← Easy start script
├── static/
│   └── index.html          ← React frontend (served by Flask)
├── vault/
│   ├── credentials.enc     ← DO NOT COMMIT — encrypted vault
│   └── vault.salt          ← DO NOT COMMIT
├── config/
│   └── app_data.json       ← Users, accounts, logs (no passwords)
└── logs/
    └── rotation_audit.log
```

---

## Security Notes

- Passwords are **never** stored in `app_data.json` — only in the encrypted vault
- The vault file is AES-128-CBC + HMAC-SHA256 encrypted
- All credential retrievals require a valid TOTP code verified server-side
- Every retrieval, rotation, login, and logout is logged with a unique code
- Session tokens expire after 8 hours; cart is cleared on logout
