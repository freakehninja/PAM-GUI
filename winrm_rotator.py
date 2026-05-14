"""winrm_rotator.py — Windows password rotation via WinRM."""

import winrm
from logger import AuditLogger

logger = AuditLogger()


def _session(hostname, username, password, port, use_ssl=False):
    proto    = "https" if use_ssl else "http"
    endpoint = f"{proto}://{hostname}:{port}/wsman"
    try:
        return winrm.Session(target=endpoint, auth=(username, password),
                             transport="ntlm", server_cert_validation="ignore",
                             operation_timeout_sec=30, read_timeout_sec=35)
    except Exception as e:
        logger.log(f"[WinRM] Session failed {username}@{hostname}: {e}", level="ERROR")
        return None


def rotate_windows(hostname, username, current_password, new_password, port=5985, use_ssl=False):
    session = _session(hostname, username, current_password, port, use_ssl)
    if not session:
        return False

    ps = f"""
$ErrorActionPreference = 'Stop'
try {{
    $p = ConvertTo-SecureString -String '{new_password.replace("'", "''")}' -AsPlainText -Force
    Set-LocalUser -Name '{username.replace("'", "''")}' -Password $p
    Write-Output 'PASSWORD_CHANGED'
}} catch {{
    Write-Error $_.Exception.Message; exit 1
}}
"""
    try:
        result = session.run_ps(ps)
        if result.status_code != 0 or b"PASSWORD_CHANGED" not in result.std_out:
            logger.log(f"[WinRM] Change failed on {hostname}: {result.std_err.decode()}", level="ERROR")
            return False
    except Exception as e:
        logger.log(f"[WinRM] Exception on {hostname}: {e}", level="ERROR")
        return False

    # Post-rotation validation
    val = _session(hostname, username, new_password, port, use_ssl)
    if not val:
        logger.log(f"[WinRM] Post-validation FAILED for {username}@{hostname}", level="ERROR")
        return False
    try:
        r = val.run_ps("Write-Output 'VALIDATION_OK'")
        if b"VALIDATION_OK" not in r.std_out:
            return False
    except Exception:
        return False

    logger.log(f"[WinRM] Post-validation PASSED for {username}@{hostname}")
    return True
