"""ssh_rotator.py — Linux password rotation via SSH."""

import paramiko
import socket
from logger import AuditLogger

logger = AuditLogger()


def _connect(hostname, username, password, port):
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(hostname=hostname, port=port, username=username, password=password,
                       timeout=10, banner_timeout=10, look_for_keys=False, allow_agent=False)
        return client
    except Exception as e:
        logger.log(f"[SSH] Connect failed {username}@{hostname}:{port} — {e}", level="ERROR")
        return None


def rotate_linux(hostname, username, current_password, new_password, port=22):
    client = _connect(hostname, username, current_password, port)
    if not client:
        return False
    try:
        safe_user = username.replace("'", "'\\''")
        safe_pass = new_password.replace("'", "'\\''")
        stdin, stdout, stderr = client.exec_command(f"echo '{safe_user}:{safe_pass}' | sudo -S chpasswd", timeout=30)
        stdin.write(current_password + "\n")
        stdin.flush()
        exit_code = stdout.channel.recv_exit_status()
        err = stderr.read().decode().strip()
        if exit_code != 0:
            logger.log(f"[SSH] chpasswd failed on {hostname} (exit {exit_code}): {err}", level="ERROR")
            return False
    finally:
        client.close()

    # Post-rotation validation
    val = _connect(hostname, username, new_password, port)
    if not val:
        logger.log(f"[SSH] Post-validation FAILED for {username}@{hostname}", level="ERROR")
        return False
    val.close()
    logger.log(f"[SSH] Post-validation PASSED for {username}@{hostname}")
    return True
