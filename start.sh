#!/bin/bash
# start.sh — Start the PAM Vault server
# Usage: ./start.sh
# Or with custom master password: VAULT_MASTER_PASSWORD=yourpass ./start.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Activate venv if it exists
if [ -d "venv" ]; then
  source venv/bin/activate
fi

# Prompt for vault master password if not set
if [ -z "$VAULT_MASTER_PASSWORD" ]; then
  read -s -p "Enter vault master password: " VAULT_MASTER_PASSWORD
  echo ""
  export VAULT_MASTER_PASSWORD
fi

echo ""
echo "  ⬡  PAM Vault starting..."
echo "  Open browser: http://localhost:5000"
echo "  Or from another VM: http://$(hostname -I | awk '{print $1}'):5000"
echo ""

python3 api.py
