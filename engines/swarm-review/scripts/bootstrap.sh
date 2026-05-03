#!/usr/bin/env bash
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "Checking dependencies..."
command -v python3 >/dev/null || { echo "python3 not found"; exit 1; }
command -v pip3 >/dev/null || { echo "pip3 not found"; exit 1; }

echo "Installing Python dependencies..."
pip3 install -r "$REPO_DIR/requirements.txt"

if ! command -v node >/dev/null; then
  echo "Warning: node not found (screenshots disabled)."
else
  if ! node -e "require('puppeteer')" >/dev/null 2>&1; then
    echo "Warning: puppeteer not installed. Run: npm install puppeteer"
  fi
fi

if [ ! -f "$REPO_DIR/configs/scope.json" ]; then
  echo "Missing configs/scope.json"
  exit 1
fi
if command -v jq >/dev/null; then
  domains_count="$(jq '.domains | length' "$REPO_DIR/configs/scope.json" 2>/dev/null || echo 0)"
  if [ "${domains_count:-0}" -eq 0 ]; then
    echo "configs/scope.json has no domains. Add authorized targets before running."
    exit 1
  fi
fi

echo "Installing skill..."
bash "$REPO_DIR/scripts/install_self.sh"

echo "Running swarm (cautious, OpenClaw)..."
python3 "$REPO_DIR/swarm_orchestrator.py" "${1:-example.com}" \
  --profile cautious \
  --run-vuln \
  --authorized \
  --openclaw \
  --schema-repair \
  --summary-json "$REPO_DIR/output/openclaw_summary.json" \
  --artifact-dir "$REPO_DIR/output/artifacts"
