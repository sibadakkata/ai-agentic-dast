#!/usr/bin/env bash
# OpenClaw Skill Installer for AI Agentic DAST Scanner
# Usage: bash install.sh [SCANNER_URL]
set -euo pipefail

SCANNER_URL="${1:-http://localhost:80}"
SKILL_DIR="$HOME/.openclaw/workspace/skills/ai-agentic-scanner"

echo "=== AI Agentic Scanner - OpenClaw Skill Installer ==="
echo ""

# â”€â”€ Step 1: Check if OpenClaw is installed â”€â”€
if ! command -v openclaw &>/dev/null; then
    echo "[!] OpenClaw not found. Installing via Docker..."
    echo ""
    if ! command -v docker &>/dev/null; then
        echo "ERROR: Docker is required. Install Docker first: https://docs.docker.com/get-docker/"
        exit 1
    fi

    if [ ! -d "$HOME/openclaw" ]; then
        echo "[*] Cloning OpenClaw..."
        git clone https://github.com/openclaw/openclaw.git "$HOME/openclaw"
    fi

    cd "$HOME/openclaw"

    if [ ! -f .env ]; then
        cp .env.example .env
        echo "[*] Created .env from template."
        echo "[!] IMPORTANT: Edit $HOME/openclaw/.env to configure your LLM provider."
        echo "    For Anthropic: set LLM_PROVIDER=anthropic and ANTHROPIC_API_KEY=sk-..."
        echo "    For Ollama:    set LLM_PROVIDER=ollama and OLLAMA_BASE_URL=..."
    fi

    echo "[*] Starting OpenClaw containers..."
    docker compose up -d
    echo "[*] Waiting for gateway to be ready..."
    sleep 10
    echo ""
fi

# â”€â”€ Step 2: Install the skill â”€â”€
echo "[*] Installing ai-agentic-scanner skill..."
mkdir -p "$SKILL_DIR"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cp "$SCRIPT_DIR/SKILL.md" "$SKILL_DIR/SKILL.md"

echo "[*] Skill installed to: $SKILL_DIR"

# â”€â”€ Step 3: Set scanner URL in OpenClaw env â”€â”€
OC_ENV="$HOME/.openclaw/.env"
if [ -f "$OC_ENV" ]; then
    if grep -q "SCANNER_URL" "$OC_ENV"; then
        sed -i "s|SCANNER_URL=.*|SCANNER_URL=$SCANNER_URL|" "$OC_ENV"
    else
        echo "SCANNER_URL=$SCANNER_URL" >> "$OC_ENV"
    fi
    echo "[*] SCANNER_URL set to: $SCANNER_URL"
else
    echo "[!] No OpenClaw .env found at $OC_ENV"
    echo "    Manually set: SCANNER_URL=$SCANNER_URL"
fi

echo ""
echo "=== Installation Complete ==="
echo ""
echo "Next steps:"
echo "  1. Open OpenClaw UI at http://127.0.0.1:18789"
echo "  2. Chat: 'Scan https://example.com for vulnerabilities'"
echo "  3. Chat: 'Show me the results from the last scan'"
echo ""
