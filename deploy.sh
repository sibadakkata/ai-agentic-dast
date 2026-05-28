#!/usr/bin/env bash
#
# deploy.sh — Deploy AI DAST Scanner (incremental by default, --full for greenfield)
#
# On an existing host with .last_deployed_sha, runs scripts/deploy/deploy.sh
# (hot-patch by default; UI/runner rebuild only when classify_changes says so).
# Use --full for first-time / dependency / Dockerfile rebuild (original behavior).
#
# Prerequisites on the EC2 instance:
#   - Ubuntu 22.04+ (or Amazon Linux 2023)
#   - Docker installed (Docker Compose optional but recommended)
#   - At least 4 GB RAM, 50 GB disk
#   - Port 80 (web UI) open in Security Group
#
# Usage:
#   1. Copy this entire project folder to the EC2 instance:
#        scp -i key.pem -r ./POC ubuntu@<IP>:~/ai-dast-scanner
#
#   2. SSH into the EC2 and run:
#        cd ~/ai-dast-scanner
#        cp .env.example .env       # then edit .env with your API keys
#        bash deploy.sh
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ "${1:-}" != "--full" ] && [ -f "$SCRIPT_DIR/.last_deployed_sha" ] && [ -f "$SCRIPT_DIR/scripts/deploy/deploy.sh" ]; then
    exec bash "$SCRIPT_DIR/scripts/deploy/deploy.sh"
fi

IMAGE_NAME="ai-dast-scanner"
CONTAINER_NAME="dast-scanner"

# ─── Preflight checks ───────────────────────────────────────────────
command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found. Install Docker first."; exit 1; }

if [ ! -f .env ]; then
    echo "WARNING: No .env file found. Copying .env.example -> .env"
    echo "         Edit .env to add your API keys before scanning."
    cp .env.example .env
fi

# ─── Check for active scans before deploying ─────────────────────────
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "$CONTAINER_NAME"; then
    echo "==> Checking for active scans..."
    docker cp "$SCRIPT_DIR/scripts/check_scan_active.py" "$CONTAINER_NAME:/tmp/check_scan_active.py" 2>/dev/null
    if ! docker exec "$CONTAINER_NAME" python3 /tmp/check_scan_active.py; then
        echo ""
        echo "ERROR: Active scan detected. Deployment aborted."
        echo "       Wait for the scan to finish or stop it manually, then re-run deploy.sh"
        exit 1
    fi
fi

# Load .env
set -a; source .env; set +a

# Detect docker compose availability
HAS_COMPOSE=false
if docker compose version >/dev/null 2>&1; then
    HAS_COMPOSE=true
    COMPOSE_CMD="docker compose"
elif docker-compose version >/dev/null 2>&1; then
    HAS_COMPOSE=true
    COMPOSE_CMD="docker-compose"
fi

# ─── Stop any existing containers ────────────────────────────────────
echo "==> Stopping existing containers (if any)..."
if [ "$HAS_COMPOSE" = true ]; then
    $COMPOSE_CMD down --remove-orphans 2>/dev/null || true
else
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
fi

# ─── Build & start ──────────────────────────────────────────────────
echo "==> Building image..."
if [ "$HAS_COMPOSE" = true ]; then
    $COMPOSE_CMD build
    echo "==> Starting services..."
    $COMPOSE_CMD up -d
else
    docker build -t "$IMAGE_NAME" .
    echo "==> Starting container..."
    docker run -d \
        --name "$CONTAINER_NAME" \
        --network host \
        --restart unless-stopped \
        --env-file .env \
        -e "ANTHROPIC_API_KEY=${ANTHROPIC_API_KEY:-}" \
        -e "OPENAI_API_KEY=${OPENAI_API_KEY:-}" \
        -e "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID:-}" \
        -e "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY:-}" \
        -e "AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-us-east-1}" \
        -e "DAST_AUTH_USER=${DAST_AUTH_USER:-dast-admin}" \
        -e "DAST_AUTH_PASS=${DAST_AUTH_PASS:-changeme}" \
        -e "DUAL_WRITE_PG=${DUAL_WRITE_PG:-0}" \
        -e "DATABASE_URL=${DATABASE_URL:-}" \
        -v "$(pwd)/dast-data/results:/app/results" \
        -v "$(pwd)/dast-data/imports:/app/imports" \
        "$IMAGE_NAME"
fi

# ─── Wait for services ──────────────────────────────────────────────
echo "==> Waiting for dast-scanner to become healthy..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:80/health >/dev/null 2>&1; then
        echo "    dast-scanner is up."
        break
    fi
    [ "$i" -eq 30 ] && echo "    WARNING: dast-scanner not responding after 30s"
    sleep 1
done

# ─── Record deploy SHA (incremental deploy baseline) ────────────────
if command -v git >/dev/null 2>&1 && git rev-parse HEAD >/dev/null 2>&1; then
    git rev-parse HEAD > "$SCRIPT_DIR/.last_deployed_sha"
    echo "==> Recorded $(cat "$SCRIPT_DIR/.last_deployed_sha") in .last_deployed_sha"
fi

# ─── Summary ────────────────────────────────────────────────────────
echo ""
echo "========================================================"
echo "  AI DAST Scanner deployed successfully!"
echo ""
echo "  Web UI:    http://$(curl -sf ifconfig.me 2>/dev/null || echo '<this-ip>'):80"
echo ""
echo "  Credentials: see .env (DAST_AUTH_USER / DAST_AUTH_PASS)"
echo ""
if [ "$HAS_COMPOSE" = true ]; then
    echo "  Logs:  $COMPOSE_CMD logs -f"
    echo "  Stop:  $COMPOSE_CMD down"
else
    echo "  Logs:  docker logs -f $CONTAINER_NAME"
    echo "  Stop:  docker stop $CONTAINER_NAME"
fi
echo "========================================================"
