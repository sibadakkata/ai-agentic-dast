#!/usr/bin/env bash
# Smart incremental deploy: hot-patch by default; rebuild images only when classify says so.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

CONTAINER_NAME="${CONTAINER_NAME:-dast-scanner}"
MARKER_FILE="${MARKER_FILE:-$REPO_ROOT/.last_deployed_sha}"
CLASSIFY="$REPO_ROOT/scripts/deploy/classify_changes.py"
CHECK_ACTIVE="$REPO_ROOT/scripts/check_scan_active.py"
CHECK_ENCODING="$REPO_ROOT/scripts/checks/check_no_null_bytes.py"
IMAGE_NAME="${IMAGE_NAME:-ai-dast-scanner}"

command -v docker >/dev/null 2>&1 || { echo "ERROR: docker not found"; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found"; exit 1; }

OLD_SHA="$(cat "$MARKER_FILE" 2>/dev/null || echo "")"
NEW_SHA="$(git rev-parse HEAD)"
if [ -z "$OLD_SHA" ]; then
  echo "==> No $MARKER_FILE — classifying HEAD~1..HEAD"
  REV_RANGE="HEAD~1..HEAD"
else
  REV_RANGE="${OLD_SHA}..${NEW_SHA}"
fi

echo "==> Deploy plan for $REV_RANGE"
PLAN_JSON="$(python3 "$CLASSIFY" "$REV_RANGE" --json)"
echo "$PLAN_JSON" | python3 -c "import json,sys; p=json.load(sys.stdin); print('  ui_hotpatch:', p['needs_ui_hotpatch']); print('  ui_rebuild:', p['needs_ui_rebuild']); print('  runner_rebuild:', p['needs_runner_rebuild'])"

NEEDS_UI_HOTPATCH="$(echo "$PLAN_JSON" | python3 -c "import json,sys; print('1' if json.load(sys.stdin)['needs_ui_hotpatch'] else '0')")"
NEEDS_UI_REBUILD="$(echo "$PLAN_JSON" | python3 -c "import json,sys; print('1' if json.load(sys.stdin)['needs_ui_rebuild'] else '0')")"
NEEDS_RUNNER_REBUILD="$(echo "$PLAN_JSON" | python3 -c "import json,sys; print('1' if json.load(sys.stdin)['needs_runner_rebuild'] else '0')")"

if ! python3 "$CHECK_ENCODING" --all; then
  echo "ERROR: encoding check failed — fix UTF-16/null-byte files before deploy"
  exit 1
fi

if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
  echo "==> Checking for active scans..."
  docker cp "$CHECK_ACTIVE" "$CONTAINER_NAME:/tmp/check_scan_active.py" 2>/dev/null || true
  if ! docker exec "$CONTAINER_NAME" python3 /tmp/check_scan_active.py; then
    echo "ERROR: Active scan detected. Deployment aborted."
    exit 1
  fi
fi

if [ "$NEEDS_UI_REBUILD" = "1" ]; then
  echo "==> UI image rebuild required"
  docker build -t "$IMAGE_NAME" .
  if docker ps -a --format '{{.Names}}' | grep -q "^${CONTAINER_NAME}$"; then
    docker stop "$CONTAINER_NAME" 2>/dev/null || true
    docker rm "$CONTAINER_NAME" 2>/dev/null || true
  fi
  if [ -f docker-compose.yml ] && docker compose version >/dev/null 2>&1; then
    docker compose up -d
  elif [ -f docker-compose.yml ] && docker-compose version >/dev/null 2>&1; then
    docker-compose up -d
  else
    echo "    Image rebuilt. Start container with your usual run/compose command."
  fi
elif [ "$NEEDS_UI_HOTPATCH" = "1" ]; then
  echo "==> Hot-patching UI container files"
  mapfile -t FILES < <(echo "$PLAN_JSON" | python3 -c "import json,sys; [print(f) for f in json.load(sys.stdin)['hotpatch_files']]")
  for rel in "${FILES[@]}"; do
    [ -f "$rel" ] || continue
    dest="/app/$rel"
    echo "    $rel -> $dest"
    docker cp "$rel" "$CONTAINER_NAME:$dest"
  done
  echo "==> Restarting $CONTAINER_NAME"
  docker restart "$CONTAINER_NAME"
else
  echo "==> No UI container changes to hot-patch"
fi

if [ "$NEEDS_RUNNER_REBUILD" = "1" ]; then
  echo "==> Runner image rebuild required"
  echo "    Build from repo root, e.g.:"
  echo "      docker build -f scanners/runner/Dockerfile -t dast-scanner-runner:latest ."
  echo "      # tag + push to ECR (README Step 4 or scripts/ec2_build_push_runner.py build-host)"
fi

echo "$NEW_SHA" > "$MARKER_FILE"
echo "==> Deploy complete. Recorded $NEW_SHA in $MARKER_FILE"
