#!/usr/bin/env bash
set -euo pipefail
ROOT="$(git rev-parse --show-toplevel)"
SRC="$ROOT/.githooks"
DST="$ROOT/.git/hooks"
mkdir -p "$DST"
for hook in "$SRC"/*; do
  [ -f "$hook" ] || continue
  name="$(basename "$hook")"
  cp "$hook" "$DST/$name"
  chmod +x "$DST/$name"
  echo "Installed $name -> $DST/$name"
done
echo "Done."
