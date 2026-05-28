FROM mcr.microsoft.com/playwright/python:v1.49.0-noble

WORKDIR /app

COPY scanners/runner/requirements.txt /app/scanners/runner/requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends \
    fonts-dejavu-core xmlsec1 libxmlsec1-dev pkg-config libssl-dev libffi-dev \
    && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r scanners/runner/requirements.txt
RUN playwright install chromium

COPY scanners/ scanners/
COPY scripts/ scripts/
COPY web/ web/
COPY config/scanner_config.yaml config/scanner_config.yaml
COPY config/targets.env.example config/targets.env.example

# Fail the image build if any copied source contains UTF-16 / null bytes.
RUN python3 <<'PY'
import pathlib
root = pathlib.Path("/app")
exts = {".py", ".sh", ".yaml", ".yml", ".json"}
bad = [
    str(p.relative_to(root))
    for p in root.rglob("*")
    if p.is_file() and p.suffix.lower() in exts and b"\x00" in p.read_bytes()
]
assert not bad, f"UTF-16/null-byte files in runner image: {bad[:30]}"
PY

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV DUAL_WRITE_PG=1
ENV RUNNER_PG_ONLY=1

ENTRYPOINT ["python3", "-m", "scanners.runner.main"]
