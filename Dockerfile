FROM mcr.microsoft.com/playwright/python:v1.49.0-noble

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && apt-get install -y --no-install-recommends fonts-dejavu-core && rm -rf /var/lib/apt/lists/*
RUN pip install --no-cache-dir -r requirements.txt

RUN playwright install chromium

COPY scanners/ scanners/
COPY scripts/ scripts/
COPY web/ web/
COPY config/scanner_config.yaml config/scanner_config.yaml
COPY config/targets.env.example config/targets.env.example

RUN mkdir -p results/raw results/reports results/cache imports

EXPOSE 8080

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

CMD ["uvicorn", "web.app:app", "--host", "0.0.0.0", "--port", "8080"]
