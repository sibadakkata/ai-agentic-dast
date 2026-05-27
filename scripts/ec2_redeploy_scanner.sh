set -e
cd ~/ai-dast-scanner
POSTGRES_PASSWORD=$(grep '^POSTGRES_PASSWORD=' .env | cut -d= -f2- | tr -d '\r')
export DATABASE_URL="postgresql://dast_admin:${POSTGRES_PASSWORD}@dast-postgres:5432/dast_scanner"
docker stop dast-scanner 2>/dev/null || true
docker rm dast-scanner 2>/dev/null || true
docker start dast-postgres 2>/dev/null || true
docker network connect dast-net dast-postgres 2>/dev/null || true
docker run -d --name dast-scanner --network dast-net --restart unless-stopped \
  -p 80:80 --shm-size=2g --memory=4g \
  --cap-add=NET_BIND_SERVICE \
  --sysctl net.ipv4.ip_unprivileged_port_start=80 \
  -v "$HOME/ai-dast-scanner/results:/app/results" \
  -v "$HOME/ai-dast-scanner/imports:/app/imports" \
  --env-file .env \
  -e DATABASE_URL="$DATABASE_URL" \
  -e DUAL_WRITE_PG=1 \
  dast-scanner:latest
sleep 8
docker ps --format '{{.Names}} {{.Status}}'
docker exec dast-scanner python3 /app/scripts/migrate_sqlite_to_pg.py --sqlite /app/results/scanner.db --verify-only