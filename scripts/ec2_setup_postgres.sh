set -euo pipefail
cd ~/ai-dast-scanner
if [ -f 0001_init.sql ] && [ ! -f migrations/0001_init.sql ]; then mv 0001_init.sql migrations/; fi
grep -q '^POSTGRES_PASSWORD=' .env || echo "POSTGRES_PASSWORD=$(openssl rand -hex 16)" >> .env
POSTGRES_PASSWORD=$(grep '^POSTGRES_PASSWORD=' .env | cut -d= -f2- | tr -d '\r')
export DATABASE_URL="postgresql://dast_admin:${POSTGRES_PASSWORD}@dast-postgres:5432/dast_scanner"
grep -q '^DATABASE_URL=' .env || echo "DATABASE_URL=$DATABASE_URL" >> .env
grep -q '^DUAL_WRITE_PG=' .env || echo "DUAL_WRITE_PG=1" >> .env

docker network create dast-net 2>/dev/null || true

if docker ps -a --format '{{.Names}}' | grep -qx dast-postgres; then
  docker start dast-postgres 2>/dev/null || true
else
  docker pull postgres:16-alpine
  docker run -d --name dast-postgres --network dast-net --restart unless-stopped \
    -e POSTGRES_DB=dast_scanner \
    -e POSTGRES_USER=dast_admin \
    -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
    -v dast-postgres-data:/var/lib/postgresql/data \
    postgres:16-alpine
fi

for i in $(seq 1 30); do
  docker exec dast-postgres pg_isready -U dast_admin -d dast_scanner >/dev/null 2>&1 && break
  sleep 2
done
docker exec dast-postgres pg_isready -U dast_admin -d dast_scanner

docker exec -i dast-postgres psql -U dast_admin -d dast_scanner < migrations/0001_init.sql

docker build -t dast-scanner:latest .

docker stop dast-scanner
docker rm dast-scanner
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
docker exec dast-scanner python3 -c "import web.db_pg; print(web.db_pg.health_check())"