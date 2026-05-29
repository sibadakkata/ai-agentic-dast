#!/bin/bash
cat > /tmp/scan_body.json << 'ENDJSON'
{"target_url":"https://ai.norton.com","scan_type":"ai_agent","focus_areas":["LLM"],"llm_scan_depth":"standard","scan_intensity":"standard"}
ENDJSON
docker cp /tmp/scan_body.json dast-scanner:/tmp/
docker exec dast-scanner curl -s -X POST http://localhost:80/api/scan -H "Content-Type: application/json" -d @/tmp/scan_body.json
