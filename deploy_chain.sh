#!/bin/bash
docker cp /tmp/agent.py dast-scanner:/app/scanners/ai_agent/agent.py
docker cp /tmp/tools.py dast-scanner:/app/scanners/ai_agent/tools.py
docker cp /tmp/prompts.py dast-scanner:/app/scanners/ai_agent/prompts.py
docker cp /tmp/runtime_verifier.py dast-scanner:/app/scripts/runtime_verifier.py
docker restart dast-scanner
echo "Waiting for app to come up..."
sleep 6
STATUS=$(curl -s -o /dev/null -w '%{http_code}' http://localhost:80/)
echo "App status: $STATUS"
