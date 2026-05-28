#!/bin/bash
curl -s -X POST http://localhost:80/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://ai.norton.com/",
    "username": "siba.dakkata@gendigital.com",
    "password": "Avyan@500",
    "scan_mode": "both",
    "auth_type": "auto",
    "model": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "scan_profile": "vulnerability_scan"
  }'
