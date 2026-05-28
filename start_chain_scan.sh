#!/bin/bash
curl -s -X POST http://localhost:80/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://juice-shop.herokuapp.com/",
    "model": "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
    "scan_mode": "website",
    "scan_intensity": "standard",
    "focus_areas": ["xss", "sqli", "auth", "idor", "chain"]
  }'
