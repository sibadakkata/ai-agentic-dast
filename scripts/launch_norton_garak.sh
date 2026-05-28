#!/bin/bash
curl -s -X POST http://localhost:80/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target_url":"https://ai.norton.com/","scan_mode":"standard","username":"siba.dakkata@gendigital.com","password":"Avyan@500","auth_type":"form","focus_areas":["chatbot","llm security"]}'
