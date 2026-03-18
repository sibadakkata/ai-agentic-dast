# Troubleshooting

[← Back to README](../README.md)

When a scan fails, the UI shows a red **Scan Error** banner with details. Here's every known failure mode, cause, and fix.

## Content Filtered (Guardrails)

```
ContentFiltered: Model bedrock/... refuses security-testing prompts
```

**Cause**: Model's safety guardrails block security-testing prompts.

| Model | Status |
|-------|--------|
| Amazon Nova Micro/Lite/Pro | Always blocked |
| Amazon Titan | Always blocked |
| Claude Haiku 4.5 | Works |
| Claude Sonnet 4.6 | Works |
| Ministral 8B / 14B | Works |
| Mistral Small | Works but poor quality |

**Fix**: Switch to **Claude Haiku 4.5** or **Ministral 14B**.

## Context Window Exceeded

```
ContextWindowExceeded: prompt is too long
```

**Cause**: Conversation history exceeded model's token limit on long scans.

**Auto-recovery**: Scanner trims old history and retries. If insufficient, skips the phase.

**If persistent**:
- Use Claude (200K context window)
- Reduce API endpoints in Postman collection
- Scanner already truncates large responses

## Malformed Message Sequence

```
BadRequestError: Expected toolResult blocks at messages.X.content
```

**Cause**: Bedrock requires strict tool-call pairing. Can happen during context trimming.

**Auto-recovery**: Three layers handle this:
1. `_repair_tool_pairs()` validates pairing before every LLM call
2. Error caught as `MalformedMessages` (not generic crash)
3. Messages stripped to last safe point and retried

**If in logs**: Recovery worked. No action needed.

## Rate Limit / Throttling

```
429 Too Many Requests
```

**Cause**: Too many concurrent requests to Bedrock.

**Auto-recovery**: Exponential backoff (2s → 4s → 8s), up to 3 retries.

**If persistent**:
- Run fewer concurrent scans
- Request Bedrock quota increase (AWS Service Quotas)
- Switch to less popular model

## AWS Credentials / Access Denied

```
AccessDeniedException / ExpiredTokenException
```

**Cause**: EC2 IAM role missing Bedrock permissions or wrong region.

**Fix**:
1. Verify IAM role attached to EC2
2. Check: `bedrock:InvokeModel` on `arn:aws:bedrock:*:*:inference-profile/*`
3. Ensure `AWS_DEFAULT_REGION` is set
4. Enable cross-region inference profiles if needed

## Model Not Available

```
ResourceNotFoundException / ModelNotAvailableException
```

**Cause**: Model not enabled in your AWS account or region.

**Fix**:
1. AWS Bedrock console → **Model access** → Request access
2. Some models require approval (wait time varies)
3. Verify model available in your region

## Empty Response

```
Empty response from model at phase X step Y
```

**Cause**: Model returned nothing. Can happen when confused by conversation state.

**Auto-recovery**: Breaks out of step loop, moves to next phase. No findings lost.

## Authentication Failure (Target App)

```
Auth failed / login unsuccessful
```

**Cause**: Couldn't authenticate to target with provided credentials.

**Fix**:
- Verify username/password for the target app
- Check for CAPTCHA, MFA, or IP-based rate limiting
- For API scans, provide auth tokens directly

## Quick Reference

| Error | Auto-Recovers? | Action |
|-------|----------------|--------|
| `content_filtered` | No | Switch model |
| `prompt is too long` | Yes (trims) | None |
| `Expected toolResult` | Yes (repairs) | None |
| `429` / rate limit | Yes (backoff) | Reduce concurrency |
| `AccessDeniedException` | No | Fix IAM permissions |
| `ResourceNotFoundException` | No | Enable model in Bedrock |
| `Empty response` | Yes (skips step) | None |
| `Auth failed` | Partial | Fix target credentials |
