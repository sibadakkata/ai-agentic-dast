# DAST Scanner — Operations runbook

## TLS certificate renewal (ACM + ALB)

The public UI hostname is **https://rt.ai.webscanner.gendigital.com** (ALB terminates TLS).

| Item | Value |
|------|--------|
| **Hostname** | `rt.ai.webscanner.gendigital.com` |
| **ACM cert ARN (us-east-2)** | `arn:aws:acm:us-east-2:168551359048:certificate/0b5f6f37-2a42-48d0-b3a2-778288f5e380` |
| **Expires** | **2026-12-11** (renew before expiry) |

### Renewal process

1. Obtain a new leaf + intermediate chain + private key from the same CA (Sectigo EV).
2. Re-import into the **same** ACM ARN (listeners pick up the new cert automatically):

   ```bash
   aws acm import-certificate \
     --region us-east-2 \
     --certificate-arn arn:aws:acm:us-east-2:168551359048:certificate/0b5f6f37-2a42-48d0-b3a2-778288f5e380 \
     --certificate fileb://leaf.pem \
     --private-key fileb://private.key \
     --certificate-chain fileb://chain.pem
   ```

3. No ALB listener change is required when re-importing to the same ARN.
4. Verify: `curl -v https://rt.ai.webscanner.gendigital.com/health` (expect HTTP 200).

Instance-side nginx (direct IP / break-glass) uses PEM files under `/etc/ssl/dast/` on the EC2 host; update those separately if you rely on direct HTTPS to the instance IP.
