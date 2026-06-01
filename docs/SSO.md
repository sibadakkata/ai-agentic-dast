# SSO setup and IdP handoff (DAST Scanner)

> **Operator RBAC details:** [SSO_RBAC.md](SSO_RBAC.md) (roles, invites, troubleshooting).
> **This document:** IdP ticket payload, env vars, cutover runbook, and group provisioning model.

Production URL: **https://rt.ai.webscanner.gendigital.com**

## Group provisioning model

| Source | App role |
|--------|----------|
| Entra group in `SSO_USER_GROUP_IDS` (object ID) | `user` on first login; re-login does **not** demote manually assigned admins |
| Entra group in `SSO_ADMIN_GROUP_IDS` | **Ignored** — admin is never granted from AD groups |
| Admin invite (`POST /api/users/invite` with `role=admin`) | `admin` on first SSO login |
| Admin promotes existing user (User Management → **Make admin**) | `admin` persists across SSO re-logins |
| `INITIAL_ADMIN_EMAILS` (bootstrap only) | `admin` on first SAML login |

## Environment variables (names only)

| Variable | Required | Purpose |
|----------|----------|---------|
| `SSO_ENABLED` | Yes (prod) | `true` = SAML login; `false` = interim local `/login` form |
| `SAML_IDP_METADATA_URL` | When SSO on | Entra federation metadata URL |
| `SAML_SP_ENTITY_ID` | When SSO on | SP Entity ID (Entra Identifier) |
| `SAML_SP_ACS_URL` | When SSO on | Assertion Consumer URL (`…/sso/acs`) |
| `SAML_SP_CERT_PATH` | Optional | SP signing cert PEM path |
| `SAML_SP_KEY_PATH` | Optional | SP private key PEM path |
| `SAML_IDP_ENTITY_ID` | Alt to metadata | Manual IdP entity ID |
| `SAML_IDP_SSO_URL` | Alt to metadata | Manual IdP SSO URL |
| `SAML_IDP_CERT` | Alt to metadata | IdP signing cert PEM |
| `SAML_DEBUG` | Optional | Verbose SAML errors (`false` default) |
| `SSO_USER_GROUP_IDS` | For AD auto-access | Comma-separated Entra group **object IDs** → `user` |
| `SSO_ADMIN_GROUP_IDS` | **Do not use** | Ignored by app; admin via manual elevation only |
| `SSO_GROUP_CLAIM_NAME` | Optional | Override groups claim attribute name |
| `INITIAL_ADMIN_EMAILS` | Bootstrap | Comma-separated emails → `admin` on first SAML login |
| `PUBLIC_BASE_URL` | Optional | Invite link base (default: request host) |
| `DAST_SESSION_SECRET` | Recommended | Session cookie HMAC secret |
| `DAST_COOKIE_SECURE` | Production | `true` behind HTTPS |

Store PEM files under `config/saml/` (gitignored). Never commit production values.

## SAML SP endpoints (production)

| Item | Value |
|------|--------|
| Entity ID | Value of `SAML_SP_ENTITY_ID` (e.g. `https://rt.ai.webscanner.gendigital.com/`) |
| ACS URL | `https://rt.ai.webscanner.gendigital.com/sso/acs` |
| SP metadata | `https://rt.ai.webscanner.gendigital.com/sso/metadata` |
| Login start | `https://rt.ai.webscanner.gendigital.com/sso/login` |
| SLO | **Not configured** — `/sso/logout` clears app session only (no IdP SLO) |

Metadata is served when `SAML_SP_ENTITY_ID` and `SAML_SP_ACS_URL` are set (even before `SSO_ENABLED=true`) so the IdP team can fetch SP metadata during setup.

## SAML attributes expected from IdP

| Purpose | Source | Attribute names tried (first match wins) |
|---------|--------|------------------------------------------|
| Email | NameID or attribute | NameID; `email`, `mail`, `EmailAddress`, `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress` |
| Display name | Attribute | `name`, `displayName`, `http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name`, `http://schemas.microsoft.com/identity/claims/displayname` |
| Groups | Attribute (multi-value) | `SSO_GROUP_CLAIM_NAME` if set; else `groups`; else `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |

**Entra recommendation:** NameID = email; optional claims for name; **Groups** claim with **Security groups** emitting **Group ID** (object GUIDs).

## SP signing certificate

Separate from TLS. Optional PEM pair via `SAML_SP_CERT_PATH` + `SAML_SP_KEY_PATH`. If unset, the SP does not require signed assertions (`wantAssertionsSigned=false`). Upload the SP public cert to Entra only if you enable SP signing.

## First-admin bootstrap

1. Set SAML vars and `SSO_ENABLED=true` on the host `.env` (not committed).
2. Set `INITIAL_ADMIN_EMAILS=your.email@company.com` temporarily.
3. Sign in via **Sign in with SSO** (or `/sso/login`).
4. Confirm admin in **User Management**.
5. Remove your email from `INITIAL_ADMIN_EMAILS`.
6. Optionally keep **backup admin** (`DAST_AUTH_*`) for break-glass via collapsed login form.

Until SSO is enabled, operators use the login page local form (`SSO_ENABLED=false`) or backup Basic Auth.

## Cutover runbook (enable SSO on EC2)

1. **IdP ready:** Entra enterprise app, Reply URL, Entity ID, federation metadata URL, groups claim, test user in `SSO_USER_GROUP_IDS` group.
2. **Host `.env`** (on EC2, not git): set all `SAML_*`, `SSO_ENABLED=true`, `SSO_USER_GROUP_IDS=<user-group-object-id>`, leave `SSO_ADMIN_GROUP_IDS` empty, `SAML_SP_ACS_URL=https://rt.ai.webscanner.gendigital.com/sso/acs`, `SAML_SP_ENTITY_ID=…`, `DAST_SESSION_SECRET`, `DAST_COOKIE_SECURE=true`, `PUBLIC_BASE_URL=https://rt.ai.webscanner.gendigital.com`.
3. **Scan check:** run `scripts/check_scan_active.py` — must exit 0.
4. **Restart container:** `docker compose` / `docker restart dast-scanner` (no deploy of app code required if only `.env` changed).
5. **Verify metadata:** `curl -sS https://rt.ai.webscanner.gendigital.com/sso/metadata | head`
6. **Test SSO:** non-admin test user in AD group signs in → role `user`.
7. **Test backup:** collapsed **Use backup admin login** with `DAST_AUTH_*` still works.
8. **Test admin path:** bootstrap or invite admin; promote another user via User Management → **Make admin**; confirm they stay admin after re-login.

## Post-IdP test plan

- [ ] SAML login succeeds for user in `SSO_USER_GROUP_IDS`
- [ ] User without group/invite sees `/sso/denied`
- [ ] Manually promoted admin retains `admin` after SSO re-login
- [ ] Invite with `role=admin` works on first login
- [ ] `/api/auth/config` returns `{"sso_enabled": true}`
- [ ] Automation still works with `DAST_AUTH_*` on `/api/*`

## Copy-paste IdP ticket payload

See section **IdP ticket (copy-paste)** in the parent README or paste from your deployment ticket template using the table values above. Fill `SAML_SP_ENTITY_ID` and the user group object ID from Entra after the IdP team creates the security group.