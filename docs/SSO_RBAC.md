# SSO and RBAC

The AI DAST scanner supports **SAML 2.0** sign-in via **Microsoft Entra ID** (Azure AD) and **role-based access control** with two roles: `admin` (Red Team Admin) and `user` (Member).

## Environment variables

| Variable | Required | Description |
|----------|----------|-------------|
| `SSO_ENABLED` | No | `true` to enable SAML; `false` (default) uses local username/password (`DAST_AUTH_USER` / `DAST_AUTH_PASS`). |
| `INITIAL_ADMIN_EMAILS` | No | Comma-separated emails that become `admin` on first successful SAML login. **Leave empty in production config files committed to git.** |
| `SAML_IDP_METADATA_URL` | When SSO on | Entra ID federation metadata URL. |
| `SAML_SP_ENTITY_ID` | When SSO on | Application (client) ID URI — Entra **Identifier (Entity ID)**. |
| `SAML_SP_ACS_URL` | When SSO on | Assertion Consumer Service URL — must match Entra **Reply URL** (e.g. `https://scanner.example.com/sso/acs`). |
| `SAML_SP_CERT_PATH` | No | Path to SP X.509 cert (PEM). If set with `SAML_SP_KEY_PATH`, assertions may be signed. |
| `SAML_SP_KEY_PATH` | No | Path to SP private key (PEM). |
| `SAML_IDP_ENTITY_ID` | Alt to metadata | Manual IdP entity ID if not using metadata URL. |
| `SAML_IDP_SSO_URL` | Alt to metadata | Manual IdP SSO URL. |
| `SAML_IDP_CERT` | Alt to metadata | IdP signing certificate (PEM string). |
| `PUBLIC_BASE_URL` | No | Base URL for invite links (defaults to request host). |
| `DAST_SESSION_SECRET` | Recommended | HMAC secret for session cookies (set in production). |
| `DAST_AUTH_USER` / `DAST_AUTH_PASS` | Local dev | Used when `SSO_ENABLED=false` and for Basic Auth API access. |
| `SSO_ADMIN_GROUP_IDS` | Optional | Comma-separated Entra **group object IDs** (GUIDs) that grant app role `admin`. |
| `SSO_USER_GROUP_IDS` | Optional | Comma-separated Entra group object IDs (GUIDs) that grant app role `user`. |
| `SSO_GROUP_CLAIM_NAME` | Optional | SAML attribute name for group membership (default: Microsoft `groups` claim URI; also tries short name `groups`). |

Store SAML certificates under `config/saml/` (gitignored). Do not commit real keys or production emails.

If **neither** `SSO_ADMIN_GROUP_IDS` nor `SSO_USER_GROUP_IDS` is set, sign-in remains **invite-only** (legacy behavior). When either is set, users in those Entra groups may sign in **without a manual invite**, and their app role is **re-synced from group membership on every SAML login** (admin group wins if both match).

### Access precedence (SAML login)

1. `INITIAL_ADMIN_EMAILS` — bootstrap admin on first login  
2. **Existing active user** — already provisioned accounts  
3. **Valid pending invite** — email matches invite  
4. **Entra group match** — user is in `SSO_ADMIN_GROUP_IDS` and/or `SSO_USER_GROUP_IDS`  
5. **Deny** — `not_in_required_group` when group env is configured but no match; otherwise `not_authorized`

### Entra ID: groups claim (required for group-based access)

In the enterprise application → **Single sign-on** → **Attributes & Claims**, add a **Groups** claim:

- **Claim name:** `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` (or set `SSO_GROUP_CLAIM_NAME` if you use a custom name)  
- **Value:** **Security groups** — emit **group object IDs** (GUIDs), not display names  

Provide the IdP team the two object IDs you place in `SSO_ADMIN_GROUP_IDS` and `SSO_USER_GROUP_IDS` on the scanner host.

Example (`.env` on EC2, not committed):

```bash
SSO_ADMIN_GROUP_IDS=a1b2c3d4-e5f6-7890-abcd-ef1234567890
SSO_USER_GROUP_IDS=f0e1d2c3-b4a5-9678-0123-456789abcdef
```

## Entra ID app registration

1. **App registrations** → New registration → name e.g. `AI DAST Scanner`.
2. **Redirect URI** (Web): `https://<your-host>/sso/acs` (must match `SAML_SP_ACS_URL`).
3. **Identifier (Entity ID)**: same value as `SAML_SP_ENTITY_ID`.
4. **Enterprise application** → Single sign-on → SAML → upload or note **App Federation Metadata Url** → set `SAML_IDP_METADATA_URL`.
5. **Token configuration** → add optional claims: `email`, `name` (or use NameID = email).
6. **Groups claim** → add **Groups** attribute with source **Security groups**, value = **Group ID** (object IDs). Required when using `SSO_ADMIN_GROUP_IDS` / `SSO_USER_GROUP_IDS`.
7. Assign users/groups who may authenticate at Entra (scanner access is still invite-only unless group env vars or bootstrap/invite apply).

## Bootstrapping the first admin

1. Set `SSO_ENABLED=true` and SAML variables on the server.
2. Set `INITIAL_ADMIN_EMAILS=you@example.com` in the deployment environment (not in git).
3. Sign in via **Sign in with Microsoft** — your account is created as `admin`.
4. Remove your email from `INITIAL_ADMIN_EMAILS` after bootstrap if desired.

## Inviting users

1. As **admin**, open **User Management** in the sidebar (SECURITY section).
2. Click **Invite User**, enter email and role.
3. Copy the generated link and send via Slack/Teams (v1 does not send email).
4. Invitee signs in with Microsoft; on first login the invite is consumed and the account is created.

Invites expire after **7 days** by default. Admins can revoke pending invites.

## Roles

| Capability | admin | user |
|------------|-------|------|
| Start scans | Yes | Yes |
| View own scans/reports | Yes | Yes |
| View all scans | Yes | No |
| Delete scans/reports | Yes | No |
| User management | Yes | No |
| Settings page (read) | Yes | Yes |
| UI settings write (`PUT /api/ui-settings`) | Yes | No |

## Troubleshooting

- **Signature mismatch**: Ensure IdP metadata is current; check clock skew (NTP on server); verify `SAML_SP_CERT_PATH` / key pair matches uploaded cert in Entra if signing is enabled.
- **Reply URL mismatch**: Entra Reply URL must exactly equal `SAML_SP_ACS_URL` (scheme, host, path).
- **Not authorized after login**: Email not in `INITIAL_ADMIN_EMAILS`, no pending invite, no existing user, and (if group env is set) not in a configured Entra group — ask an admin to invite you or add you to the correct security group.
- **Not in required group**: Group mapping is enabled but the SAML assertion contained no matching group object ID.
- **Local development**: Set `SSO_ENABLED=false` and use `DAST_AUTH_USER` / `DAST_AUTH_PASS` on the login form.

## Library choice

We use **python3-saml** (OneLogin) for the Service Provider. It is widely used, well documented for Entra AD, and handles metadata parsing and ACS flows with minimal boilerplate compared to **pysaml2**.
