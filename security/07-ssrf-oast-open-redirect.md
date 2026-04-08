# Security Test Plan: SSRF, Open Redirect, and Out-of-Band Testing

## Target
All endpoints accepting URLs or performing server-side requests — `http://localhost:9999`

## Context
Autentico has several features that accept or process URLs:
- `redirect_uri` in OAuth flows
- `post_logout_redirect_uris` in client configuration
- Federation/SSO provider configuration (observed `/admin/api/federation`)
- Dynamic client registration (`/oauth2/register`)
- SMTP configuration in settings (email OTP delivery)

## Tests

### 1. SSRF via Federation/Provider Configuration (HIGH)
**Why:** If the server fetches metadata from configured identity provider URLs, it may be vulnerable to SSRF.

- [ ] Configure a federation provider with an OAST domain URL — check for DNS/HTTP callbacks
- [ ] Configure a federation provider pointing to internal services: `http://127.0.0.1:9999/admin/api/settings`, `http://169.254.169.254/latest/meta-data/`
- [ ] Configure with `file:///etc/passwd` or `gopher://` scheme

### 2. SSRF via Dynamic Client Registration
**Why:** `/oauth2/register` accepts client metadata including URIs that may be fetched server-side.

- [ ] Register a client with `logo_uri`, `client_uri`, `policy_uri`, `tos_uri` pointing to OAST domains
- [ ] Register with `sector_identifier_uri` pointing to OAST domain (OIDC spec says this MUST be fetched)
- [ ] Register with `redirect_uris` containing internal IPs

### 3. Open Redirect (HIGH)
**Why:** Multiple endpoints perform redirects based on user input.

- [ ] `GET /oauth2/authorize` with `redirect_uri=https://evil.com` for a client with lax URI validation
- [ ] `POST /oauth2/logout` with `post_logout_redirect_uri=https://evil.com`
- [ ] Check if `/admin/callback` or `/account/callback` validate the redirect before following it
- [ ] Test URL parser differentials: `redirect_uri=http://localhost:9999@evil.com/callback`
- [ ] Test `redirect_uri=//evil.com/callback` (protocol-relative)

### 4. OAST-Based Discovery
**Why:** Out-of-band testing can detect blind SSRF, DNS rebinding, and other server-side interactions.

- [ ] Create OAST session
- [ ] Set OAST domain in various URL fields (federation config, client registration, SMTP server)
- [ ] Poll for DNS lookups and HTTP callbacks
- [ ] Use OAST in email-related fields if SMTP is configured (blind SSRF via email sending)

### 5. SMTP Configuration Abuse
**Why:** SMTP settings in admin panel could be used for SSRF if the server connects to arbitrary hosts.

- [ ] Set SMTP host to OAST domain — check for connection
- [ ] Set SMTP host to internal IP — potential internal port scanning
- [ ] Set SMTP host to `127.0.0.1:9999` — check for localhost connection

## Approach
1. Create OAST session using sectool
2. Configure test payloads with OAST subdomains
3. Ask user to input OAST URLs in federation/SMTP settings via admin UI
4. Poll OAST for interactions
5. Analyze any callbacks for request details
