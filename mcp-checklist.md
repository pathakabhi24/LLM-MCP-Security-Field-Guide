# MCP Security Checklist

Copy this into your project. Check each item before deploying any MCP-powered system.

---

## TRANSPORT & NETWORK
- [ ] All MCP endpoints served over HTTPS (TLS 1.3)
- [ ] No plain HTTP endpoints — not even internally
- [ ] TLS certificates valid and from trusted CA (or properly pinned)
- [ ] HSTS headers configured (`max-age=31536000; includeSubDomains`)
- [ ] MCP server NOT publicly exposed without VPN/tunnel unless required
- [ ] 492 public MCP servers found with zero auth — check if yours is one (Trend Micro, 2026)

## AUTHENTICATION & AUTHORIZATION
- [ ] OAuth 2.1 implemented (MCP spec requires this since June 2025 update)
- [ ] PKCE flow used — not implicit grant
- [ ] Per-client consent tracking (never reuse consent cookies across clients)
- [ ] Redirect URIs validated against strict allowlist
- [ ] Resource Indicators (RFC 8707) implemented
- [ ] Agent tokens: TTL ≤ 1 hour
- [ ] Token rotation implemented and verified
- [ ] No anonymous/unauthenticated tool endpoints

## TOKEN & SECRET MANAGEMENT
- [ ] Zero hardcoded credentials (run TruffleHog/gitleaks to verify)
- [ ] All secrets loaded from environment variables or secrets manager
- [ ] No tokens in URLs (use Authorization header)
- [ ] No tokens in log output
- [ ] Pre-commit hooks block credential commits
- [ ] GitHub secret scanning enabled

## TOOL SECURITY
- [ ] Tool descriptions scanned for injection patterns before loading
- [ ] Tool allowlist maintained with integrity hashes
- [ ] Unverified MCP servers blocked
- [ ] Tool definitions re-validated on each server connection
- [ ] Destructive tools require explicit human confirmation
- [ ] Tool permissions follow least-privilege principle
- [ ] All tool calls logged with full context

## CONTEXT & MEMORY
- [ ] Context isolated per session (no cross-session bleeding)
- [ ] Tool results treated as untrusted data, not instructions
- [ ] Sensitive fields filtered before passing to tools (field allowlist)
- [ ] Context integrity signed between agent hops (HMAC)

## SSRF PREVENTION
- [ ] All fetch/URL tools validate against private IP ranges
- [ ] Cloud metadata endpoints explicitly blocked (169.254.169.254, etc.)
- [ ] Only HTTPS scheme allowed (not http, file, ftp, gopher)
- [ ] DNS rebinding protection implemented (resolve + re-check IP)
- [ ] Response size limits on fetched content

## SUPPLY CHAIN
- [ ] All MCP packages pinned to exact versions with integrity hashes
- [ ] `npm audit` / `pip-audit` runs in CI on every build
- [ ] No auto-update enabled for MCP servers in production
- [ ] Internal registry of vetted/approved MCP servers maintained
- [ ] Docker images pinned by digest (not just tag)
- [ ] MCP servers run in sandboxed containers

## SANDBOXING
- [ ] MCP servers run with read-only filesystem where possible
- [ ] Network access restricted by default (allowlist approach)
- [ ] All Linux capabilities dropped (`--cap-drop=ALL`)
- [ ] `no-new-privileges` security option set
- [ ] Resource limits set (CPU, memory, file descriptors)

## MONITORING & LOGGING
- [ ] Every tool call logged: tool name, params, user, timestamp, result
- [ ] Failed authentication attempts logged and alerted
- [ ] Anomaly detection on tool usage patterns
- [ ] Alert on: high-frequency calls, unusual tool chains, auth failures
- [ ] Log retention policy defined and enforced

## INCIDENT RESPONSE
- [ ] Kill switch implemented for rapid agent shutdown
- [ ] Incident response plan documented for compromised MCP server
- [ ] Token revocation process tested
- [ ] Contact list for MCP server vendors/maintainers available
