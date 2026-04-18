# MCP04: Confused Deputy Attacks (OAuth Proxy Exploitation)

**Severity: HIGH** | OWASP MCP Top 10 | Updated: April 2026

## What Is It?

A confused deputy attack occurs when a legitimate, trusted intermediary (the MCP proxy) is tricked into performing actions on behalf of an attacker — using the proxy's elevated trust and static credentials. The "deputy" (proxy) is confused about who it's actually serving.

## The Attack — Step by Step

This exploits the combination of: static OAuth client IDs + dynamic client registration + shared consent cookies.

```
Setup:
  MCP Proxy uses a STATIC client_id "mcp-proxy-001" with third-party auth server
  Third-party auth server stores consent cookie after first user authorization

Attack:
  Step 1: Attacker registers a NEW MCP client with the proxy → gets client_id "attacker-client"
  Step 2: Attacker initiates OAuth flow via the proxy
  Step 3: Proxy forwards request to third-party auth using its STATIC client_id "mcp-proxy-001"
  Step 4: Third-party auth sees existing consent cookie → SKIPS consent screen
  Step 5: Third-party auth issues authorization code to the proxy
  Step 6: Proxy delivers token to attacker — who NEVER got user consent
  Step 7: Attacker now has a valid access token to the third-party service

The proxy was "confused" — it served the attacker using the legitimate user's consent.
```

## Vulnerable Proxy Code

```python
# ❌ VULNERABLE: Static client ID + no per-client consent tracking

class VulnerableMCPProxy:
    # Same client ID used for ALL clients connecting to this proxy
    STATIC_CLIENT_ID = "mcp-proxy-static-id-001"
    STATIC_CLIENT_SECRET = os.environ["OAUTH_SECRET"]
    
    def handle_auth_request(self, mcp_client_id: str, scope: str):
        # ❌ Uses static client_id — attacker's request looks identical to legitimate one
        auth_url = build_auth_url(
            client_id=self.STATIC_CLIENT_ID,   # Same for everyone
            scope=scope,
            redirect_uri=self.CALLBACK_URL
        )
        return redirect(auth_url)
    
    def handle_callback(self, code: str, state: str):
        # ❌ No verification of WHICH client initiated this flow
        token = exchange_code_for_token(
            code=code,
            client_id=self.STATIC_CLIENT_ID,
            client_secret=self.STATIC_CLIENT_SECRET
        )
        # ❌ Token delivered without verifying the requesting client
        return token
```

## Secure Proxy Implementation

```python
import secrets
import hashlib
from dataclasses import dataclass
from datetime import datetime, timedelta

@dataclass
class PendingAuthFlow:
    mcp_client_id: str
    scope: str
    user_id: str
    state: str          # CSRF token
    pkce_verifier: str  # PKCE
    initiated_at: datetime
    consented: bool = False

class SecureMCPProxy:
    def __init__(self):
        self.pending_flows: dict[str, PendingAuthFlow] = {}  # state → flow
        self.consent_store: dict[str, bool] = {}  # (client_id, scope, user_id) → consented
    
    def handle_auth_request(self, mcp_client_id: str, scope: str, user_id: str):
        # ✅ Generate per-flow state and PKCE
        state = secrets.token_urlsafe(32)
        pkce_verifier = secrets.token_urlsafe(64)
        pkce_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(pkce_verifier.encode()).digest()
        ).rstrip(b'=').decode()
        
        # ✅ Track this specific flow
        self.pending_flows[state] = PendingAuthFlow(
            mcp_client_id=mcp_client_id,
            scope=scope,
            user_id=user_id,
            state=state,
            pkce_verifier=pkce_verifier,
            initiated_at=datetime.utcnow()
        )
        
        # ✅ Check if this specific client already has consent for this scope
        consent_key = f"{mcp_client_id}:{scope}:{user_id}"
        if consent_key not in self.consent_store:
            # Force explicit consent — never reuse across clients
            return self.show_consent_screen(mcp_client_id, scope, state)
        
        # Existing consent — proceed but still use per-flow credentials
        return self.initiate_oauth_flow(state, pkce_challenge)
    
    def handle_callback(self, code: str, state: str):
        # ✅ Validate state matches a known pending flow
        if state not in self.pending_flows:
            raise SecurityError("Unknown state — possible CSRF or confused deputy attack")
        
        flow = self.pending_flows.pop(state)
        
        # ✅ Check flow hasn't expired (5 minute max)
        if datetime.utcnow() - flow.initiated_at > timedelta(minutes=5):
            raise SecurityError("Auth flow expired")
        
        # ✅ Must have explicit consent recorded
        if not flow.consented:
            raise SecurityError("No consent recorded for this flow")
        
        # Exchange code with PKCE verifier
        token = exchange_code(
            code=code,
            pkce_verifier=flow.pkce_verifier,
            client_id=self.get_per_client_id(flow.mcp_client_id)  # Per-client, not static
        )
        
        # ✅ Record consent only after successful flow
        consent_key = f"{flow.mcp_client_id}:{flow.scope}:{flow.user_id}"
        self.consent_store[consent_key] = True
        
        return token
    
    def get_per_client_id(self, mcp_client_id: str) -> str:
        """Each MCP client gets its own OAuth client registration"""
        # Use Dynamic Client Registration (RFC 7591)
        if mcp_client_id not in self.client_registry:
            self.client_registry[mcp_client_id] = self.register_oauth_client(mcp_client_id)
        return self.client_registry[mcp_client_id]
```

## MCP Spec Requirements (2025-06-18)

The MCP specification now mandates these controls. Verify your implementation:

```python
class MCPOAuthComplianceChecker:
    """Checks your MCP server against the June 2025 spec requirements."""
    
    REQUIREMENTS = {
        "pkce_required": "Authorization Code flow MUST use PKCE (S256 method)",
        "redirect_uri_validation": "Redirect URIs MUST be validated against registered list",
        "resource_indicators": "RFC 8707 Resource Indicators MUST be implemented",
        "https_required": "All auth endpoints MUST be served over HTTPS",
        "token_expiry": "Access tokens MUST have expiration times",
        "no_implicit_grant": "Implicit grant flow MUST NOT be used",
        "no_password_grant": "Resource Owner Password grant MUST NOT be used",
    }
    
    def check_server(self, mcp_server_url: str) -> dict:
        results = {}
        
        # Check PKCE
        results["pkce_required"] = self.test_pkce_enforcement(mcp_server_url)
        
        # Check redirect URI validation
        results["redirect_uri_validation"] = self.test_redirect_validation(mcp_server_url)
        
        # Check HTTPS
        results["https_required"] = mcp_server_url.startswith("https://")
        
        # Check implicit grant is rejected
        results["no_implicit_grant"] = self.test_implicit_grant_rejected(mcp_server_url)
        
        failing = [k for k, v in results.items() if not v]
        return {
            "compliant": len(failing) == 0,
            "failing": failing,
            "details": results
        }
```

## Testing for Confused Deputy Vulnerability

```bash
# Test script — check if your proxy is vulnerable
# Run this against your own MCP proxy BEFORE deploying

# Step 1: Register a legitimate client
CLIENT_1=$(curl -s -X POST "$MCP_PROXY/register" \
  -H "Content-Type: application/json" \
  -d '{"client_name": "legitimate-client", "redirect_uris": ["http://localhost:3000/callback"]}')
CLIENT_1_ID=$(echo $CLIENT_1 | jq -r '.client_id')

# Step 2: Complete a legitimate auth flow (sets consent cookie)
# ... complete OAuth flow with CLIENT_1 ...

# Step 3: Register an attacker client
CLIENT_2=$(curl -s -X POST "$MCP_PROXY/register" \
  -H "Content-Type: application/json" \
  -d '{"client_name": "attacker-client", "redirect_uris": ["http://attacker.com/steal"]}')
CLIENT_2_ID=$(echo $CLIENT_2 | jq -r '.client_id')

# Step 4: Try to get a token as CLIENT_2 using CLIENT_1's consent
# If this succeeds WITHOUT showing a consent screen → VULNERABLE
AUTH_URL="$MCP_PROXY/auth?client_id=$CLIENT_2_ID&scope=read&state=test123"
echo "Test this URL in a browser that has CLIENT_1 consent cookie:"
echo "$AUTH_URL"
echo "If you get a token without seeing a consent screen → your proxy is VULNERABLE to confused deputy attacks"
```

## Checklist

- [ ] Each MCP client has its own OAuth client registration (no shared static client_id)
- [ ] Per-client consent tracked separately (never reuse consent across clients)
- [ ] PKCE enforced on all authorization flows (S256 method)
- [ ] Redirect URIs validated against strict per-client allowlist
- [ ] State parameter validated on all callbacks (CSRF protection)
- [ ] Authorization flows expire after 5 minutes
- [ ] Resource Indicators (RFC 8707) implemented
- [ ] Implicit grant flow disabled
- [ ] All auth endpoints over HTTPS

## References

- [MCP Security Best Practices — modelcontextprotocol.io](https://modelcontextprotocol.io/specification/draft/basic/security_best_practices)
- [OAuth 2.1 Draft Specification](https://oauth.net/2.1/)
- [RFC 8707 — Resource Indicators for OAuth 2.0](https://datatracker.ietf.org/doc/html/rfc8707)
- [RFC 7591 — Dynamic Client Registration](https://datatracker.ietf.org/doc/html/rfc7591)
