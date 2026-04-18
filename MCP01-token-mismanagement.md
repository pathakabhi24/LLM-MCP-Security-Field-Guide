# MCP01: Token Mismanagement & Secret Exposure

**Severity: CRITICAL** | OWASP MCP Top 10 | Updated: April 2026

## What Is It?

Hard-coded credentials, long-lived tokens, and secrets stored in model memory or protocol logs that expose connected systems to full compromise.

## How Attackers Exploit It

1. **Log scraping**: MCP servers log request details including auth headers
2. **Prompt extraction**: Attacker extracts secrets injected into context via prompt injection
3. **Git history**: Credentials committed to repo and never purged from history
4. **Memory inspection**: Long-lived tokens stored in agent working memory

## Vulnerable Code Patterns

```python
# ❌ CRITICAL: Hardcoded credentials
mcp_server = MCPServer(
    github_token="ghp_xxxxxxxxxxxxxxxxxxxx",
    openai_key="sk-xxxxxxxxxxxxxxxxxxxx",
)

# ❌ HIGH: Logging tokens
logger.info(f"Authenticating with token: {auth_token}")

# ❌ HIGH: Long-lived tokens with no rotation
TOKEN = os.environ["API_TOKEN"]  # Static, never rotates, broad scope

# ❌ HIGH: Tokens passed in URLs (logged by proxies/CDNs)
url = f"https://api.example.com/data?token={secret_token}"
```

## Secure Code

```python
# ✅ Short-lived, scoped credentials
import os
import boto3
from datetime import timedelta

def get_scoped_token(resource: str, scope: str) -> dict:
    """Get a short-lived token scoped to the specific resource."""
    sts = boto3.client('sts')
    response = sts.assume_role(
        RoleArn=f"arn:aws:iam::123456789:role/mcp-agent-{scope}",
        RoleSessionName=f"mcp-session-{resource}",
        DurationSeconds=3600,  # 1 hour max
    )
    return response['Credentials']

# ✅ Secrets in environment, with scanning
GITHUB_TOKEN = os.environ["GITHUB_TOKEN"]  # From env — never hardcoded
if not GITHUB_TOKEN:
    raise EnvironmentError("GITHUB_TOKEN not set")

# ✅ Never log tokens — log IDs instead
token_id = generate_token_id(GITHUB_TOKEN)  # Hash for tracking
logger.info(f"Authenticating with token_id: {token_id[:8]}...")

# ✅ Tokens in Authorization header, never URL
headers = {"Authorization": f"Bearer {token}"}
response = requests.get(url, headers=headers)  # Not in URL
```

## CI/CD Scanning Setup

```yaml
# .github/workflows/secret-scan.yml
name: Secret Scanning
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # Full history scan

      - name: TruffleHog scan
        uses: trufflesecurity/trufflehog@main
        with:
          path: ./
          base: ${{ github.event.repository.default_branch }}
          head: HEAD

      - name: Gitleaks scan
        uses: gitleaks/gitleaks-action@v2
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
```

## Pre-commit Hook

```bash
# Install: pip install pre-commit detect-secrets
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/Yelp/detect-secrets
    rev: v1.4.0
    hooks:
      - id: detect-secrets
        args: ['--baseline', '.secrets.baseline']
  
  - repo: https://github.com/gitleaks/gitleaks
    rev: v8.18.0
    hooks:
      - id: gitleaks
```

## Checklist

- [ ] Zero hardcoded credentials in codebase (run TruffleHog to verify)
- [ ] All tokens loaded from environment variables or secrets manager
- [ ] Token TTL ≤ 1 hour for agent tokens
- [ ] Token rotation implemented and tested
- [ ] Logging sanitized — no tokens in log output
- [ ] Pre-commit hooks blocking credential commits
- [ ] GitHub secret scanning enabled on all repos
- [ ] Secrets manager in use (Vault, AWS SM, Doppler)

## References

- [CVE-2025-6514](https://nvd.nist.gov/vuln/detail/CVE-2025-6514) — mcp-remote OAuth credential leak (437k+ environments)
- [CVE-2025-59536](https://nvd.nist.gov/vuln/detail/CVE-2025-59536) — Claude Code API key exfiltration
- [OWASP MCP Top 10 — MCP01](https://owasp.org/www-project-mcp-top-10/)
