# Contributing to AI Security Field Guide

Thank you for helping make AI systems more secure.

## How to Contribute

### Report a New CVE or Incident
Open an issue with:
- CVE number (if assigned)
- Affected component and version
- CVSS score (if available)
- Brief description of impact
- Link to disclosure or write-up

### Add a Missing Attack Pattern
Submit a PR with:
- Clear description of the attack
- Example code showing the vulnerability
- Example code showing the mitigation
- Reference to source (paper, blog, CVE)

### Improve Existing Mitigations
- Working, tested code examples preferred
- Real-world tested > theoretical
- Include the language/framework version your code was tested with

### Fix Errors
If you find an error in CVE details, CVSS scores, or mitigation advice — please open a PR. Accuracy matters in security.

## Style Guidelines

- Use clear headings
- Include code examples for every attack and mitigation
- Reference your sources (CVEs, papers, blog posts)
- Keep severity labels consistent: CRITICAL / HIGH / MEDIUM / LOW
- Use ✅ for secure patterns, ❌ for vulnerable patterns

## What We Don't Accept

- Proof-of-concept exploits for unpatched vulnerabilities
- Content that primarily enables attacks without defensive value
- Unverified claims without sources

## Review Process

All PRs are reviewed for accuracy and security implications. Expect 1–3 days for review.
