# 🛡️ AI Security Field Guide — LLM + MCP Security

> **The most comprehensive, up-to-date, practitioner-first security reference for LLM applications and Model Context Protocol (MCP) deployments.**  
> Covers real CVEs, live attack patterns, OWASP frameworks, red teaming tools, and actionable checklists — updated weekly.

<p align="center">
  <img src="https://img.shields.io/github/stars/YOUR_USERNAME/ai-security-field-guide?style=for-the-badge&color=ff6b35" alt="Stars">
  <img src="https://img.shields.io/github/forks/YOUR_USERNAME/ai-security-field-guide?style=for-the-badge&color=4ecdc4" alt="Forks">
  <img src="https://img.shields.io/badge/Updated-Weekly-brightgreen?style=for-the-badge" alt="Updated">
  <img src="https://img.shields.io/badge/OWASP-Aligned-blue?style=for-the-badge" alt="OWASP">
  <img src="https://img.shields.io/badge/PRs-Welcome-purple?style=for-the-badge" alt="PRs Welcome">
</p>

---

## Why This Guide Exists

The AI security landscape shifted dramatically in 2025–2026:

- 🔴 **492 MCP servers** publicly exposed with no authentication (Trend Micro, 2026)
- 🔴 **CVE-2025-6514** compromised **437,000+ developer environments** via mcp-remote OAuth proxy
- 🔴 **1,184 malicious skills** confirmed across the ClawHub agent registry (Antiy CERT, 2026)  
- 🔴 Claude Code **RCE vulnerability** (CVE-2025-59536, CVSS 8.7) — triggered by opening a repo
- 🔴 **OWASP released 2 new frameworks**: LLM Top 10 (2025) + Agentic Top 10 / ASI (Dec 2025)

Most tutorials show you how to *build* with MCP and LLMs. Almost **none** show you how to *secure* them. This is that guide.

---

## Table of Contents

### Part 1 — LLM Security (OWASP LLM Top 10)
- [LLM01: Prompt Injection](docs/llm-security/LLM01-prompt-injection.md)
- [LLM02: Insecure Output Handling](docs/llm-security/LLM02-output-handling.md)
- [LLM03: Training Data Poisoning](docs/llm-security/LLM03-data-poisoning.md)
- [LLM04: Model Denial of Service](docs/llm-security/LLM04-dos.md)
- [LLM05: Supply Chain Vulnerabilities](docs/llm-security/LLM05-supply-chain.md)
- [LLM06: Sensitive Information Disclosure](docs/llm-security/LLM06-info-disclosure.md)
- [LLM07: Insecure Plugin Design](docs/llm-security/LLM07-plugin-design.md)
- [LLM08: Excessive Agency](docs/llm-security/LLM08-excessive-agency.md)
- [LLM09: Overreliance](docs/llm-security/LLM09-overreliance.md)
- [LLM10: Model Theft](docs/llm-security/LLM10-model-theft.md)

### Part 2 — MCP Security (OWASP MCP Top 10)
- [MCP Attack Surface Overview](docs/mcp-security/overview.md)
- [MCP01: Token Mismanagement](docs/mcp-security/MCP01-token-mismanagement.md)
- [MCP02: Tool Poisoning](docs/mcp-security/MCP02-tool-poisoning.md)
- [MCP03: Prompt Injection via MCP](docs/mcp-security/MCP03-prompt-injection.md)
- [MCP04: Confused Deputy Attacks](docs/mcp-security/MCP04-confused-deputy.md)
- [MCP05: Supply Chain Attacks](docs/mcp-security/MCP05-supply-chain.md)
- [MCP06: Context Poisoning](docs/mcp-security/MCP06-context-poisoning.md)
- [MCP07: OAuth Misconfiguration](docs/mcp-security/MCP07-oauth-misconfig.md)
- [MCP08: SSRF via Fetch Servers](docs/mcp-security/MCP08-ssrf.md)
- [MCP09: Scope Creep](docs/mcp-security/MCP09-scope-creep.md)
- [MCP10: Insecure Transport](docs/mcp-security/MCP10-transport.md)
- [Real CVE Database](docs/mcp-security/CVE-database.md)

### Part 3 — OWASP Agentic Top 10 (ASI 2026)
- [ASI01: Agent Goal Hijack](docs/owasp/ASI01-goal-hijack.md)
- [ASI02: Tool Misuse](docs/owasp/ASI02-tool-misuse.md)
- [ASI03: Identity & Privilege Abuse](docs/owasp/ASI03-identity-abuse.md)
- [ASI04–ASI10: Full Coverage](docs/owasp/ASI04-to-10.md)

### Part 4 — Red Teaming
- [Methodology](docs/red-teaming/methodology.md)
- [Tools Reference](docs/red-teaming/tools.md)
- [Attack Library](docs/red-teaming/attack-library.md)

### Part 5 — Checklists
- [MCP Security Checklist](docs/checklists/mcp-checklist.md)
- [LLM App Checklist](docs/checklists/llm-checklist.md)
- [Agentic System Checklist](docs/checklists/agentic-checklist.md)

---

## Real CVE Quick Reference

| CVE | CVSS | Component | Impact |
|-----|------|-----------|--------|
| CVE-2025-6514 | CRITICAL | mcp-remote (558k+ downloads) | RCE, 437k+ environments compromised |
| CVE-2025-59536 | 8.7 | Claude Code | RCE via `.claude/settings.json` Hook injection |
| CVE-2026-21852 | 5.3 | Claude Code | API key theft via request redirection |
| CVE-2026-28363 | 9.9 | OpenClaw | Localhost WebSocket hijack → data exfiltration |
| CVE-2025-65513 | 9.3 | mcp-fetch-server | SSRF → internal network access |
| CVE-2025-68145/43/44 | HIGH | mcp-server-git | Path bypass + RCE chain |

> Live tracker: [vulnerablemcp.info](https://vulnerablemcp.info)

---

## Frameworks Covered

| Framework | Scope | Released |
|-----------|-------|---------|
| OWASP LLM Top 10 (2025) | LLM application risks | Nov 2024 |
| OWASP Agentic Top 10 (ASI 2026) | Autonomous agent risks | Dec 2025 |
| OWASP MCP Top 10 | MCP protocol risks | 2025 (Beta) |
| OWASP Agentic Skills Top 10 | Agent skill/plugin risks | Q1 2026 |
| MITRE ATLAS | Adversarial ML tactics | Ongoing |
| NIST AI RMF | Governance framework | 2023 |

---

## Red Teaming Tools

| Tool | Best for |
|------|---------|
| [DeepTeam](https://github.com/confident-ai/deepteam) | 50+ vulnerabilities, OWASP/NIST/MITRE frameworks |
| [promptfoo](https://github.com/promptfoo/promptfoo) | CI/CD integration, OWASP plugin mapping |
| [Garak](https://github.com/leondz/garak) | 100+ automated vulnerability probes |
| [PyRIT](https://github.com/Azure/PyRIT) | Microsoft's orchestration framework |
| [agent-scan](https://github.com/agent-scan) | MCP server + agent skill scanner |

---

## Contributing

Contributions are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

- Found a new CVE? Open an issue.
- Better mitigation code? Submit a PR.
- New attack pattern? Document it.

---

## License

[CC BY 4.0](LICENSE) — Free to use, share, and build on with attribution.

---

<p align="center"><b>⭐ Star this repo if it helped you secure something. It helps others find it.</b></p>
