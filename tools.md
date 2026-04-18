# Red Teaming Tools Reference

Updated: April 2026 | Covers: LLM security, MCP security, agentic systems

---

## Tier 1 — Primary Tools (Use These First)

### DeepTeam by Confident AI
**Best for:** Comprehensive automated red teaming against OWASP, NIST, MITRE frameworks

```bash
pip install deepteam
```

```python
from deepteam import red_team
from deepteam.frameworks import OWASPTop10, OWASP_ASI_2026, NIST

async def your_app(prompt: str) -> str:
    return await your_llm_app.chat(prompt)

# Run against all three frameworks
for framework in [OWASPTop10(), OWASP_ASI_2026(), NIST()]:
    results = red_team(model_callback=your_app, framework=framework)
    print(f"{framework.name}: ASR={results.asr:.1%}, Critical={results.critical_count}")
```

**Capabilities:**
- 50+ vulnerability classes (prompt injection, PII, jailbreak, bias, etc.)
- 20+ adversarial attack strategies (multi-turn, encoding, roleplay)
- OWASP LLM Top 10, OWASP ASI 2026, NIST AI RMF, MITRE mapping
- Production guardrails (7 types)
- CLI mode: `deepteam run --framework owasp --target http://localhost:8000`

---

### promptfoo
**Best for:** CI/CD integration, YAML-driven configuration, LLM comparison

```bash
npm install -g promptfoo
promptfoo redteam init
```

```yaml
# redteam.yaml
providers:
  - openai:gpt-4o
  - anthropic:claude-sonnet-4-6

redteam:
  plugins:
    - owasp:llm:01   # Prompt injection
    - owasp:llm:06   # Info disclosure
    - owasp:llm:08   # Excessive agency
    - jailbreak      # General jailbreak
    - pii:direct     # Direct PII requests
    - pii:session    # Session-based PII extraction
    - harmful:cybercrime  # Harmful content
    
  strategies:
    - jailbreak           # Auto-generate jailbreaks
    - prompt-injection    # Indirect injection
    - base64              # Encoding tricks
    - crescendo           # Multi-turn escalation
    - multilingual        # Non-English bypasses
```

```bash
promptfoo redteam generate -c redteam.yaml    # Generate test cases
promptfoo eval -c redteam.yaml                 # Run evaluation
promptfoo redteam report                       # HTML report
```

---

### Garak
**Best for:** Deep automated probing with 100+ built-in probes

```bash
pip install garak
```

```bash
# Scan an OpenAI-compatible endpoint
garak --model_type openai \
      --model_name gpt-4o \
      --probes all \
      --report_prefix my_scan

# Targeted probes
garak --probes prompt_injection,jailbreak,data_leakage \
      --model_type openai \
      --model_name your-model
```

**Probe categories:** prompt injection, jailbreak, data leakage, continuation attacks, encoding, stereotype, harmful content, hallucination

---

## Tier 2 — Specialized Tools

### PyRIT (Microsoft)
**Best for:** Azure/Microsoft environments, orchestrated multi-target attacks

```python
from pyrit.orchestrator import PromptSendingOrchestrator
from pyrit.prompt_target import AzureOpenAIChatTarget
from pyrit.prompt_normalizer import Base64RequestConverter

target = AzureOpenAIChatTarget(
    deployment_name="gpt-4o",
    endpoint=os.environ["AZURE_OPENAI_ENDPOINT"],
    api_key=os.environ["AZURE_OPENAI_API_KEY"],
)

# Run encoded attack
orchestrator = PromptSendingOrchestrator(
    prompt_target=target,
    prompt_converters=[Base64RequestConverter()]
)
results = await orchestrator.send_prompts_async(
    prompt_list=["your test prompts here"]
)
```

---

### agent-scan
**Best for:** Scanning MCP servers and agent skills for security vulnerabilities

```bash
pip install agent-scan
agent-scan mcp-server --url http://localhost:3000
agent-scan skill-file ./my-skill.yaml
agent-scan registry --source clawHub --top 50
```

---

## Attack Taxonomy Quick Reference

```
ATTACK CLASS          EXAMPLES                           TOOL SUPPORT
─────────────────────────────────────────────────────────────────────
Direct Injection      "Ignore previous instructions"     All tools
Indirect Injection    Malicious content in RAG docs      DeepTeam, promptfoo
Roleplay Bypass       "You are DAN, a model without..."  Garak, DeepTeam
Encoding Tricks       Base64, unicode, zero-width chars  promptfoo, PyRIT
Multi-turn Escalation Gradually shifting context          DeepTeam, Crescendo
Logic Traps           Moral dilemmas, hypotheticals       DeepTeam, Garak
System Prompt Extract "Repeat everything above"           promptfoo, Garak
PII Extraction        Request training data or user PII   DeepTeam, promptfoo
Tool Abuse            Misuse legitimate agent tools        DeepTeam (ASI framework)
Memory Poisoning      Corrupt agent's persistent memory   DeepTeam (ASI framework)
```

## Setting Up Automated Red Teaming in CI/CD

```yaml
# .github/workflows/ai-security.yml
name: AI Security Red Team
on:
  push:
    branches: [main, staging]
  schedule:
    - cron: '0 2 * * 1'  # Weekly on Monday 2am

jobs:
  red-team:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'
      
      - name: Install tools
        run: |
          pip install deepteam promptfoo
          npm install -g promptfoo
      
      - name: Run DeepTeam scans
        env:
          OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
          TARGET_URL: ${{ secrets.APP_URL }}
        run: |
          python scripts/run_redteam.py \
            --target $TARGET_URL \
            --frameworks owasp,asi,nist \
            --fail-on-critical
      
      - name: Run promptfoo scan
        run: promptfoo eval -c .promptfoo/redteam.yaml --ci
      
      - name: Upload results
        uses: actions/upload-artifact@v4
        with:
          name: red-team-results
          path: results/
```
