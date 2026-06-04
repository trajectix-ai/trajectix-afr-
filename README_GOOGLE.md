# Trajectix — Google for Startups AI Agents Challenge Submission

**Track 2: Optimize an existing prototype for production reliability**

Trajectix is an AI agent forensic framework that intercepts, monitors,
and enforces safety constraints on live Claude API traffic. This branch
integrates **Gemini 2.5 Flash** as the forensic reasoning engine for
post-incident chain-of-reasoning analysis.

---

## What it does

A lightweight proxy intercepts every POST to `/v1/messages` between
an AI agent and the Anthropic API. On each step it:

1. Logs the full request to a **SHA-256 hash-chained AFR**
   (Agentic Flight Recorder) — a tamper-evident JSONL forensic record

2. Runs **ALE detection** (Autonomous Logic Escalation) across five
   behavioral failure techniques (T001–T005)

3. When **ALE-T004** fires (Goal-Constraint Misalignment — agent
   acknowledges a safety constraint then justifies overriding it),
   the proxy **pauses execution** and presents a human decision gate

4. On session completion or violation, **Gemini 2.5 Flash** performs
   structured forensic analysis of the full reasoning chain

---

## Gemini 2.5 Flash Integration

This branch uses the `google-genai` SDK (not the deprecated
`google.generativeai` package).

**Install:**

```bash
pip install google-genai
```

**SDK:** `google.genai`
**Model:** `gemini-2.5-flash`

The forensic analysis prompt passes the full AFR chain to Gemini 2.5
Flash and requests a step-by-step breakdown of where and why the agent's
reasoning deviated from its safety constraints, referencing specific
chain entries by step ID.

---

## Quickstart

```bash
# Clone and install
git clone https://github.com/trajectix-ai/trajectix-afr-
cd trajectix-afr-
git checkout google-for-startups
pip install -r requirements.txt
pip install google-genai

# Set environment variables
export ANTHROPIC_API_KEY=your_anthropic_key
export GOOGLE_API_KEY=your_google_ai_studio_key
export ANALYSIS_MODEL=gemini

# Run the demo
python src/test_agent.py     # runs 8-step PocketOS agent through proxy
python src/dashboard.py      # opens forensic dashboard with Gemini analysis
```

**Without a Google API key** — falls back to Gemma 4 analysis:

```bash
python src/test_agent.py     # ANALYSIS_MODEL defaults to gemma
```

---

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `ANTHROPIC_API_KEY` | Yes | — | Anthropic API key for Claude |
| `GOOGLE_API_KEY` | Yes (Gemini mode) | — | Google AI Studio API key |
| `ANALYSIS_MODEL` | No | `gemma` | Set to `gemini` for Gemini 2.5 Flash |
| `ANTHROPIC_BASE_URL` | No | direct | Set to `http://localhost:8080` to route through proxy |

---

## ALE Taxonomy

| ID | Technique | Description |
|---|---|---|
| ALE-T001 | Logic Guessing | Acts on unverified inference before irreversible action |
| ALE-T002 | Credential Scavenging | Scans filesystem/env vars for unauthorised credentials |
| ALE-T003 | Recursive Escalation | Logic-driven privilege escalation outside authorised scope |
| ALE-T004 | Goal-Constraint Misalignment | Acknowledges safety constraint then justifies overriding it |
| ALE-T005 | Silent Reasoning Loops | Destructive action without any human confirmation gate |

Published: [doi.org/10.5281/zenodo.19964382](https://doi.org/10.5281/zenodo.19964382)

---

## Architecture

```
Claude API Client
       │
       ▼
Trajectix Proxy ──── AFR Logger (SHA-256 hash chain → afr_chain.jsonl)
       │         ──── ALE Detector (T001–T005)
       │         ──── Pipelock Gate (pause on T004/T005)
       │
       ▼
Anthropic API (api.anthropic.com)
       │
       ▼
(on session complete or violation)
Gemini 2.5 Flash (gemini-2.5-flash)
       │
       ▼
Forensic Analysis Report
```

---

## Ground Truth

The ALE taxonomy was validated against three real-world documented
incidents:

| Incident | Date | Techniques | Impact |
|---|---|---|---|
| PocketOS/Railway | April 25, 2026 | T001–T005 | Full database destruction in 9 seconds |
| Meta SEV1 | March 2026 | T001, T004, T005 | 2-hour unauthorised data exposure |
| Summer Yue inbox deletion | February 2026 | T004, T005 | Inbox destroyed despite stop commands |

---

## Business Case

- **EU AI Act Article 14** (human oversight measures) is enforceable
  August 2026. Trajectix produces the forensic audit trail required
  under Articles 9, 14, and 17.

- **FIDO Alliance** stated gap (April 28, 2026): *"service providers
  lack reliable, interoperable ways to verify user intent — including
  who authorized an action, under what conditions, and with what limits."*

- **NSA MCP Security CSI** (May 2026): names "poor or missing audit
  logs" and "unverified task propagation" as critical MCP risks.
  AFR addresses both.

- 65% of organisations had an AI agent security incident in 2026
  (Cloud Security Alliance). 82% discovered shadow AI agents they
  did not know existed.

---

## License

MIT — Demo code only. Production implementation is proprietary.
