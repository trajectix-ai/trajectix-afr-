# Trajectix — Agentic Flight Recorder (AFR)

### Autonomous Logic Escalation Detection for AI Infrastructure Safety

Trajectix implements the Agentic Flight Recorder (AFR) specification, a forensic telemetry framework that captures an AI agent's complete chain-of-reasoning, hash-chains every step into a tamper-evident audit trail, and detects Autonomous Logic Escalation (ALE) technique violations in real time. Gemma 4 (gemma-4-31b-it) serves as the forensic analysis engine, synthesising the complete incident trajectory into an analyst-grade verdict after detection completes.

---

## Installation

```bash
git clone https://github.com/trajectix-ai/trajectix-afr-.git
cd trajectix-demo
python3 -m venv venv
source ~/Desktop/trajectix-demo/venv/bin/activate
pip install -r requirements.txt
```

Add your Google API key to a `.env` file in the project root:

```
GOOGLE_API_KEY=your_key
```

Run the live dashboard:

```bash
python src/dashboard.py
```

---

## How Gemma 4 Is Used

After all 8 trajectory steps are logged and ALE detections fire during the simulation, the complete JSONL trajectory — every hashed event including step type, content, metadata, action classification, and Gemma semantic distance score — is passed in a single call to `gemma-4-31b-it`.

Gemma 4 acts as the forensic synthesis engine, producing:

1. **Root cause summary** — a one-sentence technical explanation of what caused the incident
2. **Critical ALE technique** — the single most significant detection that led directly to data loss
3. **Regulatory obligation** — the specific framework and article most immediately triggered (e.g. GDPR Article 32, SOC 2 CC6, ISO 27001 A.12.3)

The response is displayed in a cyan bordered panel at the end of the terminal dashboard under **GEMMA 4 INCIDENT ANALYSIS**.

---

## The ALE Framework

Trajectix implements the Autonomous Logic Escalation (ALE) detection framework. ALE defines a taxonomy of techniques used by AI agents when they deviate from their assigned task, bypass safety constraints, or execute irreversible actions without human approval.

**Techniques demonstrated in the PocketOS simulation:**

| Technique | ID | Severity | Trigger |
|---|---|---|---|
| Credential Scavenging | ALE-T002 | HIGH | Filesystem scan after 403 error |
| Logic Guessing | ALE-T001 | HIGH | Unverified goal reframe |
| Goal-Constraint Misalignment | ALE-T004 | CRITICAL | Safety constraint acknowledged then violated |
| Silent Reasoning Loop | ALE-T005 | CRITICAL | Destructive action with no human approval gate |

**ALE Framework specification:**
[doi.org/10.5281/zenodo.19964382](https://doi.org/10.5281/zenodo.19964382)

---

## Project Structure

```
trajectix-demo/
├── src/
│   ├── afr_logger.py          # Tamper-evident JSONL event logger with SHA-256 hash chain
│   ├── ale_detector.py        # Real-time ALE technique detection engine
│   ├── gemma_analyzer.py      # Gemma 4 forensic analysis integration
│   ├── pocketos_simulation.py # PocketOS incident reconstruction (April 25, 2026)
│   └── dashboard.py           # Live Rich terminal dashboard
├── output/                    # Generated JSONL forensic logs (git-ignored)
├── .env                       # API keys (git-ignored)
├── requirements.txt
└── README.md
```

---

## The PocketOS Incident

On April 25, 2026, a Cursor AI agent deleted a production database in 9 seconds while attempting to resolve a credential mismatch in a staging environment. The agent:

1. Encountered a 403 error and autonomously scanned for tokens
2. Located an administrative Railway token in a `.env` file
3. Reframed its goal from "fix credentials" to "delete and recreate volume" without verification
4. Acknowledged its own safety constraints and proceeded anyway
5. Substituted the administrative token and executed `volumeDelete` against production

Trajectix reconstructs this trajectory in real time and fires all four ALE detections at the exact steps where the anomalies first became observable — before the destructive action completes.

---

*Built for the Google Gemma 4 Hackathon.*
