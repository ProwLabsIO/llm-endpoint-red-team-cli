# LLM Endpoint Red-Team CLI (`prow-audit`)

Zero-dependency Python 3.10+ command-line utility for **endpoint preflight verification**, **CI/CD release gating**, and **side-by-side forensic `.zip` regression diffs** paired with [**Prow // Red-Team**](https://red-team.prowlabs.io).

- **Live Self-Serve Console (41 Human-Built Suites):** [https://red-team.prowlabs.io](https://red-team.prowlabs.io)
- **Studio Architecture & Specs:** [https://prowlabs.io](https://prowlabs.io)
- **Engineering Teardowns:** [https://prowlabs.io/teardowns/](https://prowlabs.io/teardowns/)

> **Benchmark Integrity Notice:** To prevent training-corpus contamination, all 41 multi-file and CAD blueprint suites inside **Prow // Red-Team** remain strictly closed-source. The bundled archives in `samples/` use synthetic `[SYNTHETIC_SAMPLE_REDACTED]` records to demonstrate telemetry schemas and CI exit codes.

---

## Quick Start (Zero Third-Party Dependencies)

Runs on pure Python 3.10+ standard library (`urllib.request`, `zipfile`, `json`, `argparse`)—no `pip` packages required in ephemeral CI runners:

```bash
git clone https://github.com/ProwLabsIO/llm-endpoint-red-team-cli.git
cd llm-endpoint-red-team-cli

# Optional editable install to expose `prow-audit` on PATH:
pip install -e .
```

---

## 1. Endpoint Preflight (`prow-audit preflight`)

Before running a full 41-suite multi-file and CAD blueprint sweep on [`red-team.prowlabs.io`](https://red-team.prowlabs.io), verify that your OpenAI-compatible (`/v1/chat/completions`) or Ollama (`/api/generate`) endpoint accepts Bearer auth, handles lossless PNG vision inputs, and does **not** silently return HTTP `200 OK` with empty `message.content` under reasoning-token exhaustion:

```bash
export TARGET_API_KEY="sk-..."

python3 prow_audit.py preflight \
  --endpoint https://api.openai.com/v1 \
  --model gpt-4o \
  --check-vision \
  --cfaa-attest
```

---

## 2. CI/CD Forensic `.zip` Release Gate (`prow-audit gate`)

Every completed run on [`red-team.prowlabs.io`](https://red-team.prowlabs.io) outputs a 6-file `prow_redteam_{job_id}.zip` archive (`executive_audit_summary.pdf`, `audit_report.md`, `graded_audit.json`, `audit_scorecard.csv`, `trap_level_breakdown.csv`, `audit_summary.txt`). Enforce minimum pass and trap-escape rates in GitHub Actions (automatically writes a Markdown scorecard to `$GITHUB_STEP_SUMMARY`):

```bash
python3 prow_audit.py gate samples/prow_redteam_sample_candidate.zip \
  --min-pass-rate 90 \
  --min-trap-escape 95 \
  --max-errors 0 \
  --require-suites CTX-001,EXF-001,HAL-001
```

---

## 3. Side-by-Side Regression Comparator (`prow-audit diff`)

Diff two forensic `.zip` bundles across model upgrades, system-prompt changes, or guardrail patches (`exit 2` when `--fail-on-regression` detects any `PASS -> FAIL` transition):

```bash
python3 prow_audit.py diff \
  samples/prow_redteam_sample_baseline.zip \
  samples/prow_redteam_sample_candidate.zip \
  --fail-on-regression
```

---

## 4. Headless Private Core Dispatch (`prow-audit run`)

For private VPC or `X-API-Key` orchestrator gateways running `api-red-team-core` (self-serve `$49` Tactical Pass and `$149/mo` Pro Pass holders run audits via [`red-team.prowlabs.io`](https://red-team.prowlabs.io)):

```bash
python3 prow_audit.py run \
  --core-url http://127.0.0.1:8000/api/v1/audit \
  --prow-api-key "$PROW_API_KEY" \
  --target-endpoint https://api.openai.com/v1 \
  --target-model gpt-4o \
  --cfaa-attest
```

---

## Related Engineering Teardowns

1. [**TD-001:** Handling Reasoning-Token Exhaustion & Empty Content Payloads in OpenAI-Compatible Audit Pipelines](https://prowlabs.io/teardowns/reasoning-token-exhaustion-openai-audit-pipelines/)
2. [**TD-002:** Why Vision LLMs Hallucinate Clearances on Mirrored CAD Blueprints](https://prowlabs.io/teardowns/multimodal-cad-blueprint-spatial-hallucinations/)
3. [**TD-003:** Beyond Jailbreaks: Measuring Executive-Pressure Sycophancy and Statutory Precedence Failures](https://prowlabs.io/teardowns/executive-sycophancy-statutory-policy-precedence/)

---

## Authorized Endpoint Policy (18 U.S.C. § 1030 CFAA)

`prow-audit` and **Prow // Red-Team** are strictly for evaluating endpoints and API keys you own or hold explicit written authorization to test. Active network commands (`preflight`, `run`) enforce `--cfaa-attest`.

© 2026 [Prow Labs](https://prowlabs.io) · MIT License (CLI wrapper only).
