# Wazuh SOC Lab — Single-Node SIEM with Lab Agents

A self-hosted mini-SOC built on Wazuh: a single-node stack (manager + indexer
+ dashboard) running in Docker Compose, with two lab agents enrolled and a
repeatable detection-test plan. The goal is to practice the full SOC analyst
loop — deploy, enroll, write/run detections, triage alerts, and document a
simulated incident — on infrastructure the lab owner fully controls.

**What this demonstrates:** Wazuh single-node deployment with Docker Compose
(certs, secrets, volumes), agent deployment + enrollment (Linux/Windows),
agent groups for shared config, running MITRE-mapped detection tests (SSH
brute force, suspicious logon, FIM tampering, persistence), alert triage in
the Wazuh dashboard, and writing an analyst-grade incident report.

```
              ┌───────────────────────────────────────────────────┐
              │              WAZUH SINGLE-NODE STACK                │
              │                (Docker Compose)                   │
              │                                                   │
              │  ┌─────────────┐   ┌─────────────┐  ┌──────────┐  │
              │  │   Manager   │──▶│   Indexer   │◀─│Dashboard │  │
              │  │ analysis +  │   │ alert/event │  │HTTPS 443 │  │
              │  │ API 55000*  │   │ store :9200*│  └──────────┘  │
              │  └──────▲──────┘   └─────────────┘                │
              │         │ TLS: 1514 events · 1515 enrollment       │
              └─────────┼─────────────────────────────────────────┘
                        │
         ┌──────────────┼──────────────┐
         ▼              ▼              ▼
  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
  │ lab-linux-01│ │  lab-win-01 │ │ lab-attacker│
  │  (agent)    │ │  (agent)    │ │     -01     │
  │  group:     │ │  group:     │ │  attack VM  │
  │  lab-linux  │ │  lab-win    │ │ (not an     │
  └─────────────┘ └─────────────┘ │  agent)     │
                                  └─────────────┘
  * bound to 127.0.0.1 — not exposed on the LAN
```

## Repo layout

| Path | Purpose |
|---|---|
| `docker-compose.yml` | Single-node stack: manager, indexer, dashboard (images pinned to 4.14.9) |
| `generate-certs.yml` | One-shot TLS cert generation for manager ↔ indexer ↔ dashboard |
| `config/certs.yml` | Node definitions consumed by the cert generator |
| `.env.example` | All secrets as `<generate-your-own>` placeholders, with generation commands |
| `.gitignore` | Keeps `.env` and generated certs out of git |
| `docs/architecture.md` | Design decisions and data flow |
| `docs/interview-answers.md` | "How did you build this?" — talking points for interviews |
| `docs/agent-enrollment-runbook.md` | Step-by-step: install + enroll lab agents, verify, use groups |
| `docs/detection-test-plan.md` | MITRE-mapped detection tests, lab-scope warnings, expected alerts |
| `docs/sample-incident-report.md` | Fully written SIMULATED incident report (lab exercise) |
| `templates/incident-report-template.md` | Blank template for future lab incidents |

## Quick start

```bash
# 1. Create your secrets (never commit .env)
cp .env.example .env
# then edit .env and replace EVERY <generate-your-own>:
# openssl rand -base64 24

# 2. Raise the kernel limit the indexer needs (run ONCE on the Docker host)
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf

# 3. Generate internal TLS certificates (one-shot container)
docker compose -f generate-certs.yml run --rm generator

# 4. Set the agent enrollment password inside the manager (optional but recommended)
#    (see docs/agent-enrollment-runbook.md for the authd.pass step)

# 5. Start the stack
docker compose up -d

# 6. Open https://<host-ip>/  — login: admin / <INDEXER_PASSWORD from .env>
```

Host requirements: Linux host with Docker Compose, 4 CPU / 8 GB RAM minimum,
ports 1514 (TCP), 1515 (TCP), 443 free. The indexer and API ports (9200,
55000) are intentionally bound to `127.0.0.1`.

## Security notes

- **LAB scope only.** Every test in `docs/detection-test-plan.md` runs
  exclusively against lab VMs the owner controls. Never point the tests at
  real infrastructure or third-party targets.
- **Change every default.** Default dashboard credentials (`admin` /
  `SecretPassword`) are public knowledge. All secrets live in `.env`, which
  is git-ignored; only placeholders exist in this repo.
- The indexer's admin password and dashboard's `kibanaserver` password must
  be synced inside the indexer's user database after a change — see the
  password-rotation note in `docs/architecture.md`. Set them before first
  boot; it's the simplest path.
- The API (55000) and indexer (9200) bind to localhost in this compose.
  If you ever expose them, add authentication + firewall rules.

## Validation

- `docker-compose.yml`, `generate-certs.yml`, and `config/certs.yml`:
  parsed with `python3 -c "import yaml"` — no errors. Cross-checked
  against Wazuh's official single-node deployment (image pins 4.14.9,
  env vars, cert-mount paths, `vm.max_map_count` requirement).
- `.env.example` uses only `<generate-your-own>` placeholders — no real
  secrets anywhere in the repo (verified).
- **Not validated in this sandbox:** Docker is not installed here, so the
  stack could not be booted and no containers were run. A full end-to-end
  test (agent enrollment, detection tests firing) must happen on a real
  Docker host; the runbook + test plan documents exactly what to observe.
