# Wazuh SOC: Single-Node SIEM Implementation

A self-hosted mini-SOC built on Wazuh: a single-node stack (manager + indexer
+ dashboard) running in Docker Compose, with two test agents enrolled and a
repeatable detection-test plan. The goal is to practice the full SOC analyst
loop (deploy, enroll, write/run detections, triage alerts, and document a
simulated incident) on infrastructure the operator fully controls.

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
  │ soc-linux-01│ │  soc-win-01 │ │ soc-attacker│
  │  (agent)    │ │  (agent)    │ │     -01     │
  │  group:     │ │  group:     │ │  attack VM  │
  │  soc-linux  │ │  soc-win    │ │ (not an     │
  └─────────────┘ └─────────────┘ │  agent)     │
                                  └─────────────┘
  * bound to 127.0.0.1 - not exposed on the LAN
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
| `docs/agent-enrollment-runbook.md` | Step-by-step: install + enroll test agents, verify, use groups |
| `docs/detection-test-plan.md` | MITRE-mapped detection tests, scope warnings, expected alerts |
| `docs/sample-incident-report.md` | Tabletop walkthrough: expected detections (not observed events) |
| `templates/incident-report-template.md` | Blank template for future test incidents |
| `rules/local_rules.xml` | **v2:** custom rules 100001–100004 (SSH brute-force correlation, non-admin sudo, FIM escalation under `/etc`, persistence-location files) |
| `rules/lists/soc-admin-users` | **v2:** CDB list of admin accounts used by rule 100002 |
| `rules/README.md` | **v2:** what each custom rule detects, how to test it, deploy + `wazuh-logtest` validation steps |
| `scripts/block-offending-ip.sh` | **v2:** active-response skeleton (dry-run by default, refuses bad input), see the v2 section below |
| `docs/sample-incident-report-2.md` | **v2:** tabletop walkthrough: custom rule 100001 firing (not observed events) |

## v2: custom detections + active-response skeleton

v1 proved the stock ruleset works. v2 writes detections of our own
and rehearses the response step: deliberately stopping short of
automating it.

**Custom rules** (`rules/local_rules.xml`, IDs in the local 100000+
range, all children of stock rules: full detail in
`rules/README.md`):

| ID | Level | Detects |
|---|---|---|
| 100001 | 12 | SSH brute force: 6+ failed logins (parent 5716) from one source IP in 60s, a tighter, louder take on stock 5710, tuned for this one-host environment |
| 100002 | 10 | Successful sudo to root (parent 5402) by a user **not** in the CDB admin list `rules/lists/soc-admin-users` |
| 100003 | 12 | FIM escalation: content change (parent 550) to a monitored file under `/etc` |
| 100004 | 13 | FIM escalation: new file (parent 554) in a persistence location, `/etc/systemd/system/`, `/etc/cron*` |

Each maps to an existing test in `docs/detection-test-plan.md`
(100001 → Test 1, 100003 → Test 4, 100004 → Test 5; 100002 needs a
temporary test sudo grant, spelled out in `rules/README.md`).
`docs/sample-incident-report-2.md` (INC-002, SIMULATED) works a
full incident from 100001 firing, including the branch INC-001
never exercised: the attack *failed*, so no credential is treated
as compromised.

**Active response, kept on a leash**
(`scripts/block-offending-ip.sh`): a heavily commented skeleton in
the Wazuh AR convention, accepts the legacy execd argv form
(`add|delete <user> <srcip> <alert_id>`) or the Wazuh 4.x JSON
object on stdin, validates the IP strictly, refuses loopback /
manager / denylisted addresses, and logs every action and refusal.
It **dry-runs by default**: an "add" only logs the `iptables`
command it *would* run. Actually blocking requires
`BLOCK_IP_APPLY=1`, root, and iptables present, and it is **not**
wired to any `<active-response>` command in `ossec.conf`. That
wiring waits for a false-positive soak of rule 100001; automating
the block before that would automate the risk, not the response.

**Status:** the v2 rules and the active-response script pass static checks,
but they haven't been loaded into a running manager yet, so treat rules
100001–100004 as untested until then. First run on a Docker host: deploy per
`rules/README.md`, run `wazuh-logtest -t`, then work through Tests 1, 4, and 5
and fill in the **Observed** column of the test plan.

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

# 6. Open https://<host-ip>/  - login: admin / <INDEXER_PASSWORD from .env>
```

Host requirements: Linux host with Docker Compose, 4 CPU / 8 GB RAM minimum,
ports 1514 (TCP), 1515 (TCP), 443 free. The indexer and API ports (9200,
55000) are intentionally bound to `127.0.0.1`.

## Security notes

- **Test scope only.** Every test in `docs/detection-test-plan.md` runs
  exclusively against test VMs the owner controls. Never point the tests at
  real infrastructure or third-party targets.
- **Change every default.** Default dashboard credentials (`admin` /
  `SecretPassword`) are public knowledge. All secrets live in `.env`, which
  is git-ignored; only placeholders exist in this repo.
- The indexer's admin password and dashboard's `kibanaserver` password must
  be synced inside the indexer's user database after a change: see the
  password-rotation note in `docs/architecture.md`. Set them before first
  boot; it's the simplest path.
- The API (55000) and indexer (9200) bind to localhost in this compose.
  If you ever expose them, add authentication + firewall rules.

## Test results so far

- `docker-compose.yml`, `generate-certs.yml`, and `config/certs.yml` parse as
  valid YAML and match Wazuh's official single-node deployment (image 4.14.9,
  environment variables, certificate mounts, `vm.max_map_count`).
- `.env.example` contains only `<generate-your-own>` placeholders; there are no
  real secrets in the repo.
- `rules/local_rules.xml` is well-formed XML with four rules: 100001
  (level 12), 100002 (level 10), 100003 (level 12), 100004 (level 13). Wazuh's
  own rule check is `wazuh-logtest -t` on the manager (see `rules/README.md`).
- `scripts/block-offending-ip.sh` passes `bash -n`. Run with no arguments, it
  prints its usage, logs `REFUSED: no arguments and no JSON on stdin`, and exits
  with code 2. It has never been run with a real block action; it's a dry-run
  skeleton by design.
- Not done yet: booting the stack, enrolling the test agents, and watching the
  detections fire. The runbook and test plan list what to look for.
