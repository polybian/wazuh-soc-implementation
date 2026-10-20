# Architecture & Design Decisions

## Components

| Component | Role | Exposed (lab) |
|---|---|---|
| `wazuh.manager` | Analysis engine: decoders + rules evaluate events, raise alerts, serve the API. Filebeat ships alerts/events to the indexer. | 1514/tcp (events), 1515/tcp (enrollment), 514/udp (agentless syslog), 55000 on `127.0.0.1` (API) |
| `wazuh.indexer` | Alert/event store (OpenSearch fork). | 9200 on `127.0.0.1` only |
| `wazuh.dashboard` | Web UI: alerts, agent management, MITRE ATT&CK views, rules editor. | 443 (HTTPS) |
| `lab-linux-01` / `lab-win-01` | Lab VMs running the Wazuh agent; the only targets of detection tests. | — |
| `lab-attacker-01` | Kali/Ubuntu lab VM used to *generate* attack traffic (brute force, scans). Not an agent. | — |

## Data flow

```
agent (lab-linux-01) --TLS 1514--> manager: decoders/rules --> alert
                                               |
                          Filebeat --TLS--> indexer (9200) <-- dashboard (443)
```

1. Agent collects log/syscheck/audit data, forwards it over the encrypted
   agent channel (1514).
2. Manager's analysis engine matches decoders + rules; matches become alerts.
3. Filebeat (inside the manager container) ships alerts to the indexer.
4. Analyst works in the dashboard: alert review, MITRE ATT&CK panel,
   agent management, rule editing.

## Why single-node over a cluster

A single-node stack needs one host (4 CPU / 8 GB RAM) and boots in ~5
minutes — right for a learning lab and two agents. A cluster (manager
master/worker + multi-node indexer) buys HA and ingest scale but roughly
doubles the RAM requirement (16 GB) and the operational surface. If ingest
grows past one host, the path is: add indexer data nodes for scale, add a
manager worker tier behind the enrollment port, keep agents pinned to
managers with the load balancer.

## Why agents over agentless

Agents give full-fidelity telemetry (FIM, auditd whodata, Sysmon, process
inventory, vuln detection) and work on laptops/VMs that move networks.
Agentless (SSH-based FIM, plain syslog on 514/udp) fits routers, switches,
and legacy boxes where you can't install anything. This lab uses agents on
both lab VMs; the manager's syslog port is enabled for agentless devices
as a future extension.

## Why Wazuh over Splunk Free

- **No ingest cap games:** Splunk Free caps at 500 MB/day and disables
  scheduled alerting; Wazuh has no ingest limit and ships FIM, vulnerability
  detection, SCA (CIS hardening checks), and MITRE-mapped rules out of the box.
- **Agent included:** the agent, server, and dashboard are all free — no
  separate forwarder licensing.
- **Tradeoff, stated honestly:** Splunk has a bigger community, richer SPL,
  and mature enterprise support. Wazuh's indexing/scaling is yours to run,
  and its query language (DQL on the indexer) is less powerful than SPL.
  For a portfolio lab, Wazuh demonstrates more SOC-relevant skills per
  dollar than any free-tier SIEM.

## Hardening notes (lab defaults, production notes)

- **TLS everywhere:** the cert generator creates a root CA and per-node
  certs; Filebeat uses `FILEBEAT_SSL_VERIFICATION_MODE=full`.
- **Network:** indexer (9200) and API (55000) bind to `127.0.0.1` in this
  compose. In any shared-network deployment, keep them behind a firewall
  or reverse proxy; only 443 and the agent ports (1514/1515) need
  reachability, and 1515 only for enrollment.
- **Secrets:** `.env` is git-ignored; certs are git-ignored. Rotation plan:
  1. **Indexer `admin` / `kibanaserver`:** generate a bcrypt hash with the
     indexer's `hash.sh`, update `internal_users.yml`, and re-run the
     indexer's `securityadmin.sh` script. Then update `.env` and recreate
     the manager/dashboard containers.
  2. **API `wazuh-wui`:** change via the Wazuh API (`PUT /security/users/`)
     or `manage_users`, then update `.env`.
  3. **Enrollment password:** rotate in `authd.pass` on the manager and
     re-run the enrollment one-liner on new agents.
- **Host:** `vm.max_map_count=262144` is mandatory for the indexer
  (OpenSearch mmap). Manager volumes (`/var/ossec/etc`, `/var/ossec/logs`,
  `/var/ossec/queue`) are persisted Docker volumes — back them up before
  upgrades; rules/custom decoders live in `/var/ossec/etc/rules`.
- **Patching:** pin the images and bump deliberately (`4.14.9` → next
  minor), keeping manager/agent versions in lockstep.
