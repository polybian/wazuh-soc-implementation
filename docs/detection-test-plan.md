# Detection Test Plan: Wazuh SOC Implementation

> ## ⚠️ TEST SCOPE: READ BEFORE RUNNING ANY TEST
>
> Every test in this plan runs **only** against the test agents
> (`soc-linux-01`, `soc-win-01`) from the attacker VM
> (`soc-attacker-01`), all owned by the operator, on an isolated
> host-only / private test network.
>
> - **Never** run these techniques against real infrastructure, an
>   employer's systems, or any third-party target.
> - Tests use Atomic Red Team–**style** procedures, written generically
>   here; do not copy them into a production environment.
> - The attacker VM runs no agent and must stay on the test network.

## How verification works

For each test: note time → run the technique against a test agent → open
the **Wazuh dashboard → Threat Hunting → Events** (or the agent's own
Events view), filter by agent + time window, and confirm the expected
alert. Record the observed rule ID, severity, and the alert's MITRE
ATT&CK mapping shown in the alert detail. Fill in the **Observed**
column after each run.

## Test matrix

| # | MITRE technique | Target agent | Expected Wazuh alert | Observed |
|---|---|---|---|---|
| 1 | T1110: Brute Force (password guessing vs SSH) | soc-linux-01 | Rule 5710 "sshd: brute force trying to get access to the system" (severity 10), built from child rule 5716 auth failures | |
| 2 | T1078: Valid Accounts (suspicious logon) | soc-linux-01, soc-win-01 | Rule 5715 "sshd: authentication success" (sev 3) immediately after a 5710 burst; on Windows, event 4624 logon success, flagged when source/logon type is unusual | |
| 3 | T1059: Command and Scripting Interpreter | soc-win-01, soc-linux-01 | PowerShell/Sysmon or auditd process-creation events matching the test commands appear as agent events; encoded-command runs surface under the agent's process/script telemetry | |
| 4 | T1565.001 / T1491: Stored Data Manipulation / Defacement (FIM) | soc-linux-01 | Rule 550 "Integrity checksum changed" (severity 7) for the modified monitored file; rule 554 "File added to the system" for new files | |
| 5 | T1543: Create or Modify System Process (persistence) | soc-linux-01 | FIM alert (rules 554/550) on the new systemd unit / cron entry; SCA/policy events if the change violates the CIS profile | |

## Test details

### Test 1: T1110 SSH brute force
- **Action:** from `soc-attacker-01`, run a password-guessing tool (e.g.
  Hydra) against SSH on `soc-linux-01` with a small wordlist and a dedicated test account. ~20+ failed attempts inside a minute.
- **Expected alert:** rule **5710**, severity **10**, "sshd: brute force
  trying to get access to the system"; child alerts 5716 "sshd:
  authentication failed". MITRE panel shows T1110 / Credential Access.
- **Verify:** dashboard filter `rule.id: 5710 AND agent.name: soc-linux-01`.

### Test 2: T1078 suspicious successful logon
- **Action:** immediately after Test 1, SSH from `soc-attacker-01` into
  `soc-linux-01` with the **correct test password** for the test account
  (simulating the brute force succeeding). On Windows: RDP from
  `soc-attacker-01` to `soc-win-01` with a valid test credential.
- **Expected alert:** rule **5715** "sshd: authentication success"
  (severity 3) directly following the 5710 burst on the timeline; on
  Windows, a 4624 logon-success event from the attacker host.
  **Analyst note:** the single 5715 is low severity, the *story*
  (5710 burst → 5715 success from the same source IP) is what makes this
  an incident. That's the triage lesson; see the sample incident report.
- **Verify:** agent timeline view, filter by source IP of
  `soc-attacker-01`; screenshot for the incident report.

### Test 3: T1059 command / scripting execution
- **Action (Windows):** run a benign PowerShell payload typical of
  Atomic-style T1059.001 tests, e.g. `powershell -enc <base64 of a
  Write-Host>` and spawning `cmd.exe` from PowerShell. Harmless output only.
- **Action (Linux):** execute a small, harmless script via bash from a
  downloaded-then-run pattern inside the test environment (e.g. `curl` a text file from
  `soc-attacker-01`'s local HTTP server and pipe nothing to execution:
  observe and record, don't execute remote code beyond a local echo).
- **Expected:** the commands appear in agent telemetry (Sysmon Event ID 1
  process creation on Windows if Sysmon is installed; auditd EXECVE if
  configured) under the agent's Events view, MITRE-tagged T1059 in the
  Threat Hunting module. **Note:** stock rules treat plain command
  execution as telemetry, not a high-severity alert. This test validates
  *visibility*, which is what an analyst actually needs; write a custom
  rule if you want it to fire as an alert (extension exercise).

### Test 4: FIM (file modification in a monitored path)
- **Action:** on `soc-linux-01`, modify the content of a file under a
  syscheck-monitored directory (e.g. append a line to a test file in `/etc`
  created for this purpose), then add a brand-new file beside it.
- **Expected alert:** rule **550** "Integrity checksum changed"
  (severity 7) for the edit; rule **554** "File added to the system"
  for the new file. Dashboard: agent `soc-linux-01` → Integrity monitoring.
- **Verify:** confirm the alert shows old/new checksums and, with whodata
  enabled, the user/process that made the change.

### Test 5: Persistence via a new service
- **Action:** on `soc-linux-01`, create a dummy systemd unit
  (`/etc/systemd/system/soc-persistence-test.service`) that runs
  `/bin/true`, enable it, then disable and delete it after verification.
- **Expected:** FIM alerts (554/550) for the new unit file in the
  monitored `/etc` tree; the change appears in the agent's FIM inventory.
  MITRE mapping: T1543.002 (Systemd Service) in the Threat Hunting view.
- **Cleanup:** `systemctl disable soc-persistence-test; rm` the unit;
  confirm a follow-up FIM event for the removal.
