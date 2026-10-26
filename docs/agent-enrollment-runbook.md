# Agent Enrollment Runbook

Install + register Wazuh agents on the two test VMs (`soc-linux-01`,
`soc-win-01`), verify them in the dashboard, and organize with agent groups.

> ⚠️ **TEST SCOPE:** install agents only on VMs you own. The enrollment
> password below lives in your `.env`: never reuse it outside this environment.

## 0. Prerequisites

- Stack running: `docker compose up -d`, dashboard reachable at
  `https://<manager host IP>/`.
- The Docker host must be reachable from the test VMs on **1514/tcp**
  (events) and **1515/tcp** (enrollment). If agent enrollment fails, check
  the host firewall first.
- Set the enrollment password on the manager (once):

  ```bash
  docker compose exec wazuh.manager bash -c \
    "echo '<WAZUH_REGISTRATION_PASSWORD from .env>' > /var/ossec/etc/authd.pass \
     && chmod 640 /var/ossec/etc/authd.pass && chown root:ossec /var/ossec/etc/authd.pass"
  docker compose restart wazuh.manager
  ```

## 1. Create agent groups (dashboard)

1. Log in to the dashboard as `admin`.
2. **☰ Management → Groups → Add new group**
   - Create `soc-linux` and `soc-win`.
3. Groups receive shared configuration from the manager: after creating a
   group, edit its `agent.conf` (group config) in the dashboard; the
   manager merges it into each member agent's config automatically.

## 2. Linux agent (soc-linux-01): deployment variables method

On the Linux test VM (Debian/Ubuntu):

```bash
# Import the Wazuh GPG key and add the repo
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
  gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg \
  --import && chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt-get update

# Install and auto-enroll in one step
WAZUH_MANAGER="<manager host IP>" \
WAZUH_REGISTRATION_PASSWORD="<same password as .env>" \
WAZUH_AGENT_NAME="soc-linux-01" \
WAZUH_AGENT_GROUP="soc-linux" \
  sudo -E apt-get install wazuh-agent

sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

The installer presents the registration password to authd on 1515 and
writes the agent key to `/var/ossec/etc/client.keys`.

## 3. Windows agent (soc-win-01): installer method

On the Windows test VM, from an elevated PowerShell:

```powershell
Invoke-WebRequest -Uri https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.9-1.msi -OutFile wazuh-agent.msi
msiexec.exe /i wazuh-agent.msi /q WAZUH_MANAGER="<manager host IP>" `
  WAZUH_REGISTRATION_PASSWORD="<same password as .env>" `
  WAZUH_AGENT_NAME="soc-win-01" WAZUH_AGENT_GROUP="soc-win"
NET START WazuhSvc
```

(Or use the dashboard enroll wizard: **Modules → Agents → Deploy new
agent** → pick OS → copy the generated one-liner.)

## 4. Verify in the dashboard

1. **Modules → Agents**: both agents show **Active** with the correct
   version and group.
2. Click an agent → confirm events are flowing (last keep-alive updating).
3. On the manager host, cross-check on the CLI:

   ```bash
   docker compose exec wazuh.manager /var/ossec/bin/agent_control -l
   # Expected: soc-linux-01 and soc-win-01 listed as Active.
   ```

4. Trigger a smoke test on the Linux agent and confirm it lands in the
   dashboard (**Integrity monitoring → Events** after touching a monitored
   file):

   ```bash
   sudo touch /etc/soc-smoke-test && sudo rm /etc/soc-smoke-test
   ```

## 5. Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Agent stuck "Disconnected" | 1514 blocked, or key mismatch after re-install | Check host firewall; if the agent was re-imaged, delete the stale agent in the dashboard and re-enroll |
| "Duplicate agent name" on enrollment | Name already registered | Enroll with a unique name or remove the old agent first |
| Enrollment fails with password error | `authd.pass` missing/wrong, manager not restarted | Redo step 0, restart `wazuh.manager` |
| Agent events arrive, no alerts | Rules not matching (expected for quiet hosts) | Run the detection test plan: tests are designed to fire known rules |
| Windows agent service won't start | Wrong manager IP at install | Re-run MSI with the correct `WAZUH_MANAGER`, check `C:\Program Files (x86)\ossec-agent\ossec.log` |
