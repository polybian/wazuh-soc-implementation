# Custom Rules: v2 (test environment)

Custom detection content for the Wazuh SOC implementation, in
[`local_rules.xml`](local_rules.xml). Four rules, all in the
**100000+** ID range Wazuh reserves for local rules, all built as
children of stock rules so they inherit the stock decoders: no
custom decoders to maintain.

> ⚠️ **TEST SCOPE:** thresholds here are tuned for a two-agent test environment,
> not a fleet. Read the tuning note on each rule before reusing it
> anywhere else. These rules were **not live-tested** in the build
> environment (no Docker there): validate with `wazuh-logtest -t` on
> the manager before trusting them; see "Deploy + validate" below.

## The rules

| ID | Level | Parent | Detects |
|---|---|---|---|
| 100001 | 12 | 5716 (sshd auth failed) | SSH brute force: 6+ failed logins from one source IP in 60s |
| 100002 | 10 | 5402 (successful sudo to root) | Successful sudo to root by a user who is **not** an admin |
| 100003 | 12 | 550 (FIM checksum changed) | Content change to a monitored file under `/etc` |
| 100004 | 13 | 554 (FIM file added) | New file in a persistence location (`/etc/systemd/system/`, `/etc/cron*`) |

### 100001: SSH brute force (frequency correlation)

- **Logic:** `<if_matched_sid>5716</if_matched_sid>` with
  `frequency="6" timeframe="60"` and `<same_srcip />`: the 6th failed
  SSH authentication from the same source IP inside 60 seconds fires
  one level-12 alert instead of six level-5 ones.
- **Why not just stock 5710?** 5710 already does this job at its own
  threshold. 100001 is deliberately tighter and louder because
  this environment has one SSH target that matters and the analyst wants the
  custom alert to be unmissable in the dashboard. The trade-off is
  noise: on a shared/jump host, 6 failures a minute can be a fat
  finger, not an attack. That's the tuning conversation this rule
  exists to teach.
- **MITRE:** T1110.001 (Brute Force: Password Guessing).
- **Test it:** detection test plan **Test 1** (T1110). Run the same
  password-guessing procedure, but you only need ~6–10 attempts
  inside a minute to cross this threshold. Verify with dashboard
  filter `rule.id: 100001 AND agent.name: soc-linux-01`, and note
  whether 5710 fires too, and in what order.
- **Worked example:** `docs/sample-incident-report-2.md` is a full
  simulated incident built on this rule firing.

### 100002: sudo to root by a non-admin user

- **Logic:** parent 5402 already means "successful sudo to ROOT
  executed", so the child adds a single condition: the invoking
  user (`srcuser`) is **not** in the CDB list
  [`lists/soc-admin-users`](lists/soc-admin-users), via
  `<list field="srcuser" lookup="not_match_key">`.
- **The list:** plain `key:value` lines, one admin account per
  line (`testadmin`, `operator`, `testoperator`). With
  `not_match_key` only the keys matter; the `:admin` value is a
  label. Add a user to the list and their sudo stops alerting;
  remove them and it starts. **Deploy the list before restarting
  the manager**: a rule that references a missing list file will
  stop the analysis engine from loading.
- **Limitation:** "non-admin" here means "not on this
  hand-maintained list". It does not query the sudoers file or a
  directory. On anything bigger than a test environment, generate the list from
  your source of truth instead of editing it by hand.
- **MITRE:** T1548.003 (Abuse Elevation Control Mechanism: Sudo
  and Sudo Caching).
- **Test it:** this needs one setup step the stock test plan
  doesn't cover: in this test environment only, temporarily grant the `testuser`
  account sudo (`usermod -aG sudo testuser` on `soc-linux-01`), run
  `sudo -i` or `sudo /bin/true` as `testuser`, then **remove the
  grant again**. Expect two alerts: stock 5402 and custom 100002.
  Control case: run the same command as `testadmin`, expect 5402
  only, no 100002. That pair (fires for `testuser`, silent for
  `testadmin`) is the whole test.

### 100003: FIM escalation for changes under /etc

- **Logic:** parent 550 ("integrity checksum changed", level 7)
  fires for any monitored path. This child matches
  `<field name="file">^/etc/</field>` and raises the same event to
  level 12: under `/etc`, a changed file usually means a changed
  config, account database, or service definition.
- **MITRE:** T1565.001 (Stored Data Manipulation).
- **Test it:** detection test plan **Test 4** (FIM). Modify the test
  file under `/etc` exactly as Test 4 describes. Expect stock 550
  **and** custom 100003 for the same change; a change to a monitored
  file outside `/etc` should produce 550 only: that contrast is
  what proves the path filter works.

### 100004: new file in a persistence location

- **Logic:** parent 554 ("file added to the system") plus a path
  filter for `^/etc/(systemd/system/|cron)`. New systemd units and
  cron entries are how Test 5 installs persistence, so they get a
  dedicated level-13 alert instead of blending into generic
  file-added noise.
- **MITRE:** T1543.002 (Systemd Service), T1053.003 (Cron).
- **Test it:** detection test plan **Test 5** (persistence). Create
  the dummy unit `/etc/systemd/system/soc-persistence-test.service`
  as Test 5 describes. Expect 554 **and** 100004. Then do the
  Test 5 cleanup and confirm the removal event as well.

## Deploy + validate

```bash
# From the repo root, stack running:
docker compose cp rules/local_rules.xml \
    wazuh.manager:/var/ossec/etc/rules/local_rules.xml
docker compose cp rules/lists/soc-admin-users \
    wazuh.manager:/var/ossec/etc/lists/soc-admin-users
docker compose exec wazuh.manager bash -c \
  "chown root:ossec /var/ossec/etc/rules/local_rules.xml \
                     /var/ossec/etc/lists/soc-admin-users && \
   chmod 660 /var/ossec/etc/rules/local_rules.xml \
             /var/ossec/etc/lists/soc-admin-users"

# Syntax/rule check BEFORE restart - this is the step that catches
# bad XML, unknown parent IDs, and a missing CDB list:
docker compose exec wazuh.manager /var/ossec/bin/wazuh-logtest -t

# The CDB list must also be DECLARED in the manager's ossec.conf under
# <ruleset> (Wazuh only loads declared lists). Add once, before restart:
#   <ruleset>
#     ...
#     <list>etc/lists/soc-admin-users</list>
#   </ruleset>
# Verify against the <ruleset> block in your manager's ossec.conf.

docker compose restart wazuh.manager
```

Then feed one matching event through **Management → Ruleset →
Logtest** in the dashboard (or `wazuh-logtest` interactively) and
confirm the custom rule (not just the parent) is the one that
matches. Field names (`srcuser`, `file`) come from the stock sudo
and syscheck decoders; if logtest shows a field is not populated
the way a rule expects, logtest output is where you'll see it.

## Tuning notes

- **100001** is the noise risk. If it pages on legitimate fat-finger
  logins, raise `frequency` before lowering `level`: you want the
  alert rare *and* loud.
- **100003/100004** will fire on every package update that touches
  `/etc`. In a test environment that's a feature (you see real change traffic);
  anywhere else, baseline updates first, then decide whether to add
  exceptions.
- Custom rules that stop matching after a Wazuh upgrade usually
  broke because a stock parent ID changed: re-check the parents
  (5716, 5402, 550, 554) on every version bump.
