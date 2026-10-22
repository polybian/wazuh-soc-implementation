#!/usr/bin/env bash
# =====================================================================
# block-offending-ip.sh — ACTIVE-RESPONSE SKELETON (TEST ONLY)
#
# Blocks (drops) traffic from an offending source IP on the host that
# runs this script. Written in the Wazuh/OSSEC active-response
# convention: the script is installed in
#     /var/ossec/active-response/bin/
# on the AGENT (or manager) and Wazuh's execd invokes it when a rule
# with an <active-response> command fires.
#
# HOW WAZUH INVOKES IT — both conventions are accepted:
#
#   1) Legacy argv mode (OSSEC/Wazuh < 4.x execd, still the most common
#      invocation): execd calls
#          block-offending-ip.sh <add|delete> <user> <srcip> <alert_id> [location] ...
#      where $1 is the action, $2 the alert's user field ("-" when none),
#      $3 the offender's source IP, $4 the alert id.
#
#   2) JSON mode (Wazuh 4.x execd pipes a JSON object on stdin):
#          { "version":1,
#            "origin":{"name":"...","module":"wazuh-execd"},
#            "command":"add",
#            "parameters":{
#               "alert":{"data":{"srcip":"198.51.100.23"},
#                         "rule":{"id":"100001"},
#                         "id":"177..."} } }
#      This skeleton parses the JSON with grep/sed on purpose — no jq
#      dependency in a minimal agent container. A production version
#      should use python3 -c 'import json,sys; ...' for real parsing.
#
# SKELETON, NOT A WEAPON:
#   - The script DRY-RUNS by default: with any real "add" invocation it
#     only LOGS the iptables command it WOULD run and exits 0. Nothing
#     is blocked unless the operator sets BLOCK_IP_APPLY=1 explicitly,
#     is running as root, and iptables exists — three gates, not one.
#   - Do NOT wire this to an active-response command (ossec.conf) until
#     you have soaked rule 100001 for false positives. Auto-blocking a
#     NAT-ed or VPN source IP can lock legitimate users out of the test environment.
#
# REFUSAL CONTRACT (tested): invoked with no arguments and no JSON on
# stdin, the script prints a usage error and exits 2 — it must NEVER
# silently default to blocking 0.0.0.0 or anything else.
#
# Exit codes: 0 = handled (add/delete/dry-run ok), 2 = bad invocation
# or invalid input, 3 = refused for safety (denylisted/self IP),
# 4 = apply requested but prerequisites missing (not root / no
# iptables).
# =====================================================================

set -u   # fail on unset variables; errors are handled explicitly below

# ---------------------------------------------------------------------
# Configuration — everything tunable via environment, nothing hardcoded
# that an operator would need to edit per host.
# ---------------------------------------------------------------------
PROG="$(basename "$0")"

# Where every action (and every refusal) gets logged. On a real agent
# this is the conventional Wazuh active-responses log; when it is not
# writable we fall back to stderr so nothing fails silently.
LOG_FILE="${BLOCK_IP_AR_LOG:-/var/ossec/logs/active-responses.log}"

# Dry-run is the DEFAULT and the safe posture for this skeleton.
# Set BLOCK_IP_APPLY=1 to actually execute the iptables command — only
# after you have read the warnings at the top of this file.
APPLY="${BLOCK_IP_APPLY:-0}"

# IPs we will never touch. The manager's own address can be added via
# the WAZUH_MANAGER_IP environment variable; loopback and "all zeros"
# are always refused regardless.
MANAGER_IP="${WAZUH_MANAGER_IP:-}"
DENY_LIST_DEFAULT="127.0.0.1 0.0.0.0"
EXTRA_DENY="${BLOCK_IP_NEVER_BLOCK:-}"

# iptables binary — only consulted in apply mode.
IPTABLES_BIN="$(command -v iptables 2>/dev/null || true)"

# ---------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------

# log_action <message...>
# Appends a timestamped line to LOG_FILE; if the log is not writable
# (e.g. this skeleton run in a sandbox), echoes to stderr instead.
# Returns 0 always — logging must never be a new failure mode.
log_action() {
    local ts line
    ts="$(date -u '+%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || date)"
    line="${ts} ${PROG}[$$]: $*"
    if ! printf '%s\n' "${line}" >>"${LOG_FILE}" 2>/dev/null; then
        printf '%s\n' "${line}" >&2
    fi
    return 0
}

# refuse <message> [exit_code]
# The single funnel for every "I will not do this" path: logs it,
# tells the operator why on stderr, and exits non-zero.
refuse() {
    local msg="$1"
    local code="${2:-2}"
    log_action "REFUSED: ${msg}"
    printf '%s: REFUSED: %s\n' "${PROG}" "${msg}" >&2
    exit "${code}"
}

# usage — printed by the refusal path so the caller learns the contract.
usage() {
    cat >&2 <<EOF
${PROG}: active-response skeleton — refuses to run without its inputs.

Legacy AR invocation (Wazuh execd):
    ${PROG} <add|delete> <user> <srcip> <alert_id> [location] ...

JSON invocation (Wazuh 4.x, JSON on stdin):
    echo '<json>' | ${PROG}

Environment:
    BLOCK_IP_AR_LOG       log path (default /var/ossec/logs/active-responses.log)
    BLOCK_IP_APPLY=1      REQUIRED to actually run iptables (default 0 = dry-run)
    WAZUH_MANAGER_IP      manager IP — never block this address
    BLOCK_IP_NEVER_BLOCK  extra space-separated IPs to refuse

Called with no usable inputs, this script exits non-zero and blocks nothing.
EOF
}

# is_valid_ipv4 <addr>
# Strict IPv4 check: dotted-quad shape, each octet 0-255, and the
# structurally dangerous forms (0.0.0.0/8, 127/8 loopback, 224+/8
# multicast, 255.255.255.255 broadcast) are rejected here so they can
# never reach iptables through this script.
is_valid_ipv4() {
    local addr="$1" octet
    # shape: four 1-3 digit groups separated by dots
    if [[ ! "${addr}" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]]; then
        return 1
    fi
    for octet in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" \
                 "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
        # strip a leading zero so 08/09 are decimal, not failed octal
        octet="${octet#0}"; octet="${octet:-0}"
        if (( 10#${octet} < 0 || 10#${octet} > 255 )); then
            return 1
        fi
    done
    local first="${BASH_REMATCH[1]#0}"; first="${first:-0}"
    if (( 10#${first} == 0 || 10#${first} == 127 )); then
        return 1    # 0.0.0.0/8 "this" network / 127.0.0.0/8 loopback
    fi
    # 224.0.0.0/4 multicast and 240.0.0.0/4 reserved incl. broadcast
    if (( 10#${first} >= 224 )); then
        return 1
    fi
    return 0
}

# is_denylisted <addr>
# Refuses addresses the script must never block: loopback, all-zeros,
# the manager IP, and any operator-supplied extras.
is_denylisted() {
    local addr="$1" entry
    for entry in ${DENY_LIST_DEFAULT} ${EXTRA_DENY}; do
        [ "${addr}" = "${entry}" ] && return 0
    done
    if [ -n "${MANAGER_IP}" ] && [ "${addr}" = "${MANAGER_IP}" ]; then
        return 0
    fi
    return 1
}

# ---------------------------------------------------------------------
# Input parsing — two AR conventions, one validated result.
# Sets: ACTION (add|delete), SRCIP, CALLER_USER, ALERT_ID.
# ---------------------------------------------------------------------
ACTION=""; SRCIP=""; CALLER_USER="-"; ALERT_ID="-"

parse_legacy_args() {
    # $1=add|delete $2=user $3=srcip $4=alert_id [location] ...
    if [ "$#" -lt 4 ]; then
        usage
        refuse "legacy AR mode needs at least 4 arguments (got $#): $*"
    fi
    case "$1" in
        add|delete) ACTION="$1" ;;
        *) usage; refuse "unknown action '$1' — expected 'add' or 'delete'" ;;
    esac
    CALLER_USER="$2"
    SRCIP="$3"
    ALERT_ID="$4"
}

parse_json_stdin() {
    local input="" action_val ip_val
    # -t 5 so a stuck stdin cannot hang execd forever; -d '' reads to EOF.
    if ! IFS= read -r -t 5 -d '' input; then
        if [ -z "${input:-}" ]; then
            usage
            refuse "no arguments and no JSON on stdin — nothing to do"
        fi
    fi
    # Minimal extraction on purpose (see header): "command" and the
    # alert's srcip. Quoted-string JSON values only; a production
    # script should use a real JSON parser here.
    action_val="$(printf '%s' "${input}" | grep -o '"command"[[:space:]]*:[[:space:]]*"[^"]*"' \
                    | head -n 1 | sed -e 's/^[^:]*:[[:space:]]*"//' -e 's/"$//')"
    ip_val="$(printf '%s' "${input}" | grep -o '"srcip"[[:space:]]*:[[:space:]]*"[^"]*"' \
                | head -n 1 | sed -e 's/^[^:]*:[[:space:]]*"//' -e 's/"$//')"
    case "${action_val}" in
        add|delete) ACTION="${action_val}" ;;
        "") usage; refuse "JSON input has no \"command\" field" ;;
        *) usage; refuse "JSON \"command\"='${action_val}' — expected 'add' or 'delete'" ;;
    esac
    SRCIP="${ip_val}"
}

if [ "$#" -ge 1 ]; then
    parse_legacy_args "$@"
else
    # No arguments: only acceptable if a JSON object arrives on stdin.
    # -t 0 is a terminal, so there is no JSON coming — refuse fast.
    if [ -t 0 ]; then
        usage
        refuse "no arguments given (stdin is a terminal) — nothing to do"
    fi
    parse_json_stdin
fi

# ---------------------------------------------------------------------
# Validation — the script does NOTHING until all of these pass.
# ---------------------------------------------------------------------
if [ -z "${SRCIP}" ]; then
    refuse "empty source IP — cannot determine what to ${ACTION}"
fi
if ! is_valid_ipv4 "${SRCIP}"; then
    refuse "invalid IPv4 address '${SRCIP}' — refusing to ${ACTION}"
fi
if is_denylisted "${SRCIP}"; then
    refuse "address '${SRCIP}' is on the never-block list — refusing to ${ACTION}" 3
fi

# Safety gate against argument smuggling into a shell: SRCIP is now a
# validated dotted-quad, and it is passed to iptables as ONE quoted
# argv — never interpolated into a string that gets evaluated.
IPTABLES_DESC="iptables -I INPUT -s ${SRCIP} -j DROP"
IPTABLES_DELETE_DESC="iptables -D INPUT -s ${SRCIP} -j DROP"

log_action "validated action='${ACTION}' srcip='${SRCIP}' user='${CALLER_USER}' alert_id='${ALERT_ID}'"

# ---------------------------------------------------------------------
# Act (or dry-run — the default).
# ---------------------------------------------------------------------
do_add() {
    if [ "${APPLY}" != "1" ]; then
        log_action "DRY-RUN add: would run: ${IPTABLES_DESC} (set BLOCK_IP_APPLY=1 to apply)"
        printf '%s: DRY-RUN — would run: %s\n' "${PROG}" "${IPTABLES_DESC}"
        return 0
    fi
    # Real apply mode: three more gates before anything touches netfilter.
    [ -n "${IPTABLES_BIN}" ] \
        || refuse "BLOCK_IP_APPLY=1 but iptables was not found on PATH" 4
    [ "$(id -u)" -eq 0 ] \
        || refuse "BLOCK_IP_APPLY=1 but not running as root — refusing" 4
    log_action "APPLY add: executing ${IPTABLES_DESC}"
    if "${IPTABLES_BIN}" -I INPUT -s "${SRCIP}" -j DROP; then
        log_action "APPLY add: OK — ${SRCIP} dropped on INPUT"
        return 0
    fi
    log_action "APPLY add: FAILED for ${SRCIP}"
    return 1
}

do_delete() {
    if [ "${APPLY}" != "1" ]; then
        log_action "DRY-RUN delete: would run: ${IPTABLES_DELETE_DESC} (set BLOCK_IP_APPLY=1 to apply)"
        printf '%s: DRY-RUN — would run: %s\n' "${PROG}" "${IPTABLES_DELETE_DESC}"
        return 0
    fi
    [ -n "${IPTABLES_BIN}" ] \
        || refuse "BLOCK_IP_APPLY=1 but iptables was not found on PATH" 4
    [ "$(id -u)" -eq 0 ] \
        || refuse "BLOCK_IP_APPLY=1 but not running as root — refusing" 4
    log_action "APPLY delete: executing ${IPTABLES_DELETE_DESC}"
    if "${IPTABLES_BIN}" -D INPUT -s "${SRCIP}" -j DROP; then
        log_action "APPLY delete: OK — ${SRCIP} removed from INPUT"
        return 0
    fi
    log_action "APPLY delete: FAILED for ${SRCIP}"
    return 1
}

case "${ACTION}" in
    add)    do_add ;;
    delete) do_delete ;;
    *)      refuse "internal error: unhandled action '${ACTION}'" ;;
esac
