#!/bin/bash
# =============================================================================
# Description : CIS Kubernetes Benchmark v1.12.0 - Section 1.2 Part 1 Pipeline
# Scope       : Section 1.2.1 - 1.2.12 (API Server Arguments)
# Flow        : Check -> Confirm -> Remediate -> Verify -> kube-bench
# Requirements: Run with root privileges (sudo)
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="${SCRIPT_DIR}/check_1.2_1.py"
REMEDIATE="${SCRIPT_DIR}/remediate_1.2_1.yml"

GREEN="\033[92m"; RED="\033[91m"; YELLOW="\033[93m"
CYAN="\033[96m"; RESET="\033[0m"; BOLD="\033[1m"

log_info() { echo -e "${CYAN}[*]${RESET} $*"; }
log_ok()   { echo -e "${GREEN}[+]${RESET} $*"; }
log_warn() { echo -e "${YELLOW}[!]${RESET} $*"; }
log_err()  { echo -e "${RED}[x]${RESET} $*"; }
log_step() {
    echo -e "\n${BOLD}${CYAN}======================================================================${RESET}"
    echo -e "${BOLD}  $*${RESET}"
    echo -e "${BOLD}${CYAN}======================================================================${RESET}\n"
}

print_table() {
    local title="$1" pass="$2" fail="$3"
    echo "  +----------------------------------+--------+--------+"
    printf "  | %-32s | %-6s | %-6s |\n" "$title" "PASS" "FAIL"
    echo "  +----------------------------------+--------+--------+"
    printf "  | %-32s | %-6s | %-6s |\n" "" "$pass" "$fail"
    echo "  +----------------------------------+--------+--------+"
}

get_json() { python3 -c "import json; d=json.load(open('$1')); print(d['summary']['$2'])" 2>/dev/null || echo "?"; }
latest()   { ls -t $1 2>/dev/null | head -1; }

# Known exception: 1.2.1 anonymous-auth (Manual/Not Scored)
EXCEPTION_COUNT=1

# --------------------------------------------------------------------------- #
echo ""
echo "======================================================================="
echo " CIS Kubernetes Benchmark v1.12.0 - Section 1.2 Part 1 Pipeline"
echo " Scope: 1.2.1 - 1.2.12  |  $(date '+%Y-%m-%d %H:%M:%S')"
echo "======================================================================="
echo ""

[ "$EUID" -ne 0 ] && { log_err "Must run as root (sudo)."; exit 1; }
[ ! -f "$CHECK" ]     && { log_err "Not found: $CHECK"; exit 1; }
[ ! -f "$REMEDIATE" ] && { log_err "Not found: $REMEDIATE"; exit 1; }
log_ok "Pre-flight passed."

# --------------------------------------------------------------------------- #
log_step "STEP 1/4 -- Initial Audit"

python3 "$CHECK"
JSON_BEFORE="$(latest "${SCRIPT_DIR}/check_result_1.2_1_*.json")"
PASS_BEFORE="$(get_json "$JSON_BEFORE" pass)"
FAIL_BEFORE="$(get_json "$JSON_BEFORE" fail)"

echo ""
print_table "BEFORE Remediation  1.2.1-1.2.12" "$PASS_BEFORE" "$FAIL_BEFORE"
echo ""

# --------------------------------------------------------------------------- #
log_step "STEP 2/4 -- Confirm Remediation"

OTHER_FAILS=$((FAIL_BEFORE > EXCEPTION_COUNT ? FAIL_BEFORE - EXCEPTION_COUNT : 0))

if [ "$OTHER_FAILS" -eq 0 ]; then
    log_warn "1.2.1 anonymous-auth: Manual/Not Scored exception. See report."
    echo ""
    read -r -p "  Chay remediation de ap dung cac flag con lai? (y/n): " CONFIRM
else
    echo -e "  ${RED}${BOLD}Detected ${OTHER_FAILS} unexpected FAIL(s) + 1 known exception (1.2.1)${RESET}"
    echo ""
    read -r -p "  [2/4] Chay remediation cho Section 1.2? (y/n): " CONFIRM
fi
echo ""
[[ ! "$CONFIRM" =~ ^[Yy]$ ]] && { log_warn "Cancelled."; exit 0; }

# --------------------------------------------------------------------------- #
log_step "STEP 3/4 -- Remediation"

ansible-playbook "$REMEDIATE" -i "${SCRIPT_DIR}/inventory.ini"
RC=$?
echo ""
[ $RC -ne 0 ] && log_err "Remediation reported failures." || log_ok "Remediation completed."

# --------------------------------------------------------------------------- #
log_step "STEP 4/4 -- Verify + kube-bench"

log_info "Re-running Section 1.2 audit..."
python3 "$CHECK"
JSON_AFTER="$(latest "${SCRIPT_DIR}/check_result_1.2_1_*.json")"
PASS_AFTER="$(get_json "$JSON_AFTER" pass)"
FAIL_AFTER="$(get_json "$JSON_AFTER" fail)"

echo ""
print_table "BEFORE  1.2.1-1.2.12" "$PASS_BEFORE" "$FAIL_BEFORE"
echo ""
print_table "AFTER   1.2.1-1.2.12" "$PASS_AFTER"  "$FAIL_AFTER"
echo ""
echo -e "  ${CYAN}Result files:${RESET}"
echo "    Before : $(basename "$JSON_BEFORE")"
echo "    After  : $(basename "$JSON_AFTER")"
echo ""

# Wait for kubelet to fully reload manifest after Ansible restart
# kube-bench uses ps -ef to read live process args -- if API server
# is still restarting the old process may still appear in ps output
log_info "Waiting 15s for API server to stabilize before kube-bench..."
sleep 15

# kube-bench - filter 1.2.1 to 1.2.12 only
KB_JSON="${SCRIPT_DIR}/kube_bench_1.2_$(date +%Y%m%d_%H%M%S).json"
if command -v kube-bench &>/dev/null; then
    log_info "Running kube-bench (section 1.2, filtered to 1.2.1-1.2.12)..."
    kube-bench run --targets=master --benchmark cis-1.8 --json 2>/dev/null \
        | python3 -c "
import json, sys
d = json.load(sys.stdin)
# Keep only test_number 1.2.1 through 1.2.12
in_scope = {f'1.2.{i}' for i in range(1, 13)}
tests_12 = []
for c in d.get('Controls', []):
    for t in (c.get('tests') or []):
        if t.get('section') == '1.2':
            filtered = [r for r in t.get('results', [])
                        if r.get('test_number') in in_scope]
            if filtered:
                p = sum(1 for r in filtered if r.get('status') == 'PASS')
                f = sum(1 for r in filtered if r.get('status') == 'FAIL')
                w = sum(1 for r in filtered if r.get('status') == 'WARN')
                tests_12.append({'section':'1.2','results':filtered,
                                  'pass':p,'fail':f,'warn':w})
p_total = sum(t['pass'] for t in tests_12)
f_total = sum(t['fail'] for t in tests_12)
w_total = sum(t['warn'] for t in tests_12)
out = {'scope':'1.2.1-1.2.12','total_pass':p_total,
       'total_fail':f_total,'total_warn':w_total,'tests':tests_12}
print(json.dumps(out, indent=2))
" > "$KB_JSON" 2>/dev/null

    KB_PASS="$(python3 -c "import json; d=json.load(open('$KB_JSON')); print(d.get('total_pass','?'))" 2>/dev/null || echo '?')"
    KB_FAIL="$(python3 -c "import json; d=json.load(open('$KB_JSON')); print(d.get('total_fail','?'))" 2>/dev/null || echo '?')"
    KB_WARN="$(python3 -c "import json; d=json.load(open('$KB_JSON')); print(d.get('total_warn','?'))" 2>/dev/null || echo '?')"

    echo -e "  ${CYAN}kube-bench cross-validation (cis-1.8, scope 1.2.1-1.2.12):${RESET}"
    print_table "kube-bench  1.2.1-1.2.12" "$KB_PASS" "$KB_FAIL"
    echo "    WARN: $KB_WARN  |  Saved: $(basename "$KB_JSON")"
    echo ""

    # Cross-validate: 1.2.1 is WARN in kube-bench (Manual), so expected FAIL=0
    if [ "$KB_FAIL" = "0" ]; then
        log_ok "Cross-validation PASSED: kube-bench confirms 1.2.1-1.2.12 compliant."
    else
        log_warn "kube-bench reports ${KB_FAIL} FAIL(s) in scope. Review: $(basename "$KB_JSON")"
    fi
else
    log_warn "kube-bench not found. Skipping."
fi

echo ""
echo "======================================================================="
REMAINING=$((FAIL_AFTER > EXCEPTION_COUNT ? FAIL_AFTER - EXCEPTION_COUNT : 0))
if [ "$REMAINING" -eq 0 ]; then
    echo -e "${GREEN}${BOLD} [+] Section 1.2 PASS -- All automated checks compliant.${RESET}"
    echo -e "${YELLOW}     Exception: 1.2.1 anonymous-auth (Manual/Not Scored -- documented).${RESET}"
else
    echo -e "${RED}${BOLD} [!] Section 1.2: ${REMAINING} unexpected FAIL(s) remain.${RESET}"
fi
echo "======================================================================="
echo ""
