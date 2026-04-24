#!/bin/bash
# =============================================================================
# Description : CIS Kubernetes Benchmark v1.12.0 - Section 1.1 Pipeline
# Scope       : Section 1.1 (Control Plane Node Configuration Files)
# Flow        : Check -> Confirm -> Remediate -> Verify -> kube-bench
# Requirements: Run with root privileges (sudo)
# =============================================================================

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECK="${SCRIPT_DIR}/check_1.1.py"
REMEDIATE="${SCRIPT_DIR}/remediate_1.1.yml"

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

# Simple 2-column table: no box drawing, no color inside cells
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

# --------------------------------------------------------------------------- #
echo ""
echo "======================================================================="
echo " CIS Kubernetes Benchmark v1.12.0 - Section 1.1 Pipeline"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo "======================================================================="
echo ""

[ "$EUID" -ne 0 ] && { log_err "Must run as root (sudo)."; exit 1; }
[ ! -f "$CHECK" ]     && { log_err "Not found: $CHECK"; exit 1; }
[ ! -f "$REMEDIATE" ] && { log_err "Not found: $REMEDIATE"; exit 1; }
log_ok "Pre-flight passed."

# --------------------------------------------------------------------------- #
log_step "STEP 1/4 -- Initial Audit"

python3 "$CHECK"
JSON_BEFORE="$(latest "${SCRIPT_DIR}/check_result_1.1_*.json")"
PASS_BEFORE="$(get_json "$JSON_BEFORE" pass)"
FAIL_BEFORE="$(get_json "$JSON_BEFORE" fail)"

echo ""
print_table "BEFORE Remediation  Section 1.1" "$PASS_BEFORE" "$FAIL_BEFORE"
echo ""

# --------------------------------------------------------------------------- #
log_step "STEP 2/4 -- Confirm Remediation"

if [ "$FAIL_BEFORE" = "0" ]; then
    log_ok "All checks PASS. No remediation needed."
    exit 0
fi

echo -e "  ${RED}${BOLD}Detected ${FAIL_BEFORE} FAIL(s)${RESET}"
echo ""
read -r -p "  [2/4] Chay remediation cho Section 1.1? (y/n): " CONFIRM
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

log_info "Re-running Section 1.1 audit..."
python3 "$CHECK"
JSON_AFTER="$(latest "${SCRIPT_DIR}/check_result_1.1_*.json")"
PASS_AFTER="$(get_json "$JSON_AFTER" pass)"
FAIL_AFTER="$(get_json "$JSON_AFTER" fail)"

echo ""
print_table "BEFORE  Section 1.1" "$PASS_BEFORE" "$FAIL_BEFORE"
echo ""
print_table "AFTER   Section 1.1" "$PASS_AFTER"  "$FAIL_AFTER"
echo ""
echo -e "  ${CYAN}Result files:${RESET}"
echo "    Before : $(basename "$JSON_BEFORE")"
echo "    After  : $(basename "$JSON_AFTER")"
echo ""

# kube-bench - section 1.1 only
KB_JSON="${SCRIPT_DIR}/kube_bench_1.1_$(date +%Y%m%d_%H%M%S).json"
if command -v kube-bench &>/dev/null; then
    log_info "Running kube-bench (section 1.1 only)..."
    kube-bench run --targets=master --benchmark cis-1.8 --json 2>/dev/null \
        | python3 -c "
import json, sys
d = json.load(sys.stdin)
tests_11 = []
for c in d.get('Controls', []):
    for t in (c.get('tests') or []):
        if t.get('section') == '1.1':
            tests_11.append(t)
p = sum(t.get('pass',0) for t in tests_11)
f = sum(t.get('fail',0) for t in tests_11)
w = sum(t.get('warn',0) for t in tests_11)
out = {'section':'1.1','total_pass':p,'total_fail':f,'total_warn':w,'tests':tests_11}
print(json.dumps(out, indent=2))
" > "$KB_JSON" 2>/dev/null

    KB_PASS="$(python3 -c "import json; d=json.load(open('$KB_JSON')); print(d.get('total_pass','?'))" 2>/dev/null || echo '?')"
    KB_FAIL="$(python3 -c "import json; d=json.load(open('$KB_JSON')); print(d.get('total_fail','?'))" 2>/dev/null || echo '?')"
    KB_WARN="$(python3 -c "import json; d=json.load(open('$KB_JSON')); print(d.get('total_warn','?'))" 2>/dev/null || echo '?')"

    echo -e "  ${CYAN}kube-bench cross-validation (cis-1.8, section 1.1):${RESET}"
    print_table "kube-bench  Section 1.1" "$KB_PASS" "$KB_FAIL"
    echo "    WARN: $KB_WARN  |  Saved: $(basename "$KB_JSON")"
    echo ""
    [ "$KB_FAIL" = "0" ] \
        && log_ok "Cross-validation PASSED: kube-bench confirms Section 1.1 compliant." \
        || log_warn "kube-bench reports ${KB_FAIL} FAIL(s). Review: $(basename "$KB_JSON")"
else
    log_warn "kube-bench not found. Skipping."
fi

echo ""
echo "======================================================================="
[ "$FAIL_AFTER" = "0" ] \
    && echo -e "${GREEN}${BOLD} [+] Section 1.1 PASS -- All checks compliant.${RESET}" \
    || echo -e "${RED}${BOLD} [!] Section 1.1: ${FAIL_AFTER} FAIL(s) remain.${RESET}"
echo "======================================================================="
echo ""
