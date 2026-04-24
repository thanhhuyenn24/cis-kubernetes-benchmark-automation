#!/usr/bin/env python3
"""
=============================================================================
Description : CIS Kubernetes Benchmark v1.12.0 - Section 1.2 Audit Check
Scope       : API Server Arguments (1.2.1 - 1.2.12)
Output      : Console + check_result_1.2_1_<timestamp>.json
Requirements: Run with root privileges (sudo)
=============================================================================
"""

import subprocess
import json
import os
import sys
import re
from datetime import datetime

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #

TIMESTAMP   = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILE = f"check_result_1.2_1_{TIMESTAMP}.json"

PASS = "PASS"
FAIL = "FAIL"
WARN = "WARN"
NA   = "N/A"

GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
RESET  = "\033[0m"
BOLD   = "\033[1m"

# --------------------------------------------------------------------------- #
#  Helpers
# --------------------------------------------------------------------------- #

def run_cmd(cmd: str) -> tuple[int, str]:
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True
    )
    return result.returncode, (result.stdout + result.stderr).strip()


def get_apiserver_args() -> str:
    """Return the full kube-apiserver process command line."""
    rc, out = run_cmd("ps -ef | grep kube-apiserver | grep -v grep")
    return out


def get_flag_value(args: str, flag: str) -> str | None:
    """
    Extract value of --flag=value or --flag value from process args.
    Returns None if flag is not present.
    """
    # Try --flag=value
    m = re.search(rf"--{re.escape(flag)}=(\S+)", args)
    if m:
        return m.group(1)
    # Try --flag value (space separated)
    m = re.search(rf"--{re.escape(flag)}\s+(\S+)", args)
    if m:
        return m.group(1)
    return None


def flag_exists(args: str, flag: str) -> bool:
    return bool(re.search(rf"--{re.escape(flag)}[=\s]", args))


def make_result(check_id, title, status,
                actual="", expected="",
                remediation_tag="", note="") -> dict:
    return {
        "check_id":        check_id,
        "title":           title,
        "status":          status,
        "actual":          actual,
        "expected":        expected,
        "remediation_tag": remediation_tag,
        "note":            note,
    }


def print_result(r: dict) -> None:
    sid    = r["check_id"]
    status = r["status"]
    title  = r["title"]

    color = {PASS: GREEN, FAIL: RED, WARN: YELLOW}.get(status, CYAN)
    icon  = {PASS: "[PASS]", FAIL: "[FAIL]", WARN: "[WARN]"}.get(status, "[ N/A]")

    print(f"  {color}{BOLD}{icon}{RESET} {sid:<8} {title}")
    if status != PASS:
        print(f"           Actual  : {r['actual']}")
        print(f"           Expected: {r['expected']}")
    if r.get("note"):
        print(f"           Note    : {r['note']}")


# --------------------------------------------------------------------------- #
#  Individual Checks
# --------------------------------------------------------------------------- #

def check_1_2_1(args: str) -> dict:
    """
    1.2.1 --anonymous-auth=false (Manual / Not Scored)

    This check always returns FAIL with a documented exception note.

    Reason: k8s v1.29 readiness probe calls /readyz anonymously via HTTP.
    Setting --anonymous-auth=false causes the probe to receive 401 Unauthorized,
    leaving the pod permanently at 0/1 Running and breaking the control plane.
    The cluster uses RBAC (Node,RBAC) as a compensating control.
    Per CIS Benchmark page 62: this recommendation is Not Scored when RBAC is used.
    Risk is accepted and documented.
    """
    return make_result(
        "1.2.1",
        "Ensure --anonymous-auth argument is set to false",
        FAIL,
        actual="anonymous-auth not set explicitly (effective: true for /readyz probe)",
        expected="anonymous-auth=false",
        remediation_tag="",
        note=(
            "EXCEPTION (Manual/Not Scored): Readiness probe requires anonymous access "
            "to /readyz. Setting false breaks pod health check (0/1 Running). "
            "Compensating control: RBAC=Node,RBAC enabled. "
            "Risk accepted per CIS Benchmark v1.12.0 page 62."
        )
    )


def check_1_2_2(args: str) -> dict:
    """1.2.2 --token-auth-file must NOT be set."""
    if flag_exists(args, "token-auth-file"):
        val = get_flag_value(args, "token-auth-file")
        return make_result(
            "1.2.2",
            "Ensure --token-auth-file parameter is not set",
            FAIL,
            actual=f"--token-auth-file={val}",
            expected="Flag must not be present",
            remediation_tag="remove_token_auth_file"
        )
    return make_result(
        "1.2.2",
        "Ensure --token-auth-file parameter is not set",
        PASS,
        actual="Flag not present",
        expected="Flag must not be present",
        remediation_tag="remove_token_auth_file"
    )


def check_1_2_3(args: str) -> dict:
    """1.2.3 DenyServiceExternalIPs must be in --enable-admission-plugins."""
    val = get_flag_value(args, "enable-admission-plugins")
    if val and "DenyServiceExternalIPs" in val:
        return make_result(
            "1.2.3",
            "Ensure DenyServiceExternalIPs admission controller is set",
            PASS,
            actual=f"--enable-admission-plugins={val}",
            expected="DenyServiceExternalIPs in plugin list",
            remediation_tag="add_admission_plugin_DenyServiceExternalIPs"
        )
    return make_result(
        "1.2.3",
        "Ensure DenyServiceExternalIPs admission controller is set",
        FAIL,
        actual=val or "Flag not present",
        expected="DenyServiceExternalIPs in --enable-admission-plugins",
        remediation_tag="add_admission_plugin_DenyServiceExternalIPs"
    )


def check_1_2_4(args: str) -> dict:
    """1.2.4 --kubelet-client-certificate and --kubelet-client-key must be set."""
    cert = get_flag_value(args, "kubelet-client-certificate")
    key  = get_flag_value(args, "kubelet-client-key")

    if cert and key:
        return make_result(
            "1.2.4",
            "Ensure --kubelet-client-certificate and --kubelet-client-key are set",
            PASS,
            actual=f"cert={cert}  key={key}",
            expected="Both flags set",
            remediation_tag="set_kubelet_client_cert"
        )
    missing = []
    if not cert:
        missing.append("--kubelet-client-certificate")
    if not key:
        missing.append("--kubelet-client-key")
    return make_result(
        "1.2.4",
        "Ensure --kubelet-client-certificate and --kubelet-client-key are set",
        FAIL,
        actual="Missing: " + ", ".join(missing),
        expected="Both flags must be set",
        remediation_tag="set_kubelet_client_cert"
    )


def check_1_2_5(args: str) -> dict:
    """1.2.5 --kubelet-certificate-authority must be set."""
    val = get_flag_value(args, "kubelet-certificate-authority")
    if val:
        return make_result(
            "1.2.5",
            "Ensure --kubelet-certificate-authority is set",
            PASS,
            actual=f"--kubelet-certificate-authority={val}",
            expected="Flag must be set",
            remediation_tag="set_kubelet_cert_authority"
        )
    return make_result(
        "1.2.5",
        "Ensure --kubelet-certificate-authority is set",
        FAIL,
        actual="Flag not present",
        expected="--kubelet-certificate-authority=<ca-file>",
        remediation_tag="set_kubelet_cert_authority"
    )


def check_1_2_6(args: str) -> dict:
    """1.2.6 --authorization-mode must NOT be AlwaysAllow."""
    val = get_flag_value(args, "authorization-mode")
    if val and "AlwaysAllow" in val:
        return make_result(
            "1.2.6",
            "Ensure --authorization-mode is not set to AlwaysAllow",
            FAIL,
            actual=f"--authorization-mode={val}",
            expected="Must not contain AlwaysAllow",
            remediation_tag="set_authorization_mode"
        )
    return make_result(
        "1.2.6",
        "Ensure --authorization-mode is not set to AlwaysAllow",
        PASS,
        actual=f"--authorization-mode={val}" if val else "AlwaysAllow not present",
        expected="Must not contain AlwaysAllow",
        remediation_tag="set_authorization_mode"
    )


def check_1_2_7(args: str) -> dict:
    """1.2.7 --authorization-mode must include Node."""
    val = get_flag_value(args, "authorization-mode")
    if val and "Node" in val.split(","):
        return make_result(
            "1.2.7",
            "Ensure --authorization-mode includes Node",
            PASS,
            actual=f"--authorization-mode={val}",
            expected="Node in authorization-mode",
            remediation_tag="set_authorization_mode"
        )
    return make_result(
        "1.2.7",
        "Ensure --authorization-mode includes Node",
        FAIL,
        actual=f"--authorization-mode={val}" if val else "Flag not present",
        expected="authorization-mode must include Node",
        remediation_tag="set_authorization_mode"
    )


def check_1_2_8(args: str) -> dict:
    """1.2.8 --authorization-mode must include RBAC."""
    val = get_flag_value(args, "authorization-mode")
    if val and "RBAC" in val.split(","):
        return make_result(
            "1.2.8",
            "Ensure --authorization-mode includes RBAC",
            PASS,
            actual=f"--authorization-mode={val}",
            expected="RBAC in authorization-mode",
            remediation_tag="set_authorization_mode"
        )
    return make_result(
        "1.2.8",
        "Ensure --authorization-mode includes RBAC",
        FAIL,
        actual=f"--authorization-mode={val}" if val else "Flag not present",
        expected="authorization-mode must include RBAC",
        remediation_tag="set_authorization_mode"
    )


def check_1_2_9(args: str) -> dict:
    """1.2.9 EventRateLimit must be in --enable-admission-plugins."""
    val         = get_flag_value(args, "enable-admission-plugins")
    config_flag = get_flag_value(args, "admission-control-config-file")

    plugin_ok = val and "EventRateLimit" in val
    config_ok = config_flag and os.path.exists(config_flag)

    if plugin_ok and config_ok:
        return make_result(
            "1.2.9",
            "Ensure EventRateLimit admission controller is set",
            PASS,
            actual=f"plugins={val}  config={config_flag}",
            expected="EventRateLimit in plugins + config file present",
            remediation_tag="add_admission_plugin_EventRateLimit"
        )

    issues = []
    if not plugin_ok:
        issues.append("EventRateLimit missing from --enable-admission-plugins")
    if not config_ok:
        issues.append(
            f"--admission-control-config-file not set or file missing "
            f"(current: {config_flag or 'not set'})"
        )
    return make_result(
        "1.2.9",
        "Ensure EventRateLimit admission controller is set",
        FAIL,
        actual="; ".join(issues),
        expected="EventRateLimit in plugins + config file present",
        remediation_tag="add_admission_plugin_EventRateLimit"
    )


def check_1_2_10(args: str) -> dict:
    """1.2.10 AlwaysAdmit must NOT be in --enable-admission-plugins."""
    val = get_flag_value(args, "enable-admission-plugins")
    if val and "AlwaysAdmit" in val:
        return make_result(
            "1.2.10",
            "Ensure AlwaysAdmit admission controller is not set",
            FAIL,
            actual=f"--enable-admission-plugins={val}",
            expected="AlwaysAdmit must not be present",
            remediation_tag="remove_AlwaysAdmit"
        )
    return make_result(
        "1.2.10",
        "Ensure AlwaysAdmit admission controller is not set",
        PASS,
        actual="AlwaysAdmit not present",
        expected="AlwaysAdmit must not be present",
        remediation_tag="remove_AlwaysAdmit"
    )


def check_1_2_11(args: str) -> dict:
    """1.2.11 AlwaysPullImages must be in --enable-admission-plugins."""
    val = get_flag_value(args, "enable-admission-plugins")
    if val and "AlwaysPullImages" in val:
        return make_result(
            "1.2.11",
            "Ensure AlwaysPullImages admission controller is set",
            PASS,
            actual=f"--enable-admission-plugins={val}",
            expected="AlwaysPullImages in plugin list",
            remediation_tag="add_admission_plugin_AlwaysPullImages"
        )
    return make_result(
        "1.2.11",
        "Ensure AlwaysPullImages admission controller is set",
        FAIL,
        actual=val or "Flag not present",
        expected="AlwaysPullImages in --enable-admission-plugins",
        remediation_tag="add_admission_plugin_AlwaysPullImages"
    )


def check_1_2_12(args: str) -> dict:
    """
    1.2.12 ServiceAccount admission controller must be set.
    It is enabled by default; FAIL only if explicitly disabled.
    """
    val = get_flag_value(args, "disable-admission-plugins")
    if val and "ServiceAccount" in val:
        return make_result(
            "1.2.12",
            "Ensure ServiceAccount admission controller is set",
            FAIL,
            actual=f"--disable-admission-plugins={val}",
            expected="ServiceAccount must NOT be in disable list",
            remediation_tag="enable_ServiceAccount"
        )
    return make_result(
        "1.2.12",
        "Ensure ServiceAccount admission controller is set",
        PASS,
        actual="ServiceAccount not in --disable-admission-plugins (enabled by default)",
        expected="ServiceAccount must not be disabled",
        remediation_tag="enable_ServiceAccount"
    )


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #

def main():
    if os.geteuid() != 0:
        print(f"{RED}[!] This script must be run as root (sudo).{RESET}")
        sys.exit(1)

    print()
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"{BOLD} CIS Kubernetes Benchmark v1.12.0 - Section 1.2 Audit Check (Part 1){RESET}")
    print(f"{BOLD} Scope: 1.2.1 – 1.2.12  |  {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print()

    # Get kube-apiserver process arguments once
    args = get_apiserver_args()

    if not args:
        print(f"{RED}[!] kube-apiserver process not found. Is the cluster running?{RESET}")
        sys.exit(1)

    # Run all checks
    check_fns = [
        check_1_2_1,
        check_1_2_2,
        check_1_2_3,
        check_1_2_4,
        check_1_2_5,
        check_1_2_6,
        check_1_2_7,
        check_1_2_8,
        check_1_2_9,
        check_1_2_10,
        check_1_2_11,
        check_1_2_12,
    ]

    all_results = []
    print(f"{CYAN}{BOLD}[*] 1.2.1 – 1.2.12  API Server Arguments{RESET}")
    for fn in check_fns:
        r = fn(args)
        print_result(r)
        all_results.append(r)
    print()

    # Summary
    total   = len(all_results)
    passed  = sum(1 for r in all_results if r["status"] == PASS)
    failed  = sum(1 for r in all_results if r["status"] == FAIL)
    warned  = sum(1 for r in all_results if r["status"] == WARN)
    skipped = sum(1 for r in all_results if r["status"] == NA)
    fail_tags = sorted({
        r["remediation_tag"] for r in all_results
        if r["status"] == FAIL and r["remediation_tag"]
    })

    print(f"{BOLD}{'='*70}{RESET}")
    print(f"{BOLD} Summary{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"  Total  : {total}")
    print(f"  {GREEN}{BOLD}PASS   : {passed}{RESET}")
    print(f"  {RED}{BOLD}FAIL   : {failed}{RESET}")
    print(f"  {YELLOW}{BOLD}WARN   : {warned}{RESET}")
    print(f"  {CYAN}N/A    : {skipped}{RESET}")
    if fail_tags:
        print(f"  {RED}Fail tags : {', '.join(fail_tags)}{RESET}")
    print()

    # Export JSON
    output = {
        "benchmark":  "CIS Kubernetes Benchmark v1.12.0",
        "section":    "1.2_1",
        "scope":      "1.2.1 - 1.2.12",
        "timestamp":  datetime.now().isoformat(),
        "node":       os.uname().nodename,
        "summary": {
            "total":     total,
            "pass":      passed,
            "fail":      failed,
            "warn":      warned,
            "na":        skipped,
            "fail_tags": fail_tags,
        },
        "results": all_results,
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"  Results exported to: {BOLD}{OUTPUT_FILE}{RESET}")
    print()

    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
