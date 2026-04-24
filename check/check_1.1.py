#!/usr/bin/env python3
"""
=============================================================================
Description : CIS Kubernetes Benchmark v1.12.0 - Section 1.1 Audit Check
Scope       : Control Plane Node Configuration Files (1.1.1 - 1.1.21)
Output      : Console + check_result_1.1_<timestamp>.json
Requirements: Run with root privileges (sudo)
=============================================================================
"""

import subprocess
import json
import os
import sys
import stat
from datetime import datetime

# --------------------------------------------------------------------------- #
#  Constants
# --------------------------------------------------------------------------- #

TIMESTAMP   = datetime.now().strftime("%Y%m%d_%H%M%S")
OUTPUT_FILE = f"check_result_1.1_{TIMESTAMP}.json"

PASS   = "PASS"
FAIL   = "FAIL"
WARN   = "WARN"
NA     = "N/A"

# ANSI colors for console output
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
    """Run a shell command, return (returncode, stdout+stderr)."""
    result = subprocess.run(
        cmd, shell=True, capture_output=True, text=True
    )
    output = (result.stdout + result.stderr).strip()
    return result.returncode, output


def get_octal_perms(path: str) -> str | None:
    """Return octal permission string (e.g. '600') or None if path missing."""
    rc, out = run_cmd(f"stat -c %a {path}")
    return out.strip() if rc == 0 and out.strip() else None


def get_ownership(path: str) -> str | None:
    """Return 'user:group' string or None if path missing."""
    rc, out = run_cmd(f"stat -c %U:%G {path}")
    return out.strip() if rc == 0 and out.strip() else None


def perm_ok(actual: str, max_allowed: int) -> bool:
    """
    Return True if actual octal permission is equal to or more restrictive
    than max_allowed.  E.g. actual='600', max_allowed=644 → True.
    """
    try:
        return int(actual, 8) <= int(str(max_allowed), 8)
    except (ValueError, TypeError):
        return False


def check_file_perms(check_id: str, title: str, path: str,
                     max_perm: int, remediation_tag: str) -> dict:
    """Generic check for file permissions."""
    if not os.path.exists(path):
        return make_result(check_id, title, NA,
                           actual="File not found",
                           expected=f"<={max_perm}",
                           remediation_tag=remediation_tag,
                           note="File does not exist on this system")

    actual = get_octal_perms(path)
    if actual is None:
        return make_result(check_id, title, FAIL,
                           actual="Unable to read permissions",
                           expected=f"<={max_perm}",
                           remediation_tag=remediation_tag)

    status = PASS if perm_ok(actual, max_perm) else FAIL
    return make_result(check_id, title, status,
                       actual=actual,
                       expected=f"<={max_perm}",
                       remediation_tag=remediation_tag)


def check_file_owner(check_id: str, title: str, path: str,
                     expected_owner: str, remediation_tag: str) -> dict:
    """Generic check for file ownership."""
    if not os.path.exists(path):
        return make_result(check_id, title, NA,
                           actual="File not found",
                           expected=expected_owner,
                           remediation_tag=remediation_tag,
                           note="File does not exist on this system")

    actual = get_ownership(path)
    if actual is None:
        return make_result(check_id, title, FAIL,
                           actual="Unable to read ownership",
                           expected=expected_owner,
                           remediation_tag=remediation_tag)

    status = PASS if actual == expected_owner else FAIL
    return make_result(check_id, title, status,
                       actual=actual,
                       expected=expected_owner,
                       remediation_tag=remediation_tag)


def make_result(check_id: str, title: str, status: str,
                actual: str = "", expected: str = "",
                remediation_tag: str = "", note: str = "") -> dict:
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
    """Print a single result line to console with color."""
    sid    = r["check_id"]
    status = r["status"]
    title  = r["title"]
    actual = r["actual"]
    exp    = r["expected"]

    if status == PASS:
        color = GREEN
        icon  = "[PASS]"
    elif status == FAIL:
        color = RED
        icon  = "[FAIL]"
    elif status == WARN:
        color = YELLOW
        icon  = "[WARN]"
    else:
        color = CYAN
        icon  = "[ N/A]"

    print(f"  {color}{BOLD}{icon}{RESET} {sid:<8} {title}")
    if status != PASS:
        print(f"           Actual  : {actual}")
        print(f"           Expected: {exp}")
        if r.get("note"):
            print(f"           Note    : {r['note']}")


# --------------------------------------------------------------------------- #
#  Individual Checks
# --------------------------------------------------------------------------- #

def checks_1_1_1_to_1_1_8() -> list[dict]:
    """1.1.1-1.1.8: Manifest file permissions and ownership."""
    manifest_dir = "/etc/kubernetes/manifests"
    results = []

    files = {
        "kube-apiserver.yaml":          ("1.1.1", "1.1.2"),
        "kube-controller-manager.yaml": ("1.1.3", "1.1.4"),
        "kube-scheduler.yaml":          ("1.1.5", "1.1.6"),
        "etcd.yaml":                    ("1.1.7", "1.1.8"),
    }

    for fname, (perm_id, own_id) in files.items():
        path      = os.path.join(manifest_dir, fname)
        component = fname.replace(".yaml", "")

        results.append(check_file_perms(
            perm_id,
            f"Pod spec file permissions set to 600 or more restrictive ({component})",
            path, 600,
            f"secure_manifest_{perm_id.replace('.', '_')}"
        ))
        results.append(check_file_owner(
            own_id,
            f"Pod spec file ownership set to root:root ({component})",
            path, "root:root",
            f"secure_manifest_{own_id.replace('.', '_')}"
        ))

    return results


def checks_1_1_9_to_1_1_10() -> list[dict]:
    """1.1.9-1.1.10: CNI configuration file permissions and ownership."""
    results = []
    cni_dir = "/etc/cni/net.d"

    if not os.path.isdir(cni_dir):
        results.append(make_result(
            "1.1.9", "CNI config file permissions set to 600 or more restrictive",
            NA, actual="Directory not found", expected="<=600",
            remediation_tag="secure_cni", note=f"{cni_dir} not present"
        ))
        results.append(make_result(
            "1.1.10", "CNI config file ownership set to root:root",
            NA, actual="Directory not found", expected="root:root",
            remediation_tag="secure_cni", note=f"{cni_dir} not present"
        ))
        return results

    rc, out = run_cmd(f"find {cni_dir} -type f")
    cni_files = [f for f in out.splitlines() if f.strip()]

    if not cni_files:
        results.append(make_result(
            "1.1.9", "CNI config file permissions set to 600 or more restrictive",
            NA, actual="No files found", expected="<=600",
            remediation_tag="secure_cni"
        ))
        results.append(make_result(
            "1.1.10", "CNI config file ownership set to root:root",
            NA, actual="No files found", expected="root:root",
            remediation_tag="secure_cni"
        ))
        return results

    # Check all CNI files; report FAIL if any file is non-compliant
    perm_fails  = []
    owner_fails = []

    for f in cni_files:
        perm = get_octal_perms(f)
        if perm and not perm_ok(perm, 600):
            perm_fails.append(f"{f} ({perm})")
        owner = get_ownership(f)
        if owner and owner != "root:root":
            owner_fails.append(f"{f} ({owner})")

    if perm_fails:
        results.append(make_result(
            "1.1.9", "CNI config file permissions set to 600 or more restrictive",
            FAIL,
            actual="Non-compliant: " + "; ".join(perm_fails),
            expected="<=600 for all files",
            remediation_tag="secure_cni"
        ))
    else:
        results.append(make_result(
            "1.1.9", "CNI config file permissions set to 600 or more restrictive",
            PASS,
            actual=f"All {len(cni_files)} file(s) compliant",
            expected="<=600 for all files",
            remediation_tag="secure_cni"
        ))

    if owner_fails:
        results.append(make_result(
            "1.1.10", "CNI config file ownership set to root:root",
            FAIL,
            actual="Non-compliant: " + "; ".join(owner_fails),
            expected="root:root for all files",
            remediation_tag="secure_cni"
        ))
    else:
        results.append(make_result(
            "1.1.10", "CNI config file ownership set to root:root",
            PASS,
            actual=f"All {len(cni_files)} file(s) compliant",
            expected="root:root for all files",
            remediation_tag="secure_cni"
        ))

    return results


def checks_1_1_11_to_1_1_12() -> list[dict]:
    """1.1.11-1.1.12: etcd data directory permissions and ownership."""
    results = []

    # Find etcd data directory from running process
    rc, out = run_cmd("ps -ef | grep etcd | grep -v grep | grep -oP '(?<=--data-dir=)\\S+'")
    etcd_dir = out.strip() if rc == 0 and out.strip() else "/var/lib/etcd"

    # 1.1.11 – permissions
    if not os.path.isdir(etcd_dir):
        results.append(make_result(
            "1.1.11", "etcd data directory permissions set to 700 or more restrictive",
            NA, actual="Directory not found", expected="<=700",
            remediation_tag="secure_etcd_dir",
            note=f"{etcd_dir} not present"
        ))
    else:
        actual = get_octal_perms(etcd_dir)
        status = PASS if actual and perm_ok(actual, 700) else FAIL
        results.append(make_result(
            "1.1.11", "etcd data directory permissions set to 700 or more restrictive",
            status,
            actual=actual or "unknown",
            expected="<=700",
            remediation_tag="secure_etcd_dir"
        ))

    # 1.1.12 – ownership
    if not os.path.isdir(etcd_dir):
        results.append(make_result(
            "1.1.12", "etcd data directory ownership set to etcd:etcd",
            NA, actual="Directory not found", expected="etcd:etcd",
            remediation_tag="secure_etcd_dir"
        ))
    else:
        actual = get_ownership(etcd_dir)
        status = PASS if actual == "etcd:etcd" else FAIL
        note   = ""
        if status == FAIL and actual and actual != "etcd:etcd":
            # Check if etcd OS user exists
            rc2, _ = run_cmd("id etcd")
            if rc2 != 0:
                note = "OS user 'etcd' not found; etcd may run inside a container"
                status = WARN

        results.append(make_result(
            "1.1.12", "etcd data directory ownership set to etcd:etcd",
            status,
            actual=actual or "unknown",
            expected="etcd:etcd",
            remediation_tag="secure_etcd_dir",
            note=note
        ))

    return results


def checks_1_1_13_to_1_1_18() -> list[dict]:
    """1.1.13-1.1.18: Kubeconfig file permissions and ownership."""
    results = []

    kubeconfig_files = [
        ("/etc/kubernetes/admin.conf",              "1.1.13", "1.1.14", "admin.conf"),
        ("/etc/kubernetes/super-admin.conf",        "1.1.13b", "1.1.14b", "super-admin.conf"),
        ("/etc/kubernetes/scheduler.conf",          "1.1.15", "1.1.16", "scheduler.conf"),
        ("/etc/kubernetes/controller-manager.conf", "1.1.17", "1.1.18", "controller-manager.conf"),
    ]

    for path, perm_id, own_id, label in kubeconfig_files:
        results.append(check_file_perms(
            perm_id,
            f"Kubeconfig file permissions set to 600 or more restrictive ({label})",
            path, 600,
            f"secure_kubeconfig_{perm_id.replace('.', '_')}"
        ))
        results.append(check_file_owner(
            own_id,
            f"Kubeconfig file ownership set to root:root ({label})",
            path, "root:root",
            f"secure_kubeconfig_{own_id.replace('.', '_')}"
        ))

    return results


def checks_1_1_19_to_1_1_21() -> list[dict]:
    """1.1.19-1.1.21: PKI directory ownership and file permissions."""
    results = []
    pki_dir = "/etc/kubernetes/pki"

    if not os.path.isdir(pki_dir):
        for cid, title in [
            ("1.1.19", "Kubernetes PKI directory/file ownership set to root:root"),
            ("1.1.20", "Kubernetes PKI certificate file permissions set to 644 or more restrictive"),
            ("1.1.21", "Kubernetes PKI key file permissions set to 600"),
        ]:
            results.append(make_result(cid, title, NA,
                                       actual="Directory not found",
                                       expected="See benchmark",
                                       remediation_tag="secure_pki"))
        return results

    # 1.1.19 – ownership of entire PKI tree
    rc, out = run_cmd(
        f"find {pki_dir} ! -user root -o ! -group root 2>/dev/null | head -5"
    )
    non_root = [f for f in out.splitlines() if f.strip()]
    if non_root:
        results.append(make_result(
            "1.1.19", "Kubernetes PKI directory/file ownership set to root:root",
            FAIL,
            actual="Non-root owned: " + "; ".join(non_root),
            expected="root:root (all files)",
            remediation_tag="secure_pki"
        ))
    else:
        results.append(make_result(
            "1.1.19", "Kubernetes PKI directory/file ownership set to root:root",
            PASS,
            actual="All files/dirs owned by root:root",
            expected="root:root (all files)",
            remediation_tag="secure_pki"
        ))

    # 1.1.20 – certificate files <=644
    rc, out = run_cmd(
        f"find {pki_dir} -name '*.crt' -o -name '*.pub' 2>/dev/null"
    )
    cert_files = [f for f in out.splitlines() if f.strip()]
    cert_fails = []
    for f in cert_files:
        perm = get_octal_perms(f)
        if perm and not perm_ok(perm, 644):
            cert_fails.append(f"{f} ({perm})")

    if cert_fails:
        results.append(make_result(
            "1.1.20",
            "Kubernetes PKI certificate file permissions set to 644 or more restrictive",
            FAIL,
            actual="Non-compliant: " + "; ".join(cert_fails),
            expected="<=644",
            remediation_tag="secure_pki"
        ))
    else:
        results.append(make_result(
            "1.1.20",
            "Kubernetes PKI certificate file permissions set to 644 or more restrictive",
            PASS,
            actual=f"All {len(cert_files)} cert file(s) compliant",
            expected="<=644",
            remediation_tag="secure_pki"
        ))

    # 1.1.21 – key files <=600
    rc, out = run_cmd(f"find {pki_dir} -name '*.key' 2>/dev/null")
    key_files  = [f for f in out.splitlines() if f.strip()]
    key_fails  = []
    for f in key_files:
        perm = get_octal_perms(f)
        if perm and not perm_ok(perm, 600):
            key_fails.append(f"{f} ({perm})")

    if key_fails:
        results.append(make_result(
            "1.1.21",
            "Kubernetes PKI key file permissions set to 600",
            FAIL,
            actual="Non-compliant: " + "; ".join(key_fails),
            expected="<=600",
            remediation_tag="secure_pki"
        ))
    else:
        results.append(make_result(
            "1.1.21",
            "Kubernetes PKI key file permissions set to 600",
            PASS,
            actual=f"All {len(key_files)} key file(s) compliant",
            expected="<=600",
            remediation_tag="secure_pki"
        ))

    return results


# --------------------------------------------------------------------------- #
#  Main
# --------------------------------------------------------------------------- #

def main():
    if os.geteuid() != 0:
        print(f"{RED}[!] This script must be run as root (sudo).{RESET}")
        sys.exit(1)

    print()
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"{BOLD} CIS Kubernetes Benchmark v1.12.0 - Section 1.1 Audit Check{RESET}")
    print(f"{BOLD} {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print()

    all_results = []

    # Run all check groups
    check_groups = [
        ("1.1.1  – 1.1.8   Core Manifest Files",        checks_1_1_1_to_1_1_8),
        ("1.1.9  – 1.1.10  CNI Configuration Files",    checks_1_1_9_to_1_1_10),
        ("1.1.11 – 1.1.12  etcd Data Directory",        checks_1_1_11_to_1_1_12),
        ("1.1.13 – 1.1.18  Kubeconfig Files",           checks_1_1_13_to_1_1_18),
        ("1.1.19 – 1.1.21  PKI Directory & Key Files",  checks_1_1_19_to_1_1_21),
    ]

    for group_title, check_fn in check_groups:
        print(f"{CYAN}{BOLD}[*] {group_title}{RESET}")
        results = check_fn()
        for r in results:
            print_result(r)
        all_results.extend(results)
        print()

    # Summary
    total = len(all_results)
    passed  = sum(1 for r in all_results if r["status"] == PASS)
    failed  = sum(1 for r in all_results if r["status"] == FAIL)
    warned  = sum(1 for r in all_results if r["status"] == WARN)
    skipped = sum(1 for r in all_results if r["status"] == NA)
    fail_tags = list({r["remediation_tag"] for r in all_results
                      if r["status"] == FAIL and r["remediation_tag"]})

    print(f"{BOLD}{'='*70}{RESET}")
    print(f"{BOLD} Summary{RESET}")
    print(f"{BOLD}{'='*70}{RESET}")
    print(f"  Total  : {total}")
    print(f"  {GREEN}{BOLD}PASS   : {passed}{RESET}")
    print(f"  {RED}{BOLD}FAIL   : {failed}{RESET}")
    print(f"  {YELLOW}{BOLD}WARN   : {warned}{RESET}")
    print(f"  {CYAN}N/A    : {skipped}{RESET}")
    if fail_tags:
        print(f"  {RED}Fail tags: {', '.join(sorted(fail_tags))}{RESET}")
    print()

    # Export JSON
    output = {
        "benchmark":   "CIS Kubernetes Benchmark v1.12.0",
        "section":     "1.1",
        "timestamp":   datetime.now().isoformat(),
        "node":        os.uname().nodename,
        "summary": {
            "total":   total,
            "pass":    passed,
            "fail":    failed,
            "warn":    warned,
            "na":      skipped,
            "fail_tags": sorted(fail_tags),
        },
        "results": all_results,
    }

    with open(OUTPUT_FILE, "w") as f:
        json.dump(output, f, indent=2)

    print(f"  Results exported to: {BOLD}{OUTPUT_FILE}{RESET}")
    print()

    # Exit code reflects compliance status
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
