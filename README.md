\# CIS Kubernetes Benchmark v1.12.0 – Automated Compliance

\## Section 1.1 \& 1.2 (Control Plane – Master Node)



Automated audit and remediation for CIS Kubernetes Benchmark v1.12.0,

covering Section 1.1 (Control Plane Node Configuration Files, 21 checks) and

Section 1.2.1–1.2.12 (API Server Arguments, 12 checks) on Master Node.



\---



\## Project Structure



```

cis-k8s-benchmark/

├── check/

│   ├── check\_1.1.py          # Audit Section 1.1 – file permissions \& ownership

│   └── check\_1.2\_1.py        # Audit Section 1.2.1–1.2.12 – API Server args

├── remediate/

│   ├── remediate\_1.1.yml     # Ansible Playbook – remediate Section 1.1

│   └── remediate\_1.2\_1.yml   # Ansible Playbook – remediate Section 1.2.1–1.2.12

├── run/

│   ├── run\_1.1.sh            # Pipeline orchestrator – Section 1.1

│   └── run\_1.2\_1.sh          # Pipeline orchestrator – Section 1.2 (Part 1)

├── inventory.ini             # Ansible inventory (localhost)

└── README.md

```



\---



\## How It Works



Each pipeline runs 4 steps automatically:



```

STEP 1 → Audit       : Python script checks compliance, exports JSON result

STEP 2 → Confirm     : Prompt user y/n before making changes

STEP 3 → Remediate   : Ansible Playbook applies fixes

STEP 4 → Verify      : Re-run audit + kube-bench cross-validation

```



\---



\## Usage



\### Run full pipeline (recommended)



```bash

\# Section 1.1 – Control Plane Node Configuration Files

sudo ./run/run\_1.1.sh



\# Section 1.2 – API Server Arguments (1.2.1–1.2.12)

sudo ./run/run\_1.2\_1.sh

```



\### Run audit only



```bash

sudo python3 check/check\_1.1.py

sudo python3 check/check\_1.2\_1.py

```



Output: console + `check\_result\_1.1\_<timestamp>.json`



\### Run remediation only



```bash

ansible-playbook remediate/remediate\_1.1.yml   -i inventory.ini

ansible-playbook remediate/remediate\_1.2\_1.yml -i inventory.ini

```



\### Run by specific tag



```bash

ansible-playbook remediate/remediate\_1.2\_1.yml -i inventory.ini --tags "1.2.6"

ansible-playbook remediate/remediate\_1.2\_1.yml -i inventory.ini --tags "1.2.9"

```



\### Dry-run (no changes applied)



```bash

ansible-playbook remediate/remediate\_1.2\_1.yml -i inventory.ini --check --diff

```



\---



\## Compliance Results



| Section | Description | Total | PASS | Exception |

|---------|-------------|-------|------|-----------|

| 1.1 | Control Plane Node Configuration Files | 23 | 23 | None |

| 1.2.1–1.2.12 | API Server Arguments | 12 | 11 | 1.2.1 (see below) |

| \*\*Total\*\* | | \*\*35\*\* | \*\*34\*\* | \*\*97.1% compliant\*\* |



\### kube-bench cross-validation (benchmark cis-1.8)



| Section | PASS | FAIL | WARN |

|---------|------|------|------|

| 1.1 | 19 | 0 | 2 |

| 1.2.1–1.2.12 | 10 | 0 | 2 |



> WARN items are Manual checks in the benchmark (not scored).



\---



\## Known Exception: 1.2.1 (--anonymous-auth)



\*\*Status:\*\* Not Scored – Risk Accepted



Setting `--anonymous-auth=false` on kubeadm clusters breaks the API server

readiness probe. The probe calls `/readyz` anonymously (no credentials).

When `false`, the probe receives `401 Unauthorized` at the \*\*Authentication\*\*

layer — before RBAC is evaluated — leaving the pod permanently at `0/1 Running`

and taking down the control plane.



\*\*Compensating control:\*\* `--authorization-mode=Node,RBAC` is enforced.

Anonymous access is limited to health endpoints only.



\*\*Benchmark reference:\*\* CIS Kubernetes Benchmark v1.12.0, page 62:

> \*"If you are using RBAC authorization, it is generally considered reasonable

> to allow anonymous access to the API Server for health checks and discovery

> purposes, and hence this recommendation is not scored."\*



\---



\## Technical Highlights



\- \*\*Python audit scripts\*\* with structured JSON output (check\_id, status, actual, expected, remediation\_tag)

\- \*\*Ansible Playbooks\*\* using `file` module (permissions/ownership) and `lineinfile` module (API Server flags)

\- \*\*Idempotent\*\* – safe to run multiple times; only changes what is non-compliant

\- \*\*YAML validation\*\* before kubelet restart – auto-restores backup if syntax error

\- \*\*2-phase wait\*\* after restart: waits for pod to terminate, then waits for new pod Ready

\- \*\*kube-bench integration\*\* as independent cross-validator (filters exact scope 1.1 / 1.2.1–1.2.12)



\---



\## Environment



| Component | Version |

|-----------|---------|

| Kubernetes | v1.29.15 (kubeadm) |

| OS | Ubuntu 22.04 |

| Ansible | 2.10.8 |

| kube-bench | v0.15.0 |



\---



\## Reference



\- \[CIS Kubernetes Benchmark v1.12.0](https://www.cisecurity.org/benchmark/kubernetes)

\- \[kube-bench](https://github.com/aquasecurity/kube-bench)

