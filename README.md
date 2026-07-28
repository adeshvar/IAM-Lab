# Hybrid Identity & Access Management Lab

A hybrid identity environment modeling a 200-user financial institution:
Windows Server AD synced to Microsoft Entra ID via Entra Connect, an RBAC
model enforcing least privilege across five business roles, automated
joiner-mover-leaver lifecycle, anomaly detection, and NIST 800-53 AC-family
evidence generation.

## Components

| Path | What it does |
|---|---|
| `hr_feed/hr_feed.csv` | Simulated HR system export driving the lifecycle |
| `rbac/rbac_model.json` | Role -> group mappings, privileged flags, SoD pairs |
| `powershell/Invoke-JMLLifecycle.ps1` | Idempotent JML reconcile: joiners created, movers diffed, leavers deprovisioned. Full `-WhatIf` support, JSON-lines audit log |
| `powershell/Get-AccessAnomalies.ps1` | Stale/orphaned accounts (AC-2) + privileged-group drift (AC-6) -> entitlement report + review evidence |
| `python/impossible_travel.py` | Impossible-travel sign-in detection via Microsoft Graph (AC-2(12)); offline mode included |
| `docs/nist_ac_mapping.md` | Control-by-control mapping to generated evidence |

## Try the runnable part now (no AD required)

```bash
python python/impossible_travel.py --input python/sample_sign_ins.json
```

## Lab environment

- Domain controller: Windows Server 2022, forest `corp.bank.local`
- Entra Connect sync to a Microsoft Entra ID tenant (password hash sync)
- Conditional Access: MFA required off-network; Duo integrated for step-up
- App federation: SAML 2.0 and OIDC test apps registered in Entra
- PowerShell scripts run under a delegated service account with
  least-privilege rights over the managed OUs only

## Safety-by-design in the automation

- Every mutating call goes through `ShouldProcess` -> real `-WhatIf` dry runs
- Reconciliation is diff-based, so re-runs are no-ops (idempotent)
- Every action emits one structured JSON audit line with operator + timestamp
