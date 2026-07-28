# NIST 800-53 AC-Family Control Mapping

| Control | Requirement | Lab implementation | Evidence artifact |
|---|---|---|---|
| AC-2 | Account management | JML lifecycle automation from HR feed; orphaned/stale detection | `jml_audit.jsonl`, `entitlement_findings_*.csv` |
| AC-2(3) | Disable inactive accounts | Stale-account scan (45-day logon threshold) | `entitlement_findings_*.csv` |
| AC-2(12) | Atypical usage monitoring | Impossible-travel detection via MS Graph sign-in logs | `impossible_travel.json` |
| AC-3 | Access enforcement | RBAC group model; Conditional Access + MFA policies | `rbac_model.json`, CA policy export |
| AC-5 | Separation of duties | SoD pairs defined in RBAC model, checked in drift scan | `rbac_model.json` |
| AC-6 | Least privilege | Role-scoped groups only; privileged-drift detection | `access_review_evidence_*.json` |
