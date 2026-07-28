<#
.SYNOPSIS
  Detects access anomalies: stale accounts and privileged-group drift.

.DESCRIPTION
  Stale accounts      : enabled users with no logon in -StaleDays (default 45)
                        or terminated in HR but still enabled in AD.
  Privileged drift    : members of privileged groups (per RBAC model) whose
                        HR role does not grant that membership.
  Output: entitlement report CSV + JSON evidence bundle for access reviews,
  mapped to NIST 800-53 AC-2 (account mgmt) and AC-6 (least privilege).

.EXAMPLE
  .\Get-AccessAnomalies.ps1 -HrFeed ..\hr_feed\hr_feed.csv
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $HrFeed,
    [string] $RbacModel = "$PSScriptRoot\..\rbac\rbac_model.json",
    [int]    $StaleDays = 45,
    [string] $ReportDir = "$PSScriptRoot\..\reports"
)

Import-Module ActiveDirectory -ErrorAction Stop
$rbac = Get-Content $RbacModel -Raw | ConvertFrom-Json
$hr   = Import-Csv $HrFeed
$hrById = @{}; foreach ($e in $hr) { $hrById[$e.employee_id.ToLower()] = $e }

$findings = [System.Collections.Generic.List[object]]::new()
$cutoff = (Get-Date).AddDays(-$StaleDays)

# ---- Stale / orphaned accounts (AC-2) ----
Get-ADUser -Filter 'Enabled -eq $true' -Properties LastLogonDate | ForEach-Object {
    $sam = $_.SamAccountName
    $hrRec = $hrById[$sam]
    if ($hrRec -and $hrRec.status -eq 'terminated') {
        $findings.Add([pscustomobject]@{
            control = 'AC-2'; type = 'orphaned_account'; subject = $sam
            detail  = "Terminated in HR ($($hrRec.end_date)) but enabled in AD"
        })
    }
    elseif ($_.LastLogonDate -and $_.LastLogonDate -lt $cutoff) {
        $findings.Add([pscustomobject]@{
            control = 'AC-2'; type = 'stale_account'; subject = $sam
            detail  = "No logon since $($_.LastLogonDate.ToString('yyyy-MM-dd'))"
        })
    }
}

# ---- Privileged-group drift (AC-6) ----
$privGroups = $rbac.roles.PSObject.Properties |
    Where-Object { $_.Value.privileged } |
    ForEach-Object { $_.Value.groups } | Select-Object -Unique

foreach ($g in $privGroups) {
    Get-ADGroupMember -Identity $g | ForEach-Object {
        $sam = $_.SamAccountName
        $hrRec = $hrById[$sam]
        $allowed = $hrRec -and ($rbac.roles.($hrRec.role).groups -contains $g)
        if (-not $allowed) {
            $findings.Add([pscustomobject]@{
                control = 'AC-6'; type = 'privileged_drift'; subject = $sam
                detail  = "Member of privileged '$g' without an HR role granting it"
            })
        }
    }
}

# ---- Evidence outputs ----
$stamp = Get-Date -Format 'yyyyMMdd'
$findings | Export-Csv "$ReportDir\entitlement_findings_$stamp.csv" -NoTypeInformation
$findings | ConvertTo-Json -Depth 4 |
    Set-Content "$ReportDir\access_review_evidence_$stamp.json"
Write-Host "$($findings.Count) findings -> $ReportDir"
