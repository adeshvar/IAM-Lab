<#
.SYNOPSIS
  Joiner-Mover-Leaver lifecycle automation driven by the HR feed.

.DESCRIPTION
  Reconciles Active Directory against hr_feed.csv using the RBAC model:
    Joiners : create account, assign role groups
    Movers  : swap old role groups for new (computed diff, not blanket reset)
    Leavers : disable account, strip all groups, move to Disabled OU

  Design principles:
    - Idempotent: safe to re-run; only diffs are applied.
    - -WhatIf support on every mutating call via ShouldProcess.
    - Structured audit logging: one JSON line per action -> audit log.

.EXAMPLE
  .\Invoke-JMLLifecycle.ps1 -HrFeed ..\hr_feed\hr_feed.csv -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    [Parameter(Mandatory)] [string] $HrFeed,
    [string] $RbacModel = "$PSScriptRoot\..\rbac\rbac_model.json",
    [string] $AuditLog  = "$PSScriptRoot\..\reports\jml_audit.jsonl",
    [string] $DisabledOU = "OU=Disabled,DC=corp,DC=bank,DC=local"
)

Import-Module ActiveDirectory -ErrorAction Stop

$rbac = Get-Content $RbacModel -Raw | ConvertFrom-Json

function Write-Audit {
    param([string]$Action, [string]$Employee, [hashtable]$Detail)
    $entry = [ordered]@{
        timestamp = (Get-Date).ToString("o")
        action    = $Action
        employee  = $Employee
        detail    = $Detail
        operator  = $env:USERNAME
        whatif    = [bool]$WhatIfPreference
    } | ConvertTo-Json -Compress
    Add-Content -Path $AuditLog -Value $entry
}

function Get-RoleGroups([string]$Role) {
    $def = $rbac.roles.$Role
    if (-not $def) { throw "Role '$Role' not in RBAC model" }
    return $def.groups
}

$feed = Import-Csv $HrFeed
foreach ($emp in $feed) {
    $sam = $emp.employee_id.ToLower()
    $existing = Get-ADUser -Filter "SamAccountName -eq '$sam'" `
                           -Properties MemberOf -ErrorAction SilentlyContinue

    switch ($emp.status) {

        "active" {
            $target = Get-RoleGroups $emp.role
            if (-not $existing) {
                # ---- JOINER ----
                if ($PSCmdlet.ShouldProcess($sam, "Create user + assign $($target -join ', ')")) {
                    New-ADUser -SamAccountName $sam -Name "$($emp.first_name) $($emp.last_name)" `
                               -Department $emp.department -Enabled $true `
                               -AccountPassword (Read-Host -AsSecureString "Initial pw for $sam")
                    foreach ($g in $target) { Add-ADGroupMember -Identity $g -Members $sam }
                }
                Write-Audit "joiner.create" $sam @{ role = $emp.role; groups = $target }
            }
            else {
                # ---- Idempotent reconcile: apply only the diff ----
                $current = $existing.MemberOf | ForEach-Object { ($_ -split ',')[0] -replace '^CN=' }
                $toAdd    = $target  | Where-Object { $_ -notin $current }
                $toRemove = $current | Where-Object { $_ -like 'GRP-*' -and $_ -notin $target }
                foreach ($g in $toAdd) {
                    if ($PSCmdlet.ShouldProcess($sam, "Add to $g")) {
                        Add-ADGroupMember -Identity $g -Members $sam
                    }
                    Write-Audit "mover.group_add" $sam @{ group = $g }
                }
                foreach ($g in $toRemove) {
                    if ($PSCmdlet.ShouldProcess($sam, "Remove from $g")) {
                        Remove-ADGroupMember -Identity $g -Members $sam -Confirm:$false
                    }
                    Write-Audit "mover.group_remove" $sam @{ group = $g }
                }
            }
        }

        "moved" {
            # Movers re-enter as active with a new role next feed cycle;
            # flag for access review in the interim.
            Write-Audit "mover.flagged_for_review" $sam @{ new_role = $emp.role }
        }

        "terminated" {
            if ($existing -and $existing.Enabled) {
                # ---- LEAVER ----
                if ($PSCmdlet.ShouldProcess($sam, "Disable + strip groups + move to Disabled OU")) {
                    Disable-ADAccount -Identity $sam
                    $existing.MemberOf | ForEach-Object {
                        Remove-ADGroupMember -Identity $_ -Members $sam -Confirm:$false
                    }
                    Move-ADObject -Identity $existing.DistinguishedName -TargetPath $DisabledOU
                }
                Write-Audit "leaver.deprovision" $sam @{ end_date = $emp.end_date }
            }
        }
    }
}
Write-Host "Lifecycle reconcile complete. Audit: $AuditLog"
