<#
.SYNOPSIS
    Active Directory cleanup review helper.

.DESCRIPTION
    Reviews enabled, disabled, stale, and optionally privileged Active Directory
    accounts. Exports evidence for cleanup review and supports safe group
    membership removal testing through -WhatIf.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter()]
    [int]$StaleDays = 90,

    [Parameter()]
    [string]$SearchBase,

    [Parameter()]
    [string[]]$ReviewGroups = @(
        "Domain Admins",
        "Enterprise Admins",
        "Account Operators",
        "VPN-Access"
    ),

    [Parameter()]
    [string]$ExportPath = ".\ad-cleanup-review.csv",

    [Parameter()]
    [switch]$IncludePrivilegedGroups,

    [Parameter()]
    [string]$RemoveUserFromGroup,

    [Parameter()]
    [string]$RemoveGroup
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    throw "ActiveDirectory module was not found. Install RSAT tools before running this script."
}

Import-Module ActiveDirectory

$staleCutoff = (Get-Date).AddDays(-$StaleDays)
$userParams = @{
    Filter     = "*"
    Properties = @(
        "Enabled",
        "LastLogonDate",
        "Department",
        "Title",
        "Manager",
        "WhenCreated"
    )
}

if (-not [string]::IsNullOrWhiteSpace($SearchBase)) {
    $userParams.SearchBase = $SearchBase
}

$users = Get-ADUser @userParams

$review = foreach ($user in $users) {
    $status = if (-not $user.Enabled) {
        "Disabled"
    }
    elseif ($null -eq $user.LastLogonDate) {
        "NoLogonRecorded"
    }
    elseif ($user.LastLogonDate -lt $staleCutoff) {
        "Stale"
    }
    else {
        "Active"
    }

    [pscustomobject]@{
        Name              = $user.Name
        SamAccountName    = $user.SamAccountName
        UserPrincipalName = $user.UserPrincipalName
        Enabled           = $user.Enabled
        LastLogonDate     = $user.LastLogonDate
        Department        = $user.Department
        Title             = $user.Title
        Manager           = $user.Manager
        WhenCreated       = $user.WhenCreated
        ReviewStatus      = $status
    }
}

$review |
    Sort-Object ReviewStatus, Name |
    Export-Csv -Path $ExportPath -NoTypeInformation

Write-Host "Exported account cleanup review to '$ExportPath'."

foreach ($groupName in $ReviewGroups) {
    try {
        $members = @(Get-ADGroupMember -Identity $groupName -ErrorAction Stop)
    }
    catch {
        Write-Warning "Unable to review group '$groupName'. $($_.Exception.Message)"
        continue
    }

    Write-Host ""
    Write-Host "Group review: $groupName"
    $members |
        Sort-Object Name |
        Select-Object Name, SamAccountName, ObjectClass |
        Format-Table -AutoSize
}

if ($IncludePrivilegedGroups) {
    Write-Host ""
    Write-Host "Privileged group review was included. Validate all privileged memberships against approved access records."
}

if (-not [string]::IsNullOrWhiteSpace($RemoveUserFromGroup) -and -not [string]::IsNullOrWhiteSpace($RemoveGroup)) {
    if ($PSCmdlet.ShouldProcess($RemoveUserFromGroup, "Remove from Active Directory group '$RemoveGroup'")) {
        Remove-ADGroupMember -Identity $RemoveGroup -Members $RemoveUserFromGroup -Confirm:$false
        Write-Host "Removed '$RemoveUserFromGroup' from '$RemoveGroup'."
    }
}
elseif (-not [string]::IsNullOrWhiteSpace($RemoveUserFromGroup) -or -not [string]::IsNullOrWhiteSpace($RemoveGroup)) {
    throw "Use both -RemoveUserFromGroup and -RemoveGroup when testing group cleanup."
}
