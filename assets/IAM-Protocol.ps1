<#
.SYNOPSIS
    Identity and Access Management protocol script.

.DESCRIPTION
    Provides a repeatable IAM workflow for user onboarding, access review,
    role/group assignment, and offboarding preparation. Microsoft Graph is the
    default provider for Microsoft Entra ID workflows. The legacy on-prem
    Active Directory provider remains available with -Provider ActiveDirectory.

    The script is safe by default for supported mutations through PowerShell
    -WhatIf / -Confirm via ShouldProcess.

.NOTES
    Microsoft Graph provider requires Microsoft Graph PowerShell modules and
    delegated/admin consent for the requested scopes.
#>

[CmdletBinding(SupportsShouldProcess = $true)]
param (
    [Parameter(Mandatory = $true)]
    [ValidateSet("Onboard", "Review", "Offboard")]
    [string]$Action,

    [Parameter(Mandatory = $true)]
    [string]$UserPrincipalName,

    [Parameter()]
    [ValidateSet("MicrosoftGraph", "ActiveDirectory")]
    [string]$Provider = "MicrosoftGraph",

    [Parameter()]
    [string]$DisplayName,

    [Parameter()]
    [string]$Department,

    [Parameter()]
    [string]$JobTitle,

    [Parameter()]
    [string]$Manager,

    [Parameter()]
    [string[]]$RequestedGroups = @(),

    [Parameter()]
    [string]$TicketId = "MANUAL",

    [Parameter()]
    [string]$LogPath = ".\iam-protocol-audit.log",

    [Parameter()]
    [string]$ReviewOutputPath,

    [Parameter()]
    [string[]]$GraphScopes = @(
        "User.ReadWrite.All",
        "Group.ReadWrite.All",
        "Directory.ReadWrite.All",
        "UserAuthenticationMethod.ReadWrite.All"
    )
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Write-IamAuditLog {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [string]$Level = "INFO"
    )

    $entry = [pscustomobject]@{
        Timestamp         = (Get-Date).ToString("s")
        Level             = $Level
        TicketId          = $TicketId
        Provider          = $Provider
        UserPrincipalName = $UserPrincipalName
        Action            = $Action
        Message           = $Message
    }

    $entry | ConvertTo-Json -Compress | Add-Content -Path $LogPath
    Write-Host "[$Level] $Message"
}

function Export-IamAccessReviewEvidence {
    param (
        [Parameter(Mandatory = $true)]
        [pscustomobject]$Evidence
    )

    if ([string]::IsNullOrWhiteSpace($ReviewOutputPath)) {
        return
    }

    $Evidence |
        ConvertTo-Json -Depth 8 |
        Set-Content -Path $ReviewOutputPath -Encoding utf8

    Write-IamAuditLog "Exported access review evidence to '$ReviewOutputPath'."
}

function ConvertTo-ODataLiteral {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $Value.Replace("'", "''")
}

function Test-IsGuid {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Value
    )

    $guid = [guid]::Empty
    [guid]::TryParse($Value, [ref]$guid)
}

function Get-GraphObjectValue {
    param (
        [Parameter(Mandatory = $true)]
        [object]$Object,

        [Parameter(Mandatory = $true)]
        [string]$Name
    )

    if ($Object -is [hashtable] -and $Object.ContainsKey($Name)) {
        return $Object[$Name]
    }

    $property = $Object.PSObject.Properties[$Name]
    if ($property) {
        return $property.Value
    }

    $additionalProperties = $Object.PSObject.Properties["AdditionalProperties"]
    if ($additionalProperties -and $additionalProperties.Value -and $additionalProperties.Value.ContainsKey($Name)) {
        return $additionalProperties.Value[$Name]
    }

    $null
}

function Assert-IamPrerequisites {
    switch ($Provider) {
        "MicrosoftGraph" {
            $requiredModules = @(
                "Microsoft.Graph.Authentication",
                "Microsoft.Graph.Users",
                "Microsoft.Graph.Groups"
            )

            foreach ($module in $requiredModules) {
                if (-not (Get-Module -ListAvailable -Name $module)) {
                    throw "$module was not found. Install Microsoft Graph PowerShell with: Install-Module Microsoft.Graph -Scope CurrentUser"
                }
            }

            Import-Module Microsoft.Graph.Authentication
            Import-Module Microsoft.Graph.Users
            Import-Module Microsoft.Graph.Groups

            if (-not (Get-MgContext)) {
                Write-IamAuditLog "Connecting to Microsoft Graph with scopes: $($GraphScopes -join ', ')."
                Connect-MgGraph -Scopes $GraphScopes | Out-Null
            }

            Write-IamAuditLog "Verified Microsoft Graph PowerShell modules and connection."
        }

        "ActiveDirectory" {
            if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
                throw "ActiveDirectory module was not found. Install RSAT tools or use -Provider MicrosoftGraph."
            }

            Import-Module ActiveDirectory
            Write-IamAuditLog "Verified ActiveDirectory module is available."
        }
    }
}

function Get-GraphIamUserByIdentifier {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Identifier
    )

    $properties = @(
        "id",
        "displayName",
        "userPrincipalName",
        "department",
        "jobTitle",
        "accountEnabled"
    )

    if (Test-IsGuid -Value $Identifier) {
        try {
            return Get-MgUser -UserId $Identifier -Property $properties
        }
        catch {
            return $null
        }
    }

    $escapedIdentifier = ConvertTo-ODataLiteral -Value $Identifier
    $filter = "userPrincipalName eq '$escapedIdentifier' or mail eq '$escapedIdentifier'"
    Get-MgUser -Filter $filter -Property $properties -ConsistencyLevel eventual -CountVariable graphUserCount -Top 1
}

function Get-GraphCollection {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Uri
    )

    $items = @()
    $nextUri = $Uri

    while (-not [string]::IsNullOrWhiteSpace($nextUri)) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $nextUri
        if ($null -eq $response) {
            break
        }

        $responseValue = Get-GraphObjectValue -Object $response -Name "value"
        if ($responseValue) {
            $items += @($responseValue)
        }

        $nextUri = Get-GraphObjectValue -Object $response -Name "@odata.nextLink"
    }

    $items
}

function Get-ActiveDirectoryIamUser {
    try {
        Get-ADUser -Filter "UserPrincipalName -eq '$UserPrincipalName'" -Properties DisplayName, Department, Title, Manager, Enabled, MemberOf
    }
    catch {
        throw "Unable to query user '$UserPrincipalName'. $($_.Exception.Message)"
    }
}

function Get-IamUser {
    switch ($Provider) {
        "MicrosoftGraph" {
            Get-GraphIamUserByIdentifier -Identifier $UserPrincipalName
        }

        "ActiveDirectory" {
            Get-ActiveDirectoryIamUser
        }
    }
}

function New-GraphIamUser {
    $mailNickname = ($UserPrincipalName -split "@")[0] -replace "[^A-Za-z0-9._-]", ""

    if ([string]::IsNullOrWhiteSpace($DisplayName)) {
        throw "DisplayName is required for onboarding."
    }

    if ([string]::IsNullOrWhiteSpace($mailNickname)) {
        throw "UserPrincipalName must include a usable local part for the Graph mailNickname."
    }

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Create Microsoft Entra ID user account")) {
        $body = @{
            accountEnabled    = $true
            displayName       = $DisplayName
            mailNickname      = $mailNickname
            userPrincipalName = $UserPrincipalName
            passwordProfile   = @{
                forceChangePasswordNextSignIn = $true
                password                       = (Read-Host "Enter temporary password")
            }
        }

        if (-not [string]::IsNullOrWhiteSpace($Department)) {
            $body.department = $Department
        }

        if (-not [string]::IsNullOrWhiteSpace($JobTitle)) {
            $body.jobTitle = $JobTitle
        }

        Invoke-MgGraphRequest -Method POST -Uri "/v1.0/users" -Body $body | Out-Null
        Write-IamAuditLog "Created Microsoft Entra ID account for '$DisplayName'."
    }
}

function New-ActiveDirectoryIamUser {
    $samAccountName = ($UserPrincipalName -split "@")[0]

    if ([string]::IsNullOrWhiteSpace($DisplayName)) {
        throw "DisplayName is required for onboarding."
    }

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Create Active Directory user account")) {
        New-ADUser `
            -Name $DisplayName `
            -DisplayName $DisplayName `
            -SamAccountName $samAccountName `
            -UserPrincipalName $UserPrincipalName `
            -Department $Department `
            -Title $JobTitle `
            -Enabled $true `
            -ChangePasswordAtLogon $true `
            -AccountPassword (Read-Host "Enter temporary password" -AsSecureString)

        Write-IamAuditLog "Created Active Directory account for '$DisplayName'."
    }
}

function New-IamUser {
    switch ($Provider) {
        "MicrosoftGraph" {
            New-GraphIamUser
        }

        "ActiveDirectory" {
            New-ActiveDirectoryIamUser
        }
    }
}

function Set-GraphIamBaselineAttributes {
    param (
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    $updates = @{}

    if (-not [string]::IsNullOrWhiteSpace($Department)) {
        $updates.department = $Department
    }

    if (-not [string]::IsNullOrWhiteSpace($JobTitle)) {
        $updates.jobTitle = $JobTitle
    }

    if ($updates.Count -gt 0 -and $PSCmdlet.ShouldProcess($UserPrincipalName, "Update Microsoft Entra ID baseline attributes")) {
        Invoke-MgGraphRequest -Method PATCH -Uri "/v1.0/users/$($User.Id)" -Body $updates | Out-Null
        Write-IamAuditLog "Updated baseline attributes: $($updates.Keys -join ', ')."
    }

    if (-not [string]::IsNullOrWhiteSpace($Manager)) {
        $managerUser = Get-GraphIamUserByIdentifier -Identifier $Manager
        if ($null -eq $managerUser) {
            throw "Manager '$Manager' was not found in Microsoft Graph. Use a manager UPN, mail address, or object id."
        }

        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Set manager '$($managerUser.UserPrincipalName)'")) {
            $managerReference = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/users/$($managerUser.Id)"
            }

            Invoke-MgGraphRequest -Method PUT -Uri "/v1.0/users/$($User.Id)/manager/`$ref" -Body $managerReference | Out-Null
            Write-IamAuditLog "Assigned manager '$($managerUser.UserPrincipalName)'."
        }
    }
}

function Set-ActiveDirectoryIamBaselineAttributes {
    param (
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    $updates = @{}

    if (-not [string]::IsNullOrWhiteSpace($Department)) {
        $updates.Department = $Department
    }

    if (-not [string]::IsNullOrWhiteSpace($JobTitle)) {
        $updates.Title = $JobTitle
    }

    if ($updates.Count -gt 0 -and $PSCmdlet.ShouldProcess($UserPrincipalName, "Update Active Directory baseline attributes")) {
        Set-ADUser -Identity $User.DistinguishedName -Replace $updates
        Write-IamAuditLog "Updated baseline attributes: $($updates.Keys -join ', ')."
    }

    if (-not [string]::IsNullOrWhiteSpace($Manager) -and $PSCmdlet.ShouldProcess($UserPrincipalName, "Set manager")) {
        Set-ADUser -Identity $User.DistinguishedName -Manager $Manager
        Write-IamAuditLog "Assigned manager '$Manager'."
    }
}

function Set-IamBaselineAttributes {
    param (
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    switch ($Provider) {
        "MicrosoftGraph" {
            Set-GraphIamBaselineAttributes -User $User
        }

        "ActiveDirectory" {
            Set-ActiveDirectoryIamBaselineAttributes -User $User
        }
    }
}

function Get-GraphIamGroup {
    param (
        [Parameter(Mandatory = $true)]
        [string]$Group
    )

    if (Test-IsGuid -Value $Group) {
        try {
            return Get-MgGroup -GroupId $Group -Property Id, DisplayName
        }
        catch {
            return $null
        }
    }

    $escapedGroup = ConvertTo-ODataLiteral -Value $Group
    $matches = @(Get-MgGroup -Filter "displayName eq '$escapedGroup'" -Property Id, DisplayName -ConsistencyLevel eventual -CountVariable graphGroupCount -Top 2)

    if ($matches.Count -gt 1) {
        throw "Multiple Microsoft Entra ID groups named '$Group' were found. Use the group object id instead."
    }

    if ($matches.Count -eq 0) {
        return $null
    }

    $matches[0]
}

function Add-GraphIamGroupMembership {
    param (
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    foreach ($group in $RequestedGroups) {
        if ([string]::IsNullOrWhiteSpace($group)) {
            continue
        }

        $graphGroup = Get-GraphIamGroup -Group $group
        if ($null -eq $graphGroup) {
            throw "Microsoft Entra ID group '$group' was not found. Use display name or object id."
        }

        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Add to Microsoft Entra ID group '$($graphGroup.DisplayName)'")) {
            $memberReference = @{
                "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($User.Id)"
            }

            Invoke-MgGraphRequest -Method POST -Uri "/v1.0/groups/$($graphGroup.Id)/members/`$ref" -Body $memberReference | Out-Null
            Write-IamAuditLog "Added user to group '$($graphGroup.DisplayName)'."
        }
    }
}

function Add-ActiveDirectoryIamGroupMembership {
    param (
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    foreach ($group in $RequestedGroups) {
        if ([string]::IsNullOrWhiteSpace($group)) {
            continue
        }

        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Add to Active Directory group '$group'")) {
            Add-ADGroupMember -Identity $group -Members $User.DistinguishedName
            Write-IamAuditLog "Added user to group '$group'."
        }
    }
}

function Add-IamGroupMembership {
    param (
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    switch ($Provider) {
        "MicrosoftGraph" {
            Add-GraphIamGroupMembership -User $User
        }

        "ActiveDirectory" {
            Add-ActiveDirectoryIamGroupMembership -User $User
        }
    }
}

function Invoke-GraphIamAccessReview {
    param (
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    Write-IamAuditLog "Access review started."
    Write-Host ""
    Write-Host "Identity:"
    Write-Host "  Display name : $($User.DisplayName)"
    Write-Host "  UPN          : $($User.UserPrincipalName)"
    Write-Host "  Department   : $($User.Department)"
    Write-Host "  Job title    : $($User.JobTitle)"
    Write-Host "  Enabled      : $($User.AccountEnabled)"
    Write-Host ""
    Write-Host "Group memberships:"

    $groups = @(Get-GraphCollection -Uri "/v1.0/users/$($User.Id)/memberOf/microsoft.graph.group?`$select=id,displayName")
    $groupEvidence = @()

    if ($groups.Count -eq 0) {
        Write-Host "  No group memberships found."
    }
    else {
        $groupEvidence = @(
            $groups |
                Sort-Object displayName |
                ForEach-Object {
                    [pscustomobject]@{
                        Id          = $_.id
                        DisplayName = $_.displayName
                    }
                }
        )

        $groupEvidence |
            ForEach-Object { Write-Host "  $($_.DisplayName) [$($_.Id)]" }
    }

    $evidence = [pscustomobject]@{
        ReviewTimestamp   = (Get-Date).ToString("s")
        TicketId          = $TicketId
        Provider          = $Provider
        UserPrincipalName = $User.UserPrincipalName
        DisplayName       = $User.DisplayName
        Department        = $User.Department
        JobTitle          = $User.JobTitle
        AccountEnabled    = $User.AccountEnabled
        Groups            = $groupEvidence
    }

    Export-IamAccessReviewEvidence -Evidence $evidence
    Write-IamAuditLog "Access review completed."
}

function Invoke-ActiveDirectoryIamAccessReview {
    param (
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    Write-IamAuditLog "Access review started."
    Write-Host ""
    Write-Host "Identity:"
    Write-Host "  Display name : $($User.DisplayName)"
    Write-Host "  UPN          : $UserPrincipalName"
    Write-Host "  Department   : $($User.Department)"
    Write-Host "  Job title    : $($User.Title)"
    Write-Host "  Enabled      : $($User.Enabled)"
    Write-Host ""
    Write-Host "Group memberships:"

    $memberships = @($User.MemberOf)
    $groupEvidence = @()

    if ($memberships.Count -eq 0) {
        Write-Host "  No group memberships found."
    }
    else {
        $groupEvidence = @(
            $memberships |
            ForEach-Object { Get-ADGroup -Identity $_ } |
            Sort-Object Name |
            ForEach-Object {
                [pscustomobject]@{
                    Name              = $_.Name
                    DistinguishedName = $_.DistinguishedName
                }
            }
        )

        $groupEvidence |
            ForEach-Object { Write-Host "  $($_.Name)" }
    }

    $evidence = [pscustomobject]@{
        ReviewTimestamp   = (Get-Date).ToString("s")
        TicketId          = $TicketId
        Provider          = $Provider
        UserPrincipalName = $UserPrincipalName
        DisplayName       = $User.DisplayName
        Department        = $User.Department
        JobTitle          = $User.Title
        AccountEnabled    = $User.Enabled
        Groups            = $groupEvidence
    }

    Export-IamAccessReviewEvidence -Evidence $evidence
    Write-IamAuditLog "Access review completed."
}

function Invoke-IamAccessReview {
    param (
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    switch ($Provider) {
        "MicrosoftGraph" {
            Invoke-GraphIamAccessReview -User $User
        }

        "ActiveDirectory" {
            Invoke-ActiveDirectoryIamAccessReview -User $User
        }
    }
}

function Disable-GraphIamUserAccess {
    param (
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Disable Microsoft Entra ID account")) {
        Invoke-MgGraphRequest -Method PATCH -Uri "/v1.0/users/$($User.Id)" -Body @{ accountEnabled = $false } | Out-Null
        Write-IamAuditLog "Disabled account."
    }

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Revoke Microsoft Graph sign-in sessions")) {
        Invoke-MgGraphRequest -Method POST -Uri "/v1.0/users/$($User.Id)/revokeSignInSessions" | Out-Null
        Write-IamAuditLog "Revoked sign-in sessions."
    }

    foreach ($group in $RequestedGroups) {
        if ([string]::IsNullOrWhiteSpace($group)) {
            continue
        }

        $graphGroup = Get-GraphIamGroup -Group $group
        if ($null -eq $graphGroup) {
            throw "Microsoft Entra ID group '$group' was not found. Use display name or object id."
        }

        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Remove from Microsoft Entra ID group '$($graphGroup.DisplayName)'")) {
            Invoke-MgGraphRequest -Method DELETE -Uri "/v1.0/groups/$($graphGroup.Id)/members/$($User.Id)/`$ref" | Out-Null
            Write-IamAuditLog "Removed user from group '$($graphGroup.DisplayName)'."
        }
    }

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Remove Microsoft Entra ID app role assignments")) {
        $appRoleAssignments = @(Get-GraphCollection -Uri "/v1.0/users/$($User.Id)/appRoleAssignments?`$select=id,resourceDisplayName")
        foreach ($assignment in $appRoleAssignments) {
            Invoke-MgGraphRequest -Method DELETE -Uri "/v1.0/users/$($User.Id)/appRoleAssignments/$($assignment.id)" | Out-Null
        }

        Write-IamAuditLog "Removed $($appRoleAssignments.Count) app role assignment(s)."
    }

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Remove active Microsoft Entra ID directory role memberships")) {
        $directoryRoles = @(Get-GraphCollection -Uri "/v1.0/users/$($User.Id)/memberOf/microsoft.graph.directoryRole?`$select=id,displayName")
        foreach ($role in $directoryRoles) {
            Invoke-MgGraphRequest -Method DELETE -Uri "/v1.0/directoryRoles/$($role.id)/members/$($User.Id)/`$ref" | Out-Null
        }

        Write-IamAuditLog "Removed $($directoryRoles.Count) active directory role membership(s)."
    }

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Remove supported Microsoft Entra ID authentication methods")) {
        $authenticationMethods = @(Get-GraphCollection -Uri "/v1.0/users/$($User.Id)/authentication/methods")
        $removedMethods = 0

        foreach ($method in $authenticationMethods) {
            $methodType = Get-GraphObjectValue -Object $method -Name "@odata.type"

            $methodPath = switch ($methodType) {
                "#microsoft.graph.emailAuthenticationMethod" { "emailMethods"; break }
                "#microsoft.graph.fido2AuthenticationMethod" { "fido2Methods"; break }
                "#microsoft.graph.microsoftAuthenticatorAuthenticationMethod" { "microsoftAuthenticatorMethods"; break }
                "#microsoft.graph.phoneAuthenticationMethod" { "phoneMethods"; break }
                "#microsoft.graph.softwareOathAuthenticationMethod" { "softwareOathMethods"; break }
                "#microsoft.graph.temporaryAccessPassAuthenticationMethod" { "temporaryAccessPassMethods"; break }
                "#microsoft.graph.windowsHelloForBusinessAuthenticationMethod" { "windowsHelloForBusinessMethods"; break }
                default { $null }
            }

            if ([string]::IsNullOrWhiteSpace($methodPath)) {
                Write-IamAuditLog -Level "WARN" -Message "Skipped unsupported authentication method type '$methodType'."
                continue
            }

            Invoke-MgGraphRequest -Method DELETE -Uri "/v1.0/users/$($User.Id)/authentication/$methodPath/$($method.id)" | Out-Null
            $removedMethods++
        }

        Write-IamAuditLog "Removed $removedMethods supported authentication method(s)."
    }
}

function Disable-ActiveDirectoryIamUserAccess {
    param (
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Disable Active Directory account")) {
        Disable-ADAccount -Identity $User.DistinguishedName
        Write-IamAuditLog "Disabled account."
    }

    foreach ($group in $RequestedGroups) {
        if ([string]::IsNullOrWhiteSpace($group)) {
            continue
        }

        if ($PSCmdlet.ShouldProcess($UserPrincipalName, "Remove from Active Directory group '$group'")) {
            Remove-ADGroupMember -Identity $group -Members $User.DistinguishedName -Confirm:$false
            Write-IamAuditLog "Removed user from group '$group'."
        }
    }
}

function Disable-IamUserAccess {
    param (
        [Parameter(Mandatory = $true)]
        [object]$User
    )

    switch ($Provider) {
        "MicrosoftGraph" {
            Disable-GraphIamUserAccess -User $User
        }

        "ActiveDirectory" {
            Disable-ActiveDirectoryIamUserAccess -User $User
        }
    }
}

try {
    Assert-IamPrerequisites
    $user = Get-IamUser

    switch ($Action) {
        "Onboard" {
            if ($null -eq $user) {
                New-IamUser
                $user = Get-IamUser
            }

            if ($null -eq $user) {
                Write-IamAuditLog "Skipping post-create updates because the account does not exist. This is expected when using -WhatIf for a new user."
                break
            }

            Set-IamBaselineAttributes -User $user
            Add-IamGroupMembership -User $user
            Write-IamAuditLog "Onboarding workflow completed."
        }

        "Review" {
            if ($null -eq $user) {
                throw "User '$UserPrincipalName' was not found."
            }

            Invoke-IamAccessReview -User $user
        }

        "Offboard" {
            if ($null -eq $user) {
                throw "User '$UserPrincipalName' was not found."
            }

            Disable-IamUserAccess -User $user
            Write-IamAuditLog "Offboarding workflow completed."
        }
    }
}
catch {
    Write-IamAuditLog -Level "ERROR" -Message $_.Exception.Message
    throw
}
