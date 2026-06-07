# Active Directory Cleanup

## Objective

Practice an on-prem Active Directory cleanup workflow focused on stale account
review, disabled user cleanup, group membership validation, least privilege, and
audit-ready documentation.

## Scenario

An organization needs to review Active Directory users and security groups to
identify stale accounts, disabled users with lingering access, risky group
memberships, and access that no longer matches business need. The goal is to
produce evidence that can support cleanup approvals, IAM access certification,
or audit review.

## Lab Scope

- Active Directory Users and Computers review
- PowerShell-based user and group inventory
- Disabled and inactive account checks
- No-logon account checks
- Security group membership review
- Privileged group review
- Least-privilege cleanup recommendations
- Audit-ready documentation
- Safe cleanup testing with `-WhatIf`

## Practice Steps

1. Create or identify a test organizational unit for the lab.
2. Create test users that represent active, disabled, stale, and no-logon accounts.
3. Create security groups for baseline access, VPN access, and admin access.
4. Add users to groups based on a simple access matrix.
5. Run `AD-Cleanup-Review.ps1` to export enabled, disabled, stale, and no-logon accounts.
6. Export group memberships for review.
7. Review privileged groups such as Domain Admins or Account Operators.
8. Compare memberships against the access matrix.
9. Identify users with excessive or outdated access.
10. Document recommended removals before making changes.
11. Use `-WhatIf` when testing any removal command.
12. Export review results to CSV or JSON as audit evidence.

## Example Commands

```powershell
.\AD-Cleanup-Review.ps1 `
  -StaleDays 90 `
  -ReviewGroups "Domain Admins","VPN-Access" `
  -ExportPath ".\ad-cleanup-review.csv"
```

```powershell
Get-ADGroupMember -Identity "VPN-Access" |
  Select-Object Name,SamAccountName,ObjectClass
```

```powershell
Remove-ADGroupMember -Identity "VPN-Access" `
  -Members "jane.doe" `
  -WhatIf
```

## Validation Checklist

- Confirm disabled users are not assigned unnecessary access.
- Confirm stale and no-logon accounts are documented for review.
- Confirm privileged groups contain only approved users.
- Confirm group memberships match business need.
- Confirm recommended removals are tied to a ticket or approval.
- Confirm evidence exports do not expose sensitive production data.
- Confirm cleanup commands are tested with `-WhatIf` before execution.

## Security Rationale

Active Directory remains a core identity platform in many environments. Regular
cleanup reviews help reduce privilege creep, detect stale access, remove
unnecessary group memberships, and support least-privilege operations.
