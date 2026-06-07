# Active Directory Access Review Lab

## Objective

Practice an on-prem Active Directory access review workflow focused on user
account hygiene, group membership validation, least privilege, and cleanup
documentation.

## Scenario

An organization needs to review Active Directory users and security groups to
identify stale accounts, risky group memberships, disabled users, and access
that no longer matches business need. The goal is to produce evidence that can
support an IAM access certification or audit review.

## Lab Scope

- Active Directory Users and Computers review
- PowerShell-based user and group inventory
- Disabled and inactive account checks
- Security group membership review
- Privileged group review
- Least-privilege cleanup recommendations
- Audit-ready documentation

## Practice Steps

1. Create or identify a test organizational unit for the lab.
2. Create test users that represent active, disabled, and stale accounts.
3. Create security groups for baseline access, VPN access, and admin access.
4. Add users to groups based on a simple access matrix.
5. Use PowerShell to list enabled users, disabled users, and stale accounts.
6. Export group memberships for review.
7. Review privileged groups such as Domain Admins or Account Operators.
8. Compare memberships against the access matrix.
9. Identify users with excessive or outdated access.
10. Document recommended removals before making changes.
11. Use `-WhatIf` when testing any removal command.
12. Export review results to CSV or JSON as audit evidence.

## Example Commands

```powershell
Get-ADUser -Filter * -Properties Enabled,LastLogonDate,Department |
  Select-Object Name,UserPrincipalName,Enabled,LastLogonDate,Department
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
- Confirm stale accounts are documented for review.
- Confirm privileged groups contain only approved users.
- Confirm group memberships match business need.
- Confirm recommended removals are tied to a ticket or approval.
- Confirm evidence exports do not expose sensitive production data.

## Security Rationale

Active Directory remains a core identity platform in many environments. Regular
account and group reviews help reduce privilege creep, detect stale access, and
support least-privilege operations.
