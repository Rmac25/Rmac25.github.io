# Conditional Access Policy Lab

## Objective

Design a Microsoft Entra ID Conditional Access policy approach that improves
identity security without blocking normal user productivity. The lab focuses on
least privilege, MFA enforcement, group-scoped rollout, policy validation, and
break-glass account safety.

## Scenario

An organization wants to strengthen access to Microsoft 365 and cloud
applications. The IAM team needs a controlled rollout plan that requires MFA for
targeted users, excludes emergency access accounts, validates expected sign-in
behavior, and documents troubleshooting steps before broad enforcement.

## Lab Scope

- Microsoft Entra ID Conditional Access
- MFA enforcement
- User and group targeting
- Cloud application targeting
- Exclusion handling for break-glass accounts
- Report-only validation before enforcement
- Sign-in log review and troubleshooting

## Practice Steps

1. Create a pilot security group for Conditional Access testing.
2. Add one test user to the pilot group.
3. Confirm the test user is registered for MFA.
4. Identify and document any break-glass accounts that must be excluded.
5. Create a Conditional Access policy in Microsoft Entra ID.
6. Assign the policy to the pilot security group.
7. Exclude documented break-glass accounts.
8. Select Microsoft 365 or another test cloud application.
9. Configure the grant control to require multifactor authentication.
10. Set the policy to report-only mode.
11. Sign in as the test user from a browser and mobile client.
12. Review Entra ID sign-in logs and confirm the policy result.
13. Document expected behavior, interruptions, and troubleshooting notes.
14. Move the policy to enforced mode only after validation is complete.

## Policy Design

| Area | Design Choice |
| --- | --- |
| Users | Target pilot security group before broad rollout |
| Exclusions | Exclude approved break-glass accounts |
| Cloud apps | Start with Microsoft 365 and selected SaaS apps |
| Conditions | Validate user risk, location, and client application needs |
| Controls | Require multifactor authentication |
| Mode | Start in report-only, then move to on after validation |

## Validation Checklist

- Confirm target users are included in the pilot group.
- Confirm emergency access accounts are excluded.
- Confirm the policy appears in report-only results.
- Review sign-in logs for expected grant controls.
- Test browser and mobile sign-in behavior.
- Document blocked or interrupted sign-ins.
- Move policy to enforced mode only after validation passes.

## Troubleshooting Notes

- Review sign-in logs to confirm whether the policy applied.
- Check user/group assignment before changing grant controls.
- Validate exclusions before enforcement.
- Confirm MFA registration state for affected users.
- Use report-only mode to reduce rollout risk.

## Security Rationale

Conditional Access supports adaptive identity security by applying controls
based on user, group, application, risk, device, and location context. A staged
rollout gives IAM teams a safer path to enforce MFA while preserving emergency
administrative access and maintaining evidence for change-management review.
