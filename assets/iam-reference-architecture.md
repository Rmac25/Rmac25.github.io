# IAM Reference Architecture Project

## Objective

Design a target-state Identity and Access Management architecture that connects
identity lifecycle, access governance, authentication controls, privileged
access, monitoring, and audit evidence into one coherent model.

## Scenario

An organization has Microsoft Entra ID, Active Directory, Microsoft 365, SaaS
applications, service desk workflows, and security monitoring tools. The IAM
team needs a reference architecture that explains how identities are created,
secured, reviewed, monitored, and removed across the environment.

## Architecture Scope

- Authoritative identity sources such as HR or service desk intake
- Microsoft Entra ID and Active Directory identity platforms
- Joiner, mover, and leaver lifecycle flows
- MFA and Conditional Access controls
- SSO and application federation
- Role-based access control and group strategy
- Privileged access management considerations
- Access reviews and audit evidence
- Logging, monitoring, and incident response handoff

## Target-State Architecture

| Layer | Architecture Decision |
| --- | --- |
| Identity Source | HR or approved ticket triggers lifecycle actions |
| Directory Layer | Entra ID and AD hold user, group, and access data |
| Access Layer | RBAC groups, app assignments, and privileged roles govern access |
| Control Layer | MFA, Conditional Access, and least privilege reduce risk |
| Governance Layer | Access reviews, tickets, approvals, and evidence support audit |
| Monitoring Layer | Sign-in logs, audit logs, SIEM alerts, and incident response provide visibility |

## Practice Steps

1. Define the business goal for the IAM architecture.
2. Identify authoritative identity sources.
3. Map identity lifecycle events for joiners, movers, and leavers.
4. Document where identities live: Entra ID, AD, apps, and SaaS platforms.
5. Define access assignment patterns such as groups, roles, and app assignments.
6. Map authentication controls such as MFA and Conditional Access.
7. Identify privileged roles and emergency access requirements.
8. Define access review cadence and evidence retention expectations.
9. Document logging sources and monitoring handoffs.
10. Create a phased roadmap from current state to target state.

## Architecture Principles

- Use least privilege by default.
- Prefer group- and role-based access over direct assignment.
- Require approval and ticket context for access changes.
- Validate high-risk changes before broad rollout.
- Preserve evidence for onboarding, review, offboarding, and exceptions.
- Protect emergency access accounts without weakening normal controls.
- Monitor identity activity and route suspicious events to security operations.

## Deliverables

- IAM target-state architecture summary
- Lifecycle workflow map
- Control matrix
- Governance and evidence model
- Implementation roadmap
- Risk and dependency notes

## Security Rationale

An IAM architecture project demonstrates the ability to design identity systems
instead of only administering individual controls. It connects operational work
to business risk, governance, auditability, and long-term security maturity.
