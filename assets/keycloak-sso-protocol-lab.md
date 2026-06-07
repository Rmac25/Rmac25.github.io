# Keycloak SSO Protocol Lab

## Objective

Build a practical single sign-on lab that demonstrates how an identity provider
brokers authentication for applications through SAML, OAuth 2.0, and OpenID
Connect concepts.

## Scenario

An organization needs centralized authentication for applications instead of
separate local accounts. The lab uses Keycloak to model the identity provider
role, client application configuration, redirect URI behavior, token issuance,
and troubleshooting signals that IAM teams use during SSO integrations.

## Lab Scope

- Keycloak realm configuration
- Test user and group setup
- Client application configuration
- Redirect URI validation
- OpenID Connect authorization flow
- SAML role comparison
- Token claim review
- Login troubleshooting

## Practice Steps

1. Create a Keycloak realm for the lab.
2. Create a test user and set a temporary password.
3. Create a client application for the test app.
4. Configure the valid redirect URI for the application callback.
5. Configure allowed web origins if the application requires them.
6. Create test roles or groups in the realm.
7. Assign the test user to the expected role or group.
8. Add mappers or scopes needed to include identity claims.
9. Start the application login flow and confirm redirection to Keycloak.
10. Authenticate as the test user.
11. Confirm the browser returns to the approved redirect URI.
12. Review token or assertion contents for subject, email, roles, and groups.
13. Break one setting intentionally, such as the redirect URI, and observe the error.
14. Document the troubleshooting signal and the fix.

## Core Concepts

| Concept | Lab Meaning |
| --- | --- |
| Identity Provider | Keycloak authenticates the user and issues assertions or tokens |
| Client / Service Provider | Application redirects users to Keycloak and consumes the result |
| Redirect URI | Approved return location after authentication |
| Claims / Attributes | Identity data passed to applications for authorization decisions |
| Tokens / Assertions | Signed artifacts that prove authentication occurred |

## Validation Checklist

- Confirm the realm contains the expected test user.
- Confirm the client has the correct redirect URI.
- Confirm the login flow redirects to Keycloak.
- Confirm successful authentication returns to the application.
- Review tokens or assertions for expected subject, email, roles, and groups.
- Document common failures such as redirect mismatch, invalid client, expired
  session, and missing claims.

## Troubleshooting Notes

- A redirect URI mismatch usually means the application callback URL was not
  added to the client configuration.
- Missing roles or groups usually means mappers or scopes need review.
- Invalid client errors usually point to client ID, secret, or access type
  configuration.
- Authentication loops can indicate cookie, session, or incorrect base URL
  settings.

## Security Rationale

SSO centralizes authentication, reduces local password sprawl, and gives IAM
teams a clearer place to enforce authentication policy. Understanding the
protocol flow helps troubleshoot access issues and explain how identity data
moves from the provider to the application.
