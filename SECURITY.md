# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |

Only the latest release is actively supported with security fixes.

## Reporting a Vulnerability

If you discover a security vulnerability in AgeSharp, **please do not open a public issue.**

Instead, report it privately using one of the following methods:

1. **GitHub Private Vulnerability Reporting:**
   Go to [Security Advisories](https://github.com/pscheid92/AgeSharp/security/advisories) and click "Report a vulnerability."

2. **Email:**
   Send details to [p.scheid92@gmail.com](mailto:p.scheid92@gmail.com) with the subject line `[AgeSharp Security]`.

Please include:

- A description of the vulnerability
- Steps to reproduce or a proof of concept
- The affected version(s)
- Any potential impact assessment

## What to Expect

- **Acknowledgment** within 48 hours of your report.
- **Status update** within 7 days with an initial assessment.
- **Fix timeline** communicated once the issue is confirmed. Critical vulnerabilities will be prioritized for the next release.
- **Credit** in the release notes (unless you prefer to remain anonymous).

## Scope

This policy covers the AgeSharp library (`Age/`), CLI (`Age.Cli/`), and any published NuGet packages. It does not cover third-party dependencies like BouncyCastle, which have their own disclosure processes.

## Security Design

AgeSharp implements the [age-encryption.org/v1](https://age-encryption.org/v1) specification. It relies on [BouncyCastle.Cryptography](https://www.bouncycastle.org/csharp/) for all cryptographic primitives and does not implement custom ciphers, key exchanges, or hash functions.
