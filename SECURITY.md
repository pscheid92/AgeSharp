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

This policy covers the AgeSharp library (`Age/`) and the published NuGet packages. It does not cover third-party dependencies like BouncyCastle, which have their own disclosure processes.

## Security Design

AgeSharp implements the [age-encryption.org/v1](https://age-encryption.org/v1) specification. Cryptographic primitives come from three sources:

- **.NET's built-in [`System.Security.Cryptography`](https://learn.microsoft.com/dotnet/api/system.security.cryptography)** — ChaCha20-Poly1305 (payload and recipient wrap AEAD), HKDF-SHA256, HMAC-SHA256, SHA-256.
- **[BouncyCastle.Cryptography](https://www.bouncycastle.org/csharp/)** — scrypt (passphrase KDF), X25519 and P-256 key agreement, Ed25519, ML-KEM-768 (post-quantum KEM), SHA3-256, RSA-OAEP, SSH key parsing, and the managed ChaCha20-Poly1305 used in the browser.
- **[SSH.NET](https://github.com/sshnet/SSH.NET)** — decrypting passphrase-protected OpenSSH keys (bcrypt_pbkdf and the key-file ciphers).

AgeSharp implements no ciphers, hash functions or curve arithmetic of its own. It does compose the specified constructions on top of these primitives: age's stanza formats, the HPKE key schedule of RFC 9180, DHKEM(P-256), and the X-Wing and MLKEM768-P256 hybrid KEMs. These follow the reference implementations (go-age and filippo.io/hpke) and are checked against their test vectors and against go-age. They have not been audited.

### Hostile input

Everything in a header is read before anything in it is authenticated, so the header is read
under limits (`AgeDecryptOptions`): by default go-age's, 2 MiB for the whole header, 1024
stanzas and 128 arguments to a stanza, and 1 KiB for an armor line. Whatever is wrong with a
file, reading it fails with an `AgeException`: an `AgeFormatException` for what does not parse,
an `AgeAuthenticationException` for a check that fails. This is tested against the 147 C2SP
conformance vectors, read seven ways each, and against files damaged over a thousand ways and
read through every path; no other exception escapes.

### Key material

Types that hold secrets clear them when disposed: identities, `Passphrase` (which keeps only a
UTF-8 copy of the passphrase), `FileKey`, `FileKeyIdentity`, `EncryptedIdentityFile` and the
`Identities` sets that parsed their keys. Callbacks that hand over a secret (`IPluginCallbacks.
RequestSecret`, `EncryptedIdentityFile`'s passphrase) return a `char[]`, which is cleared once
used. Plaintext passes only through buffers the library clears. A `string` cannot be cleared
by anyone, so where a secret is held for long, pass characters you can clear yourself. Messages
never quote a key: a line that fails to parse as one is named by its number, and a no-match
names identities by type and public recipient only.

