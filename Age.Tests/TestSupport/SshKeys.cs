using System.Text;

namespace Age.Tests;

/// <summary>SSH private keys built in place, for tests that need one but not a particular one.</summary>
internal static class SshKeys
{
    /// <summary>An unprotected OpenSSH Ed25519 private key, from an all-zero seed.</summary>
    public static string Ed25519Pem()
    {
        var key = new Org.BouncyCastle.Crypto.Parameters.Ed25519PrivateKeyParameters(new byte[32]);
        var blob = Org.BouncyCastle.Crypto.Utilities.OpenSshPrivateKeyUtilities.EncodePrivateKey(key);
        var b64 = Convert.ToBase64String(blob);

        var pem = new StringBuilder("-----BEGIN OPENSSH PRIVATE KEY-----\n");
        for (var i = 0; i < b64.Length; i += 70)
            pem.Append(b64.AsSpan(i, Math.Min(70, b64.Length - i))).Append('\n');

        return pem.Append("-----END OPENSSH PRIVATE KEY-----\n").ToString();
    }

    /// <summary>An unprotected 2048-bit RSA private key in PKCS#1 PEM.</summary>
    public static string RsaPem()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        return rsa.ExportRSAPrivateKeyPem();
    }
}
