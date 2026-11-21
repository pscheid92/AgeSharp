using System.Security.Cryptography;

namespace AgeSharp.Crypto;

/// <summary>
/// The key one file's payload is sealed under, derived from its file key and payload nonce, as
/// the ChaCha20-Poly1305 cipher that uses it. The key's bytes exist only on the stack while the
/// cipher is made from them, and are cleared at once; after that only the cipher holds the key,
/// and <see cref="Dispose"/> releases it.
/// </summary>
/// <remarks>
/// A stream that is handed one owns it and disposes it. Before this, each stream kept the raw
/// key in an array only to clear it on dispose, and a constructor that failed between the
/// derivation and the handover left it uncleared.
/// </remarks>
internal sealed class PayloadKey : IDisposable
{
    private PayloadKey(IAeadCipher cipher) => Cipher = cipher;

    /// <summary>The cipher, keyed with the payload key.</summary>
    public IAeadCipher Cipher { get; }

    /// <summary>The payload key for the file key and nonce: HKDF-SHA256, salt the nonce, info "payload".</summary>
    public static PayloadKey Derive(FileKey fileKey, ReadOnlySpan<byte> nonce)
    {
        Span<byte> key = stackalloc byte[StreamEncryption.PayloadKeySize];

        try
        {
            CryptoHelper.HkdfDerive(fileKey.Bytes, nonce, "payload", key);
            return new PayloadKey(AeadCipher.Create(key));
        }
        finally
        {
            CryptographicOperations.ZeroMemory(key);
        }
    }

    /// <summary>Releases the cipher, and with it the key.</summary>
    public void Dispose() => Cipher.Dispose();
}
