namespace Age.Crypto;

/// <summary>
/// Minimal ChaCha20-Poly1305 AEAD abstraction. The method shapes mirror
/// <see cref="System.Security.Cryptography.ChaCha20Poly1305"/> exactly, so the native
/// wrapper is a pure pass-through and a managed implementation can be substituted on
/// platforms — notably browser/WebAssembly — where the platform cipher is unavailable.
/// Instances are not thread-safe: a single instance is used sequentially, like the
/// platform cipher.
/// </summary>
internal interface IAeadCipher : IDisposable
{
    /// <summary>
    /// Encrypts <paramref name="plaintext"/> into <paramref name="ciphertext"/> and writes
    /// the 16-byte authentication tag to <paramref name="tag"/>.
    /// </summary>
    void Encrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> plaintext, Span<byte> ciphertext, Span<byte> tag);

    /// <summary>
    /// Decrypts <paramref name="ciphertext"/> into <paramref name="plaintext"/>, verifying
    /// <paramref name="tag"/>. Throws
    /// <see cref="System.Security.Cryptography.AuthenticationTagMismatchException"/> when
    /// authentication fails.
    /// </summary>
    void Decrypt(ReadOnlySpan<byte> nonce, ReadOnlySpan<byte> ciphertext, ReadOnlySpan<byte> tag, Span<byte> plaintext);
}
