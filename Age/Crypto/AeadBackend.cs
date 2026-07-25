namespace AgeSharp.Crypto;

internal enum AeadBackend
{
    /// <summary>
    ///     The platform <see cref="System.Security.Cryptography.ChaCha20Poly1305" /> — native, fast,
    ///     zero per-chunk allocation. Unavailable on browser/WebAssembly.
    /// </summary>
    Native,

    /// <summary>
    ///     The managed BouncyCastle ChaCha20-Poly1305. Works on every platform including the browser,
    ///     at lower throughput and with a small per-chunk allocation.
    /// </summary>
    Portable
}