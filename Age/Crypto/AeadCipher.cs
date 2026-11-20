using System.Security.Cryptography;

namespace AgeSharp.Crypto;

/// <summary>
/// Factory for <see cref="IAeadCipher"/> instances. Uses the native platform cipher where it is
/// supported and the managed BouncyCastle cipher otherwise — so browser/WebAssembly works with
/// no configuration and server/desktop keep the fast, zero-allocation path.
/// </summary>
internal static class AeadCipher
{
    /// <summary>Creates a cipher using the default backend for the current platform.</summary>
    public static IAeadCipher Create(ReadOnlySpan<byte> key) => Create(key, DefaultBackend());

    /// <summary>
    /// Creates a cipher using an explicit backend. Used by tests to exercise a specific
    /// implementation regardless of the platform default.
    /// </summary>
    internal static IAeadCipher Create(ReadOnlySpan<byte> key, AeadBackend backend) =>
        backend == AeadBackend.Portable ? new BouncyCastleAeadCipher(key) : new BclAeadCipher(key);

    private static AeadBackend DefaultBackend() =>
#if FORCE_PORTABLE_AEAD
        // Test hook (`dotnet test -p:ForcePortableAead=true`): force the managed backend so the
        // whole suite and the CCTV vectors exercise the browser/WASM path. Never defined in a
        // normal or packaged build.
        AeadBackend.Portable;
#else
        ChaCha20Poly1305.IsSupported ? AeadBackend.Native : AeadBackend.Portable;
#endif
}
