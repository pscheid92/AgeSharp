using System.Security.Cryptography;

namespace AgeSharp.Crypto;

// Picks the AEAD backend: the BCL's where it is available, BouncyCastle where it is not
// (browser/WASM). Both must pass the whole suite — see ForcePortableAead in Age.csproj.
internal static class AeadCipher
{
    public static IAeadCipher Create(ReadOnlySpan<byte> key)
    {
        return Create(key, DefaultBackend());
    }

    // Backend-explicit overload, for tests that must exercise a specific one.
    internal static IAeadCipher Create(ReadOnlySpan<byte> key, AeadBackend backend)
    {
        return backend == AeadBackend.Portable ? new BouncyCastleAeadCipher(key) : new BclAeadCipher(key);
    }

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