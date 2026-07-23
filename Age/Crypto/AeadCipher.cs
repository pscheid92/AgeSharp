namespace Age.Crypto;

/// <summary>
/// Factory for <see cref="IAeadCipher"/> instances. Phase A always returns the native
/// backend; the backend selection (native vs. portable) is added in Phase B.
/// </summary>
internal static class AeadCipher
{
    public static IAeadCipher Create(ReadOnlySpan<byte> key) => new BclAeadCipher(key);
}
