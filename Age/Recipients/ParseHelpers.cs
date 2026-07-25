using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

internal static class ParseHelpers
{
    /// <summary>
    ///     The TryParse contract shared by every key type: null input → false,
    ///     <see cref="AgeFormatException" /> from <paramref name="parse" /> → false,
    ///     anything else propagates (an unexpected exception is a bug signal, not
    ///     a malformed input). Method-group conversions to <paramref name="parse" />
    ///     are cached by the compiler, so forwarding here does not allocate.
    /// </summary>
    internal static bool TryParse<T>(string? s, Func<string, T> parse, [MaybeNullWhen(false)] out T result)
        where T : class
    {
        if (s is not null)
            try
            {
                result = parse(s);
                return true;
            }
            catch (AgeFormatException)
            {
            }

        result = null;
        return false;
    }

    /// <summary>
    ///     Decodes a base64-unpadded stanza argument into raw bytes, validating its
    ///     length. A malformed encoding or wrong length is reported as an
    ///     <see cref="AgeFormatException" /> naming <paramref name="what" /> (e.g.
    ///     "X25519 ephemeral key"), matching the per-stanza error wording.
    /// </summary>
    internal static byte[] DecodeArg(string arg, int expectedLength, string what)
    {
        byte[] bytes;
        try
        {
            bytes = Base64Unpadded.Decode(arg);
        }
        catch (AgeFormatException ex)
        {
            throw new AgeFormatException($"invalid {what} encoding: {ex.Message}", ex);
        }

        if (bytes.Length != expectedLength)
            throw new AgeFormatException($"{what} must be {expectedLength} bytes, got {bytes.Length}");

        return bytes;
    }

    /// <summary>
    ///     Decodes a bech32 secret-key string (uppercase, HRP compared
    ///     case-insensitively) into its raw bytes, validating the HRP and length.
    ///     The returned buffer is the exact key material — the caller owns it and
    ///     should zero it when done. On any failure the decoded bytes are zeroed
    ///     before throwing, since they are secret-derived.
    /// </summary>
    internal static byte[] DecodeSecretKey(string s, string hrp, int length, string label)
    {
        if (s != s.ToUpperInvariant())
            throw new AgeFormatException("age secret key must be uppercase");

        var (actualHrp, data) = Bech32.Decode(s);
        try
        {
            if (!string.Equals(actualHrp, hrp, StringComparison.OrdinalIgnoreCase))
                throw new AgeFormatException($"expected HRP '{hrp}', got '{actualHrp}'");

            if (data.Length != length)
                throw new AgeFormatException($"{label} must be {length} bytes, got {data.Length}");
        }
        catch
        {
            CryptographicOperations.ZeroMemory(data);
            throw;
        }

        return data;
    }

    /// <summary>
    ///     Decodes a bech32 recipient string (lowercase, HRP compared exactly) into
    ///     its raw public-key bytes, validating the HRP, length, and casing.
    /// </summary>
    internal static byte[] DecodeRecipientKey(string s, string hrp, int length, string label)
    {
        var (actualHrp, data) = Bech32.Decode(s);

        if (actualHrp != hrp)
            throw new AgeFormatException($"expected HRP '{hrp}', got '{actualHrp}'");

        if (data.Length != length)
            throw new AgeFormatException($"{label} must be {length} bytes, got {data.Length}");

        if (s != s.ToLowerInvariant())
            throw new AgeFormatException("age recipient must be lowercase");

        return data;
    }
}