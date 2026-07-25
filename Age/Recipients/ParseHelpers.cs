using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

internal static class ParseHelpers
{
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