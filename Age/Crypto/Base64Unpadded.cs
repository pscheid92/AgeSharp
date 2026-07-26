namespace AgeSharp.Crypto;

internal static class Base64Unpadded
{
    private const int StackAllocThreshold = 256;

    /// <summary>
    ///     Encodes into a caller-supplied buffer, returning the length written. For secret
    ///     bodies, where the string overload would leave an unclearable copy behind.
    /// </summary>
    public static int Encode(ReadOnlySpan<byte> data, Span<char> destination)
    {
        if (data.IsEmpty)
            return 0;

        if (!Convert.TryToBase64Chars(data, destination, out var written))
            throw new InvalidOperationException("base64 encode failed");

        while (written > 0 && destination[written - 1] == '=')
            written--;

        return written;
    }

    /// <summary>Maximum characters <see cref="Encode(ReadOnlySpan{byte}, Span{char})" /> can write.</summary>
    public static int MaxEncodedLength(int byteCount)
    {
        return (byteCount + 2) / 3 * 4;
    }

    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return "";

        var maxLen = (data.Length + 2) / 3 * 4;

        var buf = maxLen <= StackAllocThreshold
            ? stackalloc char[maxLen]
            : new char[maxLen];

        return Convert.TryToBase64Chars(data, buf, out var written)
            ? new string(buf[..written].TrimEnd('='))
            : throw new InvalidOperationException("base64 encode failed");
    }

    public static byte[] Decode(ReadOnlySpan<char> chars)
    {
        if (chars.IsEmpty)
            return [];

        if (chars.Contains('='))
            throw new AgeFormatException("base64 input must not contain padding");

        var decoded = DecodeWithPadding(chars);
        VerifyCanonical(decoded, chars);

        return decoded;
    }

    private static byte[] DecodeWithPadding(ReadOnlySpan<char> chars)
    {
        var paddedLen = (chars.Length + 3) / 4 * 4;

        var padded = paddedLen <= StackAllocThreshold
            ? stackalloc char[paddedLen]
            : new char[paddedLen];

        padded[chars.Length..].Fill('=');
        chars.CopyTo(padded);

        var result = new byte[paddedLen / 4 * 3];

        return Convert.TryFromBase64Chars(padded, result, out var bytesWritten)
            ? result[..bytesWritten]
            : throw new AgeFormatException("invalid base64 input");
    }

    private static void VerifyCanonical(ReadOnlySpan<byte> decoded, ReadOnlySpan<char> originalChars)
    {
        var maxLen = (decoded.Length + 2) / 3 * 4;

        var reencoded = maxLen <= StackAllocThreshold
            ? stackalloc char[maxLen]
            : new char[maxLen];

        if (!Convert.TryToBase64Chars(decoded, reencoded, out var written))
            throw new AgeFormatException("canonicality check failed");

        var trimmed = reencoded[..written].TrimEnd('=');
        if (!trimmed.SequenceEqual(originalChars))
            throw new AgeFormatException("non-canonical base64 encoding");
    }
}