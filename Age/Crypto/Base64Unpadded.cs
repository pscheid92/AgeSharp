namespace Age.Crypto;

internal static class Base64Unpadded
{
    public static string Encode(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty) return "";
        int maxLen = ((data.Length + 2) / 3) * 4;
        Span<char> buf = maxLen <= 256 ? stackalloc char[maxLen] : new char[maxLen];
        if (!Convert.TryToBase64Chars(data, buf, out int written))
            throw new InvalidOperationException("base64 encode failed");
        // Strip padding
        var span = buf[..written];
        while (written > 0 && span[written - 1] == '=')
            written--;
        return new string(span[..written]);
    }

    public static byte[] Decode(ReadOnlySpan<char> chars)
    {
        if (chars.IsEmpty) return [];

        // Reject padding characters
        for (int i = 0; i < chars.Length; i++)
        {
            if (chars[i] == '=')
                throw new FormatException("base64 input must not contain padding");
        }

        // Add correct padding
        int padCount = (4 - (chars.Length % 4)) % 4;
        int paddedLen = chars.Length + padCount;
        Span<char> padded = paddedLen <= 256 ? stackalloc char[paddedLen] : new char[paddedLen];
        chars.CopyTo(padded);
        for (int i = 0; i < padCount; i++)
            padded[chars.Length + i] = '=';

        int maxBytes = (paddedLen / 4) * 3;
        byte[] result = new byte[maxBytes];
        if (!Convert.TryFromBase64Chars(padded, result, out int bytesWritten))
            throw new FormatException("invalid base64 input");

        // Verify canonicality: re-encode and compare
        Span<char> reencoded = paddedLen <= 256 ? stackalloc char[paddedLen] : new char[paddedLen];
        if (!Convert.TryToBase64Chars(result.AsSpan(0, bytesWritten), reencoded, out int reencodedLen))
            throw new FormatException("canonicality check failed");
        // Compare without padding
        int reencodedUnpadded = reencodedLen;
        while (reencodedUnpadded > 0 && reencoded[reencodedUnpadded - 1] == '=')
            reencodedUnpadded--;
        if (reencodedUnpadded != chars.Length || !padded[..chars.Length].SequenceEqual(reencoded[..reencodedUnpadded]))
            throw new FormatException("non-canonical base64 encoding");

        return result[..bytesWritten];
    }
}
