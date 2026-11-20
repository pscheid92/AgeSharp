namespace Age.Tests;

/// <summary>
/// What <c>AgeRandomAccess</c> offered, over the seekable stream <c>DecryptReader</c> returns
/// for a seekable binary file, so the tests written against it keep their assertions.
/// </summary>
internal static class SeekableReading
{
    /// <summary>
    /// The plaintext from <paramref name="offset"/> into <paramref name="buffer"/>, as much as
    /// there is: zero before the start or at or past the end.
    /// </summary>
    public static int ReadAt(this Stream plaintext, long offset, Span<byte> buffer)
    {
        if (offset < 0 || offset >= plaintext.Length)
            return 0;

        plaintext.Position = offset;
        return plaintext.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);
    }

    /// <summary>The same stream, positioned at <paramref name="offset"/>.</summary>
    public static Stream From(this Stream plaintext, long offset = 0)
    {
        plaintext.Position = offset;
        return plaintext;
    }
}
