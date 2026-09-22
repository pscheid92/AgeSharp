namespace Age.Cli;

/// <summary>
/// Input the library can auto-detect armor on, which it does only for seekable streams.
/// </summary>
internal static class SeekableInput
{
    /// <summary>
    /// Returns <paramref name="input"/> itself when it can seek — a file is read in place, so its
    /// size costs nothing — and otherwise a buffered copy of it, positioned at its start.
    /// </summary>
    /// <remarks>
    /// Only a pipe pays for the buffer, and a pipe of more than 2 GiB still fails, which is
    /// MemoryStream's limit. Removing that needs armor detection that peeks instead of seeking.
    /// </remarks>
    public static Stream From(Stream input)
    {
        if (input.CanSeek)
            return input;

        var buffer = new MemoryStream();
        input.CopyTo(buffer);
        buffer.Position = 0;
        return buffer;
    }
}
