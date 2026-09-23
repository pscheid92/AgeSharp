namespace Age.Cli;

/// <summary>
/// Reads the command's key files — identity and recipients files — within go-age v1.3.2's size
/// limits, and keeps each open until disposed.
/// </summary>
/// <remarks>
/// Kept open so the output cannot be created over one of them: the output is created with an
/// exclusive open, which the OS refuses while a file is held for reading — by path, symlink, hard
/// link or case variant alike — and it is refused before anything is truncated. The input is held
/// the same way by the command. This is how a file is recognised as "the same" without opening the
/// output an extra time: an output can be a pipe, which an extra open for reading would block on.
/// <para>
/// Read in chunks rather than sized from the file's length, because a key file can be a pipe too —
/// <c>age -d -i &lt;(pass show age-key)</c> — and a pipe has no length.
/// </para>
/// </remarks>
internal sealed class KeyFiles : IDisposable
{
    /// <summary>go-age's limit for recipients and identity files (cmd/age/parse.go).</summary>
    public const int Limit = 16 * 1024 * 1024;

    /// <summary>go-age's limit for an SSH private key: a file must be smaller than this.</summary>
    public const int SshKeyLimit = 16 * 1024;

    private readonly List<FileStream> _held = [];

    /// <summary>The file's contents, read to at most one byte past <see cref="Limit"/>.</summary>
    public byte[] Read(string path)
    {
        var file = File.OpenRead(path);
        _held.Add(file);

        using var contents = new MemoryStream();
        var chunk = new byte[64 * 1024];
        int read;

        while (contents.Length <= Limit && (read = file.Read(chunk)) > 0)
            contents.Write(chunk, 0, (int)Math.Min(read, Limit + 1 - contents.Length));

        return contents.ToArray();
    }

    public void Dispose()
    {
        foreach (var file in _held)
            file.Dispose();
    }
}
