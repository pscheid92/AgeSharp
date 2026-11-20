namespace AgeSharp;

/// <summary>
/// Reads header lines from a stream for <see cref="Header.Parse"/>, through a
/// <see cref="HeaderLineFramer"/>, one byte at a time so that no payload byte is consumed.
/// </summary>
/// <remarks>
/// <see cref="PrefillAsync"/> reads the whole header asynchronously up front, after which
/// parsing reads only buffered lines and does no I/O. It stops after the MAC line: the first line
/// that starts with <c>---</c>, since stanza lines start with <c>-&gt; </c> and body lines are
/// base64. The stream is then left at the payload nonce, as a synchronous read leaves it.
/// </remarks>
internal sealed class HeaderReader(Stream stream, AgeDecryptOptions? options = null)
{
    private readonly HeaderLineFramer _framer = new((options ?? AgeDecryptOptions.Default).MaxHeaderBytes);

    private Queue<string>? _prefilled;
    private string? _pushedBack;

    /// <summary>The limits the header is parsed under.</summary>
    public AgeDecryptOptions Options { get; } = options ?? AgeDecryptOptions.Default;

    /// <summary>All raw header bytes read so far: what the MAC is computed over.</summary>
    public ReadOnlySpan<byte> RawBytes =>
        _framer.RawBytes;

    /// <summary>Pushes a line back, so the next <see cref="ReadLine"/> returns it.</summary>
    public void PushBack(string line) =>
        _pushedBack = line;

    /// <summary>The next header line without its LF, or null at the end.</summary>
    /// <exception cref="AgeHeaderException">The line breaks the header's rules.</exception>
    public string? ReadLine()
    {
        if (_pushedBack is { } pushed)
        {
            _pushedBack = null;
            return pushed;
        }

        if (_prefilled is not null)
            return _prefilled.TryDequeue(out var line) ? line : null;

        while (true)
        {
            var b = stream.ReadByte();

            if (b < 0)
                return _framer.FinishAtEnd();

            if (_framer.Feed((byte)b) is { } line)
                return line;
        }
    }

    /// <summary>Reads the header asynchronously, up to and including the MAC line.</summary>
    /// <exception cref="AgeHeaderException">A line breaks the header's rules.</exception>
    public async ValueTask PrefillAsync(CancellationToken cancellationToken)
    {
        var lines = new Queue<string>();
        var one = new byte[1];

        while (true)
        {
            if (await stream.ReadAsync(one, cancellationToken).ConfigureAwait(false) == 0)
            {
                _framer.FinishAtEnd();
                break;
            }

            if (_framer.Feed(one[0]) is not { } line)
                continue;

            lines.Enqueue(line);

            if (line.StartsWith("---", StringComparison.Ordinal))
                break;
        }

        _prefilled = lines;
    }

    /// <summary>Reads payload bytes, which are not part of the header and not recorded.</summary>
    public int ReadPayloadBytes(Span<byte> buffer) =>
        stream.ReadAtLeast(buffer, buffer.Length, throwOnEndOfStream: false);

    /// <summary>The asynchronous <see cref="ReadPayloadBytes"/>.</summary>
    public ValueTask<int> ReadPayloadBytesAsync(Memory<byte> buffer, CancellationToken cancellationToken) =>
        stream.ReadAtLeastAsync(buffer, buffer.Length, throwOnEndOfStream: false, cancellationToken);
}
