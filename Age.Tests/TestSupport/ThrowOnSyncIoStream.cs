namespace AgeSharp.Tests;

/// <summary>
/// Wraps a stream and throws on every synchronous <c>Read</c>/<c>Write</c>/<c>Flush</c>
/// (and <c>ReadByte</c>/<c>WriteByte</c>), forwarding only the asynchronous
/// overloads to the inner stream. This is the ASP.NET Core
/// <c>AllowSynchronousIO = false</c> contract, testable without Kestrel: any code
/// path that blocks on sync I/O against this stream fails loudly. The inner stream
/// is never disposed, so tests can read its bytes afterward.
/// </summary>
internal sealed class ThrowOnSyncIoStream(Stream inner) : Stream
{
    private const string Message = "Synchronous IO is disallowed on this stream.";

    public override bool CanRead => inner.CanRead;
    public override bool CanSeek => inner.CanSeek;
    public override bool CanWrite => inner.CanWrite;
    public override long Length => inner.Length;

    public override long Position
    {
        get => inner.Position;
        set => inner.Position = value;
    }

    // --- Synchronous surface: always throws ---

    public override int Read(byte[] buffer, int offset, int count) => throw new InvalidOperationException(Message);
    public override int Read(Span<byte> buffer) => throw new InvalidOperationException(Message);
    public override int ReadByte() => throw new InvalidOperationException(Message);
    public override void Write(byte[] buffer, int offset, int count) => throw new InvalidOperationException(Message);
    public override void Write(ReadOnlySpan<byte> buffer) => throw new InvalidOperationException(Message);
    public override void WriteByte(byte value) => throw new InvalidOperationException(Message);
    public override void Flush() => throw new InvalidOperationException(Message);

    // --- Asynchronous surface: forwarded to the inner stream ---

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => inner.ReadAsync(buffer, offset, count, cancellationToken);

    public override ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
        => inner.ReadAsync(buffer, cancellationToken);

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => inner.WriteAsync(buffer, offset, count, cancellationToken);

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
        => inner.WriteAsync(buffer, cancellationToken);

    public override Task FlushAsync(CancellationToken cancellationToken) => inner.FlushAsync(cancellationToken);

    // Seeking is not I/O; the ASP.NET contract permits it.
    public override long Seek(long offset, SeekOrigin origin) => inner.Seek(offset, origin);
    public override void SetLength(long value) => inner.SetLength(value);
}
