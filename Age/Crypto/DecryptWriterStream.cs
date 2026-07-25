using System.Buffers;
using System.Security.Cryptography;

namespace AgeSharp.Crypto;

/// <summary>
/// Push-side decryptor: a write-only <see cref="Stream"/> that consumes age
/// ciphertext and writes plaintext to a destination. The mirror of
/// <see cref="EncryptWriterStream"/>, and the fourth cell of the streaming grid.
/// </summary>
/// <remarks>
/// <para>
/// Unlike the other three, setup cannot be eager: nothing is known until enough
/// bytes have been pushed. The stream walks three stages as they arrive — armor
/// framing, then the header (unwrapped once its MAC line lands), then the payload
/// nonce, then STREAM chunks. A caller error such as "no identity matches" therefore
/// surfaces from a <c>Write</c> rather than from the factory.
/// </para>
/// <para>
/// A full encrypted chunk is decrypted as non-final only once one further byte
/// proves it is not the last; the rest is held so <see cref="Dispose(bool)"/> can
/// decrypt it with the final flag set. That is the same hold-back
/// <see cref="EncryptWriterStream"/> performs, and it is what makes truncation
/// detectable: a file cut short leaves a chunk that never gets its final flag.
/// </para>
/// <para>
/// Memory is bounded: one chunk buffer pair plus the header, which must be buffered
/// whole in any case to verify its MAC.
/// </para>
/// </remarks>
internal sealed class DecryptWriterStream : Stream
{
    private enum Stage
    {
        Header,
        Nonce,
        Payload,
    }

    private enum Framing
    {
        Undecided,
        Binary,
        Armored,
    }

    // One byte past a full chunk: enough to prove the chunk is not the last.
    private const int HoldSize = StreamEncryption.EncryptedChunkSize + 1;

    private readonly Stream _destination;
    private readonly IIdentity[] _identities;
    private readonly AgeDecryptOptions _options;

    private Framing _framing = Framing.Undecided;
    private byte[]? _probe = new byte[AsciiArmor.ProbeSize];
    private int _probeLength;

    private ArmorLineAccumulator? _armorLines;
    private ArmorDecoder? _armorDecoder;
    private byte[]? _armorDecoded;

    private readonly HeaderLineAccumulator _headerLines;
    private Stage _stage = Stage.Header;
    private byte[]? _fileKey;

    private readonly byte[] _payloadNonce = new byte[Age.PayloadNonceSize];
    private int _nonceLength;

    private byte[]? _payloadKey;
    private IAeadCipher? _cipher;
    private byte[]? _chunkBuffer;
    private byte[]? _plaintextBuffer;
    private int _chunkLength;
    private long _counter;

    private bool _finalized;
    private bool _faulted;
    private bool _disposed;

    public DecryptWriterStream(Stream destination, IIdentity[] identities, AgeDecryptOptions options)
    {
        _destination = destination;
        _identities = identities;
        _options = options;
        _headerLines = new HeaderLineAccumulator(options.MaxHeaderLineBytes, options.MaxHeaderBytes);
    }

    public override bool CanRead => false;
    public override bool CanSeek => false;
    public override bool CanWrite => true;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
        => Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            Consume(buffer);
        }
        catch
        {
            // Once the stream has faulted, Dispose must not finalize: doing so would
            // throw a second, less informative exception out of the `using` and hide
            // the real one.
            _faulted = true;
            throw;
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        // Decryption is CPU-bound; the only I/O is writing plaintext onward. Keeping
        // this synchronous would block the caller's destination, so the write path is
        // shared and only the destination writes differ — see WriteOut.
        ObjectDisposedException.ThrowIf(_disposed, this);
        return ConsumeAsync(buffer, cancellationToken);
    }

    // --- framing ------------------------------------------------------------

    private void Consume(ReadOnlySpan<byte> raw)
    {
        if (_framing == Framing.Undecided)
        {
            raw = BufferProbe(raw);

            if (_framing == Framing.Undecided)
                return;
        }

        Route(raw);
    }

    private async ValueTask ConsumeAsync(ReadOnlyMemory<byte> raw, CancellationToken cancellationToken)
    {
        // The synchronous path is reused wholesale: with _inAsyncWrite set it stages
        // plaintext instead of writing it, and the staged bytes are drained here with
        // a real await. Nothing blocks on the caller's destination.
        _inAsyncWrite = true;
        try
        {
            Consume(raw.Span);
        }
        catch
        {
            _faulted = true;
            throw;
        }
        finally
        {
            _inAsyncWrite = false;
        }

        await DrainAsync(cancellationToken).ConfigureAwait(false);
    }

    // Accumulates into the detection probe, deciding as soon as it is full.
    // Returns whatever is left over once a decision was made.
    private ReadOnlySpan<byte> BufferProbe(ReadOnlySpan<byte> raw)
    {
        var take = Math.Min(AsciiArmor.ProbeSize - _probeLength, raw.Length);
        raw[..take].CopyTo(_probe!.AsSpan(_probeLength));
        _probeLength += take;

        if (!CanDecideFraming())
            return default;

        DecideFraming();
        return raw[take..];
    }

    // Waiting for the probe to fill would stall every file smaller than it — nothing
    // would be decrypted, and errors would surface from Dispose instead of the write
    // that caused them. Only leading whitespace is genuinely ambiguous, so a decision
    // is possible as soon as marker-length bytes sit past it.
    private bool CanDecideFraming()
    {
        if (_probeLength == AsciiArmor.ProbeSize)
            return true;

        var start = 0;
        while (start < _probeLength && AsciiArmor.IsArmorWhitespace(_probe![start]))
            start++;

        return _probeLength - start >= AsciiArmor.MarkerLength;
    }

    // A file shorter than the marker never reaches a decision, so this also runs
    // from Finish().
    private void DecideFraming()
    {
        var probe = _probe!;
        var length = _probeLength;
        _probe = null;
        _probeLength = 0;

        var armored = AsciiArmor.StartsWithMarker(probe.AsSpan(0, length));

        if (_options.RequireArmor && !armored)
            throw new AgeFormatException("input is not ASCII-armored, but AgeDecryptOptions.RequireArmor required it to be");

        if (armored)
        {
            _armorLines = new ArmorLineAccumulator(_options.MaxArmorLineBytes);
            _armorDecoder = new ArmorDecoder();
            _armorDecoded = new byte[ArmorDecoder.MaxDecodedPerLine];
        }

        _framing = armored ? Framing.Armored : Framing.Binary;
        Route(probe.AsSpan(0, length));
    }

    private void Route(ReadOnlySpan<byte> data)
    {
        if (_framing == Framing.Binary)
        {
            ConsumeBinary(data);
            return;
        }

        // Armored: the sans-I/O line accumulator and decoder are byte-fed, so the
        // same core that drives pull-side dearmor works unchanged when pushed.
        foreach (var b in data)
        {
            if (!_armorLines!.Feed(b))
                continue;

            var decoded = _armorDecoder!.ProcessLine(_armorLines.Line, _armorDecoded!);
            if (decoded > 0)
                ConsumeBinary(_armorDecoded!.AsSpan(0, decoded));
        }
    }

    // --- stages -------------------------------------------------------------

    private void ConsumeBinary(ReadOnlySpan<byte> data)
    {
        while (!data.IsEmpty)
            data = _stage switch
            {
                Stage.Header => FeedHeader(data),
                Stage.Nonce => FeedNonce(data),
                _ => FeedPayload(data),
            };
    }

    private ReadOnlySpan<byte> FeedHeader(ReadOnlySpan<byte> data)
    {
        for (var i = 0; i < data.Length; i++)
        {
            // The MAC line is the only header line starting with "---".
            if (_headerLines.Feed(data[i]) is not { } line || !line.StartsWith("---", StringComparison.Ordinal))
                continue;

            UnwrapHeader();
            return data[(i + 1)..];
        }

        return default;
    }

    // Re-parses the buffered header through the shared reader so that stanza
    // parsing, the scrypt-alone rule, identity matching, and MAC verification are
    // the same code the pull path runs — not a second implementation.
    private void UnwrapHeader()
    {
        using var buffered = new MemoryStream(_headerLines.RawBytes.ToArray(), writable: false);
        var reader = new HeaderReader(buffered, _options.MaxHeaderLineBytes, _options.MaxHeaderBytes);

        _fileKey = Age.UnwrapHeader(reader, _identities);
        _stage = Stage.Nonce;
    }

    private ReadOnlySpan<byte> FeedNonce(ReadOnlySpan<byte> data)
    {
        var take = Math.Min(Age.PayloadNonceSize - _nonceLength, data.Length);
        data[..take].CopyTo(_payloadNonce.AsSpan(_nonceLength));
        _nonceLength += take;

        if (_nonceLength == Age.PayloadNonceSize)
            StartPayload();

        return data[take..];
    }

    private void StartPayload()
    {
        _payloadKey = CryptoHelper.HkdfDerive(_fileKey!, _payloadNonce, "payload", Age.PayloadKeySize);
        CryptographicOperations.ZeroMemory(_fileKey!);
        _fileKey = null;

        _cipher = AeadCipher.Create(_payloadKey);
        _chunkBuffer = ArrayPool<byte>.Shared.Rent(HoldSize);
        _plaintextBuffer = ArrayPool<byte>.Shared.Rent(StreamEncryption.ChunkSize);
        _stage = Stage.Payload;
    }

    private ReadOnlySpan<byte> FeedPayload(ReadOnlySpan<byte> data)
    {
        var take = Math.Min(HoldSize - _chunkLength, data.Length);
        data[..take].CopyTo(_chunkBuffer!.AsSpan(_chunkLength));
        _chunkLength += take;

        // The held byte proves more ciphertext follows, so this chunk is not final.
        if (_chunkLength == HoldSize)
            DecryptChunk(isFinal: false);

        return data[take..];
    }

    private int DecryptChunk(bool isFinal)
    {
        var chunkLength = isFinal ? _chunkLength : StreamEncryption.EncryptedChunkSize;

        if (chunkLength < StreamEncryption.TagSize)
            throw new AgeAuthenticationException("chunk too small for authentication tag");

        StreamEncryption.DecryptChunk(
            _cipher!, _counter, isFinal,
            _chunkBuffer!.AsSpan(0, chunkLength),
            _plaintextBuffer);

        var plaintextLength = chunkLength - StreamEncryption.TagSize;
        WriteOut(_plaintextBuffer!.AsSpan(0, plaintextLength));
        _counter++;

        if (isFinal)
        {
            _chunkLength = 0;
        }
        else
        {
            // Carry the look-ahead byte to the front of the next chunk.
            _chunkBuffer![0] = _chunkBuffer[StreamEncryption.EncryptedChunkSize];
            _chunkLength = 1;
        }

        return plaintextLength;
    }

    // --- output -------------------------------------------------------------

    // Plaintext is staged here rather than written straight out, so the one shared
    // decrypt path can serve both the sync and async writes: sync drains inline,
    // async drains with an await after Consume returns.
    private MemoryStream? _pending;

    private void WriteOut(ReadOnlySpan<byte> plaintext)
    {
        if (_inAsyncWrite)
        {
            (_pending ??= new MemoryStream()).Write(plaintext);
            return;
        }

        _destination.Write(plaintext);
    }

    private bool _inAsyncWrite;

    private async ValueTask DrainAsync(CancellationToken cancellationToken)
    {
        if (_pending is null || _pending.Length == 0)
            return;

        await _destination.WriteAsync(_pending.GetBuffer().AsMemory(0, (int)_pending.Length), cancellationToken)
                          .ConfigureAwait(false);
        _pending.SetLength(0);
    }

    // --- finalization -------------------------------------------------------

    private void Finish()
    {
        // A stream that already threw has nothing to finalize, and finalizing anyway
        // would replace the caller's real exception with a truncation complaint.
        if (_finalized || _faulted)
            return;

        _finalized = true;

        // A file shorter than the detection probe never triggered a decision.
        if (_framing == Framing.Undecided)
            DecideFraming();

        if (_framing == Framing.Armored)
        {
            if (_armorLines!.FinishAtEof())
            {
                var decoded = _armorDecoder!.ProcessLine(_armorLines.Line, _armorDecoded!);
                if (decoded > 0)
                    ConsumeBinary(_armorDecoded!.AsSpan(0, decoded));
            }

            _armorDecoder!.FinishAtEof();
        }

        if (_stage != Stage.Payload)
            throw new AgeFormatException("input ended before the age payload began");

        if (_counter == 0 && _chunkLength == 0)
            throw new AgeAuthenticationException("payload is empty (no chunks)");

        var plaintextLength = DecryptChunk(isFinal: true);

        // An empty final chunk is legal only when it is the sole chunk.
        if (plaintextLength == 0 && _counter > 1)
            throw new AgeAuthenticationException("final STREAM chunk is empty but there were preceding chunks");

        // Touch the destination even for empty plaintext — matters for lazy-creating
        // writers that only materialize on first write.
        WriteOut(ReadOnlySpan<byte>.Empty);
    }

    protected override void Dispose(bool disposing)
    {
        if (!disposing || _disposed)
        {
            base.Dispose(disposing);
            return;
        }

        _disposed = true;

        try
        {
            Finish();
        }
        finally
        {
            ReleaseResources();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (_disposed)
        {
            await base.DisposeAsync().ConfigureAwait(false);
            return;
        }

        _disposed = true;

        try
        {
            _inAsyncWrite = true;
            Finish();
            await DrainAsync(default).ConfigureAwait(false);
        }
        finally
        {
            _inAsyncWrite = false;
            ReleaseResources();
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    private void ReleaseResources()
    {
        _cipher?.Dispose();

        if (_fileKey is not null)
            CryptographicOperations.ZeroMemory(_fileKey);

        if (_payloadKey is not null)
            CryptographicOperations.ZeroMemory(_payloadKey);

        if (_plaintextBuffer is not null)
        {
            CryptographicOperations.ZeroMemory(_plaintextBuffer.AsSpan(0, StreamEncryption.ChunkSize));
            ArrayPool<byte>.Shared.Return(_plaintextBuffer);
            _plaintextBuffer = null;
        }

        if (_chunkBuffer is not null)
        {
            ArrayPool<byte>.Shared.Return(_chunkBuffer);
            _chunkBuffer = null;
        }

        if (_pending is not null)
        {
            CryptographicOperations.ZeroMemory(_pending.GetBuffer());
            _pending = null;
        }
    }

    public override void Flush()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _destination.Flush();
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _destination.FlushAsync(cancellationToken);
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
