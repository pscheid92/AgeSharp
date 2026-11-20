using System.Buffers;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;

namespace AgeSharp.Crypto;

/// <summary>
/// The push half of decryption: an age file written to it, binary or armored, reaches the
/// destination as plaintext, a chunk at a time as each authenticates. Nothing is decided by
/// seeking or reading ahead: armor is recognised, the header parsed and the file key unwrapped as
/// the bytes arrive, by the same rules the reading side applies.
/// </summary>
/// <remarks>
/// <para>
/// A full chunk is held back until a further byte proves it is not the last. Only disposing says
/// the input has ended, so that is where a truncated file, or one that never got past its header,
/// is reported.
/// </para>
/// <para>
/// Fail-stop: once a write has thrown, every later write throws the same exception, and disposing
/// finishes nothing and throws nothing more. After a failure the next chunk boundary is unknown.
/// </para>
/// </remarks>
internal sealed class DecryptWriterStream(Stream destination, Identities identities, AgeDecryptOptions options) : Stream
{
    private const int HoldSize = StreamEncryption.EncryptedChunkSize + 1;

    private enum Framing { Undecided, Binary, Armored }

    private enum Stage { Header, Nonce, Payload }

    private enum End { Draining, Payload, Done }

    // Framing: the bytes looked at to tell armor from binary, then replayed.
    private byte[] _probe = new byte[AsciiArmor.InitialLookahead];
    private int _probeLength;
    private int _probeStart;
    private int _lookahead = AsciiArmor.InitialLookahead;
    private Framing _framing = Framing.Undecided;

    // Armor, once recognised: lines, the rules, and what the last line decoded to.
    private ArmorLineFramer? _armorLines;
    private ArmorDecoder? _armor;
    private readonly byte[] _decoded = new byte[ArmorDecoder.MaxDecodedPerLine];
    private int _decodedStart;
    private int _decodedEnd;

    // The binary file: header, nonce, payload.
    private Stage _stage = Stage.Header;
    private readonly HeaderLineFramer _headerLines = new(options.MaxHeaderBytes);
    private FileKey? _fileKey;
    private readonly byte[] _nonce = new byte[StreamEncryption.PayloadNonceSize];
    private int _nonceLength;
    private byte[]? _payloadKey;
    private IAeadCipher? _cipher;
    private byte[]? _hold;
    private int _holdLength;
    private byte[]? _plaintext;
    private int _plaintextLength;
    private long _counter;

    private End _end = End.Draining;
    private bool _disposed;
    private ExceptionDispatchInfo? _failure;

    public override void Write(byte[] buffer, int offset, int count) =>
        Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ThrowIfUnusable();

        try
        {
            while (Advance(ref buffer))
                destination.Write(_plaintext!, 0, _plaintextLength);
        }
        catch (Exception ex)
        {
            _failure = ExceptionDispatchInfo.Capture(ex);
            throw;
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfUnusable();

        try
        {
            while (true)
            {
                var span = buffer.Span;
                var ready = Advance(ref span);
                buffer = buffer[(buffer.Length - span.Length)..];

                if (!ready)
                    return;

                await destination.WriteAsync(_plaintext.AsMemory(0, _plaintextLength), cancellationToken).ConfigureAwait(false);
            }
        }
        catch (Exception ex)
        {
            // Cancellation included: the destination may have taken part of a chunk.
            _failure = ExceptionDispatchInfo.Capture(ex);
            throw;
        }
    }

    private void ThrowIfUnusable()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _failure?.Throw();
    }

    /// <summary>
    /// Takes input until a chunk of plaintext is ready in <c>_plaintext</c> (true) or the input is
    /// used up (false). Bytes held from earlier, looked at or decoded, go first.
    /// </summary>
    private bool Advance(ref ReadOnlySpan<byte> input)
    {
        while (_framing == Framing.Undecided)
        {
            if (input.IsEmpty)
                return false;

            var take = Math.Min(_lookahead - _probeLength, input.Length);
            input[..take].CopyTo(_probe.AsSpan(_probeLength));
            _probeLength += take;
            input = input[take..];

            if (_probeLength == _lookahead)
                DecideFraming();
        }

        ReplayProbe();
        return AdvanceFramed(ref input);
    }

    // What was looked at to tell armor from binary is read first, once. It never completes a
    // chunk: binary input looked at past the marker's length starts with whitespace, which the
    // header refuses at its first line; armored input gets at most its whitespace allowance and
    // a line or two past the marker, a few hundred bytes of payload at most.
    private void ReplayProbe()
    {
        if (_probeStart == _probeLength)
            return;

        ReadOnlySpan<byte> probe = _probe.AsSpan(_probeStart, _probeLength - _probeStart);
        _probeStart = _probeLength;

        if (AdvanceFramed(ref probe))
            throw new InvalidOperationException("the bytes looked at to tell armor from binary completed a chunk");
    }

    // Decides from what was looked at, or asks to look further, as reading armor detection does.
    // A prefix shorter than the lookahead means the input ended.
    private void DecideFraming()
    {
        var decided = AsciiArmor.Decide(_probe.AsSpan(0, _probeLength), ref _lookahead, options);

        if (decided is not { } armored)
        {
            Array.Resize(ref _probe, _lookahead);
            return;
        }

        if (!armored && options.RequireArmor)
            throw AsciiArmor.NotArmored();

        if (armored)
        {
            _armorLines = new ArmorLineFramer(options.MaxArmorLineBytes);
            _armor = new ArmorDecoder();
        }

        _framing = armored ? Framing.Armored : Framing.Binary;
    }

    private bool AdvanceFramed(ref ReadOnlySpan<byte> input)
    {
        if (_framing == Framing.Binary)
            return Feed(ref input);

        while (true)
        {
            if (_decodedStart < _decodedEnd)
            {
                ReadOnlySpan<byte> decoded = _decoded.AsSpan(_decodedStart, _decodedEnd - _decodedStart);
                var ready = Feed(ref decoded);
                _decodedStart = _decodedEnd - decoded.Length;

                if (ready)
                    return true;

                continue;
            }

            if (input.IsEmpty)
                return false;

            if (_armorLines!.TryTakeLine(ref input, out var line))
                Decode(line);
        }
    }

    private void Decode(ArmorLine line)
    {
        _decodedStart = 0;
        _decodedEnd = _armor!.TakeLine(line, _decoded);
    }

    /// <summary>Takes binary bytes until a chunk of plaintext is ready (true) or they are used up.</summary>
    private bool Feed(ref ReadOnlySpan<byte> binary)
    {
        while (!binary.IsEmpty)
        {
            switch (_stage)
            {
                case Stage.Header:
                    binary = FeedHeader(binary);
                    break;

                case Stage.Nonce:
                    var take = Math.Min(_nonce.Length - _nonceLength, binary.Length);
                    binary[..take].CopyTo(_nonce.AsSpan(_nonceLength));
                    _nonceLength += take;
                    binary = binary[take..];

                    if (_nonceLength == _nonce.Length)
                        StartPayload();
                    break;

                default:
                    var held = Math.Min(HoldSize - _holdLength, binary.Length);
                    binary[..held].CopyTo(_hold.AsSpan(_holdLength));
                    _holdLength += held;
                    binary = binary[held..];

                    // A chunk and one byte more: the chunk is not the last.
                    if (_holdLength == HoldSize)
                    {
                        DecryptChunk(isFinal: false);
                        return true;
                    }
                    break;
            }
        }

        return false;
    }

    // The header is collected up to its MAC line, the first that starts with "---", then parsed
    // and unwrapped whole, as the reading side's prefill does.
    private ReadOnlySpan<byte> FeedHeader(ReadOnlySpan<byte> binary)
    {
        for (var i = 0; i < binary.Length; i++)
        {
            if (_headerLines.Feed(binary[i]) is { } line && line.StartsWith("---", StringComparison.Ordinal))
            {
                Unlock();
                return binary[(i + 1)..];
            }
        }

        return default;
    }

    private void Unlock()
    {
        var reader = new HeaderReader(new MemoryStream(_headerLines.RawBytes.ToArray(), writable: false), options);
        _fileKey = identities.Unlock(Identities.ParseHeader(reader));
        _stage = Stage.Nonce;
    }

    private void StartPayload()
    {
        _payloadKey = Identities.PayloadKey(_fileKey!, _nonce, _nonceLength);
        _fileKey!.Dispose();
        _fileKey = null;

        _cipher = AeadCipher.Create(_payloadKey);
        _hold = ArrayPool<byte>.Shared.Rent(HoldSize);
        _plaintext = ArrayPool<byte>.Shared.Rent(StreamEncryption.ChunkSize);
        _stage = Stage.Payload;
    }

    // The same checks, in the same order and words, as the reading side's DecryptStream.
    private void DecryptChunk(bool isFinal)
    {
        var length = isFinal ? _holdLength : StreamEncryption.EncryptedChunkSize;

        if (length < StreamEncryption.TagSize)
            throw new AgePayloadException("chunk too small for authentication tag");

        var previous = _plaintextLength;
        StreamEncryption.DecryptChunk(_cipher!, _counter, isFinal, _hold.AsSpan(0, length), _plaintext);
        _plaintextLength = length - StreamEncryption.TagSize;
        _counter++;

        // Stale plaintext from a longer chunk before it is cleared.
        if (previous > _plaintextLength)
            CryptographicOperations.ZeroMemory(_plaintext.AsSpan(_plaintextLength, previous - _plaintextLength));

        if (isFinal)
        {
            _holdLength = 0;

            if (_plaintextLength == 0 && _counter > 1)
                throw new AgePayloadException("final STREAM chunk is empty but there were preceding chunks");
        }
        else
        {
            _hold![0] = _hold[StreamEncryption.EncryptedChunkSize];
            _holdLength = 1;
        }
    }

    /// <summary>
    /// Takes the end of the input one step at a time: true while a chunk of plaintext is ready to
    /// be written, the final one last (empty for an empty file, which still reaches the
    /// destination as a write).
    /// </summary>
    private bool FinishNext()
    {
        while (true)
        {
            switch (_end)
            {
                case End.Draining:
                    if (_framing == Framing.Undecided)
                        DecideFraming();

                    // What writes left behind is drained already; only a file shorter than the
                    // lookahead, decided just now, still has bytes to read.
                    ReplayProbe();

                    // The armor's end rules apply as soon as its last line is in, before anything
                    // that line decodes to is used, as the reading side applies them. A line that
                    // decodes to anything is a body line, and a body cut off is refused here.
                    if (_framing == Framing.Armored)
                    {
                        if (_armorLines!.TryFinishAtEnd(out var last))
                            Decode(last);

                        _armor!.Finish();
                    }

                    _end = End.Payload;
                    break;

                case End.Payload:
                    FinishPayload();
                    _end = End.Done;
                    return true;

                default:
                    return false;
            }
        }
    }

    private void FinishPayload()
    {
        if (_stage == Stage.Header)
            Unlock();

        if (_stage == Stage.Nonce)
            StartPayload();

        if (_holdLength == 0 && _counter == 0)
            throw new AgePayloadException("payload is empty (no chunks)");

        DecryptChunk(isFinal: true);
    }

    // Disposing ends the input: it decrypts and writes the final chunk, and throws if the file is
    // truncated or malformed at its end. After a failed write it finishes nothing.
    protected override void Dispose(bool disposing)
    {
        if (_disposed)
        {
            base.Dispose(disposing);
            return;
        }

        _disposed = true;

        try
        {
            if (_failure is null)
            {
                while (FinishNext())
                    destination.Write(_plaintext!, 0, _plaintextLength);
            }
        }
        finally
        {
            Release();
            base.Dispose(disposing);
        }
    }

    public override async ValueTask DisposeAsync()
    {
        if (_disposed)
            return;

        _disposed = true;

        try
        {
            if (_failure is null)
            {
                while (FinishNext())
                    await destination.WriteAsync(_plaintext.AsMemory(0, _plaintextLength)).ConfigureAwait(false);
            }
        }
        finally
        {
            Release();
            GC.SuppressFinalize(this);
        }
    }

    private void Release()
    {
        _fileKey?.Dispose();
        _cipher?.Dispose();

        if (_payloadKey is not null)
            CryptographicOperations.ZeroMemory(_payloadKey);

        if (_plaintext is not null)
        {
            CryptographicOperations.ZeroMemory(_plaintext.AsSpan(0, StreamEncryption.ChunkSize));
            ArrayPool<byte>.Shared.Return(_plaintext);
            _plaintext = null;
        }

        if (_hold is not null)
        {
            ArrayPool<byte>.Shared.Return(_hold);
            _hold = null;
        }
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

    public override void Flush()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        destination.Flush();
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return destination.FlushAsync(cancellationToken);
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
