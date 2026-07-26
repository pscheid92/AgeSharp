using System.Buffers;
using System.Security.Cryptography;

namespace AgeSharp.Crypto;

// Setup cannot be eager, so caller errors surface from a Write, not the factory. A full
// chunk is held back until a further byte proves it is not the last, which is what makes
// truncation detectable.
internal sealed class DecryptWriterStream : Stream
{
    private const int HoldSize = StreamEncryption.EncryptedChunkSize + 1;

    private readonly Stream _destination;

    private readonly HeaderLineAccumulator _headerLines;
    private readonly IIdentity[] _identities;
    private readonly AgeDecryptOptions _options;

    private readonly byte[] _payloadNonce = new byte[Age.PayloadNonceSize];
    private byte[]? _armorDecoded;
    private ArmorDecoder? _armorDecoder;

    private ArmorLineAccumulator? _armorLines;
    private byte[]? _chunkBuffer;
    private int _chunkLength;
    private IAeadCipher? _cipher;
    private long _counter;
    private bool _disposed;
    private bool _faulted;
    private byte[]? _fileKey;

    private bool _finalized;

    private Framing _framing = Framing.Undecided;

    private bool _inAsyncWrite;
    private int _nonceLength;

    private byte[]? _payloadKey;

    private MemoryStream? _stagedPlaintext;

    private bool _destinationNeedsWrite;
    private byte[]? _plaintextBuffer;
    private byte[]? _probe = new byte[AsciiArmor.ProbeSize];
    private int _probeLength;
    private Stage _stage = Stage.Header;

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
    {
        Write(buffer.AsSpan(offset, count));
    }

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        try
        {
            Consume(buffer);
        }
        catch
        {
            // Finalizing a faulted stream would hide the real exception behind a truncation complaint.
            _faulted = true;
            throw;
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    public override ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return ConsumeAsync(buffer, cancellationToken);
    }

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

    // Deciding early: only leading whitespace is ambiguous, and a short file may never fill the probe.
    private bool CanDecideFraming()
    {
        if (_probeLength == AsciiArmor.ProbeSize)
            return true;

        var start = 0;
        while (start < _probeLength && AsciiArmor.IsArmorWhitespace(_probe![start]))
            start++;

        return _probeLength - start >= AsciiArmor.MarkerLength;
    }

    private void DecideFraming()
    {
        var probe = _probe!;
        var length = _probeLength;
        _probe = null;
        _probeLength = 0;

        var armored = AsciiArmor.StartsWithMarker(probe.AsSpan(0, length));

        if (_options.RequireArmor && !armored)
            throw new AgeFormatException(
                "input is not ASCII-armored, but AgeDecryptOptions.RequireArmor required it to be");

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

        foreach (var b in data)
        {
            if (!_armorLines!.Feed(b))
                continue;

            var decoded = _armorDecoder!.ProcessLine(_armorLines.Line, _armorDecoded!);
            if (decoded > 0)
                ConsumeBinary(_armorDecoded!.AsSpan(0, decoded));
        }
    }

    private void ConsumeBinary(ReadOnlySpan<byte> data)
    {
        while (!data.IsEmpty)
            data = _stage switch
            {
                Stage.Header => FeedHeader(data),
                Stage.Nonce => FeedNonce(data),
                _ => FeedPayload(data)
            };
    }

    private ReadOnlySpan<byte> FeedHeader(ReadOnlySpan<byte> data)
    {
        for (var i = 0; i < data.Length; i++)
        {
            if (_headerLines.Feed(data[i]) is not { } line || !line.StartsWith("---", StringComparison.Ordinal))
                continue;

            UnwrapHeader();
            return data[(i + 1)..];
        }

        return default;
    }

    private void UnwrapHeader()
    {
        using var buffered = new MemoryStream(_headerLines.RawBytes.ToArray(), false);
        var reader = new HeaderReader(buffered, _options.MaxHeaderLineBytes, _options.MaxHeaderBytes);

        _fileKey = new byte[Age.FileKeySize];
        Age.UnwrapHeader(reader, _identities, _fileKey);
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
        _payloadKey = new byte[Age.PayloadKeySize];
        CryptoHelper.HkdfDerive(_fileKey!, _payloadNonce, "payload", _payloadKey);
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

        if (_chunkLength == HoldSize)
            DecryptChunk(false);

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
            _chunkBuffer![0] = _chunkBuffer[StreamEncryption.EncryptedChunkSize];
            _chunkLength = 1;
        }

        return plaintextLength;
    }

    private void WriteOut(ReadOnlySpan<byte> plaintext)
    {
        if (_inAsyncWrite)
        {
            (_stagedPlaintext ??= new MemoryStream()).Write(plaintext);
            _destinationNeedsWrite = true;
            return;
        }

        _destination.Write(plaintext);
    }

    private async ValueTask DrainAsync(CancellationToken cancellationToken)
    {
        if (!_destinationNeedsWrite)
            return;

        _destinationNeedsWrite = false;

        var staged = _stagedPlaintext is null
            ? ReadOnlyMemory<byte>.Empty
            : _stagedPlaintext.GetBuffer().AsMemory(0, (int)_stagedPlaintext.Length);

        await _destination.WriteAsync(staged, cancellationToken).ConfigureAwait(false);
        _stagedPlaintext?.SetLength(0);
    }

    private void Finish()
    {
        if (_finalized || _faulted)
            return;

        _finalized = true;

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

        var plaintextLength = DecryptChunk(true);

        if (plaintextLength == 0 && _counter > 1)
            throw new AgeAuthenticationException("final STREAM chunk is empty but there were preceding chunks");

        // A lazy-creating writer must still materialize.
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

        if (_stagedPlaintext is not null)
        {
            CryptographicOperations.ZeroMemory(_stagedPlaintext.GetBuffer());
            _stagedPlaintext = null;
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

    public override int Read(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    private enum Stage
    {
        Header,
        Nonce,
        Payload
    }

    private enum Framing
    {
        Undecided,
        Binary,
        Armored
    }
}