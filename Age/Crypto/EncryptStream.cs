using System.Buffers;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;

namespace AgeSharp.Crypto;

internal sealed class EncryptStream(byte[] headerBytes, byte[] payloadNonce, PayloadKey payloadKey, Stream plaintext) : Stream
{
    private const int PlaintextBufferSize = StreamEncryption.ChunkSize + 1;
    private const int CiphertextBufferSize = StreamEncryption.EncryptedChunkSize;

    private bool _disposed;
    private ExceptionDispatchInfo? _failure;
    private readonly byte[] _preamble = [..headerBytes, ..payloadNonce];
    private int _preambleOffset;

    private readonly byte[] _plaintextBuffer = ArrayPool<byte>.Shared.Rent(PlaintextBufferSize);
    private readonly byte[] _ciphertextBuffer = ArrayPool<byte>.Shared.Rent(CiphertextBufferSize);
    private readonly IAeadCipher _cipher = payloadKey.Cipher;
    private int _chunkLength;
    private int _chunkOffset;
    private long _counter;
    private bool _emittedFinal;
    private bool _pendingByte;

    public override bool CanRead => true;
    public override bool CanSeek => false;
    public override bool CanWrite => false;
    public override long Length => throw new NotSupportedException();

    public override long Position
    {
        get => throw new NotSupportedException();
        set => throw new NotSupportedException();
    }

    public override int Read(byte[] buffer, int offset, int count)
        => Read(buffer.AsSpan(offset, count));

    public override int Read(Span<byte> buffer)
    {
        ThrowIfUnusable();

        try
        {
            var total = 0;

            while (true)
            {
                total += EmitReady(buffer[total..]);

                // Short of a full buffer, EmitReady has handed out everything encrypted so far.
                if (total == buffer.Length || _emittedFinal)
                    return total;

                EncryptChunk(ReadPlaintext());
            }
        }
        catch (Exception ex)
        {
            _failure = ExceptionDispatchInfo.Capture(ex);
            throw;
        }
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken) =>
        ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    // The same steps as Read, with the plaintext read awaited: the only I/O this stream does.
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ThrowIfUnusable();

        try
        {
            var total = 0;

            while (true)
            {
                total += EmitReady(buffer.Span[total..]);

                // Short of a full buffer, EmitReady has handed out everything encrypted so far.
                if (total == buffer.Length || _emittedFinal)
                    return total;

                EncryptChunk(await ReadPlaintextAsync(cancellationToken).ConfigureAwait(false));
            }
        }
        catch (Exception ex)
        {
            _failure = ExceptionDispatchInfo.Capture(ex);
            throw;
        }
    }

    private void ThrowIfUnusable()
    {
        // See DecryptStream.Read: the pooled buffers no longer belong to this stream.
        ObjectDisposedException.ThrowIf(_disposed, this);

        // A failed read has already consumed the look-ahead byte. Carrying on would encrypt the
        // plaintext without it, and the result would still authenticate — so fail every read.
        _failure?.Throw();
    }

    // Copies out what is already encrypted, the header and nonce first, without reading
    // plaintext. Stops when the buffer is full or the next chunk has to be read.
    private int EmitReady(Span<byte> dest)
    {
        var total = EmitBuffer(_preamble, ref _preambleOffset, dest);

        if (_preambleOffset == _preamble.Length)
            total += EmitBuffer(_ciphertextBuffer.AsSpan(0, _chunkLength), ref _chunkOffset, dest[total..]);

        return total;
    }


    // bytesRead counts the look-ahead byte: ChunkSize + 1 means another chunk follows.
    private void EncryptChunk(int bytesRead)
    {
        var isFinal = bytesRead <= StreamEncryption.ChunkSize;
        var chunkLen = Math.Min(bytesRead, StreamEncryption.ChunkSize);

        StreamEncryption.EncryptChunk(
            _cipher, _counter, isFinal,
            _plaintextBuffer.AsSpan(0, chunkLen),
            _ciphertextBuffer);
        _chunkLength = chunkLen + StreamEncryption.TagSize;
        _chunkOffset = 0;
        _counter++;

        if (isFinal)
        {
            _emittedFinal = true;
        }
        else
        {
            _plaintextBuffer[0] = _plaintextBuffer[StreamEncryption.ChunkSize];
            _pendingByte = true;
        }
    }

    private static int EmitBuffer(ReadOnlySpan<byte> source, ref int sourceOffset, Span<byte> dest)
    {
        var available = source.Length - sourceOffset;
        var toCopy = Math.Min(available, dest.Length);

        source.Slice(sourceOffset, toCopy).CopyTo(dest);
        sourceOffset += toCopy;

        return toCopy;
    }

    // Reads ChunkSize + 1 bytes, the extra one detecting the end. _plaintextBuffer[0] already
    // holds the pending byte; the flag is cleared only once the read has succeeded, so a throw
    // leaves it describing the buffer truthfully.
    private int ReadPlaintext()
    {
        var pending = _pendingByte ? 1 : 0;
        var read = plaintext.ReadAtLeast(_plaintextBuffer.AsSpan(pending, PlaintextBufferSize - pending), PlaintextBufferSize - pending, throwOnEndOfStream: false);
        _pendingByte = false;
        return pending + read;
    }

    private async ValueTask<int> ReadPlaintextAsync(CancellationToken cancellationToken)
    {
        var pending = _pendingByte ? 1 : 0;
        var read = await plaintext.ReadAtLeastAsync(_plaintextBuffer.AsMemory(pending, PlaintextBufferSize - pending), PlaintextBufferSize - pending, throwOnEndOfStream: false, cancellationToken).ConfigureAwait(false);
        _pendingByte = false;
        return pending + read;
    }

    // See DecryptStream.Dispose: without the guard, a legal Close()+Dispose() Returns each
    // pooled buffer twice and two later renters are handed the same array.
    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            payloadKey.Dispose();
            CryptographicOperations.ZeroMemory(_plaintextBuffer.AsSpan(0, PlaintextBufferSize));
            ArrayPool<byte>.Shared.Return(_plaintextBuffer);
            ArrayPool<byte>.Shared.Return(_ciphertextBuffer);
        }

        base.Dispose(disposing);
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException();

    public override void SetLength(long value) =>
        throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();
}
