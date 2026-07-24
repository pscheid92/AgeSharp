using System.Buffers;
using System.Security.Cryptography;

namespace AgeSharp.Crypto;

/// <summary>
/// Push-side encryptor: a write-only <see cref="Stream"/> that consumes plaintext
/// and writes age ciphertext to a destination, in the spirit of
/// <see cref="System.IO.Compression.GZipStream"/>. The header and payload nonce
/// (the <c>preamble</c>) are written lazily on the first write — or on
/// <see cref="Dispose(bool)"/> when nothing was written — and the STREAM payload
/// is finalized on dispose.
/// </summary>
/// <remarks>
/// A full 64 KiB chunk is emitted as non-final only once more plaintext proves it
/// is not the last chunk; otherwise it is held so that <see cref="Dispose(bool)"/>
/// can encrypt it with the final flag set. This keeps the invariant that an empty
/// final chunk appears only for empty plaintext. The <c>destination</c> supplied by
/// the facade is never disposed; an armor wrapper created by the facade is.
/// </remarks>
internal sealed class EncryptWriterStream : Stream
{
    private readonly Stream _destination;
    private readonly bool _ownsDestination;
    private readonly byte[] _payloadKey;
    private readonly byte[] _preamble;
    private bool _preambleWritten;

    private readonly byte[] _plaintextBuffer = ArrayPool<byte>.Shared.Rent(StreamEncryption.ChunkSize);
    private readonly byte[] _ciphertextBuffer = ArrayPool<byte>.Shared.Rent(StreamEncryption.EncryptedChunkSize);
    private readonly IAeadCipher _cipher;
    private int _bufferLength;
    private long _counter;

    private bool _finalized;
    private bool _disposed;

    public EncryptWriterStream(byte[] headerBytes, byte[] payloadNonce, byte[] payloadKey, Stream destination, bool ownsDestination)
    {
        _destination = destination;
        _ownsDestination = ownsDestination;
        _payloadKey = payloadKey;
        _preamble = [.. headerBytes, .. payloadNonce];
        _cipher = AeadCipher.Create(payloadKey);
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
        WritePreamble();

        while (!buffer.IsEmpty)
        {
            // The buffer is full and there is still more plaintext to place, so this
            // chunk cannot be the final one — flush it before taking the next bytes.
            if (_bufferLength == StreamEncryption.ChunkSize)
            {
                var length = EncryptBufferedChunk(isFinal: false);
                _destination.Write(_ciphertextBuffer.AsSpan(0, length));
            }

            var take = Math.Min(StreamEncryption.ChunkSize - _bufferLength, buffer.Length);
            buffer[..take].CopyTo(_plaintextBuffer.AsSpan(_bufferLength));
            _bufferLength += take;
            buffer = buffer[take..];
        }
    }

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        await WritePreambleAsync(cancellationToken).ConfigureAwait(false);

        while (!buffer.IsEmpty)
        {
            if (_bufferLength == StreamEncryption.ChunkSize)
            {
                var length = EncryptBufferedChunk(isFinal: false);
                await _destination.WriteAsync(_ciphertextBuffer.AsMemory(0, length), cancellationToken).ConfigureAwait(false);
            }

            var take = Math.Min(StreamEncryption.ChunkSize - _bufferLength, buffer.Length);
            buffer.Span[..take].CopyTo(_plaintextBuffer.AsSpan(_bufferLength));
            _bufferLength += take;
            buffer = buffer[take..];
        }
    }

    private void WritePreamble()
    {
        if (_preambleWritten)
            return;

        _destination.Write(_preamble);
        _preambleWritten = true;
    }

    private ValueTask WritePreambleAsync(CancellationToken cancellationToken)
    {
        if (_preambleWritten)
            return ValueTask.CompletedTask;

        _preambleWritten = true;
        return _destination.WriteAsync(_preamble, cancellationToken);
    }

    // CPU-only: encrypt the buffered plaintext into _ciphertextBuffer, advance the
    // counter, reset the buffer, and return the ciphertext length to write.
    private int EncryptBufferedChunk(bool isFinal)
    {
        StreamEncryption.EncryptChunk(
            _cipher, _counter, isFinal,
            _plaintextBuffer.AsSpan(0, _bufferLength),
            _ciphertextBuffer);
        var length = _bufferLength + StreamEncryption.TagSize;
        _counter++;
        _bufferLength = 0;
        return length;
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
            if (!_finalized)
            {
                _finalized = true;
                WritePreamble();
                _destination.Write(_ciphertextBuffer.AsSpan(0, EncryptBufferedChunk(isFinal: true)));
            }

            if (_ownsDestination)
                _destination.Dispose();
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
            if (!_finalized)
            {
                _finalized = true;
                await WritePreambleAsync(default).ConfigureAwait(false);
                var length = EncryptBufferedChunk(isFinal: true);
                await _destination.WriteAsync(_ciphertextBuffer.AsMemory(0, length), default).ConfigureAwait(false);
            }

            if (_ownsDestination)
                await _destination.DisposeAsync().ConfigureAwait(false);
        }
        finally
        {
            ReleaseResources();
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    private void ReleaseResources()
    {
        _cipher.Dispose();
        CryptographicOperations.ZeroMemory(_payloadKey);
        CryptographicOperations.ZeroMemory(_plaintextBuffer.AsSpan(0, StreamEncryption.ChunkSize));
        ArrayPool<byte>.Shared.Return(_plaintextBuffer);
        ArrayPool<byte>.Shared.Return(_ciphertextBuffer);
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
