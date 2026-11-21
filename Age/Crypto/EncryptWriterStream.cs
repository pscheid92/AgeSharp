using System.Buffers;
using System.Runtime.ExceptionServices;
using System.Security.Cryptography;

namespace AgeSharp.Crypto;

/// <summary>
/// The push half of encryption: plaintext written to it reaches the destination as an age file.
/// The header goes out with the first write, and a full chunk is held back until more plaintext
/// proves it is not the last, so that disposing can mark the true final chunk.
/// </summary>
/// <remarks>
/// Fail-stop: once a write has thrown, every later write throws the same exception, and disposing
/// writes nothing more. A failed write may have consumed plaintext the destination never received,
/// so carrying on would produce a file without it.
/// </remarks>
internal sealed class EncryptWriterStream(byte[] headerBytes, byte[] payloadNonce, PayloadKey payloadKey, Stream destination, ArmorWriterStream? armor)
    : Stream
{
    private readonly Stream _out = (Stream?)armor ?? destination;
    private readonly byte[] _preamble = [.. headerBytes, .. payloadNonce];
    private readonly IAeadCipher _cipher = payloadKey.Cipher;
    private readonly byte[] _plaintext = ArrayPool<byte>.Shared.Rent(StreamEncryption.ChunkSize);
    private readonly byte[] _ciphertext = ArrayPool<byte>.Shared.Rent(StreamEncryption.EncryptedChunkSize);
    private int _length;
    private long _counter;
    private bool _preambleWritten;
    private bool _disposed;
    private ExceptionDispatchInfo? _failure;

    public override void Write(byte[] buffer, int offset, int count) =>
        Write(buffer.AsSpan(offset, count));

    public override void Write(ReadOnlySpan<byte> buffer)
    {
        ThrowIfUnusable();

        try
        {
            if (!_preambleWritten)
            {
                _preambleWritten = true;
                _out.Write(_preamble);
            }

            while (!buffer.IsEmpty)
            {
                // A full chunk with more plaintext after it is not the last.
                if (_length == StreamEncryption.ChunkSize)
                    _out.Write(_ciphertext, 0, EncryptChunk(isFinal: false));

                buffer = Take(buffer);
            }
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
            if (!_preambleWritten)
            {
                _preambleWritten = true;
                await _out.WriteAsync(_preamble, cancellationToken).ConfigureAwait(false);
            }

            while (!buffer.IsEmpty)
            {
                if (_length == StreamEncryption.ChunkSize)
                    await _out.WriteAsync(_ciphertext.AsMemory(0, EncryptChunk(isFinal: false)), cancellationToken).ConfigureAwait(false);

                var rest = Take(buffer.Span);
                buffer = buffer[(buffer.Length - rest.Length)..];
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

    private ReadOnlySpan<byte> Take(ReadOnlySpan<byte> buffer)
    {
        var take = Math.Min(StreamEncryption.ChunkSize - _length, buffer.Length);
        buffer[..take].CopyTo(_plaintext.AsSpan(_length));
        _length += take;
        return buffer[take..];
    }

    // Encrypts the held plaintext into _ciphertext and returns its length.
    private int EncryptChunk(bool isFinal)
    {
        StreamEncryption.EncryptChunk(_cipher, _counter, isFinal, _plaintext.AsSpan(0, _length), _ciphertext);
        var length = _length + StreamEncryption.TagSize;
        _counter++;
        _length = 0;
        return length;
    }

    // Disposing finishes the file: the final chunk, then the end marker if armored. After a failed
    // write it finishes nothing and throws nothing; the failure was already reported.
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
                if (!_preambleWritten)
                    _out.Write(_preamble);

                _out.Write(_ciphertext, 0, EncryptChunk(isFinal: true));
                armor?.Finish();
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
                if (!_preambleWritten)
                    await _out.WriteAsync(_preamble).ConfigureAwait(false);

                await _out.WriteAsync(_ciphertext.AsMemory(0, EncryptChunk(isFinal: true))).ConfigureAwait(false);

                if (armor is not null)
                    await armor.FinishAsync(default).ConfigureAwait(false);
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
        armor?.Dispose();
        payloadKey.Dispose();
        CryptographicOperations.ZeroMemory(_plaintext.AsSpan(0, StreamEncryption.ChunkSize));
        ArrayPool<byte>.Shared.Return(_plaintext);
        ArrayPool<byte>.Shared.Return(_ciphertext);
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
        _out.Flush();
    }

    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _out.FlushAsync(cancellationToken);
    }

    public override int Read(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
}
