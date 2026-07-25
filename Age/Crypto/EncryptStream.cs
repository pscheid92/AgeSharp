using System.Buffers;
using System.Security.Cryptography;

namespace AgeSharp.Crypto;

internal sealed class EncryptStream(byte[] headerBytes, byte[] payloadNonce, byte[] payloadKey, Stream plaintext)
    : Stream
{
    private const int PlaintextBufferSize = StreamEncryption.ChunkSize + 1;
    private const int CiphertextBufferSize = StreamEncryption.EncryptedChunkSize;
    private readonly IAeadCipher _cipher = AeadCipher.Create(payloadKey);
    private readonly byte[] _ciphertextBuffer = ArrayPool<byte>.Shared.Rent(CiphertextBufferSize);

    // Chunk buffering — rented from the shared pool, reused across chunks
    private readonly byte[] _plaintextBuffer = ArrayPool<byte>.Shared.Rent(PlaintextBufferSize);
    private readonly byte[] _preamble = [.. headerBytes, .. payloadNonce];
    private int _chunkLength;
    private int _chunkOffset;
    private long _counter;
    private bool _emittedFinal;
    private bool _pendingByte;
    private int _preambleOffset;

    private State _state = State.Preamble;

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
    {
        return Read(buffer.AsSpan(offset, count));
    }

    public override int Read(Span<byte> buffer)
    {
        var totalRead = 0;

        while (totalRead < buffer.Length)
            switch (_state)
            {
                case State.Preamble:
                    totalRead += EmitPreamble(buffer[totalRead..]);
                    break;

                case State.Chunks:
                    if (!EnsureChunkAvailable())
                        return totalRead;
                    totalRead += EmitBuffer(_ciphertextBuffer.AsSpan(0, _chunkLength), ref _chunkOffset,
                        buffer[totalRead..]);
                    break;

                case State.Done:
                    return totalRead;

                default:
                    throw new ArgumentOutOfRangeException();
            }

        return totalRead;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var totalRead = 0;

        while (totalRead < buffer.Length)
            switch (_state)
            {
                case State.Preamble:
                    totalRead += EmitPreamble(buffer.Span[totalRead..]);
                    break;

                case State.Chunks:
                    if (!await EnsureChunkAvailableAsync(cancellationToken).ConfigureAwait(false))
                        return totalRead;
                    totalRead += EmitBuffer(_ciphertextBuffer.AsSpan(0, _chunkLength), ref _chunkOffset,
                        buffer.Span[totalRead..]);
                    break;

                case State.Done:
                    return totalRead;

                default:
                    throw new ArgumentOutOfRangeException();
            }

        return totalRead;
    }

    private int EmitPreamble(Span<byte> dest)
    {
        var written = EmitBuffer(_preamble, ref _preambleOffset, dest);
        if (_preambleOffset >= _preamble.Length)
            _state = State.Chunks;

        return written;
    }

    // Ensures _ciphertextBuffer[_chunkOffset.._chunkLength] holds emittable bytes;
    // returns false once the final chunk has been fully emitted. Sync fill path.
    private bool EnsureChunkAvailable()
    {
        if (_chunkOffset < _chunkLength)
            return true;

        if (_emittedFinal)
        {
            _state = State.Done;
            return false;
        }

        EncryptChunk(ReadFromPlaintext(_plaintextBuffer, StreamEncryption.ChunkSize + 1));
        return true;
    }

    private async ValueTask<bool> EnsureChunkAvailableAsync(CancellationToken cancellationToken)
    {
        if (_chunkOffset < _chunkLength)
            return true;

        if (_emittedFinal)
        {
            _state = State.Done;
            return false;
        }

        EncryptChunk(await ReadFromPlaintextAsync(_plaintextBuffer, StreamEncryption.ChunkSize + 1, cancellationToken)
            .ConfigureAwait(false));
        return true;
    }

    // CPU-only: encrypt the freshly-read plaintext into _ciphertextBuffer. Shared
    // by the sync and async fill paths — only the read above differs.
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
            // Save the look-ahead byte for the next read
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

    private int ReadFromPlaintext(byte[] buffer, int count)
    {
        var total = TakePendingByte();

        while (total < count)
        {
            var read = plaintext.Read(buffer, total, count - total);

            if (read == 0)
                break;

            total += read;
        }

        return total;
    }

    private async ValueTask<int> ReadFromPlaintextAsync(byte[] buffer, int count, CancellationToken cancellationToken)
    {
        var total = TakePendingByte();

        while (total < count)
        {
            var read = await plaintext.ReadAsync(buffer.AsMemory(total, count - total), cancellationToken)
                .ConfigureAwait(false);

            if (read == 0)
                break;

            total += read;
        }

        return total;
    }

    private int TakePendingByte()
    {
        if (!_pendingByte)
            return 0;

        // buffer[0] already contains the pending byte
        _pendingByte = false;
        return 1;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _cipher.Dispose();
            CryptographicOperations.ZeroMemory(payloadKey);
            CryptographicOperations.ZeroMemory(_plaintextBuffer.AsSpan(0, PlaintextBufferSize));
            ArrayPool<byte>.Shared.Return(_plaintextBuffer);
            ArrayPool<byte>.Shared.Return(_ciphertextBuffer);
        }

        base.Dispose(disposing);
    }

    public override void Flush()
    {
    }

    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }

    public override void Write(byte[] buffer, int offset, int count)
    {
        throw new NotSupportedException();
    }

    private enum State
    {
        Preamble,
        Chunks,
        Done
    }
}