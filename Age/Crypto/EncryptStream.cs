using System.Buffers;
using System.Security.Cryptography;

namespace Age.Crypto;

internal sealed class EncryptStream(byte[] headerBytes, byte[] payloadNonce, byte[] payloadKey, Stream plaintext) : Stream
{
    private enum State
    {
        Preamble,
        Chunks,
        Done
    }

    private const int PlaintextBufferSize = StreamEncryption.ChunkSize + 1;
    private const int CiphertextBufferSize = StreamEncryption.EncryptedChunkSize;

    private State _state = State.Preamble;
    private readonly byte[] _preamble = [..headerBytes, ..payloadNonce];
    private int _preambleOffset;

    // Chunk buffering — rented from the shared pool, reused across chunks
    private readonly byte[] _plaintextBuffer = ArrayPool<byte>.Shared.Rent(PlaintextBufferSize);
    private readonly byte[] _ciphertextBuffer = ArrayPool<byte>.Shared.Rent(CiphertextBufferSize);
    private readonly ChaCha20Poly1305 _cipher = new(payloadKey);
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
        var totalRead = 0;

        while (totalRead < buffer.Length)
        {
            switch (_state)
            {
                case State.Preamble:
                    totalRead += EmitBuffer(_preamble, ref _preambleOffset, buffer[totalRead..]);
                    if (_preambleOffset >= _preamble.Length)
                        _state = State.Chunks;
                    break;

                case State.Chunks:
                    totalRead += EmitNextChunk(buffer[totalRead..]);
                    break;

                case State.Done:
                    return totalRead;

                default:
                    throw new ArgumentOutOfRangeException();
            }
        }

        return totalRead;
    }

    private int EmitNextChunk(Span<byte> dest)
    {
        if (_chunkOffset < _chunkLength)
            return EmitBuffer(_ciphertextBuffer.AsSpan(0, _chunkLength), ref _chunkOffset, dest);

        if (_emittedFinal)
        {
            _state = State.Done;
            return 0;
        }

        EncryptNextChunk();
        return EmitBuffer(_ciphertextBuffer.AsSpan(0, _chunkLength), ref _chunkOffset, dest);
    }

    private void EncryptNextChunk()
    {
        // Read ChunkSize+1 bytes: the extra byte detects EOF
        var bytesRead = ReadFromPlaintext(_plaintextBuffer, StreamEncryption.ChunkSize + 1);
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
        var total = 0;

        if (_pendingByte)
        {
            // buffer[0] already contains the pending byte
            total = 1;
            _pendingByte = false;
        }

        while (total < count)
        {
            var read = plaintext.Read(buffer, total, count - total);

            if (read == 0)
                break;

            total += read;
        }

        return total;
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

    public override long Seek(long offset, SeekOrigin origin) =>
        throw new NotSupportedException();

    public override void SetLength(long value) =>
        throw new NotSupportedException();

    public override void Write(byte[] buffer, int offset, int count) =>
        throw new NotSupportedException();
}
