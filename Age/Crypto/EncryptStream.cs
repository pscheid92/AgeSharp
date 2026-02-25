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

    private State _state = State.Preamble;
    private readonly byte[] _preamble = [..headerBytes, ..payloadNonce];
    private int _preambleOffset;

    // Chunk buffering
    private byte[]? _currentChunk;
    private int _chunkOffset;
    private long _counter;
    private bool _emittedFinal;
    private bool _pendingByte;

    // Buffer for reading plaintext chunks (one extra byte for EOF detection)
    private readonly byte[] _plaintextBuffer = new byte[StreamEncryption.ChunkSize + 1];

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
        // Still draining a previously encrypted chunk
        if (_currentChunk != null && _chunkOffset < _currentChunk.Length)
            return EmitBuffer(_currentChunk, ref _chunkOffset, dest);

        if (_emittedFinal)
        {
            _state = State.Done;
            return 0;
        }

        EncryptNextChunk();
        return EmitBuffer(_currentChunk!, ref _chunkOffset, dest);
    }

    private void EncryptNextChunk()
    {
        // Read ChunkSize+1 bytes: the extra byte detects EOF
        var bytesRead = ReadFromPlaintext(_plaintextBuffer, StreamEncryption.ChunkSize + 1);
        var isFinal = bytesRead <= StreamEncryption.ChunkSize;
        var chunkLen = Math.Min(bytesRead, StreamEncryption.ChunkSize);

        _currentChunk = StreamEncryption.EncryptChunk(payloadKey, _counter, isFinal, _plaintextBuffer.AsSpan(0, chunkLen));
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

    private static int EmitBuffer(byte[] source, ref int sourceOffset, Span<byte> dest)
    {
        var available = source.Length - sourceOffset;
        var toCopy = Math.Min(available, dest.Length);

        source.AsSpan(sourceOffset, toCopy).CopyTo(dest);
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
            CryptographicOperations.ZeroMemory(payloadKey);
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