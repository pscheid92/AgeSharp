using System.Security.Cryptography;

namespace Age.Crypto;

internal sealed class EncryptStream : Stream
{
    private readonly byte[] _headerBytes;
    private readonly byte[] _payloadNonce;
    private readonly byte[] _payloadKey;
    private readonly Stream _plaintext;

    private enum State { Header, Nonce, Chunks, Done }
    private State _state = State.Header;
    private int _headerOffset;
    private int _nonceOffset;

    // Chunk buffering
    private byte[]? _currentChunk;
    private int _chunkOffset;
    private long _counter;
    private bool _emittedFinal;
    private bool _pendingByte;

    // Buffer for reading plaintext chunks (one extra byte for EOF detection)
    private readonly byte[] _plaintextBuffer = new byte[StreamEncryption.ChunkSize + 1];

    public EncryptStream(byte[] headerBytes, byte[] payloadNonce, byte[] payloadKey, Stream plaintext)
    {
        _headerBytes = headerBytes;
        _payloadNonce = payloadNonce;
        _payloadKey = payloadKey;
        _plaintext = plaintext;
    }

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
        int totalRead = 0;

        while (totalRead < buffer.Length)
        {
            int copied;
            switch (_state)
            {
                case State.Header:
                    copied = CopyFromBuffer(_headerBytes, ref _headerOffset, buffer[totalRead..]);
                    totalRead += copied;
                    if (_headerOffset >= _headerBytes.Length)
                        _state = State.Nonce;
                    break;

                case State.Nonce:
                    copied = CopyFromBuffer(_payloadNonce, ref _nonceOffset, buffer[totalRead..]);
                    totalRead += copied;
                    if (_nonceOffset >= _payloadNonce.Length)
                        _state = State.Chunks;
                    break;

                case State.Chunks:
                    if (_currentChunk != null && _chunkOffset < _currentChunk.Length)
                    {
                        copied = CopyFromBuffer(_currentChunk, ref _chunkOffset, buffer[totalRead..]);
                        totalRead += copied;
                        break;
                    }

                    if (_emittedFinal)
                    {
                        _state = State.Done;
                        return totalRead;
                    }

                    // Read next plaintext chunk + 1 extra byte for EOF detection
                    int bytesRead = ReadFromPlaintext(_plaintextBuffer, StreamEncryption.ChunkSize + 1);
                    bool isFinal = bytesRead <= StreamEncryption.ChunkSize;
                    int chunkLen = Math.Min(bytesRead, StreamEncryption.ChunkSize);

                    _currentChunk = StreamEncryption.EncryptChunk(
                        _payloadKey, _counter, isFinal,
                        _plaintextBuffer.AsSpan(0, chunkLen));
                    _chunkOffset = 0;
                    _counter++;

                    if (isFinal)
                    {
                        _emittedFinal = true;
                    }
                    else
                    {
                        // We read ChunkSize+1 bytes. Save the extra byte by
                        // putting it back at the start of the buffer for next read.
                        _plaintextBuffer[0] = _plaintextBuffer[StreamEncryption.ChunkSize];
                        _pendingByte = true;
                    }
                    break;

                case State.Done:
                    return totalRead;
            }
        }

        return totalRead;
    }

    private static int CopyFromBuffer(byte[] source, ref int sourceOffset, Span<byte> dest)
    {
        int available = source.Length - sourceOffset;
        int toCopy = Math.Min(available, dest.Length);
        source.AsSpan(sourceOffset, toCopy).CopyTo(dest);
        sourceOffset += toCopy;
        return toCopy;
    }

    private int ReadFromPlaintext(byte[] buffer, int count)
    {
        int total = 0;
        if (_pendingByte)
        {
            // buffer[0] already contains the pending byte
            total = 1;
            _pendingByte = false;
        }
        while (total < count)
        {
            int read = _plaintext.Read(buffer, total, count - total);
            if (read == 0) break;
            total += read;
        }
        return total;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            CryptographicOperations.ZeroMemory(_payloadKey);
        }
        base.Dispose(disposing);
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
