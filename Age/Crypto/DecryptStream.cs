using System.Security.Cryptography;

namespace Age.Crypto;

internal sealed class DecryptStream : Stream
{
    private readonly byte[] _payloadKey;
    private readonly Stream _ciphertext;
    private readonly bool _ownsStream;

    // Chunk buffering
    private byte[]? _currentPlaintext;
    private int _plaintextOffset;
    private long _counter;
    private bool _done;

    // Buffer for reading ciphertext chunks
    private readonly byte[] _ciphertextBuffer = new byte[StreamEncryption.EncryptedChunkSize + 1];
    private byte _savedByte;
    private bool _hasSavedByte;

    public DecryptStream(byte[] payloadKey, Stream ciphertext, bool ownsStream)
    {
        _payloadKey = payloadKey;
        _ciphertext = ciphertext;
        _ownsStream = ownsStream;
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
            // Serve from current decrypted buffer
            if (_currentPlaintext != null && _plaintextOffset < _currentPlaintext.Length)
            {
                int available = _currentPlaintext.Length - _plaintextOffset;
                int toCopy = Math.Min(available, buffer.Length - totalRead);
                _currentPlaintext.AsSpan(_plaintextOffset, toCopy).CopyTo(buffer[totalRead..]);
                _plaintextOffset += toCopy;
                totalRead += toCopy;
                continue;
            }

            if (_done) return totalRead;

            // Read next encrypted chunk + 1 extra byte for EOF detection
            int bytesRead = ReadFromCiphertext();
            if (bytesRead == 0)
            {
                if (_counter == 0)
                    throw new AgePayloadException("payload is empty (no chunks)");
                throw new AgePayloadException("payload ended without a final chunk");
            }

            // Determine if this is the final chunk
            bool isFinal;
            int chunkLen;
            if (bytesRead <= StreamEncryption.EncryptedChunkSize)
            {
                isFinal = true;
                chunkLen = bytesRead;
            }
            else
            {
                isFinal = false;
                chunkLen = StreamEncryption.EncryptedChunkSize;
                // Save the extra byte BEFORE decryption reads from the buffer
                _savedByte = _ciphertextBuffer[StreamEncryption.EncryptedChunkSize];
                _hasSavedByte = true;
            }

            if (chunkLen < StreamEncryption.TagSize)
                throw new AgePayloadException("chunk too small for authentication tag");

            _currentPlaintext = StreamEncryption.DecryptChunk(
                _payloadKey, _counter, isFinal,
                _ciphertextBuffer.AsSpan(0, chunkLen));

            // The final chunk can be empty ONLY if it's the first (and only) chunk
            if (isFinal && _currentPlaintext.Length == 0 && _counter > 0)
                throw new AgePayloadException("final STREAM chunk is empty but there were preceding chunks");

            _plaintextOffset = 0;
            _counter++;

            if (isFinal)
                _done = true;
        }

        return totalRead;
    }

    private int ReadFromCiphertext()
    {
        int total = 0;
        if (_hasSavedByte)
        {
            _ciphertextBuffer[0] = _savedByte;
            total = 1;
            _hasSavedByte = false;
        }
        int target = StreamEncryption.EncryptedChunkSize + 1;
        while (total < target)
        {
            int read = _ciphertext.Read(_ciphertextBuffer, total, target - total);
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
            if (_ownsStream) _ciphertext.Dispose();
        }
        base.Dispose(disposing);
    }

    public override void Flush() { }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();
    public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
}
