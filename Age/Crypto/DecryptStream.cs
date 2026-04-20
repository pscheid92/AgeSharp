using System.Buffers;
using System.Security.Cryptography;

namespace Age.Crypto;

internal sealed class DecryptStream(byte[] payloadKey, Stream ciphertext, bool ownsStream) : Stream
{
    private enum State
    {
        Chunks,
        Done
    }

    private const int CiphertextBufferSize = StreamEncryption.EncryptedChunkSize + 1;
    private const int PlaintextBufferSize = StreamEncryption.ChunkSize;

    private State _state = State.Chunks;

    // Chunk buffering — rented from the shared pool, reused across chunks
    private readonly byte[] _ciphertextBuffer = ArrayPool<byte>.Shared.Rent(CiphertextBufferSize);
    private readonly byte[] _plaintextBuffer = ArrayPool<byte>.Shared.Rent(PlaintextBufferSize);
    private readonly ChaCha20Poly1305 _cipher = new(payloadKey);
    private int _plaintextLength;
    private int _plaintextOffset;
    private long _counter;
    private bool _hasSavedByte;

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
            // Drain any buffered plaintext first
            if (_plaintextOffset < _plaintextLength)
            {
                var available = _plaintextLength - _plaintextOffset;
                var toCopy = Math.Min(available, buffer.Length - totalRead);
                _plaintextBuffer.AsSpan(_plaintextOffset, toCopy).CopyTo(buffer[totalRead..]);
                _plaintextOffset += toCopy;
                totalRead += toCopy;
                continue;
            }

            if (_state == State.Done)
                return totalRead;

            DecryptNextChunk();
        }

        return totalRead;
    }

    private void DecryptNextChunk()
    {
        var prevPlaintextLength = _plaintextLength;
        var bytesRead = ReadFromCiphertext();

        switch (bytesRead)
        {
            case 0 when _counter == 0:
                throw new AgePayloadException("payload is empty (no chunks)");
            case 0 when _counter > 0:
                throw new AgePayloadException("payload ended without a final chunk");
        }

        var isFinal = bytesRead <= StreamEncryption.EncryptedChunkSize;
        var chunkLen = Math.Min(bytesRead, StreamEncryption.EncryptedChunkSize);

        if (chunkLen < StreamEncryption.TagSize)
            throw new AgePayloadException("chunk too small for authentication tag");

        // Save the look-ahead byte before decryption (it sits just past the chunk in the buffer)
        byte savedByte = 0;
        if (!isFinal)
            savedByte = _ciphertextBuffer[StreamEncryption.EncryptedChunkSize];

        StreamEncryption.DecryptChunk(
            _cipher, _counter, isFinal,
            _ciphertextBuffer.AsSpan(0, chunkLen),
            _plaintextBuffer);
        _plaintextLength = chunkLen - StreamEncryption.TagSize;
        _plaintextOffset = 0;

        // If the new chunk is smaller than the previous one, zero the residual
        // tail so stale plaintext from the prior chunk doesn't linger.
        if (prevPlaintextLength > _plaintextLength)
            CryptographicOperations.ZeroMemory(
                _plaintextBuffer.AsSpan(_plaintextLength, prevPlaintextLength - _plaintextLength));

        if (!isFinal)
        {
            _ciphertextBuffer[0] = savedByte;
            _hasSavedByte = true;
        }

        _counter++;

        if (!isFinal)
            return;

        // The final chunk can be empty ONLY if it's the first (and only) chunk
        if (_plaintextLength == 0 && _counter > 1)
            throw new AgePayloadException("final STREAM chunk is empty but there were preceding chunks");

        _state = State.Done;
    }

    private int ReadFromCiphertext()
    {
        var total = 0;

        if (_hasSavedByte)
        {
            // _ciphertextBuffer[0] already contains the saved byte
            total = 1;
            _hasSavedByte = false;
        }

        const int target = StreamEncryption.EncryptedChunkSize + 1;
        while (total < target)
        {
            var read = ciphertext.Read(_ciphertextBuffer, total, target - total);

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
            ArrayPool<byte>.Shared.Return(_ciphertextBuffer);
            ArrayPool<byte>.Shared.Return(_plaintextBuffer);
            if (ownsStream) ciphertext.Dispose();
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
