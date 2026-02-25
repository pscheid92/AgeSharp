using System.Security.Cryptography;

namespace Age.Crypto;

internal sealed class DecryptStream(byte[] payloadKey, Stream ciphertext, bool ownsStream) : Stream
{
    private enum State
    {
        Chunks,
        Done
    }

    private State _state = State.Chunks;

    // Chunk buffering
    private byte[]? _currentPlaintext;
    private int _plaintextOffset;
    private long _counter;

    // Buffer for reading ciphertext chunks (one extra byte for EOF detection)
    private readonly byte[] _ciphertextBuffer = new byte[StreamEncryption.EncryptedChunkSize + 1];
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
            if (_currentPlaintext != null && _plaintextOffset < _currentPlaintext.Length)
            {
                totalRead += EmitBuffer(_currentPlaintext, ref _plaintextOffset, buffer[totalRead..]);
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

        // Save the look-ahead byte before decryption (which reads from the same buffer)
        byte savedByte = 0;
        if (!isFinal)
            savedByte = _ciphertextBuffer[StreamEncryption.EncryptedChunkSize];

        _currentPlaintext = StreamEncryption.DecryptChunk(payloadKey, _counter, isFinal, _ciphertextBuffer.AsSpan(0, chunkLen));
        if (!isFinal)
        {
            _ciphertextBuffer[0] = savedByte;
            _hasSavedByte = true;
        }

        _plaintextOffset = 0;
        _counter++;

        if (!isFinal)
            return;

        // The final chunk can be empty ONLY if it's the first (and only) chunk
        if (_currentPlaintext.Length == 0 && _counter > 1)
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

    private static int EmitBuffer(byte[] source, ref int sourceOffset, Span<byte> dest)
    {
        var available = source.Length - sourceOffset;
        var toCopy = Math.Min(available, dest.Length);

        source.AsSpan(sourceOffset, toCopy).CopyTo(dest);
        sourceOffset += toCopy;

        return toCopy;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            CryptographicOperations.ZeroMemory(payloadKey);
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