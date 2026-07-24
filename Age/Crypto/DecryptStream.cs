using System.Buffers;
using System.Security.Cryptography;

namespace AgeSharp.Crypto;

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
    private readonly IAeadCipher _cipher = AeadCipher.Create(payloadKey);
    private int _plaintextLength;
    private int _plaintextOffset;
    private long _counter;
    private bool _hasSavedByte;
    private bool _disposed;

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
            if (TryDrain(buffer[totalRead..], ref totalRead))
                continue;

            if (_state == State.Done)
                return totalRead;

            ProcessChunk(ReadFromCiphertext());
        }

        return totalRead;
    }

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
        => ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken = default)
    {
        var totalRead = 0;

        while (totalRead < buffer.Length)
        {
            if (TryDrain(buffer.Span[totalRead..], ref totalRead))
                continue;

            if (_state == State.Done)
                return totalRead;

            ProcessChunk(await ReadFromCiphertextAsync(cancellationToken).ConfigureAwait(false));
        }

        return totalRead;
    }

    // Copies any buffered plaintext into dest; returns true when it did so (there
    // was buffered plaintext), false when the buffer is empty and a chunk is due.
    private bool TryDrain(Span<byte> dest, ref int totalRead)
    {
        if (_plaintextOffset >= _plaintextLength)
            return false;

        var available = _plaintextLength - _plaintextOffset;
        var toCopy = Math.Min(available, dest.Length);
        _plaintextBuffer.AsSpan(_plaintextOffset, toCopy).CopyTo(dest);
        _plaintextOffset += toCopy;
        totalRead += toCopy;

        return true;
    }

    // CPU-only: decrypt the freshly-read ciphertext chunk. Shared by the sync and
    // async read paths — only the read that produced bytesRead differs.
    private void ProcessChunk(int bytesRead)
    {
        var prevPlaintextLength = _plaintextLength;

        switch (bytesRead)
        {
            case 0 when _counter == 0:
                throw new AgeAuthenticationException("payload is empty (no chunks)");
            case 0 when _counter > 0:
                throw new AgeAuthenticationException("payload ended without a final chunk");
        }

        var isFinal = bytesRead <= StreamEncryption.EncryptedChunkSize;
        var chunkLen = Math.Min(bytesRead, StreamEncryption.EncryptedChunkSize);

        if (chunkLen < StreamEncryption.TagSize)
            throw new AgeAuthenticationException("chunk too small for authentication tag");

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
            throw new AgeAuthenticationException("final STREAM chunk is empty but there were preceding chunks");

        _state = State.Done;
    }

    private int ReadFromCiphertext()
    {
        var total = TakeSavedByte();

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

    private async ValueTask<int> ReadFromCiphertextAsync(CancellationToken cancellationToken)
    {
        var total = TakeSavedByte();

        const int target = StreamEncryption.EncryptedChunkSize + 1;
        while (total < target)
        {
            var read = await ciphertext.ReadAsync(_ciphertextBuffer.AsMemory(total, target - total), cancellationToken).ConfigureAwait(false);

            if (read == 0)
                break;

            total += read;
        }

        return total;
    }

    private int TakeSavedByte()
    {
        if (!_hasSavedByte)
            return 0;

        // _ciphertextBuffer[0] already contains the saved byte
        _hasSavedByte = false;
        return 1;
    }

    protected override void Dispose(bool disposing)
    {
        if (disposing && !_disposed)
        {
            _disposed = true;
            ReleaseResources();
            if (ownsStream) ciphertext.Dispose();
        }

        base.Dispose(disposing);
    }

    public override async ValueTask DisposeAsync()
    {
        if (!_disposed)
        {
            _disposed = true;
            ReleaseResources();
            if (ownsStream) await ciphertext.DisposeAsync().ConfigureAwait(false);
        }

        await base.DisposeAsync().ConfigureAwait(false);
    }

    private void ReleaseResources()
    {
        _cipher.Dispose();
        CryptographicOperations.ZeroMemory(payloadKey);
        CryptographicOperations.ZeroMemory(_plaintextBuffer.AsSpan(0, PlaintextBufferSize));
        ArrayPool<byte>.Shared.Return(_ciphertextBuffer);
        ArrayPool<byte>.Shared.Return(_plaintextBuffer);
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
