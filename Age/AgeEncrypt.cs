using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Age.Recipients;

namespace Age;

public static class AgeEncrypt
{
    private const int FileKeySize = 16;
    private const int PayloadNonceSize = 16;
    private const int PayloadKeySize = 32;

    public static void Encrypt(Stream input, Stream output, params ReadOnlySpan<IRecipient> recipients)
        => Encrypt(input, output, false, recipients);

    public static void Encrypt(Stream input, Stream output, bool armor, params ReadOnlySpan<IRecipient> recipients)
    {
        if (recipients.Length == 0)
            throw new ArgumentException("at least one recipient is required", nameof(recipients));

        if (armor)
        {
            using var buffer = new MemoryStream();
            EncryptToStream(input, buffer, recipients);
            buffer.Position = 0;
            AsciiArmor.Armor(buffer, output);
        }
        else
        {
            EncryptToStream(input, output, recipients);
        }
    }

    public static void EncryptDetached(Stream input, Stream headerOutput, Stream payloadOutput, params ReadOnlySpan<IRecipient> recipients)
    {
        if (recipients.Length == 0)
            throw new ArgumentException("at least one recipient is required", nameof(recipients));

        var (header, fileKey) = BuildHeaderAndFileKey(recipients);
        try
        {
            header.WriteTo(headerOutput, fileKey);
            WritePayload(fileKey, input, payloadOutput);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    public static void DecryptDetached(Stream headerInput, Stream payloadInput, Stream output, params ReadOnlySpan<IIdentity> identities)
    {
        var fileKey = UnwrapFileKey(headerInput, identities);
        try
        {
            DecryptPayload(fileKey, payloadInput, output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    public static Stream EncryptReader(Stream plaintext, params ReadOnlySpan<IRecipient> recipients)
        => EncryptReader(plaintext, false, recipients);

    public static Stream EncryptReader(Stream plaintext, bool armor, params ReadOnlySpan<IRecipient> recipients)
    {
        if (recipients.Length == 0)
            throw new ArgumentException("at least one recipient is required", nameof(recipients));

        if (armor)
        {
            using var buffer = new MemoryStream();
            EncryptToStream(plaintext, buffer, recipients);
            buffer.Position = 0;
            var armoredBuffer = new MemoryStream();
            AsciiArmor.Armor(buffer, armoredBuffer);
            armoredBuffer.Position = 0;
            return armoredBuffer;
        }

        var (header, fileKey) = BuildHeaderAndFileKey(recipients);

        using var headerMs = new MemoryStream();
        header.WriteTo(headerMs, fileKey);
        var headerBytes = headerMs.ToArray();

        var payloadNonce = new byte[PayloadNonceSize];
        RandomNumberGenerator.Fill(payloadNonce);
        var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
        CryptographicOperations.ZeroMemory(fileKey);

        return new EncryptStream(headerBytes, payloadNonce, payloadKey, plaintext);
    }

    public static Stream DecryptReader(Stream ciphertext, params ReadOnlySpan<IIdentity> identities)
    {
        var (binaryInput, needsDispose) = DeArmorIfNeeded(ciphertext);

        try
        {
            var (fileKey, reader) = UnwrapHeaderFromReader(binaryInput, identities);
            var payloadNonce = ReadPayloadNonce(reader);
            var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
            CryptographicOperations.ZeroMemory(fileKey);

            return new DecryptStream(payloadKey, binaryInput, needsDispose);
        }
        catch
        {
            if (needsDispose) binaryInput.Dispose();
            throw;
        }
    }

    public static void Decrypt(Stream input, Stream output, params ReadOnlySpan<IIdentity> identities)
    {
        var (binaryInput, needsDispose) = DeArmorIfNeeded(input);

        try
        {
            var (fileKey, reader) = UnwrapHeaderFromReader(binaryInput, identities);

            try
            {
                var payloadNonce = ReadPayloadNonce(reader);
                var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);

                StreamEncryption.Decrypt(payloadKey, binaryInput, output);

                CryptographicOperations.ZeroMemory(payloadKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(fileKey);
            }
        }
        finally
        {
            if (needsDispose) binaryInput.Dispose();
        }
    }

    private static void EncryptToStream(Stream input, Stream output, ReadOnlySpan<IRecipient> recipients)
    {
        var (header, fileKey) = BuildHeaderAndFileKey(recipients);

        try
        {
            header.WriteTo(output, fileKey);
            WritePayload(fileKey, input, output);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
    }

    private static (Header header, byte[] fileKey) BuildHeaderAndFileKey(ReadOnlySpan<IRecipient> recipients)
    {
        // Check label consistency — reject mixing PQ and non-PQ recipients
        var firstLabel = recipients[0].Label;

        for (var i = 1; i < recipients.Length; i++)
        {
            if (recipients[i].Label != firstLabel)
                throw new AgeException("cannot mix recipients with different security labels");
        }

        var fileKey = new byte[FileKeySize];
        RandomNumberGenerator.Fill(fileKey);

        var header = new Header();

        foreach (var recipient in recipients)
            header.Stanzas.Add(recipient.Wrap(fileKey));

        return (header, fileKey);
    }

    private static void WritePayload(ReadOnlySpan<byte> fileKey, Stream input, Stream output)
    {
        var payloadNonce = new byte[PayloadNonceSize];
        RandomNumberGenerator.Fill(payloadNonce);
        output.Write(payloadNonce);

        var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
        StreamEncryption.Encrypt(payloadKey, input, output);
        CryptographicOperations.ZeroMemory(payloadKey);
    }

    private static byte[] UnwrapFileKey(Stream headerInput, ReadOnlySpan<IIdentity> identities)
    {
        var (fileKey, _) = UnwrapHeaderFromReader(headerInput, identities);
        return fileKey;
    }

    internal static (byte[] fileKey, HeaderReader reader) UnwrapHeaderFromReader(Stream binaryInput, ReadOnlySpan<IIdentity> identities)
    {
        var reader = new HeaderReader(binaryInput);
        var header = ParseHeader(reader);

        // Check scrypt constraint: if any stanza is scrypt, it must be the only one
        var hasScrypt = header.Stanzas.Any(s => s.Type == "scrypt");
        if (hasScrypt && header.Stanzas.Count > 1)
            throw new AgeHeaderException("scrypt stanza must be the only stanza in the header");

        // Try each identity against all stanzas (batch unwrap supports plugin protocol)
        byte[]? fileKey = null;
        foreach (var identity in identities)
        {
            fileKey = identity.Unwrap(header.Stanzas);
            if (fileKey is not null)
                break;
        }

        if (fileKey is null)
            throw new NoIdentityMatchException();

        if (fileKey.Length != FileKeySize)
            throw new AgeHeaderException($"file key must be {FileKeySize} bytes, got {fileKey.Length}");

        header.VerifyMac(fileKey);
        return (fileKey, reader);
    }

    private static void DecryptPayload(ReadOnlySpan<byte> fileKey, Stream payloadInput, Stream output)
    {
        var payloadNonce = new byte[PayloadNonceSize];
        var total = 0;

        while (total < PayloadNonceSize)
        {
            var read = payloadInput.Read(payloadNonce.AsSpan(total));
            if (read == 0)
                break;

            total += read;
        }

        if (total != PayloadNonceSize)
            throw new AgeHeaderException($"expected {PayloadNonceSize}-byte payload nonce, got {total} bytes");

        var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", PayloadKeySize);
        StreamEncryption.Decrypt(payloadKey, payloadInput, output);
        CryptographicOperations.ZeroMemory(payloadKey);
    }

    private static (Stream binaryInput, bool needsDispose) DeArmorIfNeeded(Stream input)
    {
        if (input.CanSeek && AsciiArmor.IsArmored(input))
            return (AsciiArmor.Dearmor(input), true);

        return (input, false);
    }

    private static byte[] ReadPayloadNonce(HeaderReader reader)
    {
        var payloadNonce = new byte[PayloadNonceSize];
        var bytesRead = reader.ReadPayloadBytes(payloadNonce);

        return bytesRead == PayloadNonceSize
            ? payloadNonce
            : throw new AgeHeaderException($"expected {PayloadNonceSize}-byte payload nonce, got {bytesRead} bytes");
    }

    private static Header ParseHeader(HeaderReader reader)
    {
        try
        {
            return Header.Parse(reader);
        }
        catch (FormatException ex)
        {
            throw new AgeHeaderException($"header parse error: {ex.Message}", ex);
        }
    }
}