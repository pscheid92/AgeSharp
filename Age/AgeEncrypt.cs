using System.Security.Cryptography;
using Age.Crypto;
using Age.Format;
using Age.Recipients;

namespace Age;

public static class AgeEncrypt
{
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

    public static void EncryptDetached(
        Stream input, Stream headerOutput, Stream payloadOutput,
        params ReadOnlySpan<IRecipient> recipients)
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

    public static void DecryptDetached(
        Stream headerInput, Stream payloadInput, Stream output,
        params ReadOnlySpan<IIdentity> identities)
    {
        var (fileKey, _) = UnwrapHeader(headerInput, identities);
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
            // For armored, we need the full ciphertext to base64-encode, so buffer eagerly
            using var buffer = new MemoryStream();
            EncryptToStream(plaintext, buffer, recipients);
            buffer.Position = 0;
            var armoredBuffer = new MemoryStream();
            AsciiArmor.Armor(buffer, armoredBuffer);
            armoredBuffer.Position = 0;
            return armoredBuffer;
        }

        var (header, fileKey) = BuildHeaderAndFileKey(recipients);

        // Serialize header eagerly into a byte array
        using var headerMs = new MemoryStream();
        header.WriteTo(headerMs, fileKey);
        var headerBytes = headerMs.ToArray();

        // Generate payload nonce eagerly
        var payloadNonce = new byte[16];
        RandomNumberGenerator.Fill(payloadNonce);
        var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", 32);
        CryptographicOperations.ZeroMemory(fileKey);

        return new EncryptStream(headerBytes, payloadNonce, payloadKey, plaintext);
    }

    public static Stream DecryptReader(Stream ciphertext, params ReadOnlySpan<IIdentity> identities)
    {
        // Detect and handle ASCII armor
        Stream binaryInput;
        bool needsDispose = false;
        if (ciphertext.CanSeek && AsciiArmor.IsArmored(ciphertext))
        {
            binaryInput = AsciiArmor.Dearmor(ciphertext);
            needsDispose = true;
        }
        else
        {
            binaryInput = ciphertext;
        }

        try
        {
            var (fileKey, reader) = UnwrapHeaderFromReader(binaryInput, identities);

            // Read 16-byte payload nonce
            var payloadNonce = new byte[16];
            int nonceRead = reader.ReadPayloadBytes(payloadNonce);
            if (nonceRead != 16)
                throw new AgeHeaderException($"expected 16-byte payload nonce, got {nonceRead} bytes");

            var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", 32);
            CryptographicOperations.ZeroMemory(fileKey);

            return new DecryptStream(payloadKey, binaryInput, needsDispose);
        }
        catch
        {
            if (needsDispose) binaryInput.Dispose();
            throw;
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

    internal static (Header header, byte[] fileKey) BuildHeaderAndFileKey(ReadOnlySpan<IRecipient> recipients)
    {
        // Check label consistency — reject mixing PQ and non-PQ recipients
        string? firstLabel = recipients[0].Label;
        for (int i = 1; i < recipients.Length; i++)
        {
            if (recipients[i].Label != firstLabel)
                throw new AgeException("cannot mix recipients with different security labels");
        }

        // Generate random 16-byte file key
        var fileKey = new byte[16];
        RandomNumberGenerator.Fill(fileKey);

        // Build header
        var header = new Header();
        foreach (var recipient in recipients)
            header.Stanzas.Add(recipient.Wrap(fileKey));

        return (header, fileKey);
    }

    internal static void WritePayload(ReadOnlySpan<byte> fileKey, Stream input, Stream output)
    {
        // Generate 16-byte payload nonce
        var payloadNonce = new byte[16];
        RandomNumberGenerator.Fill(payloadNonce);
        output.Write(payloadNonce);

        // Derive payload key: HKDF-SHA-256(ikm=fileKey, salt=payloadNonce, info="payload")
        var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", 32);

        // STREAM encrypt
        StreamEncryption.Encrypt(payloadKey, input, output);

        CryptographicOperations.ZeroMemory(payloadKey);
    }

    public static void Decrypt(Stream input, Stream output, params ReadOnlySpan<IIdentity> identities)
    {
        // Detect and handle ASCII armor
        Stream binaryInput;
        bool needsDispose = false;
        if (input.CanSeek && AsciiArmor.IsArmored(input))
        {
            binaryInput = AsciiArmor.Dearmor(input);
            needsDispose = true;
        }
        else
        {
            binaryInput = input;
        }

        try
        {
            var (fileKey, reader) = UnwrapHeaderFromReader(binaryInput, identities);
            try
            {
                // Read 16-byte payload nonce
                var payloadNonce = new byte[16];
                int nonceRead = reader.ReadPayloadBytes(payloadNonce);
                if (nonceRead != 16)
                    throw new AgeHeaderException($"expected 16-byte payload nonce, got {nonceRead} bytes");

                // Derive payload key
                var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", 32);

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

    internal static (byte[] fileKey, Header header) UnwrapHeader(
        Stream headerInput, ReadOnlySpan<IIdentity> identities)
    {
        var (fileKey, _) = UnwrapHeaderFromReader(headerInput, identities);
        return (fileKey, null!); // header not needed by callers of this overload
    }

    internal static (byte[] fileKey, HeaderReader reader) UnwrapHeaderFromReader(
        Stream binaryInput, ReadOnlySpan<IIdentity> identities)
    {
        var reader = new HeaderReader(binaryInput);
        Header header;
        try
        {
            header = Header.Parse(reader);
        }
        catch (AgeHeaderException)
        {
            throw;
        }
        catch (FormatException ex)
        {
            throw new AgeHeaderException($"header parse error: {ex.Message}", ex);
        }

        // Check scrypt constraint: if any stanza is scrypt, it must be the only one
        bool hasScrypt = header.Stanzas.Any(s => s.Type == "scrypt");
        if (hasScrypt && header.Stanzas.Count > 1)
            throw new AgeHeaderException("scrypt stanza must be the only stanza in the header");

        // Try each identity against all stanzas (batch unwrap supports plugin protocol)
        byte[]? fileKey = null;
        foreach (var identity in identities)
        {
            try
            {
                fileKey = identity.Unwrap(header.Stanzas);
                if (fileKey is not null) break;
            }
            catch (AgeException)
            {
                throw;
            }
        }

        if (fileKey is null)
            throw new NoIdentityMatchException();

        if (fileKey.Length != 16)
            throw new AgeHeaderException($"file key must be 16 bytes, got {fileKey.Length}");

        // Verify header MAC
        header.VerifyMac(fileKey);

        return (fileKey, reader);
    }

    internal static void DecryptPayload(ReadOnlySpan<byte> fileKey, Stream payloadInput, Stream output)
    {
        // Read 16-byte payload nonce
        var payloadNonce = new byte[16];
        int total = 0;
        while (total < 16)
        {
            int read = payloadInput.Read(payloadNonce.AsSpan(total));
            if (read == 0) break;
            total += read;
        }
        if (total != 16)
            throw new AgeHeaderException($"expected 16-byte payload nonce, got {total} bytes");

        // Derive payload key
        var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", 32);

        StreamEncryption.Decrypt(payloadKey, payloadInput, output);

        CryptographicOperations.ZeroMemory(payloadKey);
    }
}
