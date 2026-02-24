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

    private static void EncryptToStream(Stream input, Stream output, ReadOnlySpan<IRecipient> recipients)
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

        try
        {
            // Build header
            var header = new Header();
            foreach (var recipient in recipients)
                header.Stanzas.Add(recipient.Wrap(fileKey));

            // Write header with MAC
            header.WriteTo(output, fileKey);

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
        finally
        {
            CryptographicOperations.ZeroMemory(fileKey);
        }
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

            try
            {
                if (fileKey.Length != 16)
                    throw new AgeHeaderException($"file key must be 16 bytes, got {fileKey.Length}");

                // Verify header MAC
                header.VerifyMac(fileKey);

                // Read 16-byte payload nonce
                var payloadNonce = new byte[16];
                int nonceRead = reader.ReadPayloadBytes(payloadNonce);
                if (nonceRead != 16)
                    throw new AgeHeaderException($"expected 16-byte payload nonce, got {nonceRead} bytes");

                // Derive payload key
                var payloadKey = CryptoHelper.HkdfDerive(fileKey, payloadNonce, "payload", 32);

                // Get remaining stream data for STREAM decrypt
                // We need to pass the remaining data from the underlying stream
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
}
