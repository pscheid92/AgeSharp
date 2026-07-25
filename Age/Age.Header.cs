using System.Security.Cryptography;
using AgeSharp.Crypto;

namespace AgeSharp;

// The header half of the facade: building one from recipients, taking one apart with
// identities, and the argument validation every entry point funnels through. Age.cs is
// dispatch; this is the work.
public static partial class Age
{
    private static T[] Materialize<T>(IReadOnlyList<T> items, string paramName, string noun)
    {
        ArgumentNullException.ThrowIfNull(items, paramName);

        if (items.Count == 0)
            throw new ArgumentException($"at least one {noun} is required", paramName);

        var array = items as T[] ?? [.. items];

        for (var i = 0; i < array.Length; i++)
            if (array[i] is null)
                throw new ArgumentException($"{noun} at index {i} is null", paramName);

        return array;
    }

    private static (IReadOnlyList<Stanza> stanzas, IReadOnlyCollection<string> labels) WrapWithLabels(
        IRecipient recipient, ReadOnlySpan<byte> fileKey)
    {
        if (recipient is IRecipientWithLabels labelled)
            return labelled.WrapWithLabels(fileKey);

        return (recipient.Wrap(fileKey), []);
    }

    private static bool LabelSetsEqual(IReadOnlyCollection<string> a, IReadOnlyCollection<string> b)
    {
        if (a.Count == 0 && b.Count == 0)
            return true;

        var set = new HashSet<string>(a, StringComparer.Ordinal);
        return set.SetEquals(b);
    }

    private static (Header header, byte[] fileKey) BuildHeaderAndFileKey(ReadOnlySpan<IRecipient> recipients)
    {
        var fileKey = new byte[FileKeySize];
        RandomNumberGenerator.Fill(fileKey);

        try
        {
            var header = new Header();

            // Labels can be dynamic, so they come from the wrap, not a property. Compared unordered.
            IReadOnlyCollection<string>? firstLabels = null;

            for (var i = 0; i < recipients.Length; i++)
            {
                var (stanzas, labels) = WrapWithLabels(recipients[i], fileKey);

                if (stanzas is null || stanzas.Count == 0)
                    throw new AgeException($"recipient at index {i} produced no stanzas");

                if (i == 0)
                    firstLabels = labels;
                else if (!LabelSetsEqual(firstLabels!, labels))
                    throw new AgeException("cannot mix recipients with different security labels");

                foreach (var stanza in stanzas)
                    header.Stanzas.Add(stanza);
            }

            if (header.Stanzas.Count > 1 && header.Stanzas.Any(s => s.Type == "scrypt"))
                throw new AgeException("a passphrase (scrypt) recipient must be the only recipient");

            return (header, fileKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(fileKey);
            throw;
        }
    }

    private static byte[] UnwrapFileKey(Stream headerInput, ReadOnlySpan<IIdentity> identities,
        AgeDecryptOptions options)
    {
        var (fileKey, _) = UnwrapHeaderFromReader(headerInput, identities, options);
        return fileKey;
    }

    private static (byte[] fileKey, HeaderReader reader) UnwrapHeaderFromReader(Stream binaryInput, ReadOnlySpan<IIdentity> identities, AgeDecryptOptions options)
    {
        var reader = new HeaderReader(binaryInput, options.MaxHeaderLineBytes, options.MaxHeaderBytes);
        var fileKey = UnwrapHeader(reader, identities);
        return (fileKey, reader);
    }

    internal static byte[] UnwrapHeader(HeaderReader reader, ReadOnlySpan<IIdentity> identities)
    {
        var header = ParseHeader(reader);

        var hasScrypt = header.Stanzas.Any(s => s.Type == "scrypt");
        if (hasScrypt && header.Stanzas.Count > 1)
            throw new AgeFormatException("scrypt stanza must be the only stanza in the header");

        // Batch: the plugin protocol needs the whole stanza list.
        byte[]? fileKey = null;
        foreach (var identity in identities)
        {
            fileKey = identity.Unwrap(header.Stanzas);
            if (fileKey is not null)
                break;
        }

        if (fileKey is null)
            throw new NoIdentityMatchException();

        try
        {
            if (fileKey.Length != FileKeySize)
                throw new AgeFormatException($"file key must be {FileKeySize} bytes, got {fileKey.Length}");

            header.VerifyMac(fileKey);
        }
        catch
        {
            CryptographicOperations.ZeroMemory(fileKey);
            throw;
        }

        return fileKey;
    }

    private static (Stream binaryInput, bool needsDispose) DeArmorIfNeeded(Stream input, AgeDecryptOptions options)
    {
        var (source, isArmored) = AsciiArmor.Detect(input, options.RequireArmor);

        return isArmored
            ? (AsciiArmor.Dearmor(source, options.MaxArmorLineBytes), true)
            : (source, false);
    }

    private static byte[] ReadPayloadNonce(HeaderReader reader)
    {
        var payloadNonce = new byte[PayloadNonceSize];
        var bytesRead = reader.ReadPayloadBytes(payloadNonce);

        return bytesRead == PayloadNonceSize
            ? payloadNonce
            : throw new AgeFormatException($"expected {PayloadNonceSize}-byte payload nonce, got {bytesRead} bytes");
    }

    private static Header ParseHeader(HeaderReader reader)
    {
        try
        {
            return Header.Parse(reader);
        }
        catch (AgeFormatException ex)
        {
            throw new AgeFormatException($"header parse error: {ex.Message}", ex);
        }
    }
}
