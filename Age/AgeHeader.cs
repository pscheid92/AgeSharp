namespace AgeSharp;

/// <summary>
/// The header of an age file, read without decrypting it: its stanzas, whether it was armored,
/// and where its payload starts.
/// </summary>
/// <remarks>
/// Nothing here is authenticated. The header's MAC can only be checked with the file key, which
/// takes an identity, so the stanzas are as the file presents them: fit for showing who a file
/// is addressed to, not for trusting that it is.
/// </remarks>
public sealed class AgeHeader
{
    private AgeHeader(IReadOnlyList<Stanza> stanzas, bool isArmored, long? payloadOffset)
    {
        Stanzas = stanzas;
        IsArmored = isArmored;
        PayloadOffset = payloadOffset;
    }

    /// <summary>The recipient stanzas, in the order the file holds them.</summary>
    public IReadOnlyList<Stanza> Stanzas { get; }

    /// <summary>Whether the file is ASCII-armored.</summary>
    public bool IsArmored { get; }

    /// <summary>
    /// Where the payload starts (its nonce), counted in bytes from where reading began. Null for
    /// an armored file: the offset would count decoded bytes, which are no position in the file
    /// as stored.
    /// </summary>
    public long? PayloadOffset { get; }

    /// <summary>
    /// Reads the header of an age file, binary or armored, from the stream's position, without
    /// decrypting anything. A binary file's stream is left where the header ends, at the payload,
    /// on any stream; armor is read as far as its lines run. The stream stays open.
    /// </summary>
    /// <exception cref="AgeHeaderException">The header is malformed, or breaks a limit in <paramref name="options"/>.</exception>
    /// <exception cref="AgeArmorException">The armor is malformed, or armor is required and absent.</exception>
    public static AgeHeader Read(Stream input, AgeDecryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(input);
        options ??= AgeDecryptOptions.Default;

        // A look-ahead or a dearmoring wrapper: ours to dispose, and neither disposes the caller's stream.
        var (binary, isArmored) = AsciiArmor.Open(input, options);

        using (binary)
        {
            var reader = new HeaderReader(binary, options);
            return From(Identities.ParseHeader(reader), isArmored, reader);
        }
    }

    /// <summary>The asynchronous <see cref="Read"/>: every read of <paramref name="input"/> is asynchronous.</summary>
    /// <exception cref="AgeHeaderException">The header is malformed, or breaks a limit in <paramref name="options"/>.</exception>
    /// <exception cref="AgeArmorException">The armor is malformed, or armor is required and absent.</exception>
    public static async ValueTask<AgeHeader> ReadAsync(Stream input, AgeDecryptOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(input);
        options ??= AgeDecryptOptions.Default;

        var (binary, isArmored) = await AsciiArmor.OpenAsync(input, options, cancellationToken).ConfigureAwait(false);

        await using (binary.ConfigureAwait(false))
        {
            var reader = new HeaderReader(binary, options);
            await reader.PrefillAsync(cancellationToken).ConfigureAwait(false);
            return From(Identities.ParseHeader(reader), isArmored, reader);
        }
    }

    private static AgeHeader From(Header header, bool isArmored, HeaderReader reader) =>
        new(header.Stanzas.AsReadOnly(), isArmored, isArmored ? null : reader.RawBytes.Length);
}
