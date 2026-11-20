using Age.Format;

namespace Age;

/// <summary>
/// The parsed header of an age file: its recipient stanzas and layout facts.
/// Obtained via <see cref="Parse"/> without decrypting (and without verifying
/// the header MAC, which requires an identity).
/// </summary>
public sealed class AgeHeader
{
    /// <summary>Number of recipient stanzas; equal to <c>Recipients.Count</c>.</summary>
    public int RecipientCount { get; }

    /// <summary>The recipient stanzas, in file order.</summary>
    public IReadOnlyList<Stanza> Recipients { get; }

    /// <summary>
    /// Offset of the first payload byte (the payload nonce) in the <em>binary</em>
    /// age encoding. For a binary file this is a file offset; when
    /// <see cref="IsArmored"/> is true it refers to the dearmored byte stream,
    /// not the armored file.
    /// </summary>
    public long PayloadOffset { get; }

    /// <summary>Whether the input was wrapped in ASCII armor.</summary>
    public bool IsArmored { get; }

    private AgeHeader(IReadOnlyList<Stanza> recipients, long payloadOffset, bool isArmored)
    {
        RecipientCount = recipients.Count;
        Recipients = recipients;
        PayloadOffset = payloadOffset;
        IsArmored = isArmored;
    }

    /// <summary>
    /// Parses the header of an age file, binary or armored, without decrypting it. Reads from
    /// the current position. For a binary file, the stream is left where the header ends, at
    /// the payload, on any stream; armor is read further, as far as its lines run.
    /// </summary>
    /// <param name="input">The age-encrypted source.</param>
    /// <exception cref="AgeHeaderException">The header is malformed or exceeds <see cref="AgeLimits"/>.</exception>
    /// <exception cref="AgeArmorException">The input is armored and the armor is malformed.</exception>
    public static AgeHeader Parse(Stream input)
    {
        // The binary input is a look-ahead or a dearmoring wrapper: ours to dispose, and neither
        // disposes the caller's stream.
        var (binary, isArmored) = AsciiArmor.Open(input);
        using var _ = binary;
        var reader = new HeaderReader(binary);

        Header header;
        try
        {
            header = Header.Parse(reader);
        }
        catch (FormatException ex)
        {
            throw new AgeHeaderException($"header parse error: {ex.Message}", ex);
        }

        return new AgeHeader(header.Stanzas.AsReadOnly(), reader.RawBytes.Length, isArmored);
    }
}