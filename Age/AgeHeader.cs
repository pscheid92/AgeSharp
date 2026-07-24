
namespace AgeSharp;

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
    /// Parses the header of an age file (binary, or armored when the stream is
    /// seekable) without decrypting it. Reads from the current position and
    /// leaves the stream positioned wherever header reading stopped.
    /// </summary>
    /// <param name="input">The age-encrypted source.</param>
    /// <exception cref="AgeFormatException">The header is malformed or exceeds <see cref="AgeLimits"/>.</exception>
    /// <exception cref="AgeFormatException">The input is armored and the armor is malformed.</exception>
    public static AgeHeader Parse(Stream input)
    {
        var isArmored = false;
        Stream binaryInput;
        var needsDispose = false;

        if (input.CanSeek && AsciiArmor.IsArmored(input))
        {
            isArmored = true;
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
            catch (AgeFormatException ex)
            {
                throw new AgeFormatException($"header parse error: {ex.Message}", ex);
            }

            var payloadOffset = reader.RawBytes.Length;
            return new AgeHeader(header.Stanzas.AsReadOnly(), payloadOffset, isArmored);
        }
        finally
        {
            if (needsDispose)
                binaryInput.Dispose();
        }
    }
}