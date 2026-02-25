using Age.Format;

namespace Age;

public sealed class AgeHeader
{
    public int RecipientCount { get; }
    public IReadOnlyList<Stanza> Recipients { get; }
    public long PayloadOffset { get; }
    public bool IsArmored { get; }

    private AgeHeader(IReadOnlyList<Stanza> recipients, long payloadOffset, bool isArmored)
    {
        RecipientCount = recipients.Count;
        Recipients = recipients;
        PayloadOffset = payloadOffset;
        IsArmored = isArmored;
    }

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
            catch (FormatException ex)
            {
                throw new AgeHeaderException($"header parse error: {ex.Message}", ex);
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