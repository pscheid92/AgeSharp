namespace AgeSharp;

/// <summary>
///     The parsed header of an age file: its recipient stanzas and layout facts.
///     Obtained via <see cref="Age.ReadHeader" /> without decrypting (and without
///     verifying the header MAC, which requires an identity).
/// </summary>
public sealed class AgeHeader
{
    private AgeHeader(IReadOnlyList<Stanza> stanzas, long? payloadOffset, bool isArmored)
    {
        Stanzas = stanzas;
        PayloadOffset = payloadOffset;
        IsArmored = isArmored;
    }

    /// <summary>The recipient stanzas, in file order.</summary>
    public IReadOnlyList<Stanza> Stanzas { get; }

    /// <summary>
    ///     Offset of the first payload byte — the payload nonce — in the source, or
    ///     <see langword="null" /> when <see cref="IsArmored" /> is true.
    /// </summary>
    /// <remarks>
    ///     Null for armored input rather than an offset into the dearmored stream: the caller
    ///     holds the armored file, so an offset into bytes it never sees would seek to the wrong
    ///     place. Splitting an armored file at its header means dearmoring it first.
    /// </remarks>
    public long? PayloadOffset { get; }

    /// <summary>Whether the input was wrapped in ASCII armor.</summary>
    public bool IsArmored { get; }

    internal static AgeHeader Parse(Stream input, AgeDecryptOptions options)
    {
        // The dearmor wrapper is disposed below; `input` itself never is.
        var (source, isArmored) = AsciiArmor.Detect(input, options.RequireArmor);
        var binaryInput = isArmored ? AsciiArmor.Dearmor(source, options.MaxArmorLineBytes) : source;

        try
        {
            return FromReader(new HeaderReader(binaryInput, options.MaxHeaderLineBytes, options.MaxHeaderBytes),
                              isArmored);
        }
        finally
        {
            if (isArmored)
                binaryInput.Dispose();
        }
    }

    internal static async ValueTask<AgeHeader> ParseAsync(Stream input, AgeDecryptOptions options,
                                                          CancellationToken cancellationToken)
    {
        var (source, isArmored) =
            await AsciiArmor.DetectAsync(input, options.RequireArmor, cancellationToken).ConfigureAwait(false);

        var binaryInput = isArmored
            ? await AsciiArmor.DearmorAsync(source, options.MaxArmorLineBytes, cancellationToken).ConfigureAwait(false)
            : source;

        try
        {
            var reader = new HeaderReader(binaryInput, options.MaxHeaderLineBytes, options.MaxHeaderBytes);

            // Buffer the header first; parsing it afterwards is pure, so the two paths
            // share everything below this line.
            await reader.PrefillAsync(cancellationToken).ConfigureAwait(false);

            return FromReader(reader, isArmored);
        }
        finally
        {
            if (isArmored)
                await binaryInput.DisposeAsync().ConfigureAwait(false);
        }
    }

    private static AgeHeader FromReader(HeaderReader reader, bool isArmored)
    {
        Header header;

        try
        {
            header = Header.Parse(reader);
        }
        catch (AgeFormatException ex)
        {
            throw new AgeFormatException($"header parse error: {ex.Message}", ex);
        }

        // The offset counts dearmored bytes, which is not a position in what the caller
        // handed us, so it is only meaningful for binary input.
        return new AgeHeader(header.Stanzas.AsReadOnly(), isArmored ? null : reader.RawBytes.Length,
                             isArmored);
    }
}