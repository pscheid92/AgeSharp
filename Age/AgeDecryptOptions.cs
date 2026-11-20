namespace AgeSharp;

/// <summary>
/// Options for decrypting with a set of <see cref="Identities"/>: whether armor is required, and
/// the limits that bound reading the header and the armor.
/// </summary>
/// <remarks>
/// The header is read, and buffered whole, before anything in it is authenticated, so these
/// limits are what stop a hostile or malformed stream from exhausting memory. The spec sets none;
/// the defaults are go-age's (v1.3.2), so by default AgeSharp accepts exactly the headers the
/// reference does. Raise one only for legitimate input that trips it.
/// </remarks>
public sealed class AgeDecryptOptions
{
    internal static readonly AgeDecryptOptions Default = new();

    private readonly int _maxHeaderBytes = AgeLimits.MaxHeaderBytes;
    private readonly int _maxRecipientStanzas = AgeLimits.MaxRecipientStanzas;
    private readonly int _maxStanzaArguments = AgeLimits.MaxStanzaArguments;
    private readonly int _maxArmorLineBytes = AgeLimits.MaxArmorLineBytes;

    /// <summary>
    /// Refuses input that is not ASCII-armored. Armor is detected either way; this only makes it
    /// mandatory.
    /// </summary>
    public bool RequireArmor { get; init; }

    /// <summary>
    /// The most bytes the header may take, every line up to and including the MAC line. A single
    /// line is bounded only by this, as in go-age. Default: 2 MiB, enough for well over a
    /// thousand post-quantum recipients.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not positive.</exception>
    public int MaxHeaderBytes
    {
        get => _maxHeaderBytes;
        init => _maxHeaderBytes = RequirePositive(value);
    }

    /// <summary>The most recipient stanzas a header may hold. Default: 1024.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not positive.</exception>
    public int MaxRecipientStanzas
    {
        get => _maxRecipientStanzas;
        init => _maxRecipientStanzas = RequirePositive(value);
    }

    /// <summary>The most arguments one stanza line may carry. Default: 128.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not positive.</exception>
    public int MaxStanzaArguments
    {
        get => _maxStanzaArguments;
        init => _maxStanzaArguments = RequirePositive(value);
    }

    /// <summary>
    /// The most bytes one armor line may take. Armor lines are 64 characters, and wider body lines
    /// are refused whatever this says; the bound only stops a line that never ends, which is how
    /// input that is not armor at all presents itself. Default: 1 KiB.
    /// </summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not positive.</exception>
    public int MaxArmorLineBytes
    {
        get => _maxArmorLineBytes;
        init => _maxArmorLineBytes = RequirePositive(value);
    }

    // Refused when set: a zero limit would otherwise surface as "header exceeds 0 bytes",
    // blaming the file for the caller's mistake.
    private static int RequirePositive(int value, [System.Runtime.CompilerServices.CallerMemberName] string name = "") =>
        value > 0 ? value : throw new ArgumentOutOfRangeException(name, value, $"{name} must be greater than zero");
}
