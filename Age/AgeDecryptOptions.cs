namespace AgeSharp;

/// <summary>
///     Armor strictness, plus the limits applied while reading a header — which happens
///     before any byte is authenticated, so they exist to stop a hostile stream from
///     exhausting memory. The spec sets no header size, so these are AgeSharp's own, set
///     far above any real file; raise them only if legitimate input ever trips one.
/// </summary>
public sealed class AgeDecryptOptions
{
    internal static readonly AgeDecryptOptions Default = new();
    private readonly int _maxArmorLineBytes = 64 * 1024;
    private readonly int _maxHeaderBytes = 16 * 1024 * 1024;
    private readonly int _maxHeaderLineBytes = 64 * 1024;

    /// <summary>
    ///     Rejects input that is not ASCII-armored. A strictness opt-in, not a switch: armor
    ///     is detected automatically, so the default accepts either form.
    /// </summary>
    public bool RequireArmor { get; init; }

    /// <summary>Maximum bytes in one header line. Default: 64 KiB.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not positive.</exception>
    public int MaxHeaderLineBytes
    {
        get => _maxHeaderLineBytes;
        init => _maxHeaderLineBytes = RequirePositive(value, nameof(MaxHeaderLineBytes));
    }

    /// <summary>Maximum bytes in the whole header, up to and including the MAC line. Default: 16 MiB.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not positive.</exception>
    public int MaxHeaderBytes
    {
        get => _maxHeaderBytes;
        init => _maxHeaderBytes = RequirePositive(value, nameof(MaxHeaderBytes));
    }

    /// <summary>Maximum bytes in one armor line; set high so it only rejects a hostile unterminated line. Default: 64 KiB.</summary>
    /// <exception cref="ArgumentOutOfRangeException">The value is not positive.</exception>
    public int MaxArmorLineBytes
    {
        get => _maxArmorLineBytes;
        init => _maxArmorLineBytes = RequirePositive(value, nameof(MaxArmorLineBytes));
    }

    // Rejected at construction: otherwise a zero limit surfaces as "armor line exceeds 0
    // bytes", blaming the input file for what is a caller error.
    private static int RequirePositive(int value, string name)
    {
        return value > 0
            ? value
            : throw new ArgumentOutOfRangeException(name, value, $"{name} must be greater than zero");
    }
}