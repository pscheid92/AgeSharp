namespace AgeSharp;

/// <summary>Options for encrypting to a set of <see cref="Recipients"/>.</summary>
/// <remarks>
/// Separate from the decrypt options so that every member means something where it is accepted:
/// encryption writes a header it generated itself, so the limits that guard parsing have
/// nothing to bound here. Members are init-only, so options can grow without touching a
/// signature.
/// </remarks>
public sealed class AgeEncryptOptions
{
    internal static readonly AgeEncryptOptions Default = new();

    /// <summary>
    /// If <c>true</c>, the file is written as ASCII armor (a PEM-like text block) instead of
    /// binary. Decryption detects armor by itself.
    /// </summary>
    public bool Armor { get; init; }
}
