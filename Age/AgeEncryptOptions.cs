namespace AgeSharp;

/// <summary>
/// Options for an encrypt call.
/// </summary>
/// <remarks>
/// Separate from <see cref="AgeDecryptOptions"/> so that every member of both types
/// is meaningful where it is accepted. Encryption writes a header it generated
/// itself, so the parsing limits that guard decryption have nothing to bound here.
/// </remarks>
public sealed class AgeEncryptOptions
{
    /// <summary>
    /// If <c>true</c>, produces a PEM-like ASCII-armored text block instead of raw
    /// binary. Decryption detects armor on its own; use
    /// <see cref="AgeDecryptOptions.RequireArmor"/> to insist on it there.
    /// </summary>
    public bool Armor { get; init; }

    internal static readonly AgeEncryptOptions Default = new();
}
