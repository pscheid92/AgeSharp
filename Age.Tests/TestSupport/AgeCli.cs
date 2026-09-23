namespace Age.Tests;

/// <summary>
/// The reference Go <c>age</c> / <c>age-keygen</c> CLIs. CI installs them onto PATH explicitly;
/// local shells get them via Homebrew's <c>shellenv</c>.
/// </summary>
internal static class AgeCli
{
    private static readonly ReferenceCli Age = new("age");

    public static string? AgePath => Age.Path;
    public static string? AgeKeygenPath { get; } = ReferenceCli.Find("age-keygen");

    public static bool Available => Age.Available;
    public static bool KeygenAvailable => AgeKeygenPath is not null;

    /// <summary>Encrypts <paramref name="plaintext"/> with the reference age CLI to one or more recipients.</summary>
    public static byte[] Encrypt(byte[] plaintext, bool armored, params string[] recipients) =>
        Age.Encrypt(plaintext, armored, recipients);

    /// <summary>Decrypts <paramref name="ciphertext"/> with the reference age CLI using the given identity-file contents.</summary>
    public static byte[] Decrypt(string identityFileText, byte[] ciphertext) =>
        Age.Decrypt(identityFileText, ciphertext);
}
