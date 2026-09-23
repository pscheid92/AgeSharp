namespace Age.Tests;

/// <summary>
/// Rust's <c>rage</c> CLI, the second implementation AgeSharp must agree with. CI installs it
/// onto PATH explicitly.
/// </summary>
internal static class RageCli
{
    // rage 0.11.1 panics at startup in its locale detection on a macOS region override such as
    // "en_US@rg=dezzzz"; an explicit LANG avoids that and changes nothing else.
    private static readonly ReferenceCli Rage = new("rage", new Dictionary<string, string> { ["LANG"] = "en_US.UTF-8" });

    public static bool Available => Rage.Available;

    /// <summary>Encrypts <paramref name="plaintext"/> with rage to one or more recipients.</summary>
    public static byte[] Encrypt(byte[] plaintext, bool armored, params string[] recipients) =>
        Rage.Encrypt(plaintext, armored, recipients);

    /// <summary>Decrypts <paramref name="ciphertext"/> with rage using the given identity-file contents.</summary>
    public static byte[] Decrypt(string identityFileText, byte[] ciphertext) =>
        Rage.Decrypt(identityFileText, ciphertext);
}
