namespace AgeSharp;

/// <summary>
/// Asks a passphrase callback, the one shape every protected key takes: characters, cleared by
/// whoever asked once used, or null to cancel.
/// </summary>
internal static class PassphraseSource
{
    /// <summary>The characters the source returns for <paramref name="what"/>, which the caller clears.</summary>
    /// <exception cref="AgeException">The source returned null, or failed.</exception>
    /// <exception cref="OperationCanceledException">The source threw it, to cancel.</exception>
    public static char[] Ask(Func<char[]?> source, string what)
    {
        char[]? characters;

        try
        {
            characters = source();
        }
        catch (Exception ex) when (ex is not AgeException and not OperationCanceledException)
        {
            throw new AgeException($"failed to obtain the passphrase for {what}: {ex.Message}", ex);
        }

        return characters ?? throw new AgeException($"no passphrase was given for {what}");
    }
}
