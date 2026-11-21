namespace AgeSharp;

/// <summary>Why each identity tried against a file did not open it, for <see cref="NoIdentityMatchException"/>.</summary>
internal static class IdentityMismatches
{
    /// <summary>The no-match for a header no identity in <paramref name="tried"/> opened.</summary>
    public static NoIdentityMatchException For(IReadOnlyList<Stanza> stanzas, IEnumerable<IIdentity> tried)
    {
        var types = stanzas.Select(s => s.Type).ToArray();
        return new NoIdentityMatchException(types, [.. tried.Select(identity => Of(identity, types))]);
    }

    private static IdentityMismatch Of(IIdentity identity, string[] stanzaTypes)
    {
        var type = StanzaTypeOf(identity);
        var reason = type is null
            ? IdentityMismatchReason.DidNotMatch
            : stanzaTypes.Contains(type, StringComparer.Ordinal)
                ? IdentityMismatchReason.NoStanzaForIt
                : IdentityMismatchReason.NoStanzaOfItsType;

        return new IdentityMismatch(Describe(identity), reason, type);
    }

    // The stanza type each of AgeSharp's own identities opens. Others do not say.
    private static string? StanzaTypeOf(IIdentity identity) => identity switch
    {
        X25519Identity => AgeProtocol.X25519StanzaType,
        MlKem768X25519Identity => AgeProtocol.MlKemStanzaType,
        Passphrase => "scrypt",
        SshEd25519Identity => AgeProtocol.SshEd25519StanzaType,
        SshRsaIdentity => AgeProtocol.SshRsaStanzaType,
        EncryptedSshIdentity encrypted => encrypted.Recipient is SshEd25519Recipient
            ? AgeProtocol.SshEd25519StanzaType
            : AgeProtocol.SshRsaStanzaType,
        _ => null,
    };

    // The identity's type and the start of its recipient: public, and enough to tell keys apart.
    // Never ToString: a custom identity's may print its secret.
    private static string Describe(IIdentity identity)
    {
        var name = identity.GetType().Name;

        try
        {
            if (identity is IIdentityWithRecipient { Recipient: { } recipient })
            {
                var text = recipient.ToString() ?? "";
                return text.Length == 0 ? name : $"{name} ({(text.Length > 16 ? text[..16] + "…" : text)})";
            }
        }
        catch (Exception)
        {
            // A recipient that cannot be had (a disposed identity, a custom one that throws) still
            // leaves the identity's type to name it by.
        }

        return name;
    }
}
