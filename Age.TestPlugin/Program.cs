using System.Text;
using AgeSharp;

// age-plugin-agesharptest: its keys carry a native X25519 key as their data, so its recipients
// wrap to that key and its identities unwrap with it. Wrapping says so through the client, to
// exercise the plugin talking to the user. "keygen" prints a new identity and its recipient.
var plugin = new AgePlugin("agesharptest");

plugin.HandleRecipient(data => new Announcing(plugin, X25519Recipient.Parse(Utf8(data))));
plugin.HandleIdentityAsRecipient(data =>
{
    using var identity = X25519Identity.Parse(Utf8(data));
    return new Announcing(plugin, identity.Recipient);
});
plugin.HandleIdentity(data => X25519Identity.Parse(Utf8(data)));

if (args is ["keygen"])
{
    using var key = X25519Identity.Generate();
    Console.WriteLine(plugin.EncodeIdentity(Encoding.UTF8.GetBytes(key.ToSecretString())));
    Console.WriteLine(plugin.EncodeRecipient(Encoding.UTF8.GetBytes(key.Recipient.ToString())));
    return 0;
}

return plugin.Run(args);

static string Utf8(byte[] data) => Encoding.UTF8.GetString(data);

sealed class Announcing(AgePlugin plugin, IRecipient inner) : IRecipient
{
    public IReadOnlyList<Stanza> Wrap(ReadOnlySpan<byte> fileKey)
    {
        plugin.DisplayMessage("wrapping to an agesharptest key");
        return inner.Wrap(fileKey);
    }
}
