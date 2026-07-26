namespace AgeSharp;

// Derivation labels only — the stanza type strings live on Stanza, where a consumer
// inspecting a header can reach them.
internal static class AgeProtocol
{
    public const string X25519HkdfLabel = "age-encryption.org/v1/X25519";

    public const string SshEd25519HkdfLabel = "age-encryption.org/v1/ssh-ed25519";

    public const string SshRsaOaepLabel = "age-encryption.org/v1/ssh-rsa";

    public static readonly byte[] MlKemHpkeInfo = "age-encryption.org/mlkem768x25519"u8.ToArray();
}