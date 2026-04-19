namespace Age.Recipients;

internal static class AgeProtocol
{
    public const string X25519StanzaType = "X25519";
    public const string X25519HkdfLabel = "age-encryption.org/v1/X25519";

    public const string SshEd25519StanzaType = "ssh-ed25519";
    public const string SshEd25519HkdfLabel = "age-encryption.org/v1/ssh-ed25519";

    public const string SshRsaStanzaType = "ssh-rsa";
    public const string SshRsaOaepLabel = "age-encryption.org/v1/ssh-rsa";

    public const string MlKemStanzaType = "mlkem768x25519";
    public static readonly byte[] MlKemHpkeInfo = "age-encryption.org/mlkem768x25519"u8.ToArray();
}
