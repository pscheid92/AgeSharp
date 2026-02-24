using Age.Recipients;

namespace Age;

public static class AgeKeygen
{
    public static X25519Identity Generate() => X25519Identity.Generate();

    public static X25519Identity ParseIdentity(string s) => X25519Identity.Parse(s);

    public static X25519Recipient ParseRecipient(string s) => X25519Recipient.Parse(s);
}
