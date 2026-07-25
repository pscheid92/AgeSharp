using AgeSharp.Crypto;
using Xunit;

namespace AgeSharp.Tests;

public class RecipientsFileTests
{
    // Found by brute force: a real X25519 key whose recipient's bech32 data happens to start
    // with "pq", so the string begins "age1pq" exactly like an ML-KEM-768 recipient does.
    private const string PqLookalikeIdentity =
        "AGE-SECRET-KEY-1LRKLPKJT609NGXMQ8FJ2T985FU95PK29M9YZRPAW4WWZ5WWZWFRSNV7M2H";

    private const string PqLookalikeRecipient = "age1pqw26wvuhkqsmmqh0flpkkt7hmn2mrwmr83v84fm8zjmalnqavuq2tj4sg";

    [Fact]
    public void ParseRecipientsFile_X25519()
    {
        using var identity = X25519Identity.Generate();
        var text = $"# my recipient\n{identity.Recipient}\n";

        var parsed = Age.ParseRecipients(text);
        Assert.Single(parsed);
        Assert.Equal(identity.Recipient.ToString(), parsed[0].ToString());
    }

    [Fact]
    public void ParseRecipientsFile_PqRecipient()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var text = $"{identity.Recipient}\n";

        var parsed = Age.ParseRecipients(text);
        Assert.Single(parsed);
        Assert.Equal(identity.Recipient.ToString(), parsed[0].ToString());
    }

    [Fact]
    public void ParseRecipientsFile_SshEd25519()
    {
        var pubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJQGjgPbMDwrhAEaWNKLdSIHAxiKJDtMCmLj7Zeg844 test@host";
        var text = $"# SSH key\n{pubKey}\n";

        var parsed = Age.ParseRecipients(text);
        Assert.Single(parsed);
    }

    [Fact]
    public void ParseRecipientsFile_Multiple_Mixed()
    {
        using var x25519 = X25519Identity.Generate();
        using var pq = MlKem768X25519Identity.Generate();
        var sshKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJQGjgPbMDwrhAEaWNKLdSIHAxiKJDtMCmLj7Zeg844 test@host";

        var text = $"""
                    # X25519
                    {x25519.Recipient}

                    # PQ
                    {pq.Recipient}

                    # SSH
                    {sshKey}
                    """;

        var parsed = Age.ParseRecipients(text);
        Assert.Equal(3, parsed.Length);
    }

    [Fact]
    public void ParseRecipientsFile_BlankLinesAndComments()
    {
        using var identity = X25519Identity.Generate();
        var text = $"# comment 1\n\n# comment 2\n\n{identity.Recipient}\n\n";

        var parsed = Age.ParseRecipients(text);
        Assert.Single(parsed);
    }

    [Fact]
    public void ParseRecipientsFile_UnrecognizedLine_Throws()
    {
        var text = "NOT-A-VALID-RECIPIENT\n";
        var ex = Assert.Throws<AgeFormatException>(() => Age.ParseRecipients(text));
        Assert.Contains("unrecognized recipient", ex.Message);
    }

    [Fact]
    public void ParseRecipientsFile_X25519StartingWithAge1Pq_ParsesAsX25519()
    {
        using var identity = X25519Identity.Parse(PqLookalikeIdentity);
        Assert.Equal(PqLookalikeRecipient, identity.Recipient.ToString());

        var parsed = Age.ParseRecipients($"{PqLookalikeRecipient}\n");
        Assert.Single(parsed);
        Assert.IsType<X25519Recipient>(parsed[0]);
    }

    [Fact]
    public void ParseRecipientsFile_X25519StartingWithAge1Pq_RoundTrips()
    {
        using var identity = X25519Identity.Parse(PqLookalikeIdentity);
        var recipients = Age.ParseRecipients($"{PqLookalikeRecipient}\n");
        var plaintext = "pq-lookalike recipient"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        Age.Encrypt(encInput, encOutput, recipients.ToArray());

        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        Age.Decrypt(encOutput, decOutput, [identity]);
        Assert.Equal(plaintext, decOutput.ToArray());
    }

    [Fact]
    public void ParseRecipientsFile_PluginNameStartingWithPq_ParsesAsPlugin()
    {
        var recipient = Bech32.Encode("age1pqtest", [0x01, 0x02, 0x03]);
        var parsed = Age.ParseRecipients($"{recipient}\n");
        Assert.Single(parsed);
        Assert.IsType<PluginRecipient>(parsed[0]);
    }

    [Fact]
    public void ParseRecipientsFile_Empty_ReturnsEmpty()
    {
        Assert.Empty(Age.ParseRecipients(""));
    }

    [Fact]
    public void ParseRecipientsFile_RoundTrip_EncryptDecrypt()
    {
        using var id1 = X25519Identity.Generate();
        using var id2 = X25519Identity.Generate();
        var text = $"# Recipients\n{id1.Recipient}\n{id2.Recipient}\n";

        var recipients = Age.ParseRecipients(text);
        var plaintext = "Hello, recipients file!"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        Age.Encrypt(encInput, encOutput, recipients.ToArray());

        // Decrypt with first identity
        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        Age.Decrypt(encOutput, decOutput, [id1]);
        Assert.Equal(plaintext, decOutput.ToArray());

        // Decrypt with second identity
        encOutput.Position = 0;
        using var decOutput2 = new MemoryStream();
        Age.Decrypt(encOutput, decOutput2, [id2]);
        Assert.Equal(plaintext, decOutput2.ToArray());
    }
}