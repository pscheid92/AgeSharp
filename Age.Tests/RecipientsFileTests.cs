using Age;
using Age.Recipients;
using Xunit;

namespace Age.Tests;

public class RecipientsFileTests
{
    [Fact]
    public void ParseRecipientsFile_X25519()
    {
        using var identity = X25519Identity.Generate();
        var text = $"# my recipient\n{identity.Recipient}\n";

        var parsed = AgeKeygen.ParseRecipientsFile(text);
        Assert.Single(parsed);
        Assert.Equal(identity.Recipient.ToString(), parsed[0].ToString());
    }

    [Fact]
    public void ParseRecipientsFile_PqRecipient()
    {
        using var identity = MlKem768X25519Identity.Generate();
        var text = $"{identity.Recipient}\n";

        var parsed = AgeKeygen.ParseRecipientsFile(text);
        Assert.Single(parsed);
        Assert.Equal(identity.Recipient.ToString(), parsed[0].ToString());
    }

    [Fact]
    public void ParseRecipientsFile_SshEd25519()
    {
        var pubKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGJQGjgPbMDwrhAEaWNKLdSIHAxiKJDtMCmLj7Zeg844 test@host";
        var text = $"# SSH key\n{pubKey}\n";

        var parsed = AgeKeygen.ParseRecipientsFile(text);
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

        var parsed = AgeKeygen.ParseRecipientsFile(text);
        Assert.Equal(3, parsed.Count);
    }

    [Fact]
    public void ParseRecipientsFile_BlankLinesAndComments()
    {
        using var identity = X25519Identity.Generate();
        var text = $"# comment 1\n\n# comment 2\n\n{identity.Recipient}\n\n";

        var parsed = AgeKeygen.ParseRecipientsFile(text);
        Assert.Single(parsed);
    }

    [Fact]
    public void ParseRecipientsFile_UnrecognizedLine_Throws()
    {
        var text = "NOT-A-VALID-RECIPIENT\n";
        var ex = Assert.Throws<FormatException>(() => AgeKeygen.ParseRecipientsFile(text));
        Assert.Contains("unrecognized line", ex.Message);
    }

    [Fact]
    public void ParseRecipientsFile_Empty_ReturnsEmpty()
    {
        Assert.Empty(AgeKeygen.ParseRecipientsFile(""));
    }

    [Fact]
    public void ParseRecipientsFile_RoundTrip_EncryptDecrypt()
    {
        using var id1 = X25519Identity.Generate();
        using var id2 = X25519Identity.Generate();
        var text = $"# Recipients\n{id1.Recipient}\n{id2.Recipient}\n";

        var recipients = AgeKeygen.ParseRecipientsFile(text);
        var plaintext = "Hello, recipients file!"u8.ToArray();

        using var encInput = new MemoryStream(plaintext);
        using var encOutput = new MemoryStream();
        AgeEncrypt.Encrypt(encInput, encOutput, recipients.ToArray());

        // Decrypt with first identity
        encOutput.Position = 0;
        using var decOutput = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput, id1);
        Assert.Equal(plaintext, decOutput.ToArray());

        // Decrypt with second identity
        encOutput.Position = 0;
        using var decOutput2 = new MemoryStream();
        AgeEncrypt.Decrypt(encOutput, decOutput2, id2);
        Assert.Equal(plaintext, decOutput2.ToArray());
    }
}
