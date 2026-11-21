using System.Text;
using AgeSharp;
using AgeSharp.Crypto;
using Xunit;

namespace Age.Tests;

/// <summary>
/// What a failure is called says what went wrong, not where: a structure that does not parse is
/// an <see cref="AgeFormatException"/>, a check that fails an <see cref="AgeAuthenticationException"/>.
/// </summary>
public class ErrorKindsTests
{
    private static readonly byte[] Plaintext = new byte[100_000];

    [Fact]
    public void AHeaderThatDoesNotParse_IsAFormatError()
    {
        using var alice = X25519Identity.Generate();

        Assert.Throws<AgeFormatException>(() => new Identities(alice).Decrypt("age-encryption.org/v1\n-> X25519\n"u8));
    }

    [Fact]
    public void ArmorThatDoesNotParse_IsAFormatError()
    {
        using var alice = X25519Identity.Generate();

        Assert.Throws<AgeFormatException>(() => new Identities(alice).Decrypt("-----BEGIN AGE ENCRYPTED FILE-----\n!!!\n"u8));
    }

    [Fact]
    public void ABrokenLimit_IsAFormatError()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);

        Assert.Throws<AgeFormatException>(() => new Identities(alice).Decrypt(file, new AgeDecryptOptions { MaxHeaderBytes = 10 }));
    }

    [Fact]
    public void AHeaderAlteredAfterEncryption_IsAnAuthenticationError()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var mac = Encoding.ASCII.GetString(file).IndexOf("\n--- ", StringComparison.Ordinal) + 5;
        file[mac] = (byte)(file[mac] == 'A' ? 'B' : 'A');

        Assert.Throws<AgeAuthenticationException>(() => new Identities(alice).Decrypt(file));
    }

    [Fact]
    public void ATamperedOrTruncatedPayload_IsAnAuthenticationError()
    {
        using var alice = X25519Identity.Generate();
        var file = new Recipients(alice.Recipient).Encrypt(Plaintext);
        var tampered = file.ToArray();
        tampered[^3] ^= 1;

        Assert.Throws<AgeAuthenticationException>(() => new Identities(alice).Decrypt(tampered));
        Assert.Throws<AgeAuthenticationException>(() => new Identities(alice).Decrypt(file.AsSpan(0, file.Length - StreamEncryption.EncryptedChunkSize)));
    }

    // A caller's mistake found only mid-operation is neither: it is the base type itself.
    [Fact]
    public void MixedLabels_AreAnAgeException_NeitherFormatNorAuthentication()
    {
        using var classical = X25519Identity.Generate();
        using var postQuantum = MlKem768X25519Identity.Generate();

        var ex = Assert.Throws<AgeException>(() => new Recipients(classical.Recipient, postQuantum.Recipient).Encrypt(Plaintext));

        Assert.IsNotType<AgeFormatException>(ex);
        Assert.IsNotType<AgeAuthenticationException>(ex);
    }

    // Parsing text keeps .NET's own convention.
    [Fact]
    public void AKeyThatDoesNotParse_IsAFormatException_NotAnAgeException()
    {
        var ex = Assert.Throws<FormatException>(() => X25519Identity.Parse("AGE-SECRET-KEY-1NOPE"));

        Assert.IsNotAssignableFrom<AgeException>(ex);
    }

    [Fact]
    public void BothKinds_CarryTheirCause()
    {
        var cause = new InvalidOperationException("cause");

        Assert.Same(cause, new AgeFormatException("m", cause).InnerException);
        Assert.Same(cause, new AgeAuthenticationException("m", cause).InnerException);
        Assert.IsAssignableFrom<AgeException>(new AgeFormatException("m"));
        Assert.IsAssignableFrom<AgeException>(new AgeAuthenticationException("m"));
    }
}
