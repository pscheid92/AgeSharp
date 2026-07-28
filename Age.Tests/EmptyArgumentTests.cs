using Age.Recipients;
using Xunit;

namespace Age.Tests;

/// <summary>
/// Encrypting to nobody, or decrypting with nothing, is a caller mistake rather than a format
/// error: it can only ever fail. Every public entry point rejects it at the door, naming the
/// argument, instead of letting it surface later as a header with no stanzas or as
/// <see cref="NoIdentityMatchException"/>. Six entry points enforced this and none was tested.
/// </summary>
public class EmptyArgumentTests
{
    private static MemoryStream Empty() => new();

    private static byte[] SomeCiphertext(X25519Identity identity)
    {
        using var input = new MemoryStream("x"u8.ToArray());
        using var output = new MemoryStream();
        AgeEncrypt.Encrypt(input, output, identity.Recipient);
        return output.ToArray();
    }

    [Fact]
    public void Encrypt_WithNoRecipients_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            AgeEncrypt.Encrypt(Empty(), Empty(), ReadOnlySpan<IRecipient>.Empty));

        Assert.Equal("recipients", ex.ParamName);
        Assert.Contains("at least one recipient", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void EncryptArmored_WithNoRecipients_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            AgeEncrypt.Encrypt(Empty(), Empty(), true, ReadOnlySpan<IRecipient>.Empty));

        Assert.Equal("recipients", ex.ParamName);
    }

    [Fact]
    public void EncryptReader_WithNoRecipients_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            AgeEncrypt.EncryptReader(Empty(), ReadOnlySpan<IRecipient>.Empty));

        Assert.Equal("recipients", ex.ParamName);
    }

    [Fact]
    public void EncryptDetached_WithNoRecipients_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            AgeEncrypt.EncryptDetached(Empty(), Empty(), Empty(), ReadOnlySpan<IRecipient>.Empty));

        Assert.Equal("recipients", ex.ParamName);
    }

    [Fact]
    public void Decrypt_WithNoIdentities_Throws()
    {
        using var identity = X25519Identity.Generate();
        using var source = new MemoryStream(SomeCiphertext(identity));

        var ex = Assert.Throws<ArgumentException>(() =>
            AgeEncrypt.Decrypt(source, Empty(), ReadOnlySpan<IIdentity>.Empty));

        Assert.Equal("identities", ex.ParamName);
        Assert.Contains("at least one identity", ex.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void DecryptReader_WithNoIdentities_Throws()
    {
        using var identity = X25519Identity.Generate();
        using var source = new MemoryStream(SomeCiphertext(identity));

        var ex = Assert.Throws<ArgumentException>(() =>
            AgeEncrypt.DecryptReader(source, ReadOnlySpan<IIdentity>.Empty));

        Assert.Equal("identities", ex.ParamName);
    }

    [Fact]
    public void DecryptDetached_WithNoIdentities_Throws()
    {
        var ex = Assert.Throws<ArgumentException>(() =>
            AgeEncrypt.DecryptDetached(Empty(), Empty(), Empty(), ReadOnlySpan<IIdentity>.Empty));

        Assert.Equal("identities", ex.ParamName);
    }

    [Fact]
    public void RandomAccess_WithNoIdentities_Throws()
    {
        using var identity = X25519Identity.Generate();
        using var source = new MemoryStream(SomeCiphertext(identity));

        var ex = Assert.Throws<ArgumentException>(() =>
            new AgeRandomAccess(source, ReadOnlySpan<IIdentity>.Empty));

        Assert.Equal("identities", ex.ParamName);
    }

    // The guard must fire before anything else touches the input — a caller passing no
    // recipients should not have their stream read first.
    [Fact]
    public void TheGuardRunsBeforeTheInputIsTouched()
    {
        var input = new ThrowOnReadStream();

        Assert.Throws<ArgumentException>(() =>
            AgeEncrypt.Encrypt(input, Empty(), ReadOnlySpan<IRecipient>.Empty));
    }

    private sealed class ThrowOnReadStream : Stream
    {
        public override bool CanRead => true;
        public override bool CanSeek => false;
        public override bool CanWrite => false;
        public override long Length => throw new NotSupportedException();

        public override long Position
        {
            get => throw new NotSupportedException();
            set => throw new NotSupportedException();
        }

        public override int Read(byte[] buffer, int offset, int count) =>
            throw new InvalidOperationException("the input was read before the argument check ran");

        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
        public override void SetLength(long value) => throw new NotSupportedException();
        public override void Write(byte[] buffer, int offset, int count) => throw new NotSupportedException();
    }
}
