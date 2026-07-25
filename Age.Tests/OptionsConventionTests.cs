using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Every synchronous entry point that can act on <see cref="AgeDecryptOptions" /> takes it
///     the same way — a second overload with the options positional, before the params
///     span — and the options it takes actually reach the parser.
/// </summary>
public class OptionsConventionTests
{
    // A limit low enough that a real header trips it, proving the value was threaded
    // through rather than silently replaced by the default.
    private static AgeDecryptOptions Tiny => new() { MaxHeaderBytes = 32 };

    private static byte[] Ciphertext(IRecipient recipient, bool armor = false)
    {
        return Age.Encrypt("options"u8, new AgeEncryptOptions { Armor = armor }, recipient);
    }

    [Fact]
    public void ReadHeader_OptionsOverload_AppliesTheLimit()
    {
        using var identity = X25519Identity.Generate();
        using var input = new MemoryStream(Ciphertext(identity.Recipient));

        Assert.Throws<AgeFormatException>(() => Age.ReadHeader(input, Tiny));
    }

    [Fact]
    public void ReadHeader_WithoutOptions_UsesTheDefaults()
    {
        using var identity = X25519Identity.Generate();
        using var input = new MemoryStream(Ciphertext(identity.Recipient));

        Assert.Single(Age.ReadHeader(input).Stanzas);
    }

    [Fact]
    public void DecryptDetached_OptionsOverload_AppliesTheLimit()
    {
        // The detached pair previously hardcoded the defaults, so a caller could not
        // raise (or lower) the header limits when decrypting a detached header.
        using var identity = X25519Identity.Generate();
        var (header, payload) = EncryptDetached(identity.Recipient);

        using var output = new MemoryStream();
        Assert.Throws<AgeFormatException>(() =>
            Age.DecryptDetached(new MemoryStream(header), new MemoryStream(payload), output, Tiny, identity));
    }

    [Fact]
    public void DecryptDetached_WithoutOptions_StillRoundTrips()
    {
        using var identity = X25519Identity.Generate();
        var (header, payload) = EncryptDetached(identity.Recipient);

        using var output = new MemoryStream();
        Age.DecryptDetached(new MemoryStream(header), new MemoryStream(payload), output, identity);

        Assert.Equal("detached"u8.ToArray(), output.ToArray());
    }

    [Fact]
    public void DecryptDetached_OptionsOverload_RoundTripsWithGenerousLimits()
    {
        using var identity = X25519Identity.Generate();
        var (header, payload) = EncryptDetached(identity.Recipient);

        using var output = new MemoryStream();
        Age.DecryptDetached(new MemoryStream(header), new MemoryStream(payload), output,
            new AgeDecryptOptions { MaxHeaderBytes = 1024 * 1024 }, identity);

        Assert.Equal("detached"u8.ToArray(), output.ToArray());
    }

    [Theory]
    [MemberData(nameof(OptionsRespectingEntryPoints))]
    public void EveryOptionsOverload_ThreadsTheLimitThrough(string name, Action<AgeDecryptOptions> call)
    {
        // One shape for all of them: pass a limit no real header can satisfy and
        // require it to be honoured. A hardcoded default would let these pass.
        var ex = Record.Exception(() => call(Tiny));

        Assert.True(ex is AgeFormatException,
            $"{name} ignored the options it was given (got {ex?.GetType().Name ?? "no exception"})");
    }

    public static TheoryData<string, Action<AgeDecryptOptions>> OptionsRespectingEntryPoints()
    {
        using var identity = X25519Identity.Generate();
        var recipient = identity.Recipient;
        var binary = Age.Encrypt("options"u8, recipient);
        var secret = identity.ToSecretString();

        return new TheoryData<string, Action<AgeDecryptOptions>>
        {
            {
                "Decrypt(stream)", o =>
                {
                    using var id = X25519Identity.Parse(secret);
                    Age.Decrypt(new MemoryStream(binary), new MemoryStream(), o, id);
                }
            },
            {
                "Decrypt(byte[])", o =>
                {
                    using var id = X25519Identity.Parse(secret);
                    Age.Decrypt(binary, o, id);
                }
            },
            {
                "DecryptReader", o =>
                {
                    using var id = X25519Identity.Parse(secret);
                    Age.DecryptReader(new MemoryStream(binary), o, id).Dispose();
                }
            },
            { "ReadHeader", o => Age.ReadHeader(new MemoryStream(binary), o) }
        };
    }

    private static (byte[] header, byte[] payload) EncryptDetached(IRecipient recipient)
    {
        using var input = new MemoryStream("detached"u8.ToArray());
        using var header = new MemoryStream();
        using var payload = new MemoryStream();

        Age.EncryptDetached(input, header, payload, recipient);

        return (header.ToArray(), payload.ToArray());
    }
}