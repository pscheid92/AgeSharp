using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// Compile-and-resolve probe for the <c>Age.Encrypt</c>/<c>Age.Decrypt</c> overload set.
/// The buffer (<c>byte[]</c>) and stream overloads share the same
/// <c>params ReadOnlySpan&lt;...&gt;</c> tail, so the first argument's type must select the
/// overload unambiguously. Every documented call shape is exercised here; a future
/// overload that introduces an ambiguity would fail to compile in this file. The
/// <c>byte[]</c>-typed assignments double as a check that the buffer overloads are the
/// ones selected (they only compile if the call returns <c>byte[]</c>).
/// </summary>
public class OverloadResolutionTests
{
    [Fact]
    public void Encrypt_EveryCallShape_Resolves()
    {
        using var id = X25519Identity.Generate();
        IRecipient r = id.Recipient;
        var recipients = new[] { r };
        var options = new AgeOptions();
        var plaintext = "probe"u8.ToArray();

        // Stream overloads
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), r));
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), options, r));
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), recipients)); // array → span
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), r, r));        // multiple params

        // Buffer overloads (each must return byte[])
        byte[] c1 = Age.Encrypt(plaintext, r);
        byte[] c2 = Age.Encrypt(plaintext, options, r);
        byte[] c3 = Age.Encrypt(plaintext, recipients);        // array → span
        byte[] c4 = Age.Encrypt(plaintext.AsSpan(), r);        // explicit span
        byte[] c5 = Age.Encrypt(plaintext, r, r);              // multiple params

        Assert.All([c1, c2, c3, c4, c5], c => Assert.NotEmpty(c));

        static void EncryptToStream(Action<MemoryStream> encrypt)
        {
            using var input = new MemoryStream("probe"u8.ToArray());
            encrypt(input);
        }
    }

    [Fact]
    public void Decrypt_EveryCallShape_Resolves()
    {
        using var id = X25519Identity.Generate();
        IIdentity i = id;
        var identities = new[] { i };
        var options = new AgeOptions();
        var expected = "probe"u8.ToArray();
        var ct = Age.Encrypt(expected, id.Recipient);

        // Buffer overloads (each must return byte[])
        byte[] p1 = Age.Decrypt(ct, i);
        byte[] p2 = Age.Decrypt(ct, options, i);
        byte[] p3 = Age.Decrypt(ct, identities);   // array → span
        byte[] p4 = Age.Decrypt(ct.AsSpan(), i);   // explicit span

        Assert.All([p1, p2, p3, p4], p => Assert.Equal(expected, p));

        // Stream overloads
        using (var input = new MemoryStream(ct))
        using (var output = new MemoryStream())
        {
            Age.Decrypt(input, output, i);
            Assert.Equal(expected, output.ToArray());
        }

        using (var input = new MemoryStream(ct))
        using (var output = new MemoryStream())
        {
            Age.Decrypt(input, output, options, i);
            Assert.Equal(expected, output.ToArray());
        }
    }
}
