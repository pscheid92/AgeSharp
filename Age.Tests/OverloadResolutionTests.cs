using AgeSharp;
using Xunit;

namespace AgeSharp.Tests;

/// <summary>
/// Compile-and-resolve probe for the <c>Age.Encrypt</c>/<c>Age.Decrypt</c> overload set.
/// The buffer (<c>byte[]</c>) and stream overloads share the same
/// <c>first, params ReadOnlySpan&lt;...&gt;</c> tail, so the first argument's type must
/// select the overload unambiguously. Every documented call shape is exercised here; a
/// future overload that introduces an ambiguity would fail to compile in this file. The
/// <c>byte[]</c>-typed assignments double as a check that the buffer overloads are the
/// ones selected (they only compile if the call returns <c>byte[]</c>).
/// </summary>
/// <remarks>
/// Each family offers four shapes — with and without options, crossed with the
/// <c>first, params rest</c> and collection forms. The pairing matters: taking the
/// first element as its own parameter is what makes a zero-recipient call a compile
/// error, but it also means a collection can no longer be splatted with <c>[.. list]</c>
/// (a collection expression has no conversion to <c>IRecipient</c>). The collection
/// overloads are what keep that case callable, so both halves are probed together.
/// </remarks>
public class OverloadResolutionTests
{
    [Fact]
    public void Encrypt_EveryCallShape_Resolves()
    {
        using var id = X25519Identity.Generate();
        IRecipient r = id.Recipient;
        var recipients = new[] { r };
        // The case that motivated the collection overloads: List<T> has no conversion
        // to IRecipient, so before them this was only callable via a [.. list] splat.
        List<IRecipient> recipientList = [r, r];
        var options = new AgeEncryptOptions();
        var plaintext = "probe"u8.ToArray();

        // Stream overloads
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), r));
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), options, r));
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), r, r));                  // multiple params
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), recipients));            // array → collection
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), recipientList));         // List<T> → collection
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), options, recipientList));

        // Buffer overloads (each must return byte[])
        byte[] c1 = Age.Encrypt(plaintext, r);
        byte[] c2 = Age.Encrypt(plaintext, options, r);
        byte[] c3 = Age.Encrypt(plaintext, recipients);          // array → collection
        byte[] c4 = Age.Encrypt(plaintext.AsSpan(), r);          // explicit span
        byte[] c5 = Age.Encrypt(plaintext, r, r);                // multiple params
        byte[] c6 = Age.Encrypt(plaintext, recipientList);       // List<T> → collection
        byte[] c7 = Age.Encrypt(plaintext, options, recipientList);

        Assert.All([c1, c2, c3, c4, c5, c6, c7], c => Assert.NotEmpty(c));

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
        List<IIdentity> identityList = [i];
        var options = new AgeDecryptOptions();
        var expected = "probe"u8.ToArray();
        var ct = Age.Encrypt(expected, id.Recipient);

        // Buffer overloads (each must return byte[])
        byte[] p1 = Age.Decrypt(ct, i);
        byte[] p2 = Age.Decrypt(ct, options, i);
        byte[] p3 = Age.Decrypt(ct, identities);          // array → collection
        byte[] p4 = Age.Decrypt(ct.AsSpan(), i);          // explicit span
        byte[] p5 = Age.Decrypt(ct, identityList);        // List<T> → collection
        byte[] p6 = Age.Decrypt(ct, options, identityList);

        Assert.All([p1, p2, p3, p4, p5, p6], p => Assert.Equal(expected, p));

        // Stream overloads
        DecryptFromStream(output => Age.Decrypt(new MemoryStream(ct), output, i));
        DecryptFromStream(output => Age.Decrypt(new MemoryStream(ct), output, options, i));
        DecryptFromStream(output => Age.Decrypt(new MemoryStream(ct), output, identityList));
        DecryptFromStream(output => Age.Decrypt(new MemoryStream(ct), output, options, identityList));

        void DecryptFromStream(Action<MemoryStream> decrypt)
        {
            using var output = new MemoryStream();
            decrypt(output);
            Assert.Equal(expected, output.ToArray());
        }
    }

    /// <summary>
    /// The streaming and detached families gained the same four shapes; this pins
    /// that they resolve, since a collection there binds a different parameter slot
    /// than in the buffer families above.
    /// </summary>
    [Fact]
    public void StreamingAndDetached_EveryCallShape_Resolves()
    {
        using var id = X25519Identity.Generate();
        IRecipient r = id.Recipient;
        IIdentity i = id;
        List<IRecipient> recipientList = [r];
        List<IIdentity> identityList = [i];
        var encryptOptions = new AgeEncryptOptions();
        var decryptOptions = new AgeDecryptOptions();
        var expected = "probe"u8.ToArray();

        Age.EncryptReader(new MemoryStream(expected), r).Dispose();
        Age.EncryptReader(new MemoryStream(expected), encryptOptions, r).Dispose();
        Age.EncryptReader(new MemoryStream(expected), recipientList).Dispose();
        Age.EncryptReader(new MemoryStream(expected), encryptOptions, recipientList).Dispose();

        Age.OpenWrite(new MemoryStream(), r).Dispose();
        Age.OpenWrite(new MemoryStream(), encryptOptions, r).Dispose();
        Age.OpenWrite(new MemoryStream(), recipientList).Dispose();
        Age.OpenWrite(new MemoryStream(), encryptOptions, recipientList).Dispose();

        var ct = Age.Encrypt(expected, r);
        Age.OpenRead(new MemoryStream(ct), i).Dispose();
        Age.OpenRead(new MemoryStream(ct), decryptOptions, i).Dispose();
        Age.OpenRead(new MemoryStream(ct), identityList).Dispose();
        Age.OpenRead(new MemoryStream(ct), decryptOptions, identityList).Dispose();

        // Detached: the header and payload streams push the recipient slot out by two.
        RoundTripDetached((header, payload, input) => Age.EncryptDetached(input, header, payload, r),
                          (header, payload, output) => Age.DecryptDetached(header, payload, output, i));
        RoundTripDetached((header, payload, input) => Age.EncryptDetached(input, header, payload, recipientList),
                          (header, payload, output) => Age.DecryptDetached(header, payload, output, identityList));
        RoundTripDetached((header, payload, input) => Age.EncryptDetached(input, header, payload, r),
                          (header, payload, output) => Age.DecryptDetached(header, payload, output, decryptOptions, i));
        RoundTripDetached((header, payload, input) => Age.EncryptDetached(input, header, payload, recipientList),
                          (header, payload, output) => Age.DecryptDetached(header, payload, output, decryptOptions, identityList));

        void RoundTripDetached(Action<MemoryStream, MemoryStream, MemoryStream> encrypt,
                               Action<MemoryStream, MemoryStream, MemoryStream> decrypt)
        {
            using var header = new MemoryStream();
            using var payload = new MemoryStream();
            using var input = new MemoryStream(expected);
            encrypt(header, payload, input);

            header.Position = 0;
            payload.Position = 0;
            using var output = new MemoryStream();
            decrypt(header, payload, output);

            Assert.Equal(expected, output.ToArray());
        }
    }
}
