using Xunit;

namespace AgeSharp.Tests;

/// <summary>
///     Compile-and-resolve probe for the <c>Age</c> facade. Each operation has exactly one
///     method — recipients or identities as an <c>IReadOnlyList&lt;&gt;</c>, options last and
///     optional — except <c>Encrypt</c>/<c>Decrypt</c>, which additionally have a
///     <c>byte[]</c> form. Those two must stay unambiguous, and the first argument's type
///     (<c>Stream</c> vs <c>ReadOnlySpan&lt;byte&gt;</c>) is what separates them.
/// </summary>
/// <remarks>
///     Every documented call shape is exercised: a collection expression for one recipient
///     and for several, plus an array and a <c>List&lt;T&gt;</c> passed through directly.
///     The <c>byte[]</c>-typed assignments double as a check that the buffer form is the one
///     selected — they only compile if the call returns <c>byte[]</c>. A future overload that
///     introduced an ambiguity would fail to compile in this file.
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
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), [r]));
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), [r], options));
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), [r, r])); // multiple params
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), recipients)); // array → collection
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), recipientList)); // List<T> → collection
        EncryptToStream(input => Age.Encrypt(input, new MemoryStream(), recipientList, options));

        // Buffer overloads (each must return byte[])
        var c1 = Age.Encrypt(plaintext, [r]);
        var c2 = Age.Encrypt(plaintext, [r], options);
        var c3 = Age.Encrypt(plaintext, recipients); // array → collection
        var c4 = Age.Encrypt(plaintext.AsSpan(), [r]); // explicit span
        var c5 = Age.Encrypt(plaintext, [r, r]); // several recipients inline
        var c6 = Age.Encrypt(plaintext, recipientList); // List<T> → collection
        var c7 = Age.Encrypt(plaintext, recipientList, options);

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
        var ct = Age.Encrypt(expected, [id.Recipient]);

        // Buffer overloads (each must return byte[])
        var p1 = Age.Decrypt(ct, [i]);
        var p2 = Age.Decrypt(ct, [i], options);
        var p3 = Age.Decrypt(ct, identities); // array → collection
        var p4 = Age.Decrypt(ct.AsSpan(), [i]); // explicit span
        var p5 = Age.Decrypt(ct, identityList); // List<T> → collection
        var p6 = Age.Decrypt(ct, identityList, options);

        Assert.All([p1, p2, p3, p4, p5, p6], p => Assert.Equal(expected, p));

        // Stream overloads
        DecryptFromStream(output => Age.Decrypt(new MemoryStream(ct), output, [i]));
        DecryptFromStream(output => Age.Decrypt(new MemoryStream(ct), output, [i], options));
        DecryptFromStream(output => Age.Decrypt(new MemoryStream(ct), output, identityList));
        DecryptFromStream(output => Age.Decrypt(new MemoryStream(ct), output, identityList, options));

        void DecryptFromStream(Action<MemoryStream> decrypt)
        {
            using var output = new MemoryStream();
            decrypt(output);
            Assert.Equal(expected, output.ToArray());
        }
    }

    /// <summary>
    ///     The streaming and detached families gained the same four shapes; this pins
    ///     that they resolve, since a collection there binds a different parameter slot
    ///     than in the buffer families above.
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

        Age.EncryptReader(new MemoryStream(expected), [r]).Dispose();
        Age.EncryptReader(new MemoryStream(expected), [r], encryptOptions).Dispose();
        Age.EncryptReader(new MemoryStream(expected), recipientList).Dispose();
        Age.EncryptReader(new MemoryStream(expected), recipientList, encryptOptions).Dispose();

        Age.EncryptWriter(new MemoryStream(), [r]).Dispose();
        Age.EncryptWriter(new MemoryStream(), [r], encryptOptions).Dispose();
        Age.EncryptWriter(new MemoryStream(), recipientList).Dispose();
        Age.EncryptWriter(new MemoryStream(), recipientList, encryptOptions).Dispose();

        var ct = Age.Encrypt(expected, [r]);
        Age.DecryptReader(new MemoryStream(ct), [i]).Dispose();
        Age.DecryptReader(new MemoryStream(ct), [i], decryptOptions).Dispose();
        Age.DecryptReader(new MemoryStream(ct), identityList).Dispose();
        Age.DecryptReader(new MemoryStream(ct), identityList, decryptOptions).Dispose();

        // Detached: the header and payload streams push the recipient slot out by two.
        RoundTripDetached((header, payload, input) => Age.EncryptDetached(input, header, payload, [r]),
            (header, payload, output) => Age.DecryptDetached(header, payload, output, [i]));
        RoundTripDetached((header, payload, input) => Age.EncryptDetached(input, header, payload, recipientList),
            (header, payload, output) => Age.DecryptDetached(header, payload, output, identityList));
        RoundTripDetached((header, payload, input) => Age.EncryptDetached(input, header, payload, [r]),
            (header, payload, output) => Age.DecryptDetached(header, payload, output, [i], decryptOptions));
        RoundTripDetached((header, payload, input) => Age.EncryptDetached(input, header, payload, recipientList),
            (header, payload, output) => Age.DecryptDetached(header, payload, output, identityList, decryptOptions));

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