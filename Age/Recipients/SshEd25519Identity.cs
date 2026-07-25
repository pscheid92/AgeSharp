using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using AgeSharp.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace AgeSharp;

/// <summary>
///     An identity backed by an ssh-ed25519 private key, converted to X25519 for the
///     age <c>ssh-ed25519</c> recipient type. Disposing zeroes the converted key.
/// </summary>
public sealed class SshEd25519Identity : IIdentityWithRecipient, IDisposable
{
    private const int KeySize = 32;
    private const int WrappedKeySize = 32; // 16-byte file key + 16-byte Poly1305 tag
    private readonly byte[] _sshWireBytes;
    private readonly string _tag;

    private readonly byte[] _x25519PrivateKey;
    private readonly byte[] _x25519PublicKey;
    private bool _disposed;

    private SshEd25519Identity(byte[] x25519PrivateKey, byte[] x25519PublicKey, byte[] sshWireBytes)
    {
        _x25519PrivateKey = x25519PrivateKey;
        _x25519PublicKey = x25519PublicKey;
        _sshWireBytes = sshWireBytes;
        _tag = SshKeyParser.ComputeTag(sshWireBytes);
    }

    /// <summary>The matching recipient, derived from the SSH public key.</summary>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public SshEd25519Recipient Recipient
    {
        get
        {
            // A disposed identity is unusable by contract, even where the public half survives.
            ObjectDisposedException.ThrowIf(_disposed, this);
            return new SshEd25519Recipient(_sshWireBytes, _x25519PublicKey);
        }
    }

    IRecipient IIdentityWithRecipient.Recipient => Recipient;

    /// <summary>Returns null for stanzas of another type, or wrapped for a different key.</summary>
    /// <exception cref="AgeFormatException">The stanza claims to be ssh-ed25519 but is malformed.</exception>
    /// <exception cref="ObjectDisposedException">The identity has been disposed.</exception>
    public byte[]? Unwrap(Stanza stanza)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);

        if (stanza.Type != AgeProtocol.SshEd25519StanzaType)
            return null;

        if (stanza.Args.Count != 2)
            throw new AgeFormatException($"ssh-ed25519 stanza must have exactly 2 arguments, got {stanza.Args.Count}");

        var stanzaTag = stanza.Args[0];
        if (stanzaTag != _tag)
            return null;

        var ephPubBytes = ParseHelpers.DecodeArg(stanza.Args[1], KeySize, "ssh-ed25519 ephemeral key");

        if (stanza.Body.Length != WrappedKeySize)
            throw new AgeFormatException(
                $"ssh-ed25519 stanza body must be {WrappedKeySize} bytes, got {stanza.Body.Length}");

        var ephPub = new X25519PublicKeyParameters(ephPubBytes);
        var privateKey = new X25519PrivateKeyParameters(_x25519PrivateKey);

        // Guarded against a low-order ephemeral, so a crafted stanza cannot leak a BC exception.
        var rawSS = CryptoHelper.X25519Agree(privateKey, ephPub);

        var tweak = CryptoHelper.HkdfDerive([], _sshWireBytes, AgeProtocol.SshEd25519HkdfLabel, KeySize);

        var tweakPrivate = new X25519PrivateKeyParameters(tweak);
        var rawSSPub = new X25519PublicKeyParameters(rawSS);

        var tweakedSS = CryptoHelper.X25519Agree(tweakPrivate, rawSSPub);

        var salt = (byte[])[.. ephPubBytes, .. _x25519PublicKey];
        var wrapKey = CryptoHelper.HkdfDerive(tweakedSS, salt, AgeProtocol.SshEd25519HkdfLabel, KeySize);

        try
        {
            var zeroNonce = new byte[12];
            return CryptoHelper.ChaChaDecrypt(wrapKey, zeroNonce, stanza.Body.Span);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(wrapKey);
            CryptographicOperations.ZeroMemory(tweakedSS);
            CryptographicOperations.ZeroMemory(rawSS);
            CryptographicOperations.ZeroMemory(tweak);
        }
    }

    /// <summary>Zeroes the converted private key material.</summary>
    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        CryptographicOperations.ZeroMemory(_x25519PrivateKey);
    }

    /// <summary>Parses an ssh-ed25519 private key from PEM text (OpenSSH format).</summary>
    /// <exception cref="AgeFormatException">The text is not a valid ssh-ed25519 private key.</exception>
    public static SshEd25519Identity Parse(string pemText)
    {
        var (keyType, publicWireBytes, privateKey) = SshKeyParser.ParsePrivateKey(pemText);

        if (keyType != "ssh-ed25519")
            throw new AgeFormatException($"expected ssh-ed25519 private key, got {keyType}");

        if (privateKey is not Ed25519PrivateKeyParameters ed25519Private)
            throw new AgeFormatException("declared ssh-ed25519 but the key data is a different type");

        var x25519Private = Ed25519Converter.PrivateKeyToX25519(ed25519Private.GetEncoded());

        var x25519PrivateParam = new X25519PrivateKeyParameters(x25519Private);
        var x25519Pub = x25519PrivateParam.GeneratePublicKey().GetEncoded();

        return new SshEd25519Identity(x25519Private, x25519Pub, publicWireBytes);
    }

    /// <summary>Returns false instead of throwing when the input is null or malformed.</summary>
    public static bool TryParse([NotNullWhen(true)] string? pemText,
        [MaybeNullWhen(false)] out SshEd25519Identity result)
    {
        return ParseHelpers.TryParse(pemText, Parse, out result);
    }
}