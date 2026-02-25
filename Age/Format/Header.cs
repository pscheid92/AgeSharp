using System.Security.Cryptography;
using System.Text;
using Age.Crypto;

namespace Age.Format;

internal sealed class Header
{
    private const string VersionLine = "age-encryption.org/v1";

    public List<Stanza> Stanzas { get; } = new();
    public byte[] Mac { get; private set; } = [];

    /// <summary>
    /// Raw header bytes through "--- " (inclusive, before MAC value) for MAC computation.
    /// </summary>
    public byte[] HeaderBytesForMac { get; private set; } = [];

    public static Header Parse(HeaderReader reader)
    {
        var header = new Header();

        var versionLine = reader.ReadLine()
            ?? throw new AgeHeaderException("empty header");

        if (versionLine != VersionLine)
            throw new AgeHeaderException($"unsupported version: {versionLine}");

        // Read stanzas until we hit the MAC line
        while (true)
        {
            var line = reader.ReadLine()
                ?? throw new AgeHeaderException("unexpected end of header");

            if (line.StartsWith("-> "))
            {
                reader.PushBack(line);
                header.Stanzas.Add(Stanza.Parse(reader));
            }
            else if (line.StartsWith("---"))
            {
                ParseMacLine(header, line, reader);
                break;
            }
            else
            {
                throw new AgeHeaderException($"unexpected line in header: {line}");
            }
        }

        if (header.Stanzas.Count == 0)
            throw new AgeHeaderException("header contains no stanzas");

        return header;
    }

    private static void ParseMacLine(Header header, string line, HeaderReader reader)
    {
        if (!line.StartsWith("--- "))
            throw new AgeHeaderException($"expected MAC line starting with '--- ', got: {line}");

        var macB64 = line[4..];

        try
        {
            header.Mac = Base64Unpadded.Decode(macB64);
        }
        catch (FormatException ex)
        {
            throw new AgeHeaderException($"invalid MAC encoding: {ex.Message}", ex);
        }

        if (header.Mac.Length != 32)
            throw new AgeHeaderException($"MAC must be 32 bytes, got {header.Mac.Length}");

        // The Go reference computes MAC over everything through "---" (no trailing space).
        // The raw bytes include "--- <mac_b64>\n", so strip the suffix.
        var allRaw = reader.RawBytes;
        var macSuffix = Encoding.ASCII.GetBytes(" " + macB64 + "\n");
        header.HeaderBytesForMac = allRaw[..^macSuffix.Length].ToArray();
    }

    public void VerifyMac(ReadOnlySpan<byte> fileKey)
    {
        var computedMac = ComputeMac(fileKey, HeaderBytesForMac);
        if (!CryptographicOperations.FixedTimeEquals(computedMac, Mac))
            throw new AgeHmacException("header MAC verification failed");
    }

    public static byte[] ComputeMac(ReadOnlySpan<byte> fileKey, ReadOnlySpan<byte> headerBytes)
    {
        // HKDF-SHA-256(ikm=fileKey, salt="", info="header") → hmac_key (32 bytes)
        var hmacKeyBytes = CryptoHelper.HkdfDerive(fileKey, ReadOnlySpan<byte>.Empty, "header", 32);

        // HMAC-SHA-256(key=hmac_key, message=headerBytes)
        return CryptoHelper.HmacSha256(hmacKeyBytes, headerBytes);
    }

    public void WriteTo(Stream stream, ReadOnlySpan<byte> fileKey)
    {
        var headerStream = new MemoryStream();
        var writer = new StreamWriter(headerStream, leaveOpen: true) { NewLine = "\n" };

        writer.Write(VersionLine);
        writer.Write('\n');
        writer.Flush();

        foreach (var stanza in Stanzas)
            stanza.WriteTo(headerStream);

        writer.Write("---");
        writer.Flush();

        // Compute MAC over everything written so far (through "---", no trailing space)
        var headerBytesForMac = headerStream.ToArray();
        var mac = ComputeMac(fileKey, headerBytesForMac);

        writer.Write(' ');
        writer.Write(Base64Unpadded.Encode(mac));
        writer.Write('\n');
        writer.Flush();

        // Write to actual output
        headerStream.Position = 0;
        headerStream.CopyTo(stream);
    }
}
