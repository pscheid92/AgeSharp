using System.Security.Cryptography;
using System.Text;
using AgeSharp.Crypto;

namespace AgeSharp;

internal sealed class Header
{
    private const string VersionLine = "age-encryption.org/v1";

    public List<Stanza> Stanzas { get; } = new();
    public byte[] Mac { get; private set; } = [];

    private byte[] HeaderBytesForMac { get; set; } = [];

    public static Header Parse(HeaderReader reader)
    {
        var header = new Header();

        var versionLine = reader.ReadLine() ?? throw new AgeFormatException("empty header");

        if (versionLine != VersionLine)
            throw new AgeFormatException($"unsupported version: {versionLine}");

        while (true)
        {
            var line = reader.ReadLine() ?? throw new AgeFormatException("unexpected end of header");

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
                throw new AgeFormatException($"unexpected line in header: {line}");
            }
        }

        return header.Stanzas.Count > 0
            ? header
            : throw new AgeFormatException("header contains no stanzas");
    }

    private static void ParseMacLine(Header header, string line, HeaderReader reader)
    {
        if (!line.StartsWith("--- "))
            throw new AgeFormatException($"expected MAC line starting with '--- ', got: {line}");

        var macB64 = line[4..];

        try
        {
            header.Mac = Base64Unpadded.Decode(macB64);
        }
        catch (AgeFormatException ex)
        {
            throw new AgeFormatException($"invalid MAC encoding: {ex.Message}", ex);
        }

        if (header.Mac.Length != 32)
            throw new AgeFormatException($"MAC must be 32 bytes, got {header.Mac.Length}");

        // The MAC covers everything through "---", no trailing space; the raw bytes include the
// "--- <mac>\n" line, so strip that suffix.
        var allRaw = reader.RawBytes;
        var macSuffix = Encoding.ASCII.GetBytes(" " + macB64 + "\n");
        header.HeaderBytesForMac = allRaw[..^macSuffix.Length].ToArray();
    }

    public void VerifyMac(ReadOnlySpan<byte> fileKey)
    {
        var computedMac = ComputeMac(fileKey, HeaderBytesForMac);
        if (!CryptographicOperations.FixedTimeEquals(computedMac, Mac))
            throw new AgeAuthenticationException("header MAC verification failed");
    }

    public static byte[] ComputeMac(ReadOnlySpan<byte> fileKey, ReadOnlySpan<byte> headerBytes)
    {
        var hmacKeyBytes = CryptoHelper.HkdfDerive(fileKey, ReadOnlySpan<byte>.Empty, "header", 32);

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

        var headerBytesForMac = headerStream.ToArray();
        var mac = ComputeMac(fileKey, headerBytesForMac);

        writer.Write(' ');
        writer.Write(Base64Unpadded.Encode(mac));
        writer.Write('\n');
        writer.Flush();

        headerStream.Position = 0;
        headerStream.CopyTo(stream);
    }
}