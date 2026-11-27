using System.Text;
using System.Text.RegularExpressions;

namespace Age.Fuzz;

/// <summary>
/// Mutates an input from the pool: byte flips, insertions of format tokens, cuts, splices,
/// repeats for the limits, swapped lines; and, inside base64 (PEM bodies, armor, stanza bodies)
/// and Bech32 (keys, recipients), mutations of the decoded bytes, encoded again so that they
/// reach past the encoding and the checksum.
/// </summary>
internal static class Mutator
{
    /// <summary>The longest input the mutator makes, and the longest seed the worker takes.</summary>
    public const int MaxLength = 1 << 20;

    private static readonly string[] Tokens =
    [
        "\n", "\r\n", "\r", " ", "\t", "\0", "-> ", "---", "--- ", "=", "==", "AAAA", "////", "+",
        "age-encryption.org/v1", "age-encryption.org/v2", "X25519", "scrypt", "ssh-ed25519", "ssh-rsa",
        "mlkem768x25519", "p256tag", "mlkem768p256tag", "piv-p256", "grease",
        "-----BEGIN AGE ENCRYPTED FILE-----", "-----END AGE ENCRYPTED FILE-----",
        "-----BEGIN OPENSSH PRIVATE KEY-----", "-----END OPENSSH PRIVATE KEY-----",
        "-----BEGIN RSA PRIVATE KEY-----", "-----END RSA PRIVATE KEY-----", "Proc-Type: 4,ENCRYPTED",
        "DEK-Info: AES-128-CBC,", "AGE-SECRET-KEY-1", "AGE-SECRET-KEY-PQ-1", "AGE-PLUGIN-", "age1", "age1pq1",
        "age1tag1", "age1tagpq1", "age1x", "#", "# public key: ", "0", "1", "10", "18", "22", "64",
        "4294967295", "18446744073709551615", "-1", "99999999999999999999",
        "add-recipient", "add-identity", "wrap-file-key", "recipient-stanza", "extension-labels", "labels",
        "done", "ok", "fail", "unsupported", "msg", "confirm", "request-public", "request-secret",
        "file-key", "error", "internal", "recipient", "identity",
    ];

    private static readonly byte[][] Binary =
    [
        [0, 0, 0, 0], [0, 0, 0, 1], [0x7f, 0xff, 0xff, 0xff], [0xff, 0xff, 0xff, 0xff], [0x80, 0, 0, 0],
        [0, 0, 0, 0x0b], [0, 0, 0, 0x20], [0, 0, 0, 0x40], [0, 1, 0, 0],
        "openssh-key-v1\0"u8.ToArray(), "none"u8.ToArray(), "bcrypt"u8.ToArray(), "aes256-ctr"u8.ToArray(),
        "aes256-gcm@openssh.com"u8.ToArray(), "chacha20-poly1305@openssh.com"u8.ToArray(),
    ];

    // One in four from the seeds themselves (the first seedCount of the pool), so that however
    // the pool grows they are not crowded out.
    public static byte[] Mutate(List<byte[]> pool, int seedCount, Random rng)
    {
        var input = pool[rng.Next(seedCount > 0 && rng.Next(4) == 0 ? seedCount : pool.Count)];
        var rounds = 1 << rng.Next(4);
        for (var i = 0; i < rounds; i++)
            input = rng.Next(10) switch
            {
                < 2 when Base64Section(input, rng) is { } inner => inner,
                < 3 when Bech32Section(input, rng) is { } inner => inner,
                _ => Bytes(input, pool, rng),
            };
        return input.Length > MaxLength ? input[..MaxLength] : input;
    }

    // A plain byte mutation.
    private static byte[] Bytes(byte[] input, List<byte[]> pool, Random rng)
    {
        var b = input.ToList();
        var at = b.Count == 0 ? 0 : rng.Next(b.Count + 1);
        switch (rng.Next(12))
        {
            case 0 when b.Count > 0:
                b[Math.Min(at, b.Count - 1)] ^= (byte)(1 << rng.Next(8));
                break;
            case 1 when b.Count > 0:
                b[Math.Min(at, b.Count - 1)] = (byte)rng.Next(256);
                break;
            case 2 when b.Count > 0:
                b.RemoveRange(Math.Min(at, b.Count - 1), Math.Min(b.Count - Math.Min(at, b.Count - 1), 1 + rng.Next(16)));
                break;
            case 3:
                b.InsertRange(at, Encoding.ASCII.GetBytes(Tokens[rng.Next(Tokens.Length)]));
                break;
            case 4:
                b.InsertRange(at, Binary[rng.Next(Binary.Length)]);
                break;
            case 5 when b.Count > 0:
                // Overwrite with a binary token, as a length or a name in place.
                var token = Binary[rng.Next(Binary.Length)];
                for (var i = 0; i < token.Length && at + i < b.Count; i++)
                    b[at + i] = token[i];
                break;
            case 6 when b.Count > 0:
                // Duplicate a run.
                var start = rng.Next(b.Count);
                var len = Math.Min(b.Count - start, 1 + rng.Next(256));
                b.InsertRange(at, b.GetRange(start, len));
                break;
            case 7:
                // Truncate.
                return input[..(input.Length == 0 ? 0 : rng.Next(input.Length))];
            case 8:
                // Splice with another input.
                var other = pool[rng.Next(pool.Count)];
                var cut = other.Length == 0 ? 0 : rng.Next(other.Length);
                return [.. input[..Math.Min(at, input.Length)], .. other[cut..]];
            case 9:
                // Repeat a byte many times, for limits.
                b.InsertRange(at, Enumerable.Repeat(b.Count > 0 ? b[rng.Next(b.Count)] : (byte)'A', 1 << rng.Next(17)));
                break;
            case 10:
                // Swap two lines.
                var lines = Encoding.Latin1.GetString(input).Split('\n');
                if (lines.Length > 1)
                {
                    int x = rng.Next(lines.Length), y = rng.Next(lines.Length);
                    (lines[x], lines[y]) = (lines[y], lines[x]);
                }
                return Encoding.Latin1.GetBytes(string.Join('\n', lines));
            default:
                b.Insert(at, (byte)rng.Next(256));
                break;
        }
        return [.. b];
    }

    // Decodes the longest base64 run (PEM bodies, armor, stanza bodies, SSH blobs), mutates the
    // bytes, and encodes them again, wrapped as before.
    private static byte[]? Base64Section(byte[] input, Random rng)
    {
        var text = Encoding.Latin1.GetString(input);
        var lines = text.Split('\n');
        int bestStart = -1, bestEnd = -1;
        for (var i = 0; i < lines.Length; i++)
        {
            var j = i;
            while (j < lines.Length && lines[j].TrimEnd('\r').Length > 0 && lines[j].TrimEnd('\r').All(IsBase64))
                j++;
            if (j - i > bestEnd - bestStart)
                (bestStart, bestEnd) = (i, j);
            i = j;
        }
        if (bestStart < 0)
            return null;

        var joined = string.Concat(lines[bestStart..bestEnd].Select(l => l.TrimEnd('\r')));
        var padded = joined.TrimEnd('=');
        var bytes = TryBase64(padded);
        if (bytes is null || bytes.Length < 4)
            return null;
        var width = lines[bestStart].TrimEnd('\r').Length;
        var mutated = Bytes(bytes, [bytes], rng);
        var encoded = Convert.ToBase64String(mutated);
        if (!joined.EndsWith('='))
            encoded = encoded.TrimEnd('=');
        var wrapped = Enumerable.Range(0, (encoded.Length + width - 1) / Math.Max(width, 1)).Select(k => encoded.Substring(k * width, Math.Min(width, encoded.Length - k * width)));
        return Encoding.Latin1.GetBytes(string.Join('\n', [.. lines[..bestStart], .. wrapped, .. lines[bestEnd..]]));
    }

    private static bool IsBase64(char c) => char.IsAsciiLetterOrDigit(c) || c is '+' or '/' or '=';

    private static byte[]? TryBase64(string unpadded)
    {
        var s = unpadded + new string('=', (4 - unpadded.Length % 4) % 4);
        try
        {
            return Convert.FromBase64String(s);
        }
        catch (FormatException)
        {
            return null;
        }
    }

    // Decodes a Bech32 string (keys and recipients), mutates its data, and encodes it again with
    // a valid checksum, so the mutation reaches past the checksum.
    private static byte[]? Bech32Section(byte[] input, Random rng)
    {
        var text = Encoding.Latin1.GetString(input);
        var match = Regex.Match(text, "(age1[a-z0-9]*|AGE-[A-Z0-9-]*-1)[" + Bech32Checksum.Charset + Bech32Checksum.Charset.ToUpperInvariant() + "]{6,}");
        if (!match.Success)
            return null;
        var word = match.Value;
        var sep = word.LastIndexOf('1');
        var hrp = word[..sep];
        var upper = word.Any(char.IsAsciiLetterUpper);
        var data = word[(sep + 1)..].ToLowerInvariant().Select(c => (byte)Bech32Checksum.Charset.IndexOf(c)).ToArray();
        if (data.Any(d => d > 31) || data.Length < 7)
            return null;
        string encoded;
        if (rng.Next(2) == 0)
        {
            // The 5-bit groups themselves, for the padding and the length rules.
            var groups = Bytes(data[..^6], [data[..^6]], rng).Select(g => (byte)(g & 31)).ToArray();
            encoded = Bech32Checksum.EncodeGroups(hrp.ToLowerInvariant(), groups);
        }
        else
        {
            var payload = Bech32Checksum.ConvertBits(data[..^6], 5, 8, pad: false);
            if (payload is null)
                return null;
            encoded = Bech32Checksum.Encode(hrp.ToLowerInvariant(), Bytes(payload, [payload], rng));
        }
        if (upper)
            encoded = encoded.ToUpperInvariant();
        return Encoding.Latin1.GetBytes(text[..match.Index] + encoded + text[(match.Index + match.Length)..]);
    }
}

