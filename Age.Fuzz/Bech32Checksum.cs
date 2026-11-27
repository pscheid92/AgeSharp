namespace Age.Fuzz;

/// <summary>A Bech32 encoder of the fuzzer's own (BIP 173), so that mutated keys carry valid checksums.</summary>
internal static class Bech32Checksum
{
    public const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    public static string Encode(string hrp, byte[] payload) =>
        EncodeGroups(hrp, ConvertBits(payload, 8, 5, pad: true)!);

    /// <summary>Encodes 5-bit groups as they are, padding and all, with a valid checksum.</summary>
    public static string EncodeGroups(string hrp, byte[] data)
    {
        var values = HrpExpand(hrp).Concat(data).Concat(new byte[6]).ToArray();
        var mod = Polymod(values) ^ 1;
        var checksum = Enumerable.Range(0, 6).Select(i => (byte)((mod >> (5 * (5 - i))) & 31));
        return hrp + "1" + new string(data.Concat(checksum).Select(d => Charset[d]).ToArray());
    }

    public static byte[]? ConvertBits(byte[] data, int from, int to, bool pad)
    {
        int acc = 0, bits = 0, max = (1 << to) - 1;
        var result = new List<byte>();
        foreach (var value in data)
        {
            acc = (acc << from) | value;
            bits += from;
            while (bits >= to)
            {
                bits -= to;
                result.Add((byte)((acc >> bits) & max));
            }
        }
        if (pad && bits > 0)
            result.Add((byte)((acc << (to - bits)) & max));
        else if (!pad && (bits >= from || ((acc << (to - bits)) & max) != 0))
            return null;
        return [.. result];
    }

    private static byte[] HrpExpand(string hrp) =>
        [.. hrp.Select(c => (byte)(c >> 5)), 0, .. hrp.Select(c => (byte)(c & 31))];

    private static uint Polymod(byte[] values)
    {
        uint[] gen = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
        uint chk = 1;
        foreach (var v in values)
        {
            var b = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (var i = 0; i < 5; i++)
                if (((b >> i) & 1) != 0)
                    chk ^= gen[i];
        }
        return chk;
    }
}

