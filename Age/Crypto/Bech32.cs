namespace Age.Crypto;

internal static class Bech32
{
    private const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    private static readonly int[] Generator = { 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };

    private static int Polymod(ReadOnlySpan<byte> values)
    {
        int chk = 1;
        foreach (byte v in values)
        {
            int b = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (int i = 0; i < 5; i++)
            {
                if (((b >> i) & 1) != 0)
                    chk ^= Generator[i];
            }
        }
        return chk;
    }

    private static byte[] HrpExpand(string hrp)
    {
        var ret = new byte[hrp.Length * 2 + 1];
        for (int i = 0; i < hrp.Length; i++)
            ret[i] = (byte)(hrp[i] >> 5);
        ret[hrp.Length] = 0;
        for (int i = 0; i < hrp.Length; i++)
            ret[hrp.Length + 1 + i] = (byte)(hrp[i] & 31);
        return ret;
    }

    private static bool VerifyChecksum(string hrp, ReadOnlySpan<byte> data)
    {
        var hrpExp = HrpExpand(hrp);
        var combined = new byte[hrpExp.Length + data.Length];
        hrpExp.CopyTo(combined, 0);
        data.CopyTo(combined.AsSpan(hrpExp.Length));
        return Polymod(combined) == 1;
    }

    private static byte[] CreateChecksum(string hrp, ReadOnlySpan<byte> data)
    {
        var hrpExp = HrpExpand(hrp);
        var values = new byte[hrpExp.Length + data.Length + 6];
        hrpExp.CopyTo(values, 0);
        data.CopyTo(values.AsSpan(hrpExp.Length));
        int polymod = Polymod(values) ^ 1;
        var ret = new byte[6];
        for (int i = 0; i < 6; i++)
            ret[i] = (byte)((polymod >> (5 * (5 - i))) & 31);
        return ret;
    }

    public static string Encode(string hrp, ReadOnlySpan<byte> data)
    {
        // Bech32 checksums are always computed over the lowercase HRP
        string lowerHrp = hrp.ToLowerInvariant();
        var data5 = ConvertBits(data, 8, 5, true);
        var checksum = CreateChecksum(lowerHrp, data5);
        var result = new char[hrp.Length + 1 + data5.Length + 6];
        for (int i = 0; i < hrp.Length; i++)
            result[i] = hrp[i];
        result[hrp.Length] = '1';
        for (int i = 0; i < data5.Length; i++)
            result[hrp.Length + 1 + i] = Charset[data5[i]];
        for (int i = 0; i < 6; i++)
            result[hrp.Length + 1 + data5.Length + i] = Charset[checksum[i]];
        return new string(result);
    }

    public static (string Hrp, byte[] Data) Decode(string bech)
    {
        // Find separator (last '1')
        int sepPos = bech.LastIndexOf('1');
        if (sepPos < 1 || sepPos + 7 > bech.Length)
            throw new FormatException("invalid bech32 string: separator not found or invalid position");

        // Check for mixed case
        bool hasLower = false, hasUpper = false;
        foreach (char c in bech)
        {
            if (c >= 'a' && c <= 'z') hasLower = true;
            if (c >= 'A' && c <= 'Z') hasUpper = true;
        }
        if (hasLower && hasUpper)
            throw new FormatException("invalid bech32 string: mixed case");

        string lower = bech.ToLowerInvariant();
        string hrp = lower[..sepPos];
        string dataStr = lower[(sepPos + 1)..];

        var data5 = new byte[dataStr.Length];
        for (int i = 0; i < dataStr.Length; i++)
        {
            int idx = Charset.IndexOf(dataStr[i]);
            if (idx < 0)
                throw new FormatException($"invalid bech32 character: {dataStr[i]}");
            data5[i] = (byte)idx;
        }

        if (!VerifyChecksum(hrp, data5))
            throw new FormatException("invalid bech32 checksum");

        // Strip checksum
        var data5NoCheck = data5[..^6];
        var data8 = ConvertBits(data5NoCheck, 5, 8, false);
        return (hrp, data8);
    }

    private static byte[] ConvertBits(ReadOnlySpan<byte> data, int fromBits, int toBits, bool pad)
    {
        int acc = 0;
        int bits = 0;
        int maxv = (1 << toBits) - 1;
        var ret = new List<byte>();

        foreach (byte value in data)
        {
            if ((value >> fromBits) != 0)
                throw new FormatException($"invalid value for {fromBits}-bit encoding: {value}");
            acc = (acc << fromBits) | value;
            bits += fromBits;
            while (bits >= toBits)
            {
                bits -= toBits;
                ret.Add((byte)((acc >> bits) & maxv));
            }
        }

        if (pad)
        {
            if (bits > 0)
                ret.Add((byte)((acc << (toBits - bits)) & maxv));
        }
        else
        {
            if (bits >= fromBits)
                throw new FormatException("excess padding in bech32 data");
            if (((acc << (toBits - bits)) & maxv) != 0)
                throw new FormatException("non-zero padding bits in bech32 data");
        }

        return ret.ToArray();
    }
}
