namespace AgeSharp.Crypto;

// Bech32 encoding/decoding per BIP-173.
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
internal static class Bech32
{
    private const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    private static readonly int[] BchGeneratorPolynomial =
        [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    private static int Polymod(ReadOnlySpan<byte> values)
    {
        var chk = 1;

        foreach (var v in values)
        {
            var b = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (var i = 0; i < 5; i++)
                if (((b >> i) & 1) != 0)
                    chk ^= BchGeneratorPolynomial[i];
        }

        return chk;
    }

    private static byte[] HrpExpand(string hrp)
    {
        var ret = new byte[hrp.Length * 2 + 1];

        for (var i = 0; i < hrp.Length; i++)
            ret[i] = (byte)(hrp[i] >> 5);

        ret[hrp.Length] = 0;
        for (var i = 0; i < hrp.Length; i++)
            ret[hrp.Length + 1 + i] = (byte)(hrp[i] & 31);

        return ret;
    }

    // BIP-173: valid iff polymod(hrpExpand(hrp) || data) == 1.
    private static bool VerifyChecksum(string hrp, ReadOnlySpan<byte> data)
    {
        var hrpExp = HrpExpand(hrp);
        var combined = new byte[hrpExp.Length + data.Length];

        hrpExp.CopyTo(combined, 0);
        data.CopyTo(combined.AsSpan(hrpExp.Length));

        return Polymod(combined) == 1;
    }

    // The XOR with 1 is what makes an all-zero checksum invalid.
    private static byte[] CreateChecksum(string hrp, ReadOnlySpan<byte> data)
    {
        var hrpExp = HrpExpand(hrp);
        var values = new byte[hrpExp.Length + data.Length + 6];

        hrpExp.CopyTo(values, 0);
        data.CopyTo(values.AsSpan(hrpExp.Length));

        var polymod = Polymod(values) ^ 1;

        var ret = new byte[6];
        for (var i = 0; i < 6; i++)
            ret[i] = (byte)((polymod >> (5 * (5 - i))) & 31);

        return ret;
    }

    public static string Encode(string hrp, ReadOnlySpan<byte> data)
    {
        var lowerHrp = hrp.ToLowerInvariant();
        var data5 = ConvertBits(data, 8, 5, true);
        var checksum = CreateChecksum(lowerHrp, data5);

        var result = new char[hrp.Length + 1 + data5.Length + 6];
        for (var i = 0; i < hrp.Length; i++)
            result[i] = hrp[i];

        result[hrp.Length] = '1';
        for (var i = 0; i < data5.Length; i++)
            result[hrp.Length + 1 + i] = Charset[data5[i]];

        for (var i = 0; i < 6; i++)
            result[hrp.Length + 1 + data5.Length + i] = Charset[checksum[i]];

        return new string(result);
    }

    public static (string Hrp, byte[] Data) Decode(string bech)
    {
        var sepPos = bech.LastIndexOf('1');
        if (sepPos < 1 || sepPos + 7 > bech.Length)
            throw new AgeFormatException("invalid bech32 string: separator not found or invalid position");

        // BIP-173: "Decoders MUST NOT accept strings where some characters are uppercase and some are lowercase."
        bool hasLower = false, hasUpper = false;
        foreach (var c in bech)
            switch (c)
            {
                case >= 'a' and <= 'z':
                    hasLower = true;
                    break;
                case >= 'A' and <= 'Z':
                    hasUpper = true;
                    break;
            }

        if (hasLower && hasUpper)
            throw new AgeFormatException("invalid bech32 string: mixed case");

        var lower = bech.ToLowerInvariant();
        var hrp = lower[..sepPos];
        var dataStr = lower[(sepPos + 1)..];

        var data5 = new byte[dataStr.Length];
        for (var i = 0; i < dataStr.Length; i++)
        {
            var idx = Charset.IndexOf(dataStr[i]);
            if (idx < 0)
                throw new AgeFormatException($"invalid bech32 character: {dataStr[i]}");

            data5[i] = (byte)idx;
        }

        if (!VerifyChecksum(hrp, data5))
            throw new AgeFormatException("invalid bech32 checksum");

        var data5NoCheck = data5[..^6];
        var data8 = ConvertBits(data5NoCheck, 5, 8, false);

        return (hrp, data8);
    }

    private static byte[] ConvertBits(ReadOnlySpan<byte> data, int fromBits, int toBits, bool pad)
    {
        var acc = 0;
        var bits = 0;
        var maxv = (1 << toBits) - 1;
        var ret = new List<byte>();

        foreach (var value in data)
        {
            if (value >> fromBits != 0)
                throw new AgeFormatException($"invalid value for {fromBits}-bit encoding: {value}");

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
                throw new AgeFormatException("excess padding in bech32 data");
            if (((acc << (toBits - bits)) & maxv) != 0)
                throw new AgeFormatException("non-zero padding bits in bech32 data");
        }

        return ret.ToArray();
    }
}