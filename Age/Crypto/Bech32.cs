namespace Age.Crypto;

// Bech32 encoding/decoding per BIP-173.
// Reference: https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
internal static class Bech32
{
    // BIP-173: "We use the same character set as in base32 [RFC 4648], but in a different order."
    private const string Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

    // BIP-173: Generator polynomial coefficients for the BCH code used in the checksum.
    private static readonly int[] Generator =
        [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

    // BIP-173: "The values [...] are fed into a feedback mechanism [...] xored into a checksum."
    // Computes the BCH checksum over the expanded HRP + data. Valid data produces polymod == 1.
    private static int Polymod(ReadOnlySpan<byte> values)
    {
        var chk = 1;

        foreach (var v in values)
        {
            var b = chk >> 25;
            chk = ((chk & 0x1ffffff) << 5) ^ v;
            for (var i = 0; i < 5; i++)
            {
                if (((b >> i) & 1) != 0)
                    chk ^= Generator[i];
            }
        }

        return chk;
    }

    // BIP-173: Expand the HRP into two halves — high bits (>> 5) and low bits (& 31) —
    // separated by a zero byte. This is fed into Polymod to bind the checksum to the HRP.
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

    // BIP-173: "A valid Bech32 string [...] MUST pass this check: polymod(hrpExpand(hrp) || data) == 1"
    private static bool VerifyChecksum(string hrp, ReadOnlySpan<byte> data)
    {
        var hrpExp = HrpExpand(hrp);
        var combined = new byte[hrpExp.Length + data.Length];

        hrpExp.CopyTo(combined, 0);
        data.CopyTo(combined.AsSpan(hrpExp.Length));

        return Polymod(combined) == 1;
    }

    // BIP-173: Compute 6-byte checksum such that polymod(hrpExpand(hrp) || data || checksum) == 1.
    // The XOR with 1 ensures the all-zero checksum is not valid.
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

    // BIP-173: Encode as HRP + "1" + base32(data) + checksum.
    // The separator "1" is the last occurrence of "1" in the string.
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

    // BIP-173: Decode by finding the last "1" separator, validating the checksum,
    // and converting the 5-bit data back to 8-bit bytes.
    public static (string Hrp, byte[] Data) Decode(string bech)
    {
        // BIP-173: "The last '1' in the string is the separator."
        var sepPos = bech.LastIndexOf('1');
        if (sepPos < 1 || sepPos + 7 > bech.Length)
            throw new FormatException("invalid bech32 string: separator not found or invalid position");

        // BIP-173: "Decoders MUST NOT accept strings where some characters are uppercase and some are lowercase."
        bool hasLower = false, hasUpper = false;
        foreach (var c in bech)
        {
            switch (c)
            {
                case >= 'a' and <= 'z':
                    hasLower = true;
                    break;
                case >= 'A' and <= 'Z':
                    hasUpper = true;
                    break;
            }
        }

        if (hasLower && hasUpper)
            throw new FormatException("invalid bech32 string: mixed case");

        var lower = bech.ToLowerInvariant();
        var hrp = lower[..sepPos];
        var dataStr = lower[(sepPos + 1)..];

        var data5 = new byte[dataStr.Length];
        for (var i = 0; i < dataStr.Length; i++)
        {
            var idx = Charset.IndexOf(dataStr[i]);
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

    // BIP-173: General power-of-2 base conversion. Regroups bits from fromBits-sized groups
    // to toBits-sized groups. Used for 8-bit <-> 5-bit conversion.
    private static byte[] ConvertBits(ReadOnlySpan<byte> data, int fromBits, int toBits, bool pad)
    {
        var acc = 0;
        var bits = 0;
        var maxv = (1 << toBits) - 1;
        var ret = new List<byte>();

        foreach (var value in data)
        {
            if (value >> fromBits != 0)
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