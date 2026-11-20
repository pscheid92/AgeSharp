namespace AgeSharp;

/// <summary>
/// age's ASCII armor on its own, with no key: converting a binary age file to its armored form
/// and back. Armor is a text container around the ciphertext, so converting only re-encodes it.
/// </summary>
/// <remarks>
/// Encryption armors by itself when asked to (<see cref="AgeEncryptOptions.Armor"/>), and
/// decryption recognises armor by itself; these are for files that are already encrypted.
/// Neither method disposes the streams it is given.
/// </remarks>
public static class Armor
{
    /// <summary>
    /// Writes <paramref name="binary"/>, read to its end, to <paramref name="armored"/> as ASCII
    /// armor: the begin marker, 64-column base64 lines, the end marker.
    /// </summary>
    public static void Encode(Stream binary, Stream armored)
    {
        ArgumentNullException.ThrowIfNull(binary);
        ArgumentNullException.ThrowIfNull(armored);

        using var writer = new ArmorWriterStream(armored);
        binary.CopyTo(writer);
        writer.Finish();
    }

    /// <summary>The asynchronous <see cref="Encode"/>.</summary>
    public static async Task EncodeAsync(Stream binary, Stream armored, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(binary);
        ArgumentNullException.ThrowIfNull(armored);

        await using var writer = new ArmorWriterStream(armored);
        await binary.CopyToAsync(writer, cancellationToken).ConfigureAwait(false);
        await writer.FinishAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Writes what the armor in <paramref name="armored"/>, read to its end, decodes to, to
    /// <paramref name="binary"/>. The armor is held to the rules decryption applies: canonical
    /// base64 in 64-column lines, the markers, and only whitespace around them.
    /// </summary>
    /// <param name="armored">The armored file.</param>
    /// <param name="binary">Where the binary file is written.</param>
    /// <param name="options">The armor line bound (<see cref="AgeDecryptOptions.MaxArmorLineBytes"/>); the other options do not apply.</param>
    /// <exception cref="AgeArmorException">The input is not armor, or breaks its rules.</exception>
    public static void Decode(Stream armored, Stream binary, AgeDecryptOptions? options = null)
    {
        ArgumentNullException.ThrowIfNull(armored);
        ArgumentNullException.ThrowIfNull(binary);

        using var decoded = AsciiArmor.Dearmor(armored, options);
        decoded.CopyTo(binary);
    }

    /// <summary>The asynchronous <see cref="Decode"/>.</summary>
    /// <exception cref="AgeArmorException">The input is not armor, or breaks its rules.</exception>
    public static async Task DecodeAsync(Stream armored, Stream binary, AgeDecryptOptions? options = null, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(armored);
        ArgumentNullException.ThrowIfNull(binary);

        var decoded = await AsciiArmor.DearmorAsync(armored, cancellationToken, options).ConfigureAwait(false);

        await using (decoded.ConfigureAwait(false))
            await decoded.CopyToAsync(binary, cancellationToken).ConfigureAwait(false);
    }
}
