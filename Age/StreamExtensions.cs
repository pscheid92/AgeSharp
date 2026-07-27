namespace Age;

/// <summary>
/// Adds <see cref="EnsureMaterialized"/> to <see cref="Stream"/>.
/// </summary>
/// <remarks>
/// A C# 14 extension member, internal for the same reason as
/// <see cref="ArgumentExceptionExtensions"/>: extending a framework type is a liberty taken
/// for this library's own call sites, not for anything a consumer would see.
/// </remarks>
internal static class StreamExtensions
{
    extension(Stream stream)
    {
        /// <summary>
        /// Guarantees the stream has received at least one <c>Write</c> call.
        /// </summary>
        /// <remarks>
        /// Some writers create their destination lazily on the first write — the CLI's output
        /// file does this so a failed decrypt leaves no file behind. When the plaintext is
        /// empty, <c>CopyTo</c> never calls <c>Write</c> and such a destination would never
        /// come into existence, turning "decrypted an empty file" into "produced no file".
        /// An empty write forces materialization and is a no-op on ordinary streams.
        /// Call it only after a successful copy, so failures still leave no output behind.
        /// </remarks>
        public void EnsureMaterialized() => stream.Write(ReadOnlySpan<byte>.Empty);
    }
}
