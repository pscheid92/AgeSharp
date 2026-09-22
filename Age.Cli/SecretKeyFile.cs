namespace Age.Cli;

/// <summary>
/// A file holding secret key material: always a new file, and readable by its owner alone from
/// the moment it exists.
/// </summary>
/// <remarks>
/// Both properties come from the single open that creates it. Writing with default permissions
/// and restricting them afterwards left the key world-readable in between; checking for an
/// existing file and then writing let a symlink planted in between redirect the key elsewhere.
/// <see cref="FileMode.CreateNew"/> is O_CREAT|O_EXCL, which refuses anything already at the
/// path, symlinks included, and <see cref="FileStreamOptions.UnixCreateMode"/> sets the mode at
/// creation. This matches go-age, which opens with O_EXCL and 0600. On Windows the file takes
/// the directory's ACL instead.
/// </remarks>
internal static class SecretKeyFile
{
    /// <summary>Creates <paramref name="path"/> and writes <paramref name="contents"/> to it as UTF-8.</summary>
    /// <exception cref="IOException">Something already exists at <paramref name="path"/>.</exception>
    public static void Create(string path, string contents)
    {
        var options = new FileStreamOptions { Mode = FileMode.CreateNew, Access = FileAccess.Write };

        if (!OperatingSystem.IsWindows())
            options.UnixCreateMode = UnixFileMode.UserRead | UnixFileMode.UserWrite;

        using var writer = new StreamWriter(path, options);
        writer.Write(contents);
    }
}
