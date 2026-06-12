using System.ComponentModel;
using System.Diagnostics;
using Age.Crypto;

namespace Age.Plugin;

internal sealed class PluginConnection : IDisposable
{
    private readonly TextReader _reader;
    private readonly TextWriter _writer;
    private readonly Process? _process;

    /// <summary>
    /// Production constructor: finds age-plugin-{name} on PATH, starts with --age-plugin={stateMachine}.
    /// </summary>
    public PluginConnection(string pluginName, string stateMachine)
    {
        // Defense-in-depth: never spawn a process from an unvalidated name.
        // The name becomes part of the executable path, so a value containing
        // path separators or "." could redirect execution to an arbitrary binary.
        ValidatePluginName(pluginName);
        var binaryName = $"age-plugin-{pluginName}";
        var startInfo = new ProcessStartInfo
        {
            FileName = binaryName,
            Arguments = $"--age-plugin={stateMachine}",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };

        try
        {
            _process = Process.Start(startInfo) ?? throw new AgePluginException($"failed to start plugin: {binaryName}");
        }
        catch (Win32Exception ex)
        {
            throw new AgePluginException($"plugin not found: {binaryName}", ex);
        }

        _reader = _process.StandardOutput;
        _writer = _process.StandardInput;
    }

    /// <summary>
    /// Test constructor: uses provided streams, no process.
    /// </summary>
    internal PluginConnection(TextReader reader, TextWriter writer)
    {
        _reader = reader;
        _writer = writer;
    }

    /// <summary>
    /// Validates a plugin name before it is used to build an executable path.
    /// Per the age-plugin spec a name is a non-empty sequence of lowercase
    /// letters, digits, and hyphens. Rejecting anything else prevents a crafted
    /// recipient/identity string from steering process execution (e.g. a name
    /// containing "/" or ".." resolving to an attacker-chosen binary).
    /// </summary>
    public static void ValidatePluginName(string pluginName)
    {
        if (string.IsNullOrEmpty(pluginName))
            throw new FormatException("plugin name must not be empty");

        foreach (var c in pluginName)
        {
            var ok = c is (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-';
            if (!ok)
                throw new FormatException($"invalid character in plugin name '{pluginName}': 0x{(int)c:X2}");
        }
    }

    public void WriteStanza(string type, string[] args, byte[] body)
    {
        _writer.Write("-> ");
        _writer.Write(type);

        foreach (var arg in args)
        {
            _writer.Write(' ');
            _writer.Write(arg);
        }

        _writer.Write('\n');

        var encoded = Base64Unpadded.Encode(body);
        var offset = 0;

        while (offset < encoded.Length)
        {
            var len = Math.Min(64, encoded.Length - offset);
            _writer.Write(encoded.AsSpan(offset, len));
            _writer.Write('\n');
            offset += len;
        }

        // Empty body or exact multiple of 64 chars both need an empty terminator line
        if (encoded.Length % 64 == 0)
            _writer.Write('\n');

        _writer.Flush();
    }

    public (string Type, string[] Args, byte[] Body)? ReadStanza()
    {
        var line = _reader.ReadLine();

        if (line == null)
            return null;

        if (!line.StartsWith("-> "))
            throw new AgePluginException($"expected stanza prefix '-> ', got: {line}");

        var parts = line[3..].Split(' ');

        if (parts.Length < 1 || string.IsNullOrEmpty(parts[0]))
            throw new AgePluginException("stanza must have at least a type");

        var stanzaType = parts[0];
        var stanzaArgs = parts.Length > 1 ? parts[1..] : [];
        var body = ReadBody();

        return (stanzaType, stanzaArgs, body);
    }

    private byte[] ReadBody()
    {
        var bodyChunks = new List<byte[]>();

        while (true)
        {
            var bodyLine = _reader.ReadLine() ?? throw new AgePluginException("unexpected end of stream while reading stanza body");

            switch (bodyLine.Length)
            {
                case > 64:
                    throw new AgePluginException("stanza body line exceeds 64 characters");
                case > 0:
                    bodyChunks.Add(Base64Unpadded.Decode(bodyLine));
                    break;
            }

            if (bodyLine.Length < 64)
                break;
        }

        var totalLen = bodyChunks.Sum(c => c.Length);
        var body = new byte[totalLen];
        var pos = 0;

        foreach (var chunk in bodyChunks)
        {
            chunk.CopyTo(body, pos);
            pos += chunk.Length;
        }

        return body;
    }

    public void Dispose()
    {
        if (_process is null)
            return;

        try
        {
            _process.StandardInput.Close();
        }
        catch
        {
            // EMPTY
        }

        _process.WaitForExit(5000);
        _process.Dispose();
    }
}