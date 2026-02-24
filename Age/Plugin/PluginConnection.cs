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
            _process = Process.Start(startInfo)
                ?? throw new AgePluginException($"failed to start plugin: {binaryName}");
        }
        catch (System.ComponentModel.Win32Exception ex)
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

        string encoded = Base64Unpadded.Encode(body);
        int offset = 0;
        while (offset < encoded.Length)
        {
            int len = Math.Min(64, encoded.Length - offset);
            _writer.Write(encoded.AsSpan(offset, len));
            _writer.Write('\n');
            offset += len;
        }
        // If the body encodes to an exact multiple of 64 chars, we need an empty final line
        if (encoded.Length > 0 && encoded.Length % 64 == 0)
        {
            _writer.Write('\n');
        }
        // If body is empty, write an empty line
        if (encoded.Length == 0)
        {
            _writer.Write('\n');
        }

        _writer.Flush();
    }

    public (string Type, string[] Args, byte[] Body)? ReadStanza()
    {
        string? line = _reader.ReadLine();
        if (line == null)
            return null;

        if (!line.StartsWith("-> "))
            throw new AgePluginException($"expected stanza prefix '-> ', got: {line}");

        string rest = line[3..];
        string[] parts = rest.Split(' ');
        if (parts.Length < 1 || string.IsNullOrEmpty(parts[0]))
            throw new AgePluginException("stanza must have at least a type");

        string type = parts[0];
        string[] args = parts.Length > 1 ? parts[1..] : [];

        // Read base64 body lines
        var bodyChunks = new List<byte[]>();
        while (true)
        {
            string? bodyLine = _reader.ReadLine();
            if (bodyLine == null)
                throw new AgePluginException("unexpected end of stream while reading stanza body");

            if (bodyLine.Length > 64)
                throw new AgePluginException("stanza body line exceeds 64 characters");

            if (bodyLine.Length > 0)
                bodyChunks.Add(Base64Unpadded.Decode(bodyLine));

            // A short line (< 64 chars) or empty line terminates the body
            if (bodyLine.Length < 64)
                break;
        }

        int totalLen = 0;
        foreach (var chunk in bodyChunks) totalLen += chunk.Length;
        var body = new byte[totalLen];
        int pos = 0;
        foreach (var chunk in bodyChunks)
        {
            chunk.CopyTo(body, pos);
            pos += chunk.Length;
        }

        return (type, args, body);
    }

    public void Dispose()
    {
        if (_process is not null)
        {
            try { _process.StandardInput.Close(); } catch { }
            _process.WaitForExit(5000);
            _process.Dispose();
        }
    }
}
