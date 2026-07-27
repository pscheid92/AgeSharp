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
        // Defense in depth: the caller should already have validated the name, but this is
        // the sink that turns it into an executable path, so never launch an invalid one.
        if (!PluginNameValidator.IsValid(pluginName))
            throw new AgePluginException($"refusing to launch plugin with invalid name: '{pluginName}'");

        var binaryName = $"age-plugin-{pluginName}";

        // Resolve against PATH explicitly. Process.Start would otherwise find a bare file
        // name in the caller's current working directory — arbitrary code execution from
        // any untrusted tree the caller happens to be sitting in — which the age-plugin
        // spec prohibits verbatim.
        var binaryPath = PluginLocator.Find(binaryName)
                         ?? throw new AgePluginException($"plugin not found: {binaryName}");

        var startInfo = new ProcessStartInfo
        {
            FileName = binaryPath,
            Arguments = $"--age-plugin={stateMachine}",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            // Don't hand the plugin the caller's working directory either; go-age uses
            // the temp directory here for the same reason.
            WorkingDirectory = Path.GetTempPath(),
        };

        try
        {
            _process = Process.Start(startInfo) ?? throw new AgePluginException($"failed to start plugin: {binaryName}");
        }
        catch (Win32Exception ex)
        {
            throw new AgePluginException($"failed to start plugin: {binaryName}: {ex.Message}", ex);
        }

        _reader = _process.StandardOutput;
        _writer = _process.StandardInput;

        // The redirect above creates a pipe. Nothing read it, so once a chatty plugin wrote past
        // the OS pipe buffer (65536 bytes on macOS and Linux) its write(2) blocked while we sat
        // blocked reading stdout — a deadlock with no timeout. Drain it off-thread, and keep the
        // tail so a failure can quote what the plugin actually said.
        _process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is null)
                return;

            lock (_stderrTail)
            {
                _stderrTail.Enqueue(e.Data);

                while (_stderrTail.Count > StderrTailLines)
                    _stderrTail.Dequeue();
            }
        };

        _process.BeginErrorReadLine();
    }

    private const int StderrTailLines = 20;

    private readonly Queue<string> _stderrTail = new();

    /// <summary>The last few lines the plugin wrote to stderr, for quoting in error messages.</summary>
    internal string StderrTail
    {
        get
        {
            lock (_stderrTail)
                return _stderrTail.Count == 0 ? "" : string.Join('\n', _stderrTail);
        }
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

        // Stanza.Parse validates the charset on the file-parsing path; this path did not, so a
        // plugin's strings reached `new Stanza(...)` and surfaced as a raw ArgumentException out
        // of a method documented to throw AgePluginException. Two consecutive spaces sufficed.
        // Validating here covers PluginRecipient and PluginIdentity with one guard.
        ValidateStanzaString(stanzaType, "type");

        foreach (var arg in stanzaArgs)
            ValidateStanzaString(arg, "argument");

        var body = ReadBody();

        return (stanzaType, stanzaArgs, body);
    }

    // Printable ASCII only (0x21-0x7E): a space or newline would corrupt the stanza framing.
    private static void ValidateStanzaString(string s, string what)
    {
        if (string.IsNullOrEmpty(s))
            throw new AgePluginException($"plugin sent an empty stanza {what}");

        var invalid = s.AsSpan().IndexOfAnyExceptInRange('!', '~');

        if (invalid >= 0)
            throw new AgePluginException(
                $"plugin sent an invalid character in a stanza {what}: 0x{(int)s[invalid]:X2}");
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
                    // Base64Unpadded.Decode throws FormatException for malformed, padded and
                    // non-canonical input alike. Unwrapped, that escaped a method documented to
                    // throw AgePluginException — DecodeOptionLabel next door already got this right.
                    try
                    {
                        bodyChunks.Add(Base64Unpadded.Decode(bodyLine));
                    }
                    catch (FormatException ex)
                    {
                        throw new AgePluginException($"plugin sent an invalid stanza body: {ex.Message}", ex);
                    }

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
            // Already closed or the process is gone; nothing to do either way.
        }

        // Closing stdin asks the plugin to exit. If it declines, kill it: previously the wait
        // simply expired and the process was abandoned, leaking it (and its hold on any hardware
        // token) for the lifetime of the host.
        if (!_process.WaitForExit(ExitGraceMilliseconds))
        {
            try
            {
                _process.Kill(entireProcessTree: true);
                _process.WaitForExit(ExitGraceMilliseconds);
            }
            catch (InvalidOperationException)
            {
                // Raced us and exited on its own between the wait and the kill.
            }
        }

        _process.Dispose();
    }

    private const int ExitGraceMilliseconds = 5000;
}