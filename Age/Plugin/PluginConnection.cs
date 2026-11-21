using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using AgeSharp.Crypto;

namespace AgeSharp;

internal sealed class PluginConnection : IDisposable
{
    private readonly TextReader _reader;
    // To a plugin process, stanzas go to stdin's stream as bytes this connection clears; never
    // through Process.StandardInput, a StreamWriter whose buffers keep the last text written, a
    // file key or a secret, until something overwrites it. The writer is the test seam's.
    private readonly Stream? _stdin;
    private readonly TextWriter? _writer;
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

        // Resolved explicitly: Process.Start would find a bare name in the caller's working
        // directory, which age-plugin.md prohibits ("MUST NOT be searched").
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
        _stdin = _process.StandardInput.BaseStream;

        // Drained off-thread: an undrained stderr pipe deadlocks once the plugin writes past the
        // OS buffer (65536 bytes on macOS and Linux). The tail is kept for error messages.
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

    private const int StderrFlushMilliseconds = 500;

    private readonly Queue<string> _stderrTail = new();

    /// <summary>
    /// Builds an <see cref="AgePluginException"/> carrying the last few lines the plugin wrote to
    /// stderr. When a plugin dies or misbehaves its diagnostics are the only evidence of why, and
    /// before the stderr pipe was drained they were unreachable.
    /// </summary>
    internal AgePluginException Failure(string message, Exception? inner = null)
    {
        // BeginErrorReadLine delivers asynchronously, so the plugin's last words may not have
        // arrived yet. WaitForExit(int) does not flush the async readers; the parameterless
        // overload does.
        if (_process is not null && _process.WaitForExit(StderrFlushMilliseconds))
            _process.WaitForExit();

        string tail;

        lock (_stderrTail)
            tail = _stderrTail.Count == 0 ? "" : string.Join('\n', _stderrTail);

        var full = tail.Length == 0 ? message : $"{message}; plugin stderr:\n{tail}";

        return inner is null ? new AgePluginException(full) : new AgePluginException(full, inner);
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
    /// Writes one stanza to the plugin.
    /// </summary>
    /// <remarks>
    /// A plugin that has already died leaves us writing into a closed pipe, which surfaces as a
    /// raw <see cref="IOException"/> out of a path documented to throw
    /// <see cref="AgePluginException"/>. Which end of the protocol noticed the death first is a
    /// timing accident — the client writes its whole request before reading a byte, so on a fast
    /// machine the write fails and on a slow one the read does. Both now report the same way,
    /// with the plugin's stderr attached.
    /// </remarks>
    /// <exception cref="AgePluginException">The plugin exited or the pipe broke.</exception>
    public void WriteStanza(string type, string[] args, byte[] body)
    {
        try
        {
            WriteStanzaCore(type, args, body);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            throw Failure("the plugin exited before the request could be sent", ex);
        }
    }

    private void WriteStanzaCore(string type, string[] args, byte[] body)
    {
        // The whole stanza, laid out as the wire has it, in buffers that are cleared once it is
        // written: the body may be a file key, or a secret the user typed.
        var encodedLength = Base64Unpadded.MaxEncodedLength(body.Length);
        var encoded = ArrayPool<char>.Shared.Rent(encodedLength);
        var line = ArrayPool<byte>.Shared.Rent(StanzaLength(type, args, encodedLength));

        try
        {
            var length = Base64Unpadded.Encode(body, encoded);
            var written = Lay(type, args, encoded.AsSpan(0, length), line);

            if (_stdin is not null)
            {
                _stdin.Write(line, 0, written);
                _stdin.Flush();
            }
            else
            {
                _writer!.Write(Encoding.ASCII.GetString(line, 0, written));
                _writer.Flush();
            }
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(encoded.AsSpan()));
            CryptographicOperations.ZeroMemory(line);
            ArrayPool<char>.Shared.Return(encoded);
            ArrayPool<byte>.Shared.Return(line);
        }
    }

    // "-> type args\n", then the body in 64-column lines, the last shorter (empty for a body
    // that fills its lines), each ended by a newline.
    private static int StanzaLength(string type, string[] args, int encodedLength) =>
        3 + type.Length + args.Sum(a => 1 + a.Length) + 1 + encodedLength + encodedLength / Stanza.ColumnsPerLine + 1;

    private static int Lay(string type, string[] args, ReadOnlySpan<char> encoded, Span<byte> into)
    {
        var at = Ascii("-> ", into);
        at += Ascii(type, into[at..]);

        foreach (var arg in args)
        {
            into[at++] = (byte)' ';
            at += Ascii(arg, into[at..]);
        }

        into[at++] = (byte)'\n';

        while (encoded.Length >= Stanza.ColumnsPerLine)
        {
            at += Ascii(encoded[..Stanza.ColumnsPerLine], into[at..]);
            into[at++] = (byte)'\n';
            encoded = encoded[Stanza.ColumnsPerLine..];
        }

        at += Ascii(encoded, into[at..]);
        into[at++] = (byte)'\n';
        return at;
    }

    // Types, arguments and base64 are ASCII by the stanza rules, so a character is a byte.
    private static int Ascii(ReadOnlySpan<char> text, Span<byte> into)
    {
        for (var i = 0; i < text.Length; i++)
            into[i] = (byte)text[i];

        return text.Length;
    }

    /// <summary>The plugin's next command; the plugin ending here instead is a failure.</summary>
    /// <exception cref="AgePluginException">The plugin ended, or wrote something that is not a stanza.</exception>
    public (string Type, string[] Args, byte[] Body) ReadNextStanza() =>
        // stderr is the only account of why the plugin died, so Failure() quotes it.
        ReadStanza() ?? throw Failure("unexpected end of plugin output");

    public (string Type, string[] Args, byte[] Body)? ReadStanza()
    {
        var line = _reader.ReadLine();

        if (line == null)
            return null;

        if (!line.StartsWith("-> ", StringComparison.Ordinal))
            throw new AgePluginException($"expected stanza prefix '-> ', got: {line}");

        var parts = line[3..].Split(' ');

        if (parts.Length < 1 || string.IsNullOrEmpty(parts[0]))
            throw new AgePluginException("stanza must have at least a type");

        var stanzaType = parts[0];
        var stanzaArgs = parts.Length > 1 ? parts[1..] : [];

        // Validated here rather than at `new Stanza(...)`, so both plugin types are covered and
        // a malformed stanza is an AgePluginException rather than a raw ArgumentException.
        ThrowIfMalformed(stanzaType, "type");

        foreach (var arg in stanzaArgs)
            ThrowIfMalformed(arg, "argument");

        var body = ReadBody();

        return (stanzaType, stanzaArgs, body);
    }

    /// <summary>
    /// The string came from the plugin, so a bad one means the plugin misbehaved. Same rule
    /// <see cref="Stanza"/> applies to its own input — a space or newline would corrupt the
    /// framing — but worded to name the plugin, since that is who got it wrong here.
    /// </summary>
    private static void ThrowIfMalformed(string s, string what)
    {
        if (string.IsNullOrEmpty(s))
            throw new AgePluginException($"plugin sent an empty stanza {what}");

        var invalid = Stanza.IndexOfNonVChar(s);

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
                    // Decode throws FormatException for malformed, padded and non-canonical input
                    // alike; the plugin path reports all three as AgePluginException.
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

        // Closing stdin asks the plugin to exit; if it declines, kill it rather than leak the
        // process and its hold on any hardware token.
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