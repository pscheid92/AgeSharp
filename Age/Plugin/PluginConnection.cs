using AgeSharp.Crypto;
using System.Buffers;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace AgeSharp;

internal sealed class PluginConnection : IDisposable
{
    private readonly Process? _process;
    private readonly TextReader _reader;
    private readonly TextWriter _writer;

    public PluginConnection(string pluginName, string stateMachine)
    {
        // Defense in depth: the caller should already have validated the name, but this is
        // the sink that turns it into an executable path, so never launch an invalid one.
        if (!PluginNameValidator.IsValid(pluginName))
            throw new AgePluginException($"refusing to launch plugin with invalid name: '{pluginName}'");

        var binaryName = $"age-plugin-{pluginName}";
        var startInfo = new ProcessStartInfo
        {
            FileName = binaryName,
            Arguments = $"--age-plugin={stateMachine}",
            RedirectStandardInput = true,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };

        try
        {
            _process = Process.Start(startInfo) ??
                       throw new AgePluginException($"failed to start plugin: {binaryName}");
        }
        catch (Win32Exception ex)
        {
            throw new AgePluginException($"plugin not found: {binaryName}", ex);
        }

        _reader = _process.StandardOutput;
        _writer = _process.StandardInput;
    }

    // For tests: drives the protocol over in-memory pipes instead of a child process.
    internal PluginConnection(TextReader reader, TextWriter writer)
    {
        _reader = reader;
        _writer = writer;
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

        // Encoded into a rented buffer and cleared, not into a string. Three stanza bodies
        // that cross this wire are secret — wrap-file-key carries the raw file key, file-key
        // carries the unwrapped one back, and an ok answering request-secret carries a PIN —
        // and a string holding any of them could never be cleared.
        var encoded = ArrayPool<char>.Shared.Rent(Base64Unpadded.MaxEncodedLength(body.Length));

        try
        {
            var length = Base64Unpadded.Encode(body, encoded);
            var offset = 0;

            while (offset < length)
            {
                var run = Math.Min(64, length - offset);
                _writer.Write(encoded.AsSpan(offset, run));
                _writer.Write('\n');
                offset += run;
            }

            // Empty body or an exact multiple of 64 both need an empty terminator line.
            if (length % 64 == 0)
                _writer.Write('\n');

            _writer.Flush();
        }
        finally
        {
            CryptographicOperations.ZeroMemory(MemoryMarshal.AsBytes(encoded.AsSpan()));
            ArrayPool<char>.Shared.Return(encoded);
        }
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
            var bodyLine = _reader.ReadLine() ??
                           throw new AgePluginException("unexpected end of stream while reading stanza body");

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
}