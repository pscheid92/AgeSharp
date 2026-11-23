using System.ComponentModel;
using System.Diagnostics;
using AgeSharp.Crypto;

namespace AgeSharp;

internal sealed class PluginConnection : IDisposable
{
    // To a plugin process, stanzas go to stdin's stream as bytes the channel clears; never
    // through Process.StandardInput, a StreamWriter whose buffers keep the last text written, a
    // file key or a secret, until something overwrites it.
    private readonly StanzaChannel _channel;
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

        _channel = new StanzaChannel(_process.StandardOutput, _process.StandardInput.BaseStream, peer: "plugin");

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
        // arrived yet. WaitForExit(int) does not flush the async readers; WaitForExitAsync waits
        // for them to reach the end of stderr, which a background agent the plugin started may
        // hold open for as long as it lives, so that wait has a deadline too.
        if (_process is not null && _process.WaitForExit(StderrFlushMilliseconds))
        {
            using var flushed = new CancellationTokenSource(StderrFlushMilliseconds);

            try
            {
                _process.WaitForExitAsync(flushed.Token).GetAwaiter().GetResult();
            }
            catch (OperationCanceledException)
            {
                // Something still holds stderr: what has arrived is what there is to show.
            }
        }

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
        _channel = new StanzaChannel(reader, writer, peer: "plugin");
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
            _channel.Write(type, args, body);
        }
        catch (Exception ex) when (ex is IOException or ObjectDisposedException)
        {
            throw Failure("the plugin exited before the request could be sent", ex);
        }
    }

    /// <summary>The plugin's next command; the plugin ending here instead is a failure.</summary>
    /// <exception cref="AgePluginException">The plugin ended, or wrote something that is not a stanza.</exception>
    public (string Type, string[] Args, byte[] Body) ReadNextStanza() =>
        // stderr is the only account of why the plugin died, so Failure() quotes it.
        ReadStanza() ?? throw Failure("unexpected end of plugin output");

    /// <summary>The plugin's next stanza, or null where its output ends.</summary>
    /// <exception cref="AgePluginException">The plugin wrote something that is not a stanza.</exception>
    public (string Type, string[] Args, byte[] Body)? ReadStanza() =>
        _channel.Read();

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