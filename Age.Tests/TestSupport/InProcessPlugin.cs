using System.IO.Pipes;
using System.Text;
using AgeSharp;

namespace Age.Tests;

/// <summary>
/// Runs an <see cref="AgePlugin"/> and AgeSharp's own client against each other in one process,
/// over two anonymous pipes, as a plugin process and its client would be.
/// </summary>
internal static class InProcessPlugin
{
    public sealed record Outcome<T>(int ExitCode, T? Result, Exception? ClientFailure, string Stderr);

    private static readonly TimeSpan Timeout = TimeSpan.FromSeconds(30);

    /// <summary>
    /// Runs <paramref name="plugin"/> as <paramref name="stateMachine"/> and
    /// <paramref name="client"/> against it; the client's exception, if any, is caught and returned.
    /// </summary>
    public static Outcome<T> Run<T>(AgePlugin plugin, string stateMachine, Func<PluginConnection, T> client) =>
        Run(plugin, [$"--age-plugin={stateMachine}"], client);

    /// <summary>The same, with the plugin's command line given in full.</summary>
    public static Outcome<T> Run<T>(AgePlugin plugin, string[] args, Func<PluginConnection, T> client)
    {
        using var toPlugin = new AnonymousPipeServerStream(PipeDirection.Out);
        using var pluginInput = new AnonymousPipeClientStream(PipeDirection.In, toPlugin.ClientSafePipeHandle);
        using var fromPlugin = new AnonymousPipeServerStream(PipeDirection.In);
        var pluginOutput = new AnonymousPipeClientStream(PipeDirection.Out, fromPlugin.ClientSafePipeHandle);
        var stderr = new StringWriter();

        // Both sides get threads of their own, not the pool's: the test thread blocks until they
        // finish, and under a loaded parallel run a pool thread can take seconds to start.
        var server = Task.Factory.StartNew(() =>
        {
            try
            {
                return plugin.Run(args, pluginInput, pluginOutput, stderr);
            }
            finally
            {
                // The client sees the end of the plugin's output, as it would when a process exits.
                pluginOutput.Dispose();
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        T? result = default;
        Exception? failure = null;

        // The client runs on its own task too, so that a plugin that never answers fails the test
        // instead of hanging it: once the time is up, closing both pipes ends both sides' reads.
        var conversation = Task.Factory.StartNew(() =>
        {
            try
            {
                var conn = new PluginConnection(new StreamReader(fromPlugin, Encoding.ASCII), new StreamWriter(toPlugin, Encoding.ASCII));
                result = client(conn);
            }
            catch (Exception ex)
            {
                failure = ex;
            }
            finally
            {
                // And the plugin sees the end of the client's, as when the client closes its stdin.
                toPlugin.Dispose();
            }
        }, CancellationToken.None, TaskCreationOptions.LongRunning, TaskScheduler.Default);

        if (!Task.WaitAll([conversation, server], Timeout))
        {
            toPlugin.Dispose();
            fromPlugin.Dispose();
            pluginInput.Dispose();
            throw new TimeoutException("the plugin and its client were still waiting on each other");
        }

        return new Outcome<T>(server.Result, result, failure, stderr.ToString());
    }
}
