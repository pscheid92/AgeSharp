using System.Diagnostics;
using System.Text;
using AgeSharp;
using Xunit;

namespace Age.Tests;

/// <summary>
/// A plugin built on <see cref="AgePlugin"/> (Age.TestPlugin, run as
/// <c>age-plugin-agesharptest</c>) against real clients: go-age's <c>age</c>, rage, and AgeSharp's
/// own, each launching it as a process. What any of them encrypts, all of them decrypt.
/// </summary>
[Collection(ProcessPath.Collection)]
public class PluginInteropTests
{
    private static readonly byte[] Plaintext = "encrypted through a .NET plugin"u8.ToArray();

    public static TheoryData<string, string> Pairs()
    {
        var data = new TheoryData<string, string>();

        foreach (var encryptor in new[] { "agesharp", "age", "rage" })
            foreach (var decryptor in new[] { "agesharp", "age", "rage" })
                data.Add(encryptor, decryptor);

        return data;
    }

    [SkippableTheory]
    [MemberData(nameof(Pairs))]
    public void WhatOneClientEncryptsThroughThePlugin_AnotherDecrypts(string encryptor, string decryptor)
    {
        SkipUnlessAvailable(encryptor);
        SkipUnlessAvailable(decryptor);

        using (PluginOnPath())
        {
            var (identity, recipient) = Keygen();

            var ciphertext = Encrypt(encryptor, recipient);

            Assert.Equal(Plaintext, Decrypt(decryptor, identity, ciphertext));
        }
    }

    // An identity's own recipient, which reaches the plugin as add-identity.
    [SkippableTheory]
    [InlineData("agesharp")]
    [InlineData("age")]
    public void EncryptingToThePluginsIdentity_Decrypts(string decryptor)
    {
        SkipUnlessAvailable(decryptor);

        using (PluginOnPath())
        {
            var (identity, _) = Keygen();
            var callbacks = new Callbacks();
            var ciphertext = new Recipients(PluginIdentity.Parse(identity, callbacks).Recipient).Encrypt(Plaintext);

            Assert.Equal(Plaintext, Decrypt(decryptor, identity, ciphertext));
            Assert.Equal(["agesharptest: wrapping to an agesharptest key"], callbacks.Messages);
        }
    }

    // --- Helpers ------------------------------------------------------------------------------

    private static byte[] Encrypt(string client, string recipient) => client switch
    {
        "agesharp" => new Recipients(PluginRecipient.Parse(recipient, new Callbacks())).Encrypt(Plaintext),
        "age" => AgeCli.Encrypt(Plaintext, armored: false, recipient),
        _ => RageCli.Encrypt(Plaintext, armored: false, recipient),
    };

    private static byte[] Decrypt(string client, string identity, byte[] ciphertext) => client switch
    {
        "agesharp" => new Identities(PluginIdentity.Parse(identity, new Callbacks())).Decrypt(ciphertext),
        "age" => AgeCli.Decrypt(identity + "\n", ciphertext),
        _ => RageCli.Decrypt(identity + "\n", ciphertext),
    };

    private static void SkipUnlessAvailable(string client)
    {
        Skip.If(client == "age" && !AgeCli.Available, "age CLI not found on PATH");
        Skip.If(client == "rage" && !RageCli.Available, "rage not found on PATH");
    }

    // The plugin's own keygen mode: an identity and its recipient.
    private static (string Identity, string Recipient) Keygen()
    {
        var psi = new ProcessStartInfo(PluginPath, "keygen") { RedirectStandardOutput = true, UseShellExecute = false };
        using var process = Process.Start(psi)!;
        var lines = process.StandardOutput.ReadToEnd().Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        process.WaitForExit();

        Assert.Equal(0, process.ExitCode);
        return (lines[0], lines[1]);
    }

    // Age.TestPlugin's build output, beside this project's: bin/<configuration>/net10.0.
    private static string PluginDirectory
    {
        get
        {
            var output = new DirectoryInfo(AppContext.BaseDirectory.TrimEnd(Path.DirectorySeparatorChar));
            var (framework, configuration) = (output.Name, output.Parent!.Name);
            var root = output.Parent.Parent!.Parent!.Parent!.FullName;
            return Path.Combine(root, "Age.TestPlugin", "bin", configuration, framework);
        }
    }

    private static string PluginPath =>
        Path.Combine(PluginDirectory, OperatingSystem.IsWindows() ? "age-plugin-agesharptest.exe" : "age-plugin-agesharptest");

    private static PathScope PluginOnPath()
    {
        Assert.True(File.Exists(PluginPath), $"the test plugin was not built: {PluginPath}");
        return new PathScope(PluginDirectory);
    }

    private sealed class PathScope : IDisposable
    {
        private readonly string _original = Environment.GetEnvironmentVariable("PATH") ?? "";

        public PathScope(string directory) =>
            Environment.SetEnvironmentVariable("PATH", $"{directory}{Path.PathSeparator}{_original}");

        public void Dispose() => Environment.SetEnvironmentVariable("PATH", _original);
    }

    private sealed class Callbacks : IPluginCallbacks
    {
        public List<string> Messages { get; } = [];

        public void DisplayMessage(string plugin, string message) => Messages.Add($"{plugin}: {message}");
        public string? RequestValue(string plugin, string prompt) => null;
        public char[]? RequestSecret(string plugin, string prompt) => null;
        public bool Confirm(string plugin, string message, string yes, string? no) => false;
    }
}
