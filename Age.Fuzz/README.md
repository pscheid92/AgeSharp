# Age.Fuzz

A mutation fuzzer over AgeSharp's parsers and both sides of the plugin protocol. It feeds each
entry point hostile input and checks two things. First, only the exceptions the entry point
documents come out. Second, where AgeSharp can check itself, it agrees with itself.

```sh
make fuzz                         # every target for 60 s, in parallel
make fuzz FUZZ_SECONDS=900        # for longer
dotnet run -c Release --project Age.Fuzz -- run --seconds 300 decrypt plugin   # some targets
```

It exits 1 when it found anything. It prints each target's input count and its most common
outcomes, `ok` first, which shows how deep the inputs got. Findings are saved to the output
directory (`--out`, by default a new folder under the system's temp directory), one input per
kind of finding: `<hash>.bin` is the input, `<hash>.txt` is what happened. To reproduce one:

```sh
dotnet run -c Release --project Age.Fuzz -- replay decrypt /path/to/<hash>.bin
```

`profile TARGET` times every seed, slowest first, for when a target runs slowly.

## Targets

| Target | Entry point | Allowed | Also checks |
|---|---|---|---|
| `header` | `AgeHeader.Read` | `AgeFormatException` | |
| `armor` | `Armor.Decode` | `AgeFormatException` | |
| `decrypt` | `Identities.Decrypt`, `DecryptReader` (seekable and piped), `DecryptWriter` | `AgeException` | The four ways agree: the same plaintext, or failures of the same type |
| `identities` | `Identities.Parse` | `FormatException` | Each identity opens what its own recipient wraps |
| `recipients` | `Recipients.Parse` | `FormatException` | What parses encrypts |
| `ssh` | `SshIdentity.Parse` (passphrase `hunter2`) | `FormatException` | A key the passphrase opens opens what its recipient wraps |
| `sshpub` | `Recipients.ParseOne`, `ssh-ed25519` and `ssh-rsa` | `FormatException` | What parses wraps |
| `identity-file` | `EncryptedIdentityFile` (passphrase `fuzz`) | `AgeException` | The file opens what its recipients wrap |
| `plugin` | `AgePlugin.Run`, reading what a client sent | (none) | It ends with one of its exit codes |
| `plugin-client` | `PluginRecipient` and `PluginIdentity` reading what a plugin answered | `AgePluginException` | |

The pipe and the writer in `decrypt` take the input in sizes drawn from it, so chunk, line and
armor boundaries fall in every place. The plugin's recipients and identities talk to the user (a
message, a confirmation, a value, a secret), so those exchanges are fuzzed too. An input still
running after ten seconds is a finding (`hang`); its worker then starts again.

## Seeds

Most seeds come from the repository's own test data, read where it lies:
- the C2SP test vectors in `Age.TestKit/testdata`, with their identities and passphrase;
- the SSH test keys in `Age.Tests/TestData/EncryptedSsh`.

Others are generated at startup:
- files encrypted to each `decrypt` identity, empty, one byte, and either side of a chunk boundary;
- encrypted identity files;
- plugin sessions recorded both ways between `AgePlugin` and AgeSharp's client.

`corpus/<target>/` keeps inputs by hand. `corpus/decrypt/header-and-nonce-without-payload` is a
file that ends after its nonce. Only the comparison between the four decrypt paths notices a
writer that accepts it, which is how this fuzzer was checked.

## Mutations

The mutations work on raw bytes:
- bit flips, cuts, splices, repeats;
- tokens of the formats (stanza types, armor and PEM markers, plugin commands, lengths, big numbers).

Two more are structure-aware:
- **base64** (PEM bodies, armor, stanza bodies): decoded, mutated, and encoded again;
- **Bech32** (keys, recipients): the bytes, or the 5-bit groups themselves, mutated and encoded again with a valid checksum.

Both reach past the encoding to the parser behind it.

## What it is not

- **Not coverage-guided.** An input joins the pool when it ends in an outcome not seen before (success, or an exception's type and the plain words of its message). That stands in for coverage, but nothing steers it toward code it has not reached.
- **Not exhaustive.** The encrypt side is not fuzzed, and neither are inputs that only a matching key opens past the header MAC, beyond the generated seeds.

Before this was checked in, four bugs were planted in the library and all four were found within a minute:
- a wrong exception type in the Bech32 decoder;
- a wrong exception type in the plugin client;
- a plugin exit code out of range;
- a `DecryptWriter` that accepted a missing payload.
