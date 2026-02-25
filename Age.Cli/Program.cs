using System.CommandLine;
using Age;
using Age.Cli;

// --- Root command (encrypt/decrypt) ---
var encryptOption = new Option<bool>("--encrypt", "-e") { Description = "Encrypt the input (default)" };
var decryptOption = new Option<bool>("--decrypt", "-d") { Description = "Decrypt the input" };
var armorOption = new Option<bool>("--armor", "-a") { Description = "Use ASCII armored format" };
var passphraseOption = new Option<bool>("--passphrase", "-p") { Description = "Use passphrase-based encryption" };
var recipientOption = new Option<string[]>("--recipient", "-r") { Description = "Encrypt to recipient (can be repeated)" };
var recipientsFileOption = new Option<string[]>("--recipients-file", "-R") { Description = "Path to a file with recipients (can be repeated)" };
var identityOption = new Option<string[]>("--identity", "-i") { Description = "Path to an identity file (can be repeated)" };
var outputOption = new Option<string?>("--output", "-o") { Description = "Write output to path" };
var inputArgument = new Argument<string?>("input") { Arity = ArgumentArity.ZeroOrOne, Description = "Input file (default: stdin)" };

var rootCommand = new RootCommand("age-sharp: file encryption tool")
{
    encryptOption, decryptOption, armorOption, passphraseOption,
    recipientOption, recipientsFileOption, identityOption,
    outputOption, inputArgument
};

rootCommand.SetAction(parseResult =>
    AgeCommand.Execute(
        !parseResult.GetValue(decryptOption),
        parseResult.GetValue(armorOption),
        parseResult.GetValue(passphraseOption),
        parseResult.GetValue(recipientOption) ?? [],
        parseResult.GetValue(recipientsFileOption) ?? [],
        parseResult.GetValue(identityOption) ?? [],
        parseResult.GetValue(outputOption),
        parseResult.GetValue(inputArgument)));

// --- keygen subcommand ---
var keygenOutputOption = new Option<string?>("--output", "-o") { Description = "Write the result to path" };
var convertToPublicOption = new Option<bool>("-y") { Description = "Convert an identity file to a recipients file" };
var postQuantumOption = new Option<bool>("--pq", "-pq") { Description = "Generate a post-quantum ML-KEM-768 + X25519 key pair" };
var keygenInputArgument = new Argument<string?>("input") { Arity = ArgumentArity.ZeroOrOne, Description = "Input file (for -y mode)" };

var keygenCommand = new Command("keygen", "Generate a new identity")
{
    keygenOutputOption, convertToPublicOption, postQuantumOption, keygenInputArgument
};

keygenCommand.SetAction(parseResult =>
    KeygenCommand.Execute(
        parseResult.GetValue(keygenOutputOption),
        parseResult.GetValue(convertToPublicOption),
        parseResult.GetValue(postQuantumOption),
        parseResult.GetValue(keygenInputArgument)));

rootCommand.Subcommands.Add(keygenCommand);

// --- inspect subcommand ---
var jsonOption = new Option<bool>("--json") { Description = "Output machine-readable JSON" };
var inspectInputArgument = new Argument<string?>("file") { Arity = ArgumentArity.ZeroOrOne, Description = "Input file (default: stdin, \"-\" for stdin)" };

var inspectCommand = new Command("inspect", "Inspect an age-encrypted file")
{
    jsonOption, inspectInputArgument
};

inspectCommand.SetAction(parseResult =>
{
    var filePath = parseResult.GetValue(inspectInputArgument);
    if (filePath == "-") filePath = null;
    return InspectCommand.Execute(filePath, parseResult.GetValue(jsonOption));
});

rootCommand.Subcommands.Add(inspectCommand);

// --- Parse and invoke with centralized error handling ---
var parserConfig = new ParserConfiguration { EnablePosixBundling = false };
var parsed = rootCommand.Parse(args, parserConfig);

try
{
    return parsed.Invoke(new InvocationConfiguration { EnableDefaultExceptionHandler = false });
}
catch (Exception ex) when (ex is AgeException or FormatException)
{
    Console.Error.WriteLine($"{CommandPrefix(parsed)}: {ex.Message}");
    return 1;
}
catch (FileNotFoundException ex)
{
    Console.Error.WriteLine($"{CommandPrefix(parsed)}: no such file: {ex.FileName}");
    return 1;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"{CommandPrefix(parsed)}: internal error: {ex.Message}");
    Console.Error.WriteLine("This is a bug. Please report it at https://github.com/pscheid92/AgeSharp/issues");
    return 1;
}

static string CommandPrefix(ParseResult parsed) =>
    parsed.CommandResult.Command.Name switch
    {
        "keygen" => "age-keygen",
        "inspect" => "age-inspect",
        _ => "age"
    };