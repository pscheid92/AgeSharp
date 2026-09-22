using Xunit;

namespace Age.Cli.Tests;

/// <summary>
/// Which failures the CLI reports as the user's to fix, and which as a bug in AgeSharp.
/// A missing directory or a permission problem is the former; printing "This is a bug" for them
/// sent users to the issue tracker over their own typo.
/// </summary>
public class UserErrorTests
{
    public static TheoryData<Exception> UserErrors => new()
    {
        new AgeException("header MAC verification failed"),
        new NoIdentityMatchException(),
        new FormatException("invalid bech32 checksum"),
        new DirectoryNotFoundException("Could not find a part of the path '/missing/dir/out.age'."),
        new UnauthorizedAccessException("Access to the path '/etc/out.age' is denied."),
        new IOException("No space left on device"),
    };

    [Theory]
    [MemberData(nameof(UserErrors))]
    public void UserError_IsDescribedWithItsMessage(Exception ex) =>
        Assert.Equal(ex.Message, UserError.Describe(ex));

    [Fact]
    public void MissingFile_IsNamed() =>
        Assert.Equal("no such file: /tmp/nope.age",
            UserError.Describe(new FileNotFoundException("Could not find file.", "/tmp/nope.age")));

    [Theory]
    [MemberData(nameof(Bugs))]
    public void Bug_IsNotDescribed(Exception ex) =>
        Assert.Null(UserError.Describe(ex));

    public static TheoryData<Exception> Bugs => new()
    {
        new InvalidCastException(),
        new NullReferenceException(),
        new InvalidOperationException("unexpected state"),
    };
}
