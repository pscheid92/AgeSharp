using Xunit;

namespace Age.Tests;

/// <summary>
/// The tests that put a plugin on the process's PATH and take it off again: one collection, so
/// they run one at a time and none restores a PATH another has just changed.
/// </summary>
[CollectionDefinition(Collection)]
public sealed class ProcessPath
{
    public const string Collection = "process PATH";
}
