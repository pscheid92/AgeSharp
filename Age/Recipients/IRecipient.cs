using Age.Format;

namespace Age.Recipients;

public interface IRecipient
{
    Stanza Wrap(ReadOnlySpan<byte> fileKey);
}
