namespace AgeSharp;

/// <summary>
///     What one call to <see cref="IRecipientWithLabels.WrapWithLabels" /> produced: the
///     stanzas, and the labels constraining who they may share a file with.
/// </summary>
/// <remarks>
///     A plain <see langword="struct" /> rather than a <see langword="record" />: the payload
///     is a collection, so generated value equality would compare list references and report
///     two identical results as unequal. Not offering equality is better than offering it
///     wrongly. Deconstruction still works — <c>var (stanzas, labels) = …</c>.
/// </remarks>
public readonly struct LabelledStanzas(IReadOnlyList<Stanza> stanzas, IReadOnlyCollection<string> labels)
{
    /// <summary>The stanzas the wrap produced. Never empty.</summary>
    public IReadOnlyList<Stanza> Stanzas { get; } = stanzas;

    /// <summary>
    ///     The labels this wrapping carries. Every recipient in a file must produce an equal
    ///     set — compared unordered and case-sensitively — which is what keeps post-quantum
    ///     and classical recipients from being mixed. Empty for recipients without labels.
    /// </summary>
    public IReadOnlyCollection<string> Labels { get; } = labels;

    /// <summary>Deconstructs into <see cref="Stanzas" /> and <see cref="Labels" />.</summary>
    public void Deconstruct(out IReadOnlyList<Stanza> stanzas, out IReadOnlyCollection<string> labels)
    {
        stanzas = Stanzas;
        labels = Labels;
    }
}
