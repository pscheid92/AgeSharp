using Xunit;

// The CLI talks to the process: Console streams, environment variables, the working directory.
// Those are global, so tests that redirect them would see each other's traffic if run in
// parallel. Library tests stay in Age.Tests, where parallelism is unaffected.
[assembly: CollectionBehavior(DisableTestParallelization = true)]
