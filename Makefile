BENCH_PROJ = Age.Benchmarks/Age.Benchmarks.csproj

.PHONY: all build test bench bench-filter bench-list clean

all: build

build:
	dotnet build

# Unit, interop (against the age and rage binaries, when on PATH) and conformance tests
test:
	dotnet test

# Run all benchmarks
bench:
	dotnet run -c Release --project $(BENCH_PROJ)

# Run benchmarks matching a filter (usage: make bench-filter F=*KeyGen*)
bench-filter:
	dotnet run -c Release --project $(BENCH_PROJ) -- --filter $(F)

# List available benchmarks
bench-list:
	dotnet run -c Release --project $(BENCH_PROJ) -- --list flat

clean:
	rm -rf Age/bin Age.Tests/bin Age.TestKit/bin Age.Benchmarks/bin \
	       Age/obj Age.Tests/obj Age.TestKit/obj Age.Benchmarks/obj
