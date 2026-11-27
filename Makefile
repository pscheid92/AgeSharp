BENCH_PROJ = Age.Benchmarks/Age.Benchmarks.csproj
FUZZ_PROJ = Age.Fuzz/Age.Fuzz.csproj
FUZZ_SECONDS ?= 60

.PHONY: all build test bench bench-filter bench-list fuzz clean

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

# Fuzz every target for FUZZ_SECONDS each, in parallel (usage: make fuzz FUZZ_SECONDS=900; see Age.Fuzz/README.md)
fuzz:
	dotnet run -c Release --project $(FUZZ_PROJ) -- run --seconds $(FUZZ_SECONDS)

clean:
	rm -rf Age/bin Age.Tests/bin Age.TestKit/bin Age.Benchmarks/bin Age.Fuzz/bin \
	       Age/obj Age.Tests/obj Age.TestKit/obj Age.Benchmarks/obj Age.Fuzz/obj
