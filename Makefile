BINARY     = age-sharp
CLI_PROJ   = Age.Cli/Age.Cli.csproj
BENCH_PROJ = Age.Benchmarks/Age.Benchmarks.csproj
OUT_DIR    = dist
AOT_FLAGS  = -p:PublishAot=true

.PHONY: all build test interop bench bench-list clean

# Default: build universal macOS binary
all: $(OUT_DIR)/$(BINARY)

# Universal macOS binary (arm64 + x86_64)
$(OUT_DIR)/$(BINARY): $(OUT_DIR)/$(BINARY)-arm64 $(OUT_DIR)/$(BINARY)-x64
	lipo -create $^ -output $@
	@echo "Built universal binary: $@ ($$(du -sh $@ | cut -f1))"

$(OUT_DIR)/$(BINARY)-arm64:
	@mkdir -p $(OUT_DIR)
	dotnet publish $(CLI_PROJ) -r osx-arm64 $(AOT_FLAGS) -o $(OUT_DIR)/arm64
	mv $(OUT_DIR)/arm64/Age.Cli $@
	rm -rf $(OUT_DIR)/arm64

$(OUT_DIR)/$(BINARY)-x64:
	@mkdir -p $(OUT_DIR)
	dotnet publish $(CLI_PROJ) -r osx-x64 $(AOT_FLAGS) -o $(OUT_DIR)/x64
	mv $(OUT_DIR)/x64/Age.Cli $@
	rm -rf $(OUT_DIR)/x64

# Framework-dependent build (no AOT, for development)
build:
	dotnet build

# Unit + integration tests
test:
	dotnet test

# Interoperability test vs Go age CLI
interop: $(OUT_DIR)/$(BINARY)
	./interop_test.sh $(OUT_DIR)/$(BINARY)

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
	rm -rf $(OUT_DIR) Age/bin Age.Cli/bin Age.Tests/bin Age.TestKit/bin Age.Benchmarks/bin \
	       Age/obj Age.Cli/obj Age.Tests/obj Age.TestKit/obj Age.Benchmarks/obj
