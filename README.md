# Go Project Starter Template

A comprehensive starter template for Go projects with pre-configured tooling, linting, testing, and best practices.

## Features

- **Quick Setup**: One command to initialize your project
- **Pre-configured Tooling**: golangci-lint, gci, gofumpt, staticcheck
- **Pre-commit Hooks**: Automated code quality checks before commits
- **Protocol Buffers Support**: Built-in buf configuration for gRPC/protobuf projects
- **Testing**: Pre-configured test suite with coverage
- **Documentation**: Code of Conduct and Contributing guidelines included
- **Best Practices**: Follows Go project layout standards

## Quick Start

### 1. Clone or Use This Template

#### Option A: Use as GitHub Template

```bash
# Click "Use this template" button on GitHub, then clone your new repo
git clone https://github.com/your_username/your-new-project.git
cd your-new-project
```

#### Option B: Clone Directly

```bash
git clone https://github.com/hyp3rd/starter.git my-new-project
cd my-new-project
rm -rf .git
git init
git remote add origin https://github.com/your_username/your-new-project.git
```

### 2. Run the Setup Script

The setup script will automatically:

- Detect your repository name from git remote or go.mod
- Replace all `#PROJECT` placeholders with your actual module name
- Initialize `go.mod` if it doesn't exist
- Create backups of modified files

```bash
# Auto-detect module name from git remote or existing go.mod
./setup-project.sh

# Or specify module name explicitly
./setup-project.sh --module github.com/your_username/your-project

# Get help
./setup-project.sh --help
```

### 3. Install Development Tools

```bash
# Install all required Go tools and pre-commit hooks
make prepare-toolchain
```

This will install:

- `gci` - Go import formatter
- `gofumpt` - Stricter gofmt
- `golangci-lint` - Comprehensive linter
- `staticcheck` - Advanced static analysis
- `pre-commit` - Git hook framework

### 4. Start Coding

Your project structure is ready:

```text
.
├── api/           # Public API definitions (protobuf, OpenAPI)
├── internal/      # Private application code
├── pkg/           # Public library code
├── .pre-commit/   # Pre-commit hook scripts
├── Makefile       # Common development tasks
└── go.mod         # Go module file
```

## Development Workflow

### Running Tests

```bash
# Run all tests with coverage
make test

# Run benchmarks
make bench
```

### Code Quality

```bash
# Run all linters and formatters
make lint

# Run go vet with shadow analysis
make vet

# Update dependencies
make update-deps
```

### Pre-commit Hooks

Pre-commit hooks run automatically on `git commit`. They check:

- Import formatting (gci)
- Code linting (golangci-lint)
- Unit tests
- Markdown formatting
- YAML validation
- Trailing whitespace
- Spell checking

To run hooks manually:

```bash
pre-commit run --all-files
```

### Protocol Buffers (Optional)

If you're building a gRPC service:

```bash
# Install protobuf tools
make prepare-proto-tools

# Update dependencies
make proto-update

# Lint proto files
make proto-lint

# Generate code from proto files
make proto-generate

# Format proto files
make proto-format

# Run all proto tasks
make proto
```

## Project Customization

### Update Documentation

1. Edit `README.md` - Replace this template README with your project description
1. Edit `CODE_OF_CONDUCT.md` - Add your contact method for enforcement
1. Edit `CONTRIBUTING.md` - Customize for your project's contribution process

### Configure Linters

Edit `.golangci.yaml` to customize linting rules for your project.

### Customize Spell Checker

Add project-specific words to `cspell.json` in the `words` array.

## Available Make Targets

```bash
make help                 # Show all available targets
make prepare-toolchain    # Install development tools
make test                # Run tests
make bench               # Run benchmarks
make lint                # Run all linters
make vet                 # Run go vet
make update-deps         # Update dependencies
make proto              # Run all protobuf tasks (if using gRPC)
```

## Requirements

- Go 1.25.3 or later
- Git
- Python 3.x (for pre-commit)
- Docker (optional, for containerized builds)

## Project Layout

This template follows the [Standard Go Project Layout](https://github.com/golang-standards/project-layout):

- **`/api`** - OpenAPI/Swagger specs, JSON schema files, protocol definition files
- **`/internal`** - Private application and library code
- **`/pkg`** - Library code that's ok to use by external applications

## Troubleshooting

### Pre-commit hooks fail

```bash
# Reinstall pre-commit hooks
pre-commit uninstall
pre-commit install
pre-commit install-hooks
```

### Go module issues

```bash
# Reset and reinitialize module
rm go.mod go.sum
./setup-project.sh --module github.com/your_username/your_project
go mod tidy
```

### Linter installation fails

```bash
# Clean and reinstall tools
rm -rf $(go env GOPATH)/bin/{gci,gofumpt,golangci-lint,staticcheck}
make prepare-toolchain
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on how to contribute to this project.

## Code of Conduct

This project adheres to a Code of Conduct. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) for details.

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Support

- [Documentation](https://github.com/hyp3rd/starter/wiki)
- [Issue Tracker](https://github.com/hyp3rd/starter/issues)
- [Discussions](https://github.com/hyp3rd/starter/discussions)
