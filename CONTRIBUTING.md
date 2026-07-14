# Contributing to bitcoin

Thank you for your interest in contributing to the bitcoin library! This document provides guidelines and instructions for contributing.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Branch Naming](#branch-naming)
- [Commit Conventions](#commit-conventions)
- [Code Style](#code-style)
- [Testing](#testing)
- [Pull Request Process](#pull-request-process)
- [Documentation](#documentation)
- [Releasing](#releasing)

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold its terms.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/bitcoin.git
   cd bitcoin
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/sachncs/bitcoin.git
   ```
4. **Create a branch** for your changes:
   ```bash
   git checkout -b feat/my-new-feature
   ```

## Development Setup

### Prerequisites

- Python 3.12 or later
- [uv](https://github.com/astral-sh/uv) package manager

### Installation

```bash
# Clone and set up
git clone https://github.com/sachncs/bitcoin.git
cd bitcoin
./setup.sh
```

Or manually:

```bash
uv venv
uv sync --extra dev
```

### Virtual Environment

Always work within the virtual environment:

```bash
source .venv/bin/activate
# or use uv run prefix
```

## Branch Naming

Use descriptive branch names with prefixes:

| Prefix | Purpose |
|--------|---------|
| `feat/` | New features |
| `fix/` | Bug fixes |
| `docs/` | Documentation changes |
| `refactor/` | Code refactoring |
| `test/` | Adding or updating tests |
| `chore/` | Maintenance tasks |
| `perf/` | Performance improvements |

Examples:
- `feat/add-taproot-script-support`
- `fix/sighash-legacy-edge-case`
- `docs/update-api-reference`
- `refactor/extract-signature-engine`

## Commit Conventions

This project follows [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer(s)]
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Formatting changes (no code change) |
| `refactor` | Code refactoring |
| `test` | Adding or updating tests |
| `chore` | Build process, dependencies, CI |
| `perf` | Performance improvements |
| `ci` | CI/CD changes |

### Examples

```bash
git commit -m "feat(script): add miniscript parser"
git commit -m "fix(sighash): handle edge case in legacy calculation"
git commit -m "docs(readme): add installation instructions"
git commit -m "test(extraction): add mainnet transaction vectors"
git commit -m "chore(deps): update ruff to 0.15.16"
```

### Scope

Optional scope within parentheses:
- `cli` - Command-line interface
- `curve` - Elliptic curve operations
- `script` - Script handling
- `signature` - Signature extraction/verification
- `transaction` - Transaction parsing/building
- `sighash` - Sighash computation
- `psbt` - PSBT support
- `services` - Blockchain data providers

## Code Style

### Formatting

- **Line length:** 88 characters
- **Formatter:** Ruff
- **Target:** Python 3.12+

### Linting

```bash
make lint          # Run ruff check
make typecheck     # Run mypy strict
```

### Rules

- Use type annotations on all public functions
- Follow PEP 8 naming conventions
- Use `snake_case` for functions and variables
- Use `PascalCase` for classes
- Use `UPPER_CASE` for constants
- No circular imports
- `models.py` must remain import-free (leaf module)

### Pre-commit

We use pre-commit hooks. Install them:

```bash
pre-commit install
```

## Testing

### Running Tests

```bash
make test          # Run all tests
make test-cov      # Run with coverage (99%+ required)
```

### Writing Tests

- Add tests for all new functionality
- Use Hypothesis for property-based tests when appropriate
- Test edge cases and error conditions
- Keep tests focused and well-documented

### Test Structure

```python
import pytest
from bitcoin import parse_tx, extract_signatures

class TestMyFeature:
    """Tests for my new feature."""

    def test_basic_functionality(self):
        """Test basic usage."""
        # Arrange
        # Act
        # Assert

    def test_edge_case(self):
        """Test edge case handling."""
        # ...
```

## Pull Request Process

### Before Submitting

1. **Update your fork**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run all checks**:
   ```bash
   make all  # lint + typecheck + test
   ```

3. **Update documentation** if needed
4. **Add entry to CHANGELOG.md** under `[Unreleased]`

### Submitting

1. **Push your branch**:
   ```bash
   git push origin feat/my-new-feature
   ```

2. **Create a Pull Request** on GitHub
3. **Fill out the PR template** completely
4. **Link related issues** using `Fixes #123`

### Review Process

- At least one maintainer approval required
- All CI checks must pass
- Code coverage must remain at 99%+
- Address review feedback promptly

## Documentation

### Types

- **Docstrings:** Required for all public functions/classes
- **README:** Update for new features or changed behavior
- **CHANGELOG:** Add entry under `[Unreleased]`
- **Architecture docs:** Update `docs/ARCHITECTURE.md` for structural changes

### Docstring Format

```python
def my_function(param1: str, param2: int = 0) -> bool:
    """Brief description of the function.

    Longer description if needed.

    Args:
        param1: Description of param1.
        param2: Description of param2.

    Returns:
        Description of return value.

    Raises:
        ValueError: When something is wrong.
    """
```

## Releasing

1. **Update version** in `pyproject.toml` and `bitcoin/__init__.py`
2. **Update CHANGELOG.md**:
   - Change `[Unreleased]` to `[X.Y.Z] - YYYY-MM-DD`
   - Add new `[Unreleased]` section
3. **Commit changes**:
   ```bash
   git commit -m "chore(release): v0.5.0"
   ```
4. **Tag the release**:
   ```bash
   git tag v0.5.0
   ```
5. **Push**:
   ```bash
   git push origin main --tags
   ```

The release workflow will automatically:
- Build and publish to PyPI
- Create a GitHub Release
- Generate build provenance attestation

## Questions?

- Open a [GitHub Discussion](https://github.com/sachncs/bitcoin/discussions)
- Check existing [issues](https://github.com/sachncs/bitcoin/issues)
- Review the [architecture documentation](docs/ARCHITECTURE.md)
