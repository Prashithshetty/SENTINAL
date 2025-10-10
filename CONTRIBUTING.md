# Contributing to SENTINAL

Thank you for your interest in contributing to SENTINAL! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Environment](#development-environment)
- [Contribution Workflow](#contribution-workflow)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Documentation Guidelines](#documentation-guidelines)
- [Creating New Modules](#creating-new-modules)
- [Submitting Pull Requests](#submitting-pull-requests)
- [Review Process](#review-process)
- [Community](#community)

## Code of Conduct

By participating in this project, you agree to abide by our Code of Conduct. Please read it before contributing.

- Be respectful and inclusive
- Focus on constructive feedback
- Maintain professionalism
- Report inappropriate behavior

## Getting Started

1. **Fork the repository**
   - Click the "Fork" button at the top right of the repository page

2. **Clone your fork**
   ```bash
   git clone https://github.com/YOUR_USERNAME/SENTINAL.git
   cd SENTINAL
   ```

3. **Add the upstream remote**
   ```bash
   git remote add upstream https://github.com/Prashithshetty/SENTINAL.git
   ```

4. **Create a branch for your work**
   ```bash
   git checkout -b feature/your-feature-name
   ```

## Development Environment

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)
- Git

### Setup

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   pip install -r requirements-dev.txt  # Development dependencies
   ```

2. **Set up environment variables**
   - Create a `.env` file based on `.env.example`
   - Add any necessary API keys for testing

3. **Install pre-commit hooks**
   ```bash
   pre-commit install
   ```

## Contribution Workflow

1. **Update your fork**
   ```bash
   git fetch upstream
   git checkout main
   git merge upstream/main
   git push origin main
   ```

2. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Write code
   - Add tests
   - Update documentation

4. **Commit your changes**
   ```bash
   git add .
   git commit -m "feat: add your feature description"
   ```
   
   Follow the [Conventional Commits](https://www.conventionalcommits.org/) format:
   - `feat:` for new features
   - `fix:` for bug fixes
   - `docs:` for documentation changes
   - `test:` for test additions or modifications
   - `refactor:` for code refactoring
   - `style:` for formatting changes
   - `chore:` for maintenance tasks

5. **Push your changes**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Create a pull request**
   - Go to your fork on GitHub
   - Click "New Pull Request"
   - Select your branch and provide a description

## Coding Standards

SENTINAL follows these coding standards:

### Python Style Guide

- Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/) style guide
- Use 4 spaces for indentation (no tabs)
- Maximum line length of 100 characters
- Use docstrings for all public modules, functions, classes, and methods
- Use type hints for function parameters and return values

### Naming Conventions

- `snake_case` for variables, functions, and methods
- `PascalCase` for classes
- `UPPER_CASE` for constants
- Prefix private methods and variables with underscore (`_private_method`)

### Code Organization

- Group imports in the following order:
  1. Standard library imports
  2. Related third-party imports
  3. Local application/library specific imports
- Separate import groups with a blank line
- Use absolute imports rather than relative imports

### Example

```python
"""Module docstring describing the purpose of the module."""

import os
import sys
from typing import Dict, List, Optional

import requests
from rich.console import Console

from backend.scanner.base_module import BaseScannerModule
from backend.core.config import settings


class ExampleScanner(BaseScannerModule):
    """Example scanner module for demonstration purposes.
    
    This class shows the proper formatting and structure for scanner modules.
    """
    
    def __init__(self) -> None:
        """Initialize the example scanner."""
        super().__init__(
            name="example_scanner",
            description="Example scanner for demonstration",
            version="1.0.0",
            author="Your Name"
        )
        self._private_variable = "example"
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Execute the vulnerability scan.
        
        Args:
            config: The scan configuration.
            
        Returns:
            The scan result.
        """
        result = self._create_result()
        
        try:
            # Implementation here
            result.success = True
        except Exception as e:
            result.success = False
            result.errors.append(str(e))
        
        return result
```

## Testing Guidelines

### Test Structure

- Place tests in the `tests/` directory
- Mirror the package structure in the tests directory
- Name test files with `test_` prefix
- Name test functions with `test_` prefix

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/scanner/test_example_scanner.py

# Run with coverage
pytest --cov=backend
```

### Test Requirements

- All new features must include tests
- All bug fixes must include tests that reproduce the bug
- Maintain or improve code coverage
- Tests should be independent and not rely on external services

## Documentation Guidelines

### Code Documentation

- Use docstrings for all public modules, functions, classes, and methods
- Follow the [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html#38-comments-and-docstrings) for docstrings
- Include type hints for function parameters and return values
- Document exceptions that may be raised

### Project Documentation

- Update README.md with new features or changes
- Update MODULES.md when adding or modifying scanner modules
- Update ARCHITECTURE.md when making architectural changes
- Create or update user guides as needed

## Creating New Modules

### Module Structure

1. Create a new file in `backend/scanner/modules/` with your module name
2. Implement the `BaseScannerModule` interface
3. Register your module in `backend/scanner/modules/__init__.py`

### Example Module

```python
from backend.scanner.base_module import BaseScannerModule, ScanConfig, ScanResult, Vulnerability, SeverityLevel, ScanType

class NewScanner(BaseScannerModule):
    """New vulnerability scanner module."""
    
    def __init__(self):
        super().__init__(
            name="new_scanner",
            description="Description of the new scanner",
            version="1.0.0",
            author="Your Name",
            scan_type=ScanType.PASSIVE  # or ACTIVE or AGGRESSIVE
        )
    
    async def scan(self, config: ScanConfig) -> ScanResult:
        """Execute the vulnerability scan."""
        # Initialize result
        result = self._create_result()
        
        try:
            # Implement your scanning logic here
            # ...
            
            # Add vulnerabilities if found
            if vulnerability_found:
                vuln = Vulnerability(
                    module=self.name,
                    name="Vulnerability Name",
                    description="Description of the vulnerability",
                    severity=SeverityLevel.MEDIUM,
                    affected_urls=[config.target],
                    evidence={"details": "Evidence details"}
                )
                result.vulnerabilities.append(vuln)
            
            # Mark as successful
            result.success = True
            
        except Exception as e:
            result.success = False
            result.errors.append(str(e))
        
        return result
```

### Module Registration

Add your module to `backend/scanner/modules/__init__.py`:

```python
from .new_scanner import NewScanner

SCANNER_MODULES = {
    # ... existing modules ...
    "new_scanner": NewScanner
}
```

## Submitting Pull Requests

### PR Requirements

- PRs should address a single concern (feature, bug fix, etc.)
- Include a clear description of the changes
- Reference any related issues
- Include tests for new functionality
- Update documentation as needed
- Pass all CI checks

### PR Template

```markdown
## Description
[Describe the changes you've made]

## Related Issue
Fixes #[issue number]

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Checklist
- [ ] I have read the CONTRIBUTING.md document
- [ ] My code follows the code style of this project
- [ ] I have added tests to cover my changes
- [ ] All new and existing tests passed
- [ ] I have updated the documentation
- [ ] My changes don't introduce new warnings
```

## Review Process

1. **Initial Review**: A maintainer will review your PR for basic requirements
2. **Code Review**: Detailed code review with feedback
3. **Revisions**: Address feedback and make necessary changes
4. **Final Review**: Final check before merging
5. **Merge**: PR is merged into the main branch

### Review Criteria

- Code quality and style
- Test coverage
- Documentation completeness
- Performance considerations
- Security implications

## Community

### Communication Channels

- GitHub Issues: For bug reports and feature requests
- GitHub Discussions: For general questions and discussions
- Slack/Discord: For real-time communication (links to be provided)

### Reporting Bugs

- Use the GitHub issue tracker
- Include detailed steps to reproduce
- Include expected vs. actual behavior
- Include system information
- Include logs or screenshots if applicable

### Requesting Features

- Use the GitHub issue tracker
- Clearly describe the feature and its benefits
- Provide examples of use cases
- Indicate if you're willing to help implement it

### Getting Help

- Check the documentation first
- Search existing issues and discussions
- Ask in the community channels
- Be specific about your question or problem

---

Thank you for contributing to SENTINAL! Your efforts help make this project better for everyone.
