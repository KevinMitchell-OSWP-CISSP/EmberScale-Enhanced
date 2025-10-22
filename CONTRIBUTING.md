# Contributing to EmberScale

Thank you for your interest in contributing to EmberScale! This document provides guidelines for contributing to the project.

## Code of Conduct

This project follows a code of conduct that we expect all contributors to adhere to. Please be respectful and constructive in all interactions.

## How to Contribute

### Reporting Issues

1. **Check Existing Issues**: Search existing issues before creating a new one
2. **Use the Issue Template**: Fill out the issue template completely
3. **Provide Details**: Include steps to reproduce, expected behavior, and actual behavior
4. **Include Logs**: Attach relevant log files and error messages

### Suggesting Features

1. **Check Roadmap**: Review the project roadmap for planned features
2. **Describe Use Case**: Explain how the feature would be used
3. **Provide Examples**: Include code examples or mockups if applicable
4. **Consider Impact**: Think about how the feature affects existing functionality

### Submitting Code

1. **Fork the Repository**: Create your own fork of the project
2. **Create a Branch**: Create a feature branch for your changes
3. **Make Changes**: Implement your improvements or fixes
4. **Test Changes**: Ensure all changes work correctly
5. **Submit PR**: Submit a pull request with your changes

## Development Setup

### Prerequisites

- **Python 3.8+**: For development and testing
- **Ghidra 11.4.2+**: For testing Ghidra integration
- **Git**: For version control
- **Anthropic API Key**: For testing API functionality

### Setup Steps

1. **Clone Repository**:
   ```bash
   git clone https://github.com/KevinMitchell-OSWP-CISSP/EmberScale-Enhanced.git
   cd EmberScale-Enhanced
   ```

2. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure Environment**:
   ```bash
   export ANTHROPIC_API_KEY=your-api-key-here
   export EMBERSCALE_DEBUG=true
   ```

4. **Run Tests**:
   ```bash
   python -m pytest tests/
   ```

## Coding Standards

### Python Style

- **PEP 8**: Follow Python PEP 8 style guidelines
- **Type Hints**: Use type hints for function parameters and return values
- **Docstrings**: Include comprehensive docstrings for all functions
- **Comments**: Add comments for complex logic

### Code Organization

- **Modular Design**: Keep functions focused and modular
- **Error Handling**: Include proper error handling and logging
- **Configuration**: Use configuration files for settings
- **Documentation**: Update documentation for new features

### Testing

- **Unit Tests**: Write unit tests for new functionality
- **Integration Tests**: Test Ghidra integration
- **API Tests**: Test Anthropic API integration
- **Error Tests**: Test error conditions and edge cases

## Pull Request Process

### Before Submitting

1. **Test Your Changes**: Ensure all tests pass
2. **Update Documentation**: Update relevant documentation
3. **Check Style**: Run code style checks
4. **Review Changes**: Review your changes thoroughly

### PR Description

Include the following in your PR description:

- **Summary**: Brief description of changes
- **Type**: Bug fix, feature, documentation, etc.
- **Testing**: How you tested the changes
- **Breaking Changes**: Any breaking changes
- **Related Issues**: Link to related issues

### Review Process

1. **Automated Checks**: All automated checks must pass
2. **Code Review**: At least one maintainer must approve
3. **Testing**: Changes must be tested in Ghidra environment
4. **Documentation**: Documentation must be updated

## Areas for Contribution

### High Priority

- **Bug Fixes**: Fix reported bugs and issues
- **Performance**: Improve analysis performance
- **Error Handling**: Enhance error handling and logging
- **Documentation**: Improve documentation and examples

### Medium Priority

- **New Features**: Add new analysis capabilities
- **UI Improvements**: Enhance user interface
- **Custom Skills**: Develop new reverse engineering Skills
- **Testing**: Add comprehensive test coverage

### Low Priority

- **Code Cleanup**: Refactor and optimize code
- **Examples**: Add more usage examples
- **Tutorials**: Create tutorial content
- **Translations**: Add multi-language support

## Development Guidelines

### Git Workflow

1. **Branch Naming**: Use descriptive branch names
   - `feature/analysis-improvements`
   - `bugfix/api-error-handling`
   - `docs/installation-guide`

2. **Commit Messages**: Use clear, descriptive commit messages
   - `feat: add malware analysis capabilities`
   - `fix: resolve API timeout issues`
   - `docs: update installation instructions`

3. **Pull Requests**: Keep PRs focused and manageable
   - One feature or bug fix per PR
   - Include tests and documentation
   - Keep PR size reasonable

### Code Quality

- **Readability**: Write clear, readable code
- **Maintainability**: Consider future maintenance
- **Performance**: Optimize for performance when possible
- **Security**: Follow security best practices

## Testing Guidelines

### Test Types

1. **Unit Tests**: Test individual functions and methods
2. **Integration Tests**: Test component interactions
3. **End-to-End Tests**: Test complete workflows
4. **Performance Tests**: Test performance characteristics

### Test Requirements

- **Coverage**: Maintain high test coverage
- **Reliability**: Tests should be reliable and repeatable
- **Speed**: Tests should run quickly
- **Isolation**: Tests should not depend on external services

## Documentation

### Code Documentation

- **Docstrings**: Include comprehensive docstrings
- **Comments**: Add inline comments for complex logic
- **Type Hints**: Use type hints for clarity
- **Examples**: Include usage examples in docstrings

### User Documentation

- **README**: Keep README up to date
- **Installation**: Provide clear installation instructions
- **Usage**: Include usage examples and tutorials
- **API Reference**: Document API functions and parameters

## Release Process

### Version Numbering

- **Major**: Breaking changes or major new features
- **Minor**: New features or significant improvements
- **Patch**: Bug fixes and minor improvements

### Release Checklist

1. **Update Version**: Update version numbers
2. **Update Changelog**: Update CHANGELOG.md
3. **Test Release**: Test release candidate
4. **Create Release**: Create GitHub release
5. **Update Documentation**: Update documentation

## Getting Help

### Resources

- **Documentation**: Check the comprehensive documentation
- **Issues**: Search existing issues for solutions
- **Discussions**: Use GitHub discussions for questions
- **Community**: Join the community for support

### Contact

- **GitHub Issues**: Report bugs and request features
- **GitHub Discussions**: Ask questions and share ideas
- **Email**: Contact the maintainers directly
- **Documentation**: Check the documentation first

## Recognition

Contributors will be recognized in:

- **README**: Listed as contributors
- **Changelog**: Mentioned in release notes
- **Documentation**: Credited in documentation
- **Releases**: Acknowledged in release notes

Thank you for contributing to EmberScale! 🚀
