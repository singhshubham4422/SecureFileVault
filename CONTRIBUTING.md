# Contributing to Secure File Encryption App

Thank you for considering contributing to this project! This document provides guidelines for contributing to the Secure File Encryption App. By participating in this project, you agree to abide by its terms.

## Code of Conduct

In the interest of fostering an open and welcoming environment, we as contributors and maintainers pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

## How Can I Contribute?

### Reporting Bugs

This section guides you through submitting a bug report. Following these guidelines helps maintainers and the community understand your report, reproduce the behavior, and find related reports.

* **Use the GitHub issue search** — check if the issue has already been reported.
* **Check if the issue has been fixed** — try to reproduce it using the latest `master` or development branch in the repository.
* **Use the bug report template** — when you create a new issue, use the bug report template provided.

### Suggesting Enhancements

This section guides you through submitting an enhancement suggestion, including completely new features and minor improvements to existing functionality.

* **Use the GitHub issue search** — check if the enhancement has already been suggested.
* **Use the feature request template** — when you create a new issue, use the feature request template provided.

### Pull Requests

* Fill in the required template
* Do not include issue numbers in the PR title
* Follow the style guidelines
* Update the documentation as needed
* End all files with a newline

## Style Guidelines

### Python Style Guide

* Follow [PEP 8](https://www.python.org/dev/peps/pep-0008/), the Python style guide.
* Use consistent naming for variables, functions, and classes.
* Write docstrings for all modules, classes, methods, and functions.

### Git Commit Messages

* Use the present tense ("Add feature" not "Added feature")
* Use the imperative mood ("Move cursor to..." not "Moves cursor to...")
* Limit the first line to 72 characters or less
* Reference issues and pull requests liberally after the first line

## Security Considerations

* Never commit sensitive information like API keys, passwords, or personal data.
* Always validate user input and apply proper sanitization.
* Follow secure coding practices, especially when handling file operations.
* Ensure encryption algorithms and implementations follow best practices.

## Development Environment Setup

1. Fork the repository on GitHub.
2. Clone your fork locally:
```
git clone https://github.com/your-username/secure-file-encryption-app.git
cd secure-file-encryption-app
```

3. Create a virtual environment:
```
python -m venv venv
source venv/bin/activate  # On Windows, use: venv\Scripts\activate
```

4. Install development dependencies:
```
pip install -r requirements-dev.txt
```

5. Create a branch for your feature or bug fix:
```
git checkout -b feature/your-feature-name
```

6. Make your changes, test thoroughly, and commit:
```
git commit -am 'Add some feature'
```

7. Push to your fork:
```
git push origin feature/your-feature-name
```

8. Submit a pull request through the GitHub website.

## Additional Resources

* [General GitHub documentation](https://help.github.com/)
* [GitHub pull request documentation](https://help.github.com/articles/creating-a-pull-request/)
* [Python Documentation](https://docs.python.org/3/)
* [Flask Documentation](https://flask.palletsprojects.com/)
* [Cryptography Documentation](https://cryptography.io/en/latest/)

Thank you for your contributions!