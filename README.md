# IDN Homograph Attack by N3S3

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey)

**An educational security tool that demonstrates how Internationalized Domain Name (IDN) homograph attacks work by substituting Latin characters with visually similar non-Latin characters from Cyrillic and Greek scripts. This tool helps security professionals, developers, and educators understand and defend against homograph attacks.**

## 🚀 Features

- **Character Substitution**: Expands Latin characters to visually similar Cyrillic and Greek homoglyphs
- **Professional GUI**: Modern PyQt6 interface for interactive exploration
- **Domain Analysis**: Performs WHOIS lookups to check domain registration status
- **Online Verification**: Checks if generated domains are resolvable via DNS
- **Punycode Display**: Shows ASCII representation of internationalized domain names
- **Security Checks**: Comprehensive analysis with color-coded risk indicators
- **Educational Focus**: Detailed explanations of homograph attacks and security implications

## 📋 Table of Contents

- [Installation](#installation)
- [Usage](#usage)
- [Features](#features)
- [Technical Details](#technical-details)
- [Security Disclaimer](#security-disclaimer)
- [Contributing](#contributing)
- [License](#license)

## 🛠 Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Steps

1. **Clone or download this repository**
   ```bash
   git clone github.com/Basty-devel/evilURL4.git
   cd evilURL4
Create a virtual environment (recommended)


# Create virtual environment
```bash
python -m venv homograph_env
```
# Activate on Windows
```bash
homograph_env\Scripts\activate
```
# Activate on macOS/Linux
```bash
source homograph_env/bin/activate
```
# Install dependencies

```bash
pip install -r requirements.txt
```
# 📖 Usage
Graphical Interface (Recommended)
```bash
python evilURL4.py
```
Enter a domain name in the input field (e.g., "example.com")

Select character sets to use (Cyrillic, Greek, or both)

Choose analysis options (WHOIS lookup, online checks)

Click "Analyze Domain" to generate homograph variations

View results in the table with color-coded status indicators

Double-click any result to see detailed domain information

Command Line Interface
```bash
python evilURL4.py example.com
```
The CLI mode provides text-based output of homograph variants with basic security checks.

# 🔍 Technical Details
How It Works
The tool identifies characters in domain names that have visually similar equivalents in other scripts (primarily Cyrillic and Greek). It generates all possible combinations of substitutions and performs various security checks:

Punycode Conversion: Translates international characters to ASCII-compatible encoding

WHOIS Lookup: Checks domain registration status and displays details

Online Verification: Attempts to resolve domains to identify active homograph attacks

Risk Assessment: Color-coded indicators show potential security risks

# Character Substitution Map
The tool uses a carefully curated mapping of Latin characters to their visually similar non-Latin equivalents:

Latin	Cyrillic	Greek	Description
a	а	α	Cyrillic small a, Greek alpha
c	с		Cyrillic small es
e	е		Cyrillic small ie
o	о	ο	Cyrillic small o, Greek omicron
p	р		Cyrillic small er
x	х	χ	Cyrillic small ha, Greek chi
y	у	γ	Cyrillic small u, Greek gamma
See the complete mapping in the source code.

# ⚠️ Security Disclaimer
This tool is for educational and defensive security purposes only.

# Appropriate Uses:
Security research and education

Testing your own domains and systems

Learning about homograph attack techniques

Developing defensive security measures

# Prohibited Uses:
Testing domains you don't own without explicit permission

Malicious activities or social engineering attacks

Harassment or fraudulent activities

**The authors are not responsible for any misuse of this software. Always ensure you have proper authorization before testing domains you do not own. Unauthorized use may violate terms of service or applicable laws.**

# 🐛 Contributing
Contributions are welcome! Please feel free to submit issues, suggestions, or pull requests for:

Additional character mappings

Improved GUI features

Enhanced detection capabilities

Documentation improvements

Development Setup
Fork the repository

Create a feature branch: git checkout -b feature/amazing-feature

Commit your changes: git commit -m 'Add amazing feature'

Push to the branch: git push origin feature/amazing-feature

Open a pull request

# 📄 License
This project is licensed under the MIT License - see the LICENSE file for details.

# 🔗 References
Unicode Technical Report #36: Unicode Security Considerations

ICANN IDN Guidelines

RFC 5890: Internationalized Domain Names for Applications (IDNA)

OWASP Security Guidelines

# 🆕 Changelog
Version 2.0
Added PyQt6 GUI interface

Integrated WHOIS lookup functionality

Added online domain verification

Enhanced character substitution mapping

Improved documentation and educational content

# 💬 Support
For questions or issues:

Check the existing GitHub issues

Create a new issue with detailed information

Provide the domain you're testing and steps to reproduce errors
