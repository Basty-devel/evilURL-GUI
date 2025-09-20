# Internationalized Domain Name (IDN) Homograph Attack Demonstrator

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-windows%20%7C%20linux%20%7C%20macos-lightgrey)

An educational tool that demonstrates how homograph attacks work by substituting Latin characters with visually similar non-Latin characters from Cyrillic and Greek scripts. This tool helps security professionals and educators understand and defend against Internationalized Domain Name (IDN) homograph attacks.

## Features

- **Character Substitution**: Expands Latin characters to visually similar Cyrillic and Greek homoglyphs
- **GUI Interface**: User-friendly PyQt5 interface for interactive exploration
- **Domain Analysis**: Performs WHOIS lookups to check domain registration status
- **Online Verification**: Checks if generated domains are resolvable via DNS
- **Punycode Display**: Shows the ASCII representation of internationalized domain names
- **Educational Focus**: Detailed explanations of homograph attacks and security implications

## Installation

### Prerequisites

- Python 3.6 or higher
- pip (Python package manager)

### Steps

1. Clone or download this repository
2. Navigate to the project directory
3. Install required dependencies:

```bash
pip install -r requirements.txt
```
## Usage
### Graphical Interface (Recommended)
```bash
python evilURL4.py
```
Enter a domain name in the input field (e.g., "example.com")

Select which character sets to use (Cyrillic, Greek, or both)

Choose whether to perform WHOIS lookups and online checks

Click "Analyze" to generate homograph variations

View results in the table, with color-coded status indicators

Double-click any result to see detailed information

### Command Line Interface
```bash
python evilURL4.py example.com
```
The CLI mode provides a text-based output of homograph variants with basic checks.

How It Works
The tool identifies characters in a domain name that have visually similar equivalents in other scripts (primarily Cyrillic and Greek). It then generates all possible combinations of substitutions and performs various checks:

Punycode Conversion: Translates international characters to ASCII-compatible encoding

WHOIS Lookup: Checks if the domain is registered and displays registration details

Online Verification: Attempts to resolve the domain to see if it's actively used

Character Substitution Map
The tool uses a carefully curated mapping of Latin characters to their visually similar non-Latin equivalents:

Latin	Cyrillic	Greek	Description
a	а	α	Cyrillic small a, Greek alpha
c	с		Cyrillic small es
e	е	е	Cyrillic small ie, Greek epsilon
o	о	ο	Cyrillic small o, Greek omicron
p	р		Cyrillic small er
x	х	χ	Cyrillic small ha, Greek chi
y	у	γ	Cyrillic small u, Greek gamma
...	...	...	...
See the full mapping in the source code.

## Educational Purpose
This tool is designed for:

Security researchers studying homograph attacks

Educators teaching cybersecurity concepts

System administrators testing their defenses

Developers implementing IDN validation

**Important: This tool should only be used on domains you own or have explicit permission to test. Unauthorized use may violate terms of service or applicable laws.**

## Limitations

Character substitution is limited to the most visually convincing homoglyphs

WHOIS lookups may fail for some TLDs or restricted domains

Online checks only verify DNS resolution, not HTTP availability

Some modern browsers have implemented protections against homograph attacks

## Contributing
Contributions are welcome! Please feel free to submit issues, suggestions, or pull requests for:

Additional character mappings

Improved GUI features

Enhanced detection capabilities

Documentation improvements

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer
This tool is provided for educational purposes only. The authors are not responsible for any misuse of this software. Always ensure you have proper authorization before testing domains you do not own.

## References
Unicode Technical Report #36: Unicode Security Considerations

ICANN IDN Guidelines

RFC 5890: Internationalized Domain Names for Applications (IDNA)
