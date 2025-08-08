# EvilURL4 Classroom Edition

[![PyPI](https://img.shields.io/badge/python-3.6%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

EvilURL4 Classroom Edition is an educational tool that demonstrates IDN Homograph attacks by generating visually similar domain names using Unicode characters. This GUI-based application helps security professionals and educators showcase how attackers can create deceptive URLs for phishing campaigns.

![EvilURL4 Screenshot](screenshot.png)

## Features

- 🖥️ Modern PyQt5 GUI with dark theme
- 🔠 Generate homograph variants of domains
- 🌐 Check domain connection status (UP/DOWN)
- 🔍 Check domain availability (REGISTERED/AVAILABLE)
- 📁 Batch processing from input files
- 💾 Save results to text files
- 🚦 Real-time progress tracking
- 🎨 Color-coded output for readability
- ⚙️ Configurable processing options

## Installation

1. **Prerequisites**:
   - Python 3.6 or higher
   - pip package manager

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
Run the application:

bash
python evilurl4.py
Usage
Single Domain Processing
Enter a domain in the format example.com

Select processing options:

✅ Generate homograph variants

✅ Check domain connection

✅ Check domain availability

Click "Process"

Batch Processing
Click "Browse" to select an input file containing domains (one per line)

Configure processing options

Click "Process"

Output Controls
Save Output: Export results to text file

Clear Output: Reset the output panel

Cancel: Stop ongoing processing

Command Line Options
While the GUI is the primary interface, you can also run the tool from the command line:

bash
python evilurl4.py -d example.com -g -c -a -o results.txt
Options:

-d/--domain: Target domain

-g/--generate: Generate homograph variants

-c/--check: Check domain connections

-a/--availability: Check domain availability

-f/--file: Process domains from file

-o/--output: Save results to file

Homograph Character Mapping
The tool uses Unicode characters from various scripts (Cyrillic, Greek, Cherokee, etc.) that visually resemble Latin letters. For example:

Latin	Similar Characters	Unicode Names
a	а, Ӑ, ā	Cyrillic Small Letter A, Cyrillic Small Letter A with Breve, Latin Small Letter A with Macron
c	с, ϲ, ς	Cyrillic Small Letter Es, Greek Lunate Sigma Symbol, Greek Small Letter Final Sigma
o	о, ο, օ	Cyrillic Small Letter O, Greek Small Letter Omicron, Armenian Small Letter Oh
Educational Purpose
This tool is designed for:

Security awareness training

Demonstrating IDN homograph attacks

Researching phishing techniques

Testing domain protection mechanisms

Important: Use this tool only on domains you own or have permission to test. Never use it for malicious purposes.

Contributing
Contributions are welcome! Please follow these steps:

Fork the repository

Create a feature branch (git checkout -b feature/improvement)

Commit your changes (git commit -am 'Add new feature')

Push to the branch (git push origin feature/improvement)

Open a pull request

License
This project is licensed under the MIT License - see the LICENSE file for details.

Acknowledgments
UndeadSec (Alisson Moretto) - Original EvilURL concept

Basty-devel (Sebastian Friedrich Nestler) - GUI implementation

Unicode Consortium - Character standards

Disclaimer: This tool is for educational purposes only. The developers assume no liability for any misuse of this software.

text

For optimal presentation, create a screenshot named `screenshot.png` showing the application interface and place it in the same directory as the README.md. The screenshot will automatically be displayed in GitHub's markdown renderer.

This README provides:
1. Clear installation and usage instructions
2. Feature overview with emoji visuals
3. Educational context and purpose
4. Contribution guidelines
5. Licensing information
6. Professional formatting suitable for GitHub
7. Responsive design elements (badges, tables)
8. Important disclaimer about ethical use

The requirements.txt file lists only the essential dependencies needed to run the application.
