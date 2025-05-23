# ELcazad0r XSS Scanner

A powerful and comprehensive XSS vulnerability scanner with an intuitive GUI interface.

## Features

- **Multi-vector XSS Detection**: Tests for XSS vulnerabilities in:
  - Query parameters
  - Path segments
  - File extensions
- **Customizable Payloads**:
  - Default payloads
  - Custom payloads from a file
  - Custom payloads from a list


- **User-friendly Interface**: Built with PyQt5 for a smooth user experience
  
- **Advanced Scanning Capabilities**:
  - Headless browser support
  - Multithreaded scanning
  - Pause/Resume functionality
  - Progress tracking
  
- **Reporting and Notifications**:
  - Detailed vulnerability reports
  - Telegram integration for real-time alerts
  - Save scan results for later analysis

## Requirements

- Python 3.6+
- Chrome/Chromium browser
- Required Python packages:
  - requests
  - selenium
  - PyQt5
  - webdriver-manager
  - psutil

## Installation

1. Clone the repository:
```bash
git clone https://github.com/nihaltikka/ELcazad0r-XSS.git
cd ELcazad0r-XSS
```
2. Install required packages:
```bash
pip install -r requirements.txt
```
3. Install Chrome Browser:

For Windows:

- Download Chrome from the official website
- Run the installer and follow the on-screen instructions
- Verify installation by opening Chrome
For macOS:

- Download Chrome from the official website
- Open the downloaded .dmg file
- Drag Chrome to the Applications folder
- Verify installation by opening Chrome from Applications

For Linux (Ubuntu/Debian):
```bash
wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
sudo apt install ./google-chrome-stable_current_amd64.deb
```
4. ChromeDriver is automatically managed by webdriver-manager package, so no manual installation is required.

## Usage
Run the application:
```bash
python3 elcazad0r_xss.py
```
### Scanning Options
1. Target URLs : Enter URLs to scan, one per line
2. Payloads : Use default XSS payloads or add custom ones
3. Scan Configuration :
   - Enable/disable specific test vectors
   - Configure headless mode
   - Set up Telegram notifications

### Scan Results
Results are displayed in categorized tabs:

- Query Parameter XSS
- Path XSS
- Extension XSS


## Contributing
Contributions are welcome! Please feel free to submit a Pull Request.

## Author
https://github.com/nihaltikka - GitHub Profile
## Disclaimer
This tool is for educational purposes and authorized security testing only. Always obtain proper permission before scanning any website or application.