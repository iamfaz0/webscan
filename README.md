
# 🔍 WEBSCAN - Advanced Website Security Scanner

[![Version](https://img.shields.io/badge/version-3.0-blue.svg)](https://github.com/iamfaz0/webscan)
[![Python](https://img.shields.io/badge/python-3.7+-green.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Termux-lightgrey.svg)]()

**WEBSCAN** is a powerful website security scanner with advanced JavaScript reconnaissance, subdomain enumeration, and vulnerability detection capabilities.

## ⚠️ Legal Disclaimer
> **For authorized security testing only.** You must have permission to scan any website.

## ✨ Features

- **CMS Detection** - WordPress, Joomla, Drupal, Magento
- **JavaScript Recon** - Find API keys, tokens, secrets in JS files
- **Subdomain Enumeration** - Discover hidden subdomains
- **Port Scanning** - Detect open ports and services
- **Admin Panel Finder** - Locate login panels
- **Vulnerability Checks** - Find security issues
- **Risk Scoring** - 0-100 risk assessment
- **Report Export** - JSON format reports

## 📥 Installation

### Linux / Termux

```bash
# Clone repository
git clone https://github.com/iamfaz0/webscan.git
cd webscan

# Install dependencies
pip install -r requirements.txt

# Install nmap (Termux)
pkg install nmap -y

# Run tool
python webscan.py
```

🚀 Quick Usage

```bash
# Quick scan
python webscan.py -u https://example.com

# Full scan (JS recon + subdomains)
python webscan.py -u https://example.com --full

# View scan history
python webscan.py --history

# Generate report
python webscan.py --scan-id 1

# Interactive mode
python webscan.py
```

📊 Example Output

```
============================================================
 SCANNING: https://example.com
============================================================
[+] IP Address: 93.184.216.34
[+] CMS: WordPress
[+] Database: MySQL
[+] Open ports: 80/tcp, 443/tcp

============================================================
 JAVASCRIPT RECONNAISSANCE
============================================================
[!] API Keys Found: 2
[!] Endpoints Found: 15
[!] Risk Score: 65/100

============================================================
 SUBDOMAIN ENUMERATION
============================================================
[+] Found: api.example.com
[+] Found: admin.example.com
[+] Found: mail.example.com
```

🛠️ Requirements

· Python 3.7+
· Nmap
· Internet connection

📁 Project Structure

```
webscan/
├── webscan.py          # Main tool
├── requirements.txt    # Dependencies
├── webscan.db         # Database (auto-created)
└── scan_report_*.json # Scan reports
```

❓ Common Issues

Nmap not found:

```bash
# Linux
sudo apt-get install nmap

# Termux  
pkg install nmap
```

Permission denied:

```bash
chmod +x webscan.py
```

📝 License

MIT License - Free for educational and authorized testing

🤝 Contributing

Pull requests welcome! For major changes, please open an issue first.

📞 Contact

· Author: iamfaz0
· GitHub: @iamfaz0

---

⭐ Star this repo if you find it useful!

```
