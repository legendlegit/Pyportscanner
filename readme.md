# pyportscanner 🛡️

A simple, fast, threaded TCP port scanner written in Python for **authorized** security testing and penetration testing labs.

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/github/license/yourusername/pyportscan.svg)](LICENSE)

## 🚀 Quick Start

```bash
# Clone the repo
git clone https://github.com/yourusername/pyportscan.git
cd pyportscan

# Test it
python portscan.py -t 127.0.0.1 -p 1-1024 -v
✨ Features
Scan multiple targets (IPs or hostnames)

Flexible port specification: 80, 80,443, 1-1024, 22,80,8000-8100

Threaded scanning (configurable threads/timeout)

Optional JSON output with timestamps and banners

Clean CLI with --help and verbose mode

📖 Usage Examples
Basic scan:
python portscan.py -t 10.10.10.10 -p 1-1000

Multiple targets with top web ports:
python portscan.py -t 10.10.10.10 scanme.nmap.org -p 22,80,443,8080,8443

Full scan with JSON output:
python portscan.py -t 127.0.0.1 -p 1-1024 --threads 200 --timeout 0.5 -o results.json -v

See all options:
python portscan.py -h

📁 Output Format
============================================================
Target: 127.0.0.1 (127.0.0.1)
Open ports:
  - 135/tcp open | banner: Microsoft Windows RPC
  - 445/tcp open | banner: Microsoft SMB

JSON output includes timestamps, resolved IPs, and service banners.

🛡️ Legal & Ethical Use
⚠️ Use only on systems you own or have explicit written permission to test.

This tool is for:

Educational purposes

Authorized penetration testing

Security research labs (TryHackMe, HackTheBox, etc.)

The author is not responsible for misuse or damage.

🏗️ Development
# Install (no dependencies!)
python portscan.py -h

# Run tests (add your own)
python -m pytest tests/
