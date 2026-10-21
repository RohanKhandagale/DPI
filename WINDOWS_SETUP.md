# Windows Setup Guide (Python Port)

This repository is the Python port of the DPI packet analyzer. You do not need Visual Studio, CMake, MinGW, or a C++ compiler.

## 1. Install Python

Install Python 3.10 or newer from https://www.python.org/downloads/windows/. During setup, enable **Add Python to PATH**. Open a new PowerShell window and verify:

```powershell
python --version
```

## 2. Get the repository

Download the ZIP from https://github.com/RohanKhandagale/DPI or clone it:

```powershell
git clone https://github.com/RohanKhandagale/DPI.git
cd DPI
```

## 3. Create an environment

```powershell
python -m venv .venv
.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

The engine uses the Python standard library; no third-party packet library is required. If PowerShell blocks activation, use Command Prompt and run `.venv\\Scripts\\activate.bat` instead.

## 4. Generate a test capture and run DPI

```powershell
python generate_test_pcap.py
python dpi_engine.py test_dpi.pcap output.pcap
```

The input is a classic Ethernet PCAP file. The engine writes packets allowed by the configured rules to `output.pcap` and prints a summary.

## 5. Try blocking rules

```powershell
python dpi_engine.py test_dpi.pcap filtered.pcap --block-app YouTube
python dpi_engine.py test_dpi.pcap filtered-domain.pcap --block-domain youtube.com
python dpi_engine.py test_dpi.pcap filtered-ip.pcap --block-ip 192.168.1.50
```

Rules can be repeated. Use `--help` to see the options currently supported by the main CLI.

## 6. Run tests

```powershell
python -m unittest discover -s tests -v
```

## Scope and limitations

This is offline PCAP analysis, not a live network firewall. The integrated engine supports Ethernet, common VLAN tags, IPv4, TCP/UDP, TLS ClientHello SNI, and unencrypted HTTP Host headers. It does not decrypt TLS, fully reassemble TCP streams, deeply inspect QUIC, or inspect IPv6. Encrypted ClientHello can also hide SNI. Results depend on the packets and payloads present in the capture.
