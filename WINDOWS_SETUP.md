# Windows Setup Guide

This project is written in Python and does not require Visual Studio, CMake, g++, or a C++ build step.

## Step 1: Install Python

1. Install Python 3.10 or newer from https://www.python.org/downloads/windows/.
2. During installation, select **Add Python to PATH**.
3. Open PowerShell and confirm:

\`\`\`powershell
python --version
\`\`\`

## Step 2: Open the Project

Open PowerShell or the VS Code terminal in the folder containing \`dpi_engine.py\`.

## Step 3: Create a Virtual Environment

\`\`\`powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
\`\`\`

There are no third-party packages to install. If PowerShell does not allow activation, use \`python\` directly or run \`.\.venv\Scripts\python.exe\`.

## Step 4: Generate a Test Capture

\`\`\`powershell
python generate_test_pcap.py
\`\`\`

The command creates \`test_dpi.pcap\` with synthetic test packets.

## Step 5: Run the DPI Engine

\`\`\`powershell
python dpi_engine.py test_dpi.pcap output.pcap
\`\`\`

With blocking rules:

\`\`\`powershell
python dpi_engine.py test_dpi.pcap filtered.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain facebook
\`\`\`

Use \`--help\` to view all options:

\`\`\`powershell
python dpi_engine.py --help
\`\`\`

## Step 6: Open the Result

Open \`output.pcap\` or \`filtered.pcap\` in Wireshark to inspect the allowed packets.

## Troubleshooting

### Error: 'python' is not recognized

Reinstall Python and select **Add Python to PATH**, or use the full path to your Python executable.

### Error: Input file not found

Generate the test file with \`python generate_test_pcap.py\`, or use the full path to an existing PCAP file.

### Error: Unsupported capture format

The current reader supports classic PCAP files. In Wireshark, use **File → Save As** and choose a PCAP format rather than PCAPNG.

### No domain appears in the report

The capture may not include a full visible TLS ClientHello or a plain HTTP Host header. Encrypted Client Hello, TCP segmentation, or unsupported packet formats can prevent hostname extraction.

### Important scope note

This tool filters a saved PCAP file. It is not a live network firewall and does not block packets on your network interface.
