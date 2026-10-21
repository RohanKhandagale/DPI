# DPI Engine - Deep Packet Inspection System

This guide introduces the project, explains the networking ideas behind it, and follows a packet through the Python implementation. It is intended to help readers understand the processing flow before exploring the source files.

Reference project: [Packet_analyzer](https://github.com/perryvegehan/Packet_analyzer). This repository is an independent Python implementation of the same general DPI learning concepts, not a line-by-line source copy.

## Python port layout

The uploaded original project was reviewed to map its C++ components to Python equivalents. The implementation keeps the same component responsibilities while using Python modules. The C++ executable and headers are not retained as source files; each listed component has a Python counterpart.

| Original component | Python counterpart |
|---|---|
| `include/types.h` / `src/types.cpp` | `include/types.py` / `src/types.py` |
| `include/pcap_reader.h` / `src/pcap_reader.cpp` | `include/pcap_reader.py` / `src/pcap_reader.py` |
| `include/packet_parser.h` / `src/packet_parser.cpp` | `include/packet_parser.py` / `src/packet_parser.py` |
| `include/sni_extractor.h` / `src/sni_extractor.cpp` | `include/sni_extractor.py` / `src/sni_extractor.py` |
| `include/rule_manager.h` / `src/rule_manager.cpp` | `include/rule_manager.py` / `src/rule_manager.py` |
| `include/connection_tracker.h` / `src/connection_tracker.cpp` | `include/connection_tracker.py` / `src/connection_tracker.py` |
| `include/thread_safe_queue.h` | `include/thread_safe_queue.py` / `src/thread_safe_queue.py` |
| `include/load_balancer.h` / `src/load_balancer.cpp` | `include/load_balancer.py` / `src/load_balancer.py` |
| `include/fast_path.h` / `src/fast_path.cpp` | `include/fast_path.py` / `src/fast_path.py` |
| `include/dpi_engine.h` / `src/dpi_engine.cpp` | `src/dpi_engine.py` (exports the engine orchestrator) |
| `src/dpi_mt.cpp` | `src/dpi_mt.py` |
| `src/main_dpi.cpp` | `src/main_dpi.py` |
| `src/main_working.cpp` | `src/main_working.py` |
| `src/main.cpp` | `src/main.py` |
| `src/main_simple.cpp` | `src/main_simple.py` |

The original `CMakeLists.txt` is replaced by `pyproject.toml`; Python does not need a C++ compiler or CMake. The primary fully integrated command-line implementation remains `dpi_engine.py`. Component modules under `src/` expose the original architecture in a Python-friendly form.

---

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [File Structure](#4-file-structure)
5. [The Journey of a Packet (Simple Version)](#5-the-journey-of-a-packet-simple-version)
6. [The Journey of a Packet (Multi-threaded Version)](#6-the-journey-of-a-packet-multi-threaded-version)
7. [Deep Dive: Each Component](#7-deep-dive-each-component)
8. [How SNI Extraction Works](#8-how-sni-extraction-works)
9. [How Blocking Works](#9-how-blocking-works)
10. [Building and Running](#10-building-and-running)
11. [Understanding the Output](#11-understanding-the-output)
12. [Extending the Project](#12-extending-the-project)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** examines network packets beyond their basic addressing information. A normal packet filter may check source and destination addresses, while DPI can inspect transport data and recognize application protocols or visible domain names.

### Real-World Uses

- **ISPs**: Identify traffic types for network management.
- **Enterprises**: Apply network usage policies.
- **Parental Controls**: Identify some website traffic for policy enforcement.
- **Security**: Help investigate suspicious traffic and protocol patterns.

### What This DPI Engine Does

\`\`\`
Input PCAP → [Python DPI Engine] → Output PCAP
                     |
                     ├── Parses Ethernet / IPv4 / TCP / UDP
                     ├── Identifies applications from visible HTTP Host or TLS SNI
                     ├── Applies IP, application, and domain rules
                     └── Prints packet and application statistics
\`\`\`

This is an **offline PCAP analyzer**. It processes packets saved in a capture file; it does not attach itself to a network interface or directly stop live traffic.

---

## 2. Networking Background

### The Network Stack

When a device connects to a service, data is carried through several protocol layers:

\`\`\`
Layer 7: Application    HTTP, TLS, DNS
Layer 4: Transport      TCP, UDP
Layer 3: Network        IPv4 addresses
Layer 2: Data Link      Ethernet and MAC addresses
\`\`\`

### A Packet's Structure

An Ethernet frame commonly contains nested protocol headers followed by application data:

\`\`\`
┌─────────────────────────────────────────┐
│ Ethernet Header                         │
│ ┌─────────────────────────────────────┐ │
│ │ IPv4 Header                         │ │
│ │ ┌─────────────────────────────────┐ │ │
│ │ │ TCP or UDP Header                │ │ │
│ │ │ ┌─────────────────────────────┐ │ │ │
│ │ │ │ Application Payload         │ │ │ │
│ │ │ │ HTTP data or TLS handshake  │ │ │ │
│ │ │ └─────────────────────────────┘ │ │ │
│ │ └─────────────────────────────────┘ │ │
│ └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
\`\`\`

### The Five-Tuple

The engine groups packets into flows using five values:

| Field | Example | Purpose |
|---|---|---|
| Source IP | 192.168.1.100 | Sender address |
| Destination IP | 172.217.14.206 | Destination address |
| Source Port | 54321 | Sender transport port |
| Destination Port | 443 | Service transport port |
| Protocol | TCP (6) | Transport protocol |

Packets with the same five-tuple are tracked as one flow. A flow retains its discovered application/domain and its blocked state.

### What is SNI?

**Server Name Indication (SNI)** is a TLS extension that can include the requested hostname in a ClientHello. When that information is visible in the capture, the engine can use it to classify traffic. Some modern connections use Encrypted Client Hello (ECH), and a capture may not contain a complete ClientHello in one packet; in those cases, hostname extraction may not be possible.

---

## 3. Project Overview

### What This Project Does

\`\`\`
Wireshark/tcpdump PCAP
          |
          v
     Python DPI Engine
       - Read packets
       - Parse headers
       - Classify flows
       - Apply blocking rules
       - Report statistics
          |
          v
Filtered output PCAP
\`\`\`

### Processing Modes

| Mode | Entry point | Use case |
|---|---|---|
| Single-process processing | \`dpi_engine.py\` with \`--lbs 1 --fps 1\` | Learning and debugging |
| Worker-thread processing | \`dpi_engine.py\` (default) | Demonstrates load-balancer and fast-path workers |

The implementation uses Python's standard library. No C++ compiler or external packet library is required.

---

## 4. File Structure

\`\`\`
DPI/
├── dpi_engine.py          # PCAP reader, parser, classifier, rules, worker threads and CLI
├── generate_test_pcap.py  # Creates a small synthetic test capture
├── test_dpi.pcap          # Generated locally when you run the generator
├── output.pcap            # Filtered output created when the engine runs
├── requirements.txt       # No third-party runtime dependencies
├── WINDOWS_SETUP.md       # Windows setup and run instructions
├── tests/
│   └── test_dpi_engine.py # Unit tests for packet parsing and classification
├── .gitignore
└── README.md
\`\`\`

Generated capture files are created on your computer and do not need to be committed.

---

## 5. The Journey of a Packet (Simple Version)

A packet passes through the following steps inside \`dpi_engine.py\`.

### Step 1: Read the PCAP File

\`\`\`python
reader = PcapReader("capture.pcap")
reader.open()
\`\`\`

The reader checks the classic PCAP global header, identifies byte order and timestamp precision, and reads each packet record. The original packet record header is preserved when an allowed packet is written.

### Step 2: Read Each Packet

\`\`\`python
for packet_header, packet_data in reader.packets():
    packet_info = parse_packet(packet_data)
    if packet_info is None:
        continue
\`\`\`

Each record contains a timestamp/header and the captured network bytes. Packets that do not match the supported Ethernet/IPv4/TCP/UDP formats are skipped.

### Step 3: Parse Protocol Headers

\`\`\`python
packet_info = parse_packet(packet_data)
print(packet_info.src_ip, packet_info.dst_ip)
print(packet_info.src_port, packet_info.dst_port)
print(packet_info.transport)
\`\`\`

The parser checks the Ethernet type, IPv4 header length, protocol number, and TCP or UDP header. It calculates where the application payload begins.

### Step 4: Track the Flow

\`\`\`python
flow_key = (
    packet_info.src_ip,
    packet_info.dst_ip,
    packet_info.src_port,
    packet_info.dst_port,
    packet_info.protocol,
)
flow = flows.setdefault(flow_key, FlowState())
flow.packets += 1
\`\`\`

A flow table stores the classification and blocking state for each five-tuple.

### Step 5: Inspect Application Data

For TCP destination/source port 443, the engine tries to extract TLS SNI. For port 80, it looks for an HTTP Host header. DNS traffic is classified using port 53, and HTTP/HTTPS fallback labels are used when no domain is available.

\`\`\`python
domain = extract_tls_sni(payload)
if domain:
    flow.domain = domain
    flow.app = classify_domain(domain)
\`\`\`

### Step 6: Check Blocking Rules

The rules can match a source IPv4 address, an application label, or a substring in the discovered domain. Once a flow is marked blocked, later packets assigned to that flow are dropped from the output capture.

### Step 7: Forward or Drop

Allowed packets are written to the output PCAP with their original packet header and data. Blocked packets are counted but not written.

### Step 8: Generate the Report

The report includes total packets and bytes, TCP/UDP counts, forwarded/dropped counts, active flows, worker counts, application distribution, and discovered domains.

---

## 6. The Journey of a Packet (Multi-threaded Version)

The default run uses queues and worker threads to demonstrate a pipeline.

### Architecture Overview

\`\`\`
PCAP Reader
    |
    v
Load Balancer queues (LB0, LB1, ...)
    |
    v
Fast Path workers (FP0, FP1, ...)
    |
    +---- allowed packets ----> Output queue
                                  |
                                  v
                              PCAP Writer
\`\`\`

### Why Use This Design?

1. **Load Balancers (LBs):** Route packets to a worker queue.
2. **Fast Paths (FPs):** Parse application data, maintain flow state, and apply rules.
3. **Consistent flow routing:** Packets with the same five-tuple are routed to the same fast-path worker during a run, allowing that worker to maintain the flow state.

The command-line options \`--lbs\` and \`--fps\` control the number of load balancer threads and the number of fast-path workers per load balancer.

### Thread Queues

Python's \`queue.Queue\` provides synchronized producer/consumer queues. The reader submits work, load balancers dispatch it, fast-path workers classify it, and the writer stores packets that are allowed.

---

## 7. Deep Dive: Each Component

### PCAP Reader

Reads the 24-byte classic PCAP global header and then each 16-byte packet record header followed by its packet bytes. Both little-endian and big-endian classic PCAP files are supported, including microsecond and nanosecond timestamp formats.

### Packet Parser

Parses Ethernet frames with IPv4 and TCP or UDP. Common VLAN tags are skipped before the IPv4 header. IPv6, non-initial IP fragments, and other link-layer formats are not currently inspected by this version.

### SNI and HTTP Host Extractors

- \`extract_tls_sni()\`: Walks the TLS record and ClientHello structures to locate the SNI extension.
- \`extract_http_host()\`: Reads a visible HTTP request and looks for its Host header.
- \`classify_domain()\`: Maps known hostname patterns to application labels.

### Application Types

Recognized labels include Google, YouTube, Facebook, Instagram, WhatsApp, Twitter/X, Netflix, Amazon, Microsoft, Apple, Telegram, TikTok, Spotify, Zoom, Discord, GitHub, and Cloudflare. Unrecognized domains are classified as HTTPS when SNI is found, while unknown traffic can fall back to HTTP, HTTPS, QUIC, or DNS based on ports.

### Blocking Rules

\`BlockingRules\` validates IPv4 addresses and application names. Domain rules use case-insensitive substring matching, so a rule such as \`tiktok\` matches any discovered hostname containing that text.

---

## 8. How SNI Extraction Works

### The TLS Handshake

A TLS client typically sends a ClientHello before encrypted application data begins. The ClientHello may include a server name:

\`\`\`
ClientHello
  ├── Version and Random
  ├── Session ID
  ├── Cipher Suites
  ├── Compression Methods
  └── Extensions
       └── SNI
            └── www.example.com
\`\`\`

The extractor checks the record and handshake types, safely walks the variable-length fields, then reads the hostname from the SNI extension. If the payload is incomplete or malformed, it returns no hostname rather than assuming one exists.

### Important Limitations

- SNI is available only when the relevant ClientHello bytes are visible in the captured packet.
- Encrypted Client Hello can hide the hostname.
- TCP segmentation may split a ClientHello across packets; this implementation does not reassemble TCP streams.
- TLS inspection here identifies visible metadata only. It does not decrypt HTTPS content.

---

## 9. How Blocking Works

### Rule Types

| Rule Type | Example | What it blocks |
|---|---|---|
| IP | \`192.168.1.50\` | Packets whose source IPv4 address matches |
| App | \`YouTube\` | Flows classified as YouTube |
| Domain | \`tiktok\` | Flows whose discovered domain contains the text |

### The Blocking Flow

\`\`\`
Packet arrives
     |
     v
Source IP rule matches? ---- Yes ---> Drop
     |
     No
     v
Application rule matches? - Yes ---> Drop
     |
     No
     v
Domain rule matches? ------ Yes ---> Drop
     |
     No
     v
Write packet to output PCAP
\`\`\`

### Flow-Based Blocking

A flow may initially be unknown because the first packets do not contain application metadata. When a later packet reveals a matching domain, the flow is marked blocked. Subsequent packets assigned to the same flow are also dropped.

This is PCAP filtering, not a live firewall. It does not retroactively remove earlier packets already written before the domain was discovered.

---

## 10. Building and Running

### Prerequisites

- Python 3.10 or newer
- A classic PCAP file captured with Wireshark or tcpdump
- No C++ compiler and no third-party Python packages

### Setup on Windows

Open PowerShell in the project folder:

\`\`\`powershell
python --version
python -m venv .venv
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
\`\`\`

If PowerShell blocks virtual-environment activation, run the Python commands using \`.\.venv\Scripts\python.exe\` directly.

### Create Test Data

\`\`\`powershell
python generate_test_pcap.py
\`\`\`

This creates \`test_dpi.pcap\` with synthetic HTTP, TLS, and DNS examples. It does not capture live traffic.

### Basic Usage

\`\`\`powershell
python dpi_engine.py test_dpi.pcap output.pcap
\`\`\`

### With Blocking Rules

\`\`\`powershell
python dpi_engine.py test_dpi.pcap output.pcap --block-app YouTube --block-ip 192.168.1.50 --block-domain facebook
\`\`\`

You can repeat a rule option to add more than one value:

\`\`\`powershell
python dpi_engine.py input.pcap filtered.pcap --block-app YouTube --block-app TikTok --block-domain tiktok

# Block a destination port
python dpi_engine.py input.pcap filtered.pcap --block-port 8080

# Load rules in the original section-based format
python dpi_engine.py input.pcap filtered.pcap --rules blocking_rules.example.txt
\`\`\`

### Configure Worker Threads

\`\`\`powershell
python dpi_engine.py input.pcap output.pcap --lbs 4 --fps 2
\`\`\`

This creates four load-balancer threads and eight fast-path worker threads. The writer has its own thread.

### Inspect the Output

Open \`output.pcap\` or \`filtered.pcap\` in Wireshark to inspect the packets that passed the configured rules.

---

## 11. Understanding the Output

The console report includes:

| Field | Meaning |
|---|---|
| Total Packets | Supported TCP/UDP packets processed |
| Total Bytes | Captured bytes for those packets |
| TCP Packets | TCP packets parsed |
| UDP Packets | UDP packets parsed |
| Forwarded | Packets written to the output PCAP |
| Dropped | Packets excluded by blocking rules |
| Active Flows | Distinct five-tuples tracked |
| Thread Statistics | Packets dispatched/processed by each worker |
| Application Breakdown | Packet counts by classification |
| Detected Domains/SNIs | Hostnames discovered from visible payloads |

The counts depend on the input capture, the configured rules, and which protocol metadata is visible in the packets.

---

## 12. Extending the Project

### Add More Application Signatures

Add a hostname pattern to \`APP_PATTERNS\` in \`dpi_engine.py\`. Keep specific patterns ordered thoughtfully when one service's hostname may also match another.

### Add Bandwidth Throttling

A future version could introduce a policy stage that delays packets or applies a rate limit. The current engine only forwards or drops captured packets.

### Add a Live Statistics Dashboard

A future UI could periodically read the shared statistics and display packet rates, application counts, and rule matches.

### Add QUIC/HTTP3 Support

QUIC commonly uses UDP port 443. Proper hostname extraction requires parsing QUIC Initial packets, handling packet protection, and locating TLS handshake data; this implementation currently labels such traffic by port rather than fully decoding QUIC.

### Add Persistent Rules

A future enhancement could load IP, application, and domain rules from a JSON file and save rule changes between runs.

---

## Summary

This project demonstrates:

1. **Network Protocol Parsing** - Reading Ethernet, IPv4, TCP, and UDP headers.
2. **Deep Packet Inspection** - Inspecting visible HTTP and TLS metadata.
3. **Flow Tracking** - Keeping per-connection classification and blocking state.
4. **Worker Threads** - Using queues to distribute packet processing.
5. **PCAP Filtering** - Writing allowed packets to a new capture file.

The goal is to make packet processing and basic DPI concepts easier to study with Python.

---

## Questions?

Start with a small generated capture, run the engine without blocking rules, and then try one rule at a time. Use Wireshark to compare the input and output PCAP files.

Happy learning! 🚀
