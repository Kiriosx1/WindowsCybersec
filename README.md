# 🛡️ CyberSecMult — Professional Cybersecurity Utility Suite

```
 ╔═══════════════════════════════════════════════════════════════════════╗
 ║                     🔐 CYBERSECMULT v4.0 🔐                          ║
 ║            Professional Cybersecurity Utility (C++20/Windows)         ║
 ╚═══════════════════════════════════════════════════════════════════════╝
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![C++20](https://img.shields.io/badge/C%2B%2B-20-blue.svg)](https://isocpp.org/)
[![Windows](https://img.shields.io/badge/Platform-Windows%2010%2F11-0078D6.svg)](https://microsoft.com/windows)
[![Version](https://img.shields.io/badge/Version-4.0-brightgreen.svg)](#version-history)

---

## 🎯 Overview

**CyberSecMult** is an enterprise-grade, native C++20 cybersecurity toolkit for security professionals, penetration testers, red teamers, and system administrators. It runs entirely offline with zero dependencies beyond the Windows SDK — no Python, no .NET, no third-party DLLs.

v4.0 is a major update introducing **5 new security modules** including native integration of the [Glaux](https://github.com/Kiriosx1/Glaux-) steganography engine, a threat intelligence OSINT suite, a NIST-compliant password auditor, a live privilege escalation scanner, and a network anomaly detector.

---

## 📦 Main Menu (v4.0)

```
╔════════════════════════════════════════════════════════════════════╗
║                          MAIN MENU                                 ║
╠════════════════════════════════════════════════════════════════════╣
║                                                                    ║
║  1.  🧮  Calculators & Converters                                  ║
║  2.  🖥️   System Utilities                                         ║
║  3.  🌐  Network & Security Tools                                  ║
║  4.  📁  File Operations                                           ║
║  5.  🔑  Cryptographic Tools                                       ║
║  6.  🔍  Forensics & Analysis                                      ║
║                                                                    ║
║  ─────────────────── NEW IN v4.0 ──────────────────────           ║
║                                                                    ║
║  8.  🦉  Steganography Engine (Glaux integration)                  ║
║  9.  🕵️   Threat Intelligence & OSINT                              ║
║  10. 🔓  Password Audit & Hash Cracker                             ║
║  11. 💀  PrivEsc Scanner & Hardening Advisor                       ║
║  12. 🛡️   Network Defense & Anomaly Detector                       ║
║                                                                    ║
║  0.  ❌  Exit                                                      ║
╚════════════════════════════════════════════════════════════════════╝
```

---

## 🔧 Core Modules (v1–v3)

### 1️⃣ Calculators & Converters
IP/CIDR math, subnet mask calculator, hash value converter, binary/hex/Base64 encode-decode, cryptographic strength assessment.

### 2️⃣ System Utilities
PDH-backed real-time process monitor, memory profiler, registry inspector, configuration auditor, performance benchmarker.

### 3️⃣ Network & Security Tools
Multi-threaded port scanner, SSL/TLS certificate analyser, DNS lookup/reverse DNS, packet sniffer hooks, network vulnerability checks, proxy/firewall test.

### 4️⃣ File Operations
AES-256 file encryption/decryption (CNG), secure DoD-grade file wipe, file integrity verification (SHA-256), metadata extraction, batch operations.

### 5️⃣ Cryptographic Tools
AES-256-CBC, RSA-2048/4096, ECC, SHA-256/SHA-512/BLAKE2 via Windows CNG, HMAC, digital signatures, key generation, rainbow-table defence.

### 6️⃣ Forensics & Analysis
Memory dump capture, process timeline reconstruction, log correlation, disk imaging helpers, evidence chain of custody, registry artefact extraction.

---

## 🆕 New Modules — v4.0

### 8️⃣ 🦉 Steganography Engine (Glaux Integration)

Directly integrates the [Glaux](https://github.com/Kiriosx1/Glaux-) steganography project into CyberSecMult as a first-class module. Supports LSB (Least Significant Bit) encoding inside 24-bit BMP images with optional passphrase-based XOR payload encryption.

| Sub-feature | Description |
|---|---|
| Embed | Hide any text or binary file inside a BMP carrier image |
| Extract | Recover a hidden payload from a stego-image |
| Chi-square analysis | Detect whether an image likely contains hidden data |
| Capacity check | Calculate the maximum embeddable payload size for any BMP |

Passphrase protection: payloads are XOR-encrypted with your passphrase before embedding, so the image is useless without the key. The chi-square statistical analyser detects LSB manipulation in unknown images — useful for counter-steganography investigations.

```
  Carrier capacity: 196,605 bytes | Payload: 512 bytes
  [+] Payload embedded → stego_output.bmp
```

---

### 9️⃣ 🕵️ Threat Intelligence & OSINT

A full offline threat intelligence toolkit — no API keys required.

| Sub-feature | Description |
|---|---|
| IP Threat Scorer | Heuristic scoring of IPv4 addresses (RFC1918, Tor ranges, open high-risk ports) |
| Banner Grabber | TCP banner grab for host:port intelligence |
| Entropy Scanner | Detect packed/encrypted/compressed regions in any file (4KB sliding window) |
| Process Hollowing Detector | Cross-check in-memory PE MZ headers against on-disk images |
| IOC Manager | Load, search, match, and export Indicators of Compromise lists |

The entropy scanner uses Shannon entropy analysis across 4KB chunks of any binary. Regions scoring above 7.2 bits/byte are flagged as `PACKED/ENCRYPTED` — a reliable indicator of packers (UPX, Themida), ransomware, or malicious loaders.

The process hollowing detector reads the in-memory MZ header of every running process and compares it to the on-disk image, flagging mismatches — a classic sign of process hollowing (used by many APT implants).

---

### 🔟 🔓 Password Audit & Hash Cracker

NIST SP 800-63B compliant password evaluation with offline hash cracking.

| Sub-feature | Description |
|---|---|
| Strength Evaluator | Score + entropy analysis, keyboard walk detection, repetition, year patterns |
| Dictionary Attack | Offline wordlist attack against MD5 / SHA-1 / SHA-256 / NTLM hashes |
| Mutation Engine | Automatic leet substitution + suffix mutations per word |
| Batch Hash Generator | Generate MD5, SHA-1, SHA-256, and NTLM for any input |
| Passphrase Generator | Secure Diceware-style passphrases with entropy estimation |

The wordlist attacker uses the native Windows CryptAPI (CNG) for all hashing — it runs entirely without OpenSSL or any external library. Mutation rules include leet substitution (a→@, e→3, etc.) and common numeric suffixes, which significantly extends coverage without needing a rule engine like Hashcat.

---

### 1️⃣1️⃣ 💀 PrivEsc Scanner & Hardening Advisor

Live privilege escalation assessment directly against the running Windows system.

| Check | Severity | Description |
|---|---|---|
| Unquoted Service Paths | HIGH | Enumerates all Win32 services with exploitable unquoted paths |
| AlwaysInstallElevated | CRITICAL | Detects HKCU+HKLM MSI elevation misconfiguration |
| Token Privilege Audit | CRITICAL/HIGH | Flags SeDebugPrivilege, SeImpersonatePrivilege, SeTcbPrivilege, etc. |
| LSASS RunAsPPL | HIGH | Checks if LSASS is running as Protected Process Light |
| UAC Level | CRITICAL/LOW | Detects disabled UAC or default auto-elevation level |

Every finding includes a plain-English remediation step and can be exported to a structured text report. Findings are sorted by severity (CRITICAL → INFO) automatically.

This module is invaluable during internal red team engagements and for hardening Windows servers before deployment.

---

### 1️⃣2️⃣ 🛡️ Network Defense & Anomaly Detector

A network situational awareness and defensive toolset.

| Sub-feature | Description |
|---|---|
| TCP Connection Monitor | Lists all active connections with process mapping and suspicious port flagging |
| ARP Spoof Detector | Scans the ARP table for duplicate MACs — indicator of ARP poisoning/MITM |
| Interface Enumerator | Full IP/MAC/status listing of all network adapters |
| Poisoning Risk Check | Detects LLMNR and NetBIOS enabled — vulnerability to Responder attacks |

The connection monitor flags established connections to known high-risk ports (4444, 31337, 1337, 9001, etc.) and unusual svchost.exe behaviour in real time. The LLMNR/NetBIOS check identifies one of the most common Active Directory lateral movement pre-conditions — enabled by default on most Windows systems.

---

## 🚀 Quick Start

### System Requirements

| Requirement | Minimum | Recommended |
|---|---|---|
| OS | Windows 10 64-bit | Windows 11 64-bit |
| RAM | 4 GB | 8 GB |
| Storage | 2 GB free | 5 GB free |
| CPU | 1.8 GHz dual-core | Multi-core 3 GHz+ |
| Privileges | Standard (limited) | Administrator (full functionality) |
| Runtime | Visual C++ 2022 Redist | Included in VS2022 |

### Build from Source

```bash
# Clone the repository
git clone https://github.com/Kiriosx1/WindowsCybersec.git
cd WindowsCybersec

# Generate build files
cmake -B build -DCMAKE_BUILD_TYPE=Release

# Build with all cores
cmake --build build --config Release --parallel

# Run
cd build/Release
./CyberSecMultitool.exe
```

### Precompiled Binary

Download `CyberSecMultitool.exe` from the [latest release](../../releases/latest) — no installation required. Run as Administrator for full functionality.

---

## 🔐 Modules That Require Administrator Privileges

The following features require an elevated process (Run as Administrator):

- **PrivEsc Scanner** — service enumeration, registry reads, token inspection
- **Process Hollowing Detector** — requires `PROCESS_VM_READ` on other processes
- **LSASS Protection Check** — requires HKLM registry read
- **TCP Connection Monitor** — full PID-to-process mapping requires elevated access
- **Memory Forensics** — memory dump capture requires SeDebugPrivilege

All other modules (steganography, password audit, entropy scan, etc.) work without elevation.

---

## 📋 System Specifications

```
╔════════════════════════════════════════════════════════════════════╗
║  SYSTEM SPECIFICATIONS                                             ║
╠════════════════════════════════════════════════════════════════════╣
║  Version:               4.0                                         ║
║  Language:              C++20                                       ║
║  Compiler:              MSVC 2022 / MinGW-w64 13+                  ║
║  Architecture:          x64 (Intel/AMD)                             ║
║  Target Platform:       Windows 10/11                               ║
║  Framework:             Native Windows API (Win32/CNG/WinSock2)     ║
║  Build System:          CMake 3.20+                                 ║
║  Code Standard:         ISO C++20                                   ║
║  Optimization:          /O2 (Release)                               ║
║  Total Modules:         12 security modules                         ║
║  New in v4.0:           5 modules, ~4,000+ new LOC                  ║
╚════════════════════════════════════════════════════════════════════╝
```

---

## ⚙️ Advanced Configuration

```ini
[Security]
encryption_algorithm = AES-256-CBC
hash_function = SHA-256
key_size = 256
iteration_count = 100000

[Logging]
log_level = DEBUG
log_file = ./logs/cybersec_audit.log
log_encryption = XOR_0x5A   ; upgrade to AES for production

[Network]
timeout_ms = 5000
max_connections = 100
banner_grab_timeout_ms = 3000

[Steganography]
default_algorithm = LSB_1BIT
default_encryption = XOR_PASSPHRASE

[Forensics]
artifact_collection = comprehensive
memory_analysis = enabled
hollowing_scan = on_demand
```

---

## 🏗️ Architecture

```
CyberSecMult v4.0/
├── main.cpp                    ← Entry point, event loop, v4 menu
├── ui.hpp                      ← Original menu dispatch (modules 1-7)
├── cybersec_core.hpp           ← Logger, ThreadPool, exceptions, colours
├── system_monitor.hpp          ← PDH system stats
├── network_scanner.hpp         ← Port scanner, SSL, DNS
├── crypto_engine.hpp           ← AES/RSA/ECC/SHA via CNG
├── forensics.hpp               ← Memory/disk forensics
├── secure_file_ops.hpp         ← Encrypted file operations
│
├── steganography.hpp           ← [NEW v4.0] Glaux LSB engine
├── threat_intel.hpp            ← [NEW v4.0] IOC/entropy/hollowing/OSINT
├── password_auditor.hpp        ← [NEW v4.0] NIST scoring + wordlist crack
├── privesc_checker.hpp         ← [NEW v4.0] PrivEsc scan + hardening
├── network_defense.hpp         ← [NEW v4.0] ARP/connection/poisoning
│
├── CMakeLists.txt              ← Build configuration
└── README.md
```

---

## 🗺️ Roadmap

This is the active development plan for upcoming versions. Contributions and issue reports are welcome.

### v4.1 — Scheduled
- [ ] **TLS Fingerprinting** — JA3/JA3S client/server fingerprint extraction
- [ ] **DNS over HTTPS detector** — identify DoH usage on the network
- [ ] **YARA rule scanner** — scan processes/files against YARA signatures
- [ ] **Registry persistence checker** — enumerate all Run/RunOnce and scheduled task persistence mechanisms
- [ ] **Active Directory enumeration** (read-only) — domain users, groups, SPNs
- [ ] **Kerberoastable SPN detector** — identify accounts vulnerable to offline cracking

### v4.2 — Planned
- [ ] **BloodHound-lite** — local AD attack path visualisation (text output)
- [ ] **Credential vault inspector** — enumerate Windows Credential Manager entries
- [ ] **DPAPI blob identifier** — find DPAPI-protected blobs on disk
- [ ] **Named pipe enumeration** — list all accessible named pipes + impersonation check
- [ ] **COM hijacking detector** — check for writable HKCU COM server registrations
- [ ] **Shellcode entropy heuristic** — detect shellcode patterns in process memory

### v4.3 — Planned
- [ ] **PCAP writer** — raw socket capture to PCAP format
- [ ] **HTTP request builder** — custom header fuzzer for web application testing
- [ ] **SMB share enumerator** — list accessible network shares
- [ ] **RDP brute-force detector** — monitor Event Log 4625 for RDP spray patterns
- [ ] **CVE lookup integration** — offline NVD CVE database cross-reference
- [ ] **Steganography: audio** — extend Glaux to support WAV LSB encoding

### v5.0 — Long-term Vision
- [ ] **GUI mode** (optional Win32 GUI alongside existing CLI)
- [ ] **Plugin system** — load custom modules from DLL at runtime
- [ ] **Cross-platform** — Linux support via conditional compilation
- [ ] **Report engine** — generate PDF/HTML pentesting reports
- [ ] **Docker/CI integration** — GitHub Actions automated build + test

---

## 🛠️ Development & Contributing

```bash
# Prerequisites
# - Visual Studio 2022 (Desktop Development with C++ workload)
# - CMake 3.20+
# - Windows 10 SDK 10.0.19041+

# Clone
git clone https://github.com/Kiriosx1/WindowsCybersec.git
cd WindowsCybersec

# Debug build
cmake -B build_debug -DCMAKE_BUILD_TYPE=Debug
cmake --build build_debug --parallel

# Release build  
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release --parallel 8
```

### Adding a New Module

1. Create `your_module.hpp` in the project root
2. Add it to `#include` list in `main.cpp`
3. Implement a `showYourModuleMenu()` function
4. Add a case in `dispatchMenuV4()` in `main.cpp`
5. Add the header to `CMakeLists.txt` headers list
6. Update this README

Each module follows the same pattern: a class with static methods + an inline `showXxxMenu()` function that integrates with the terminal UI system.

---

## 🐛 Known Limitations

- Requires Windows 10/11 x64 — no ARM or Linux support yet (v5.0 roadmap)
- 24-bit BMP only for steganography (PNG/JPEG support planned v4.3)
- Process hollowing scan may produce false positives on certain AV-protected processes
- NTLM hashing requires MD4 provider — falls back to informational message if unavailable
- Full network scanning features work best on directly connected network segments

---

## 📜 Legal & Ethical Use

**CyberSecMult** is released under the **MIT License**.

> ⚠️ **IMPORTANT DISCLAIMER:** This tool is designed exclusively for authorised security testing, penetration testing engagements, digital forensics, and educational purposes. Using any component of this tool against systems you do not own or have explicit written permission to test is **illegal** under the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent laws in most jurisdictions. The author assumes zero liability for misuse. Use responsibly.

---

## 🎖️ Version History

### v4.0 (Current)
- ✅ Glaux steganography integration (LSB BMP, chi-square analysis)
- ✅ Threat Intelligence & OSINT module (IOC manager, entropy scanner, hollowing detector)
- ✅ Password Audit Module (NIST scoring, offline hash crack, passphrase generator)
- ✅ PrivEsc Scanner (unquoted paths, AlwaysInstallElevated, token privileges, LSASS, UAC)
- ✅ Network Defense Module (ARP spoofing, connection monitor, LLMNR/NetBIOS risk)
- ✅ Extended main menu (0 = exit, modules 8-12 added)
- ✅ Detailed roadmap with v4.1–v5.0 planning

### v3.0
- ✅ Forensics analysis module
- ✅ Modern C++20 ThreadPool with std::jthread / stop_token
- ✅ XOR-encrypted audit logger
- ✅ Windows 11 optimisation

### v2.5
- ✅ File operations module + secure delete

### v2.0
- ✅ Network security scanner

### v1.0
- ✅ Calculator, converter, system utilities

---

## 📞 Contact

```
╔════════════════════════════════════════════════════════════════════╗
║                      CONTACT DETAILS                               ║
╠════════════════════════════════════════════════════════════════════╣
║  GitHub:       https://github.com/Kiriosx1                         ║
║  Email:        kyros.businesss@gmail.com                           ║
║  Glaux Repo:   https://github.com/Kiriosx1/Glaux-                  ║
╚════════════════════════════════════════════════════════════════════╝
```

---

Made with ❤️ and way too much coffee by **Kiriosx1**  
*Securing the digital world, one module at a time.*

```
████████████████████████████████████████████████████████████████████████████████
█                                                                              █
█  CyberSecMult v4.0 — Professional Cybersecurity Utility Suite               █
█  © 2026 Kiriosx1. All Rights Reserved. MIT Licensed.                        █
█                                                                              █
████████████████████████████████████████████████████████████████████████████████
```
