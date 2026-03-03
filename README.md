# CyberSec Multitool v3.0

Professional Windows Cybersecurity Utility — Pre-compiled, Ready to Run

A terminal-based cybersecurity toolkit for Windows, built in C++20. Covers cryptographic hashing, AES encryption, async port scanning, DoD-grade file deletion, process forensics, and more — all from a single executable with a cyberpunk-styled console interface.

Requirements
RequirementDetailsOSWindows 10 or Windows 11 (64-bit)Architecturex86 (32-bit binary — runs on both x86 and x64 systems)RuntimeVisual C++ Redistributable 2022 (see note below)PrivilegesStandard user for most features. Administrator required for Process Forensics (SeDebugPrivilege needed to inspect other processes)NetworkActive network adapter required for the Port ScannerWinsockWinsock 2 — present on all modern Windows installs, no action needed
Visual C++ Redistributable 2022
The tool is built with MSVC 14.44 and requires the Microsoft Visual C++ 2022 Redistributable (x86). If the .exe fails to launch with a missing DLL error, download and install it from Microsoft:
https://aka.ms/vs/17/release/vc_redist.x86.exe
This is a one-time install and is free. Most Windows machines already have it.

Features
Calculators & Converters

Basic Calculator — four-function arithmetic with division-by-zero protection
Temperature Converter — Celsius ↔ Fahrenheit ↔ Kelvin
BMI Calculator — body mass index with category classification

System Utilities

System Info — full hardware and OS report via systeminfo
List Processes — running process list via tasklist

Network & Security Tools

Async Port Scanner — non-blocking parallel TCP scanner using a 64-thread pool

Scan 26 common security-relevant ports in one click, or specify a custom range
Automatic hostname → IP resolution
Service name identification (FTP, SSH, RDP, SMB, MySQL, etc.)
Banner grabbing — retrieves service version strings from open ports
500 ms connect timeout per port — fast and non-blocking


Network Info — full adapter and IP config via ipconfig /all

File Operations

File Hash Calculator — genuine MD5 and SHA-256 via Windows CNG (BCrypt API) — no placeholders
Create Integrity Baseline — SHA-256 hash every file in a directory and save a baseline manifest
Verify Integrity Baseline — compare a directory against a saved baseline to detect tampering
Secure Delete (DoD 5220.22-M) — multi-pass irreversible file destruction:

Pass 1: overwrite with 0x00
Pass 2: overwrite with 0xFF
Pass 3+: overwrite with CSPRNG bytes (std::random_device → mt19937_64 — hardware entropy, not rand())
File renamed to random name before deletion to obscure path in filesystem journal
3 to 7 configurable passes



Cryptographic Tools

Base64 Encode / Decode — RFC 4648 compliant
AES-256-CBC Encrypt / Decrypt — genuine symmetric encryption via Windows BCrypt, PKCS#7 padded
Secure Password Generator — hardware-entropy CSPRNG, 5 passwords per run, configurable length (8–128 chars), uses upper, lower, digits, and symbols
Password Entropy Estimator — estimates bits of entropy for any input string

Forensics & Analysis

Process Inspector — advanced forensic snapshot of all running processes:

Process name, PID, and Parent PID
Process Owner (domain\user via token lookup)
Working set memory usage
Loaded DLL enumeration
Unsigned DLL detection via WinVerifyTrust Authenticode signature check — suspicious processes highlighted in red
System DLLs (System32 / SysWOW64) excluded to prevent false positives
Configurable minimum memory threshold filter




Audit Log
Every operation is written to cybersec_audit.log in the same directory as the executable. The log is XOR-encrypted and appended across sessions — it is not human-readable in a text editor by design.

Usage Notes

Run from a terminal that supports ANSI colour codes (Windows Terminal, PowerShell 7, or CMD with VT processing enabled). The tool enables VT processing automatically, but Windows Terminal gives the best visual result.
For the Process Inspector, right-click your terminal and select Run as Administrator before launching the tool. Without elevated privileges, many processes will show no owner or DLL information.
The Secure Delete operation is permanent and irreversible. There is a confirmation prompt — read it carefully.
The AES-256-CBC demo uses an all-zero key and IV. This is intentional for demonstration purposes. Do not use this for real data protection without integrating a proper key derivation step.
The port scanner performs active TCP connection attempts. Only scan hosts you own or have explicit written permission to test.


Legal Disclaimer
This tool is intended for authorised security testing, education, and personal research only. Port scanning and process inspection without permission may violate the Computer Fraud and Abuse Act (CFAA) and equivalent laws in your jurisdiction. The author accepts no liability for misuse.
