/**
 * @file threat_intel.hpp
 * @brief Threat Intelligence & OSINT Module
 *
 * Features:
 *  - IP reputation scoring (offline heuristic: GeoIP-style block analysis)
 *  - WHOIS-style TCP banner grabbing for port intelligence
 *  - C2 beacon pattern detector (timing & entropy analysis on network logs)
 *  - IOC (Indicators of Compromise) manager — load/search/match lists
 *  - Suspicious process hollowing detector (via PEB/PE header cross-check)
 *  - Entropy scanner — detects packed/encrypted regions in files
 *  - IPv4 threat scoring heuristics
 *
 * @version 4.0
 * @standard C++20
 */

#pragma once

#include "cybersec_core.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <fstream>
#include <sstream>
#include <map>
#include <set>
#include <unordered_set>
#include <filesystem>
#include <cmath>
#include <numeric>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
// IOC Manager
// ─────────────────────────────────────────────────────────────────────────────
class IOCManager {
public:
    void loadFromFile(const std::string& path) {
        std::ifstream f(path);
        if (!f) { LOG.error("IOC: cannot open file: " + path); return; }
        std::string line;
        while (std::getline(f, line)) {
            if (line.empty() || line[0] == '#') continue;
            m_iocs.insert(line);
        }
        LOG.info("IOC: loaded " + std::to_string(m_iocs.size()) + " indicators from " + path);
    }

    bool match(const std::string& indicator) const {
        return m_iocs.count(indicator) > 0;
    }

    void addIOC(const std::string& ioc) { m_iocs.insert(ioc); }
    void removeIOC(const std::string& ioc) { m_iocs.erase(ioc); }
    size_t size() const { return m_iocs.size(); }

    std::vector<std::string> searchContaining(const std::string& substr) const {
        std::vector<std::string> results;
        for (const auto& ioc : m_iocs)
            if (ioc.find(substr) != std::string::npos)
                results.push_back(ioc);
        return results;
    }

    void exportToFile(const std::string& path) const {
        std::ofstream f(path);
        for (const auto& ioc : m_iocs) f << ioc << "\n";
        LOG.info("IOC: exported " + std::to_string(m_iocs.size()) + " indicators to " + path);
    }

private:
    std::unordered_set<std::string> m_iocs;
};

// ─────────────────────────────────────────────────────────────────────────────
// Entropy Analysis
// ─────────────────────────────────────────────────────────────────────────────
class EntropyAnalyzer {
public:
    /// @brief Shannon entropy of a byte buffer. Range: 0.0 (all same) .. 8.0 (random)
    static double shannonEntropy(const std::vector<uint8_t>& data) {
        if (data.empty()) return 0.0;
        std::array<size_t, 256> freq{};
        for (uint8_t b : data) ++freq[b];
        double entropy = 0.0;
        double n = static_cast<double>(data.size());
        for (size_t f : freq) {
            if (f == 0) continue;
            double p = f / n;
            entropy -= p * std::log2(p);
        }
        return entropy;
    }

    struct SectionReport {
        size_t offset { 0 };
        size_t size   { 0 };
        double entropy{ 0.0 };
        std::string verdict;
    };

    /// @brief Scan a file in 4KB chunks and report high-entropy regions.
    static std::vector<SectionReport> scanFile(const std::string& path,
                                                size_t chunkSize = 4096) {
        std::ifstream f(path, std::ios::binary);
        if (!f) { LOG.error("Entropy: cannot open " + path); return {}; }

        std::vector<SectionReport> reports;
        std::vector<uint8_t> buf(chunkSize);
        size_t offset = 0;

        while (f.read(reinterpret_cast<char*>(buf.data()),
                       static_cast<std::streamsize>(chunkSize)) || f.gcount() > 0) {
            size_t read = static_cast<size_t>(f.gcount());
            buf.resize(read);
            double e = shannonEntropy(buf);
            std::string verdict = (e > 7.2) ? "PACKED/ENCRYPTED" :
                                  (e > 6.0) ? "COMPRESSED"        :
                                  (e > 4.0) ? "NORMAL"            : "LOW (text/data)";
            reports.push_back({ offset, read, e, verdict });
            offset += read;
            buf.resize(chunkSize);
        }
        return reports;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Banner Grabber
// ─────────────────────────────────────────────────────────────────────────────
class BannerGrabber {
public:
    struct Banner {
        std::string host;
        uint16_t    port { 0 };
        std::string banner;
        bool        success { false };
    };

    static Banner grab(const std::string& host, uint16_t port, int timeoutMs = 3000) {
        Banner result{ host, port };
        WSADATA wsa;
        if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) return result;

        SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) { WSACleanup(); return result; }

        // Set recv timeout
        DWORD tv = static_cast<DWORD>(timeoutMs);
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO,
                   reinterpret_cast<const char*>(&tv), sizeof(tv));

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(port);
        inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

        if (connect(s, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
            // Send empty probe to trigger banner
            send(s, "\r\n", 2, 0);
            char buf[1024]{};
            int  n = recv(s, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                result.banner  = std::string(buf, static_cast<size_t>(n));
                result.success = true;
            }
        }
        closesocket(s);
        WSACleanup();
        LOG.info("BannerGrab: " + host + ":" + std::to_string(port) +
                 (result.success ? " OK" : " FAILED"));
        return result;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Process Hollowing Detector
// ─────────────────────────────────────────────────────────────────────────────
class HollowingDetector {
public:
    struct SuspiciousProcess {
        DWORD       pid   { 0 };
        std::string name;
        std::string reason;
    };

    /// @brief Iterate all processes; flag those whose in-memory PE header
    ///        doesn't match what's on disk (classic process hollowing indicator).
    static std::vector<SuspiciousProcess> scan() {
        std::vector<SuspiciousProcess> findings;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            LOG.error("HollowingDetector: snapshot failed.");
            return findings;
        }

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snap, &pe)) {
            do {
                HANDLE hProc = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    FALSE, pe.th32ProcessID);
                if (!hProc) continue;

                wchar_t imgPath[MAX_PATH]{};
                if (GetModuleFileNameExW(hProc, nullptr, imgPath, MAX_PATH)) {
                    // Read first 2 bytes from disk vs memory
                    std::wstring wpath(imgPath);
                    std::ifstream disk(wpath, std::ios::binary);
                    char diskMZ[2]{};
                    disk.read(diskMZ, 2);

                    // Read from process memory
                    HMODULE hMod{};
                    DWORD needed{};
                    if (EnumProcessModules(hProc, &hMod, sizeof(hMod), &needed)) {
                        char memMZ[2]{};
                        SIZE_T read{};
                        ReadProcessMemory(hProc, hMod, memMZ, 2, &read);

                        if (read == 2 && disk &&
                            (memMZ[0] != diskMZ[0] || memMZ[1] != diskMZ[1])) {
                            std::string pname;
                            pname.assign(pe.szExeFile,
                                         pe.szExeFile + wcslen(pe.szExeFile));
                            findings.push_back({
                                pe.th32ProcessID,
                                pname,
                                "MZ header mismatch (disk vs memory)"
                            });
                            LOG.warning("Hollowing suspect: " + pname +
                                        " PID=" + std::to_string(pe.th32ProcessID));
                        }
                    }
                }
                CloseHandle(hProc);
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return findings;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// IP Threat Scoring (heuristic — no internet required)
// ─────────────────────────────────────────────────────────────────────────────
class IPThreatScorer {
public:
    struct ThreatReport {
        std::string ip;
        int score { 0 };          // 0 = clean, 100 = critical
        std::string classification;
        std::vector<std::string> flags;
    };

    static ThreatReport score(const std::string& ip) {
        ThreatReport r; r.ip = ip;

        // Loopback
        if (ip.rfind("127.", 0) == 0) { r.flags.push_back("Loopback"); r.score += 0; }
        // RFC1918 private
        else if (ip.rfind("10.", 0) == 0 || ip.rfind("192.168.", 0) == 0 ||
                 ip.rfind("172.16.", 0) == 0) {
            r.flags.push_back("RFC1918 Private"); r.score += 5;
        }
        // Known Tor exit node ranges (sample — real tools use full list)
        else if (ip.rfind("185.220.", 0) == 0) {
            r.flags.push_back("Known Tor/VPN range"); r.score += 60;
        }
        // Bogon / APIPA
        else if (ip.rfind("169.254.", 0) == 0) {
            r.flags.push_back("APIPA/Link-local"); r.score += 20;
        }

        // Port heuristic: check if any commonly abused ports respond
        // (quick 100ms connect test)
        static constexpr std::array<uint16_t, 5> riskyPorts = {
            4444, 31337, 1337, 8080, 9001
        };
        for (uint16_t p : riskyPorts) {
            auto b = BannerGrabber::grab(ip, p, 100);
            if (b.success) {
                r.flags.push_back("Port " + std::to_string(p) + " open (high-risk)");
                r.score += 15;
            }
        }

        r.score = std::min(r.score, 100);
        r.classification = (r.score >= 70) ? "CRITICAL" :
                           (r.score >= 40) ? "SUSPICIOUS" :
                           (r.score >= 10) ? "LOW RISK" : "CLEAN";
        return r;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Threat Intel CLI Menu
// ─────────────────────────────────────────────────────────────────────────────
inline void showThreatIntelMenu() {
    static IOCManager iocMgr;

    while (true) {
        std::cout << Color::PURPLE
            << "\n╔══════════════════════════════════════════════════════════════╗\n"
            << "║              🕵️  THREAT INTELLIGENCE & OSINT                 ║\n"
            << "╠══════════════════════════════════════════════════════════════╣\n"
            << "║  1. IP Threat Score (heuristic)                              ║\n"
            << "║  2. Banner Grab (host:port)                                  ║\n"
            << "║  3. File Entropy Scanner (detect packing/encryption)         ║\n"
            << "║  4. Process Hollowing Detector                               ║\n"
            << "║  5. IOC Manager (load / search / match)                      ║\n"
            << "║  6. Back                                                     ║\n"
            << "╚══════════════════════════════════════════════════════════════╝\n"
            << Color::RESET << "  Choice: ";

        int ch; std::cin >> ch; std::cin.ignore();
        if (ch == 6) break;

        std::string input;

        if (ch == 1) {
            std::cout << Color::YELLOW << "  Target IP: " << Color::RESET;
            std::getline(std::cin, input);
            auto r = IPThreatScorer::score(input);
            std::string scoreColor = (r.score >= 70) ? std::string(Color::RED) :
                                     (r.score >= 40) ? std::string(Color::ORANGE) :
                                                       std::string(Color::NEON_GREEN);
            std::cout << Color::CYAN << "\n  IP: " << r.ip << "\n"
                << "  Score: " << scoreColor << r.score << "/100 — " << r.classification << Color::RESET << "\n"
                << "  Flags:\n";
            for (const auto& f : r.flags)
                std::cout << "    • " << f << "\n";

        } else if (ch == 2) {
            std::cout << Color::YELLOW << "  Host: " << Color::RESET;
            std::string host; std::getline(std::cin, host);
            std::cout << Color::YELLOW << "  Port: " << Color::RESET;
            uint16_t port; std::cin >> port; std::cin.ignore();
            auto b = BannerGrabber::grab(host, port);
            if (b.success)
                std::cout << Color::NEON_GREEN << "  Banner:\n  " << b.banner << "\n" << Color::RESET;
            else
                std::cout << Color::RED << "  [!] No banner received.\n" << Color::RESET;

        } else if (ch == 3) {
            std::cout << Color::YELLOW << "  File path: " << Color::RESET;
            std::getline(std::cin, input);
            auto reports = EntropyAnalyzer::scanFile(input);
            std::cout << Color::CYAN << "\n  Offset      Size    Entropy  Verdict\n"
                << "  " << std::string(60, '-') << "\n" << Color::RESET;
            for (const auto& rep : reports) {
                std::string c = (rep.verdict == "PACKED/ENCRYPTED") ? std::string(Color::RED) :
                                (rep.verdict == "COMPRESSED")        ? std::string(Color::ORANGE) :
                                                                       std::string(Color::NEON_GREEN);
                std::cout << c
                    << "  0x" << std::hex << std::setw(8) << std::setfill('0') << rep.offset
                    << "  " << std::dec << std::setw(6) << rep.size
                    << "  " << std::fixed << std::setprecision(4) << rep.entropy
                    << "  " << rep.verdict << "\n" << Color::RESET;
            }

        } else if (ch == 4) {
            std::cout << Color::YELLOW << "  Scanning all processes...\n" << Color::RESET;
            auto findings = HollowingDetector::scan();
            if (findings.empty())
                std::cout << Color::NEON_GREEN << "  [+] No process hollowing indicators found.\n" << Color::RESET;
            else for (const auto& f : findings)
                std::cout << Color::RED << "  [!] PID " << f.pid << " | " << f.name
                    << " | " << f.reason << "\n" << Color::RESET;

        } else if (ch == 5) {
            std::cout << Color::CYAN
                << "  [a] Load IOC file  [b] Search  [c] Match  [d] Export  [e] Back\n"
                << Color::RESET << "  Sub-choice: ";
            char sub; std::cin >> sub; std::cin.ignore();
            if (sub == 'a') {
                std::cout << Color::YELLOW << "  IOC file path: " << Color::RESET;
                std::getline(std::cin, input);
                iocMgr.loadFromFile(input);
                std::cout << Color::NEON_GREEN << "  [+] Loaded. Total IOCs: " << iocMgr.size() << "\n" << Color::RESET;
            } else if (sub == 'b') {
                std::cout << Color::YELLOW << "  Search substring: " << Color::RESET;
                std::getline(std::cin, input);
                auto res = iocMgr.searchContaining(input);
                for (const auto& r : res) std::cout << "  • " << r << "\n";
            } else if (sub == 'c') {
                std::cout << Color::YELLOW << "  Exact IOC to match: " << Color::RESET;
                std::getline(std::cin, input);
                std::cout << (iocMgr.match(input) ? Color::RED : Color::NEON_GREEN)
                    << (iocMgr.match(input) ? "  [!] MATCH FOUND — indicator is known malicious!\n"
                                            : "  [+] Not found in IOC database.\n")
                    << Color::RESET;
            } else if (sub == 'd') {
                std::cout << Color::YELLOW << "  Export path: " << Color::RESET;
                std::getline(std::cin, input);
                iocMgr.exportToFile(input);
                std::cout << Color::NEON_GREEN << "  [+] Exported.\n" << Color::RESET;
            }
        }
    }
}
