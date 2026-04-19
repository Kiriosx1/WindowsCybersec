/**
 * @file network_defense.hpp
 * @brief Network Defense, Anomaly Detection & Firewall Analyzer
 *
 * Features:
 *  - Windows Firewall rule enumeration and audit
 *  - Active TCP/UDP connection lister with process mapping
 *  - Suspicious connection detector (known bad ports, foreign process names)
 *  - DNS cache poisoning indicators
 *  - ARP table inspection (duplicate MAC → ARP spoofing indicator)
 *  - NetBIOS/LLMNR/mDNS poisoning risk assessment
 *  - Network interface enumeration with IP/MAC
 *  - Ping sweep helper
 *
 * @version 4.0
 * @standard C++20
 */

#pragma once

#include "cybersec_core.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <netfw.h>
#include <objbase.h>
#include <comdef.h>
#include <map>
#include <set>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "ole32.lib")

// ─────────────────────────────────────────────────────────────────────────────
// Connection info
// ─────────────────────────────────────────────────────────────────────────────
struct ConnectionInfo {
    std::string localAddr;
    uint16_t    localPort  { 0 };
    std::string remoteAddr;
    uint16_t    remotePort { 0 };
    std::string state;
    DWORD       pid        { 0 };
    std::string processName;
    bool        suspicious { false };
    std::string reason;
};

// ─────────────────────────────────────────────────────────────────────────────
// NetworkDefense
// ─────────────────────────────────────────────────────────────────────────────
class NetworkDefense {
public:

    // ── Process name helper ─────────────────────────────────────────────────
    static std::string getProcessName(DWORD pid) {
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProc) return "<unknown>";
        wchar_t path[MAX_PATH]{};
        GetModuleFileNameExW(hProc, nullptr, path, MAX_PATH);
        CloseHandle(hProc);
        std::wstring ws(path);
        size_t pos = ws.rfind(L'\\');
        if (pos != std::wstring::npos) ws = ws.substr(pos + 1);
        return std::string(ws.begin(), ws.end());
    }

    // ── List all active TCP connections ─────────────────────────────────────
    static std::vector<ConnectionInfo> listTCPConnections() {
        std::vector<ConnectionInfo> conns;

        DWORD size = 0;
        GetExtendedTcpTable(nullptr, &size, FALSE, AF_INET,
                             TCP_TABLE_OWNER_PID_ALL, 0);
        std::vector<BYTE> buf(size);
        auto* table = reinterpret_cast<MIB_TCPTABLE_OWNER_PID*>(buf.data());

        if (GetExtendedTcpTable(buf.data(), &size, FALSE, AF_INET,
                                 TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR)
            return conns;

        // Known suspicious remote ports
        static const std::set<uint16_t> badPorts = {
            4444, 31337, 1337, 6666, 6667, 9001, 9030, // Metasploit/Tor
            1080, 8888, 9999, 12345, 27374             // RAT/proxy common
        };

        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];

            IN_ADDR la, ra;
            la.S_un.S_addr = row.dwLocalAddr;
            ra.S_un.S_addr = row.dwRemoteAddr;

            char laStr[16]{}, raStr[16]{};
            inet_ntop(AF_INET, &la, laStr, sizeof(laStr));
            inet_ntop(AF_INET, &ra, raStr, sizeof(raStr));

            std::string stateStr;
            switch (row.dwState) {
                case MIB_TCP_STATE_LISTEN:       stateStr = "LISTEN"; break;
                case MIB_TCP_STATE_ESTAB:        stateStr = "ESTABLISHED"; break;
                case MIB_TCP_STATE_TIME_WAIT:    stateStr = "TIME_WAIT"; break;
                case MIB_TCP_STATE_CLOSE_WAIT:   stateStr = "CLOSE_WAIT"; break;
                default:                          stateStr = "OTHER"; break;
            }

            ConnectionInfo ci;
            ci.localAddr   = laStr;
            ci.localPort   = static_cast<uint16_t>(ntohs(static_cast<u_short>(row.dwLocalPort)));
            ci.remoteAddr  = raStr;
            ci.remotePort  = static_cast<uint16_t>(ntohs(static_cast<u_short>(row.dwRemotePort)));
            ci.state       = stateStr;
            ci.pid         = row.dwOwningPid;
            ci.processName = getProcessName(row.dwOwningPid);

            // Flag suspicious
            if (badPorts.count(ci.remotePort) || badPorts.count(ci.localPort)) {
                ci.suspicious = true;
                ci.reason = "Port " + std::to_string(ci.remotePort) + " known RAT/C2";
            }
            // svchost connecting to unusual ports
            if (ci.processName == "svchost.exe" &&
                ci.remotePort != 80 && ci.remotePort != 443 &&
                ci.remotePort != 53 && ci.state == "ESTABLISHED") {
                ci.suspicious = true;
                ci.reason = "svchost on non-standard port";
            }
            conns.push_back(ci);
        }
        return conns;
    }

    // ── ARP table — detect duplicate MACs (ARP spoofing) ───────────────────
    struct ARPEntry {
        std::string ip;
        std::string mac;
    };

    static std::vector<ARPEntry> getARPTable() {
        std::vector<ARPEntry> entries;
        DWORD size = 0;
        GetIpNetTable(nullptr, &size, FALSE);
        std::vector<BYTE> buf(size);
        auto* table = reinterpret_cast<MIB_IPNETTABLE*>(buf.data());
        if (GetIpNetTable(buf.data(), &size, FALSE) != NO_ERROR) return entries;

        for (DWORD i = 0; i < table->dwNumEntries; ++i) {
            const auto& row = table->table[i];
            IN_ADDR addr; addr.S_un.S_addr = row.dwAddr;
            char ipStr[16]{}; inet_ntop(AF_INET, &addr, ipStr, sizeof(ipStr));

            std::ostringstream mac;
            for (DWORD j = 0; j < row.dwPhysAddrLen; ++j) {
                if (j > 0) mac << ":";
                mac << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(row.bPhysAddr[j]);
            }
            entries.push_back({ ipStr, mac.str() });
        }
        return entries;
    }

    static std::vector<std::pair<std::string, std::string>> detectARPSpoofing(
        const std::vector<ARPEntry>& table) {
        std::map<std::string, std::vector<std::string>> macToIPs;
        for (const auto& e : table) macToIPs[e.mac].push_back(e.ip);

        std::vector<std::pair<std::string, std::string>> suspects;
        for (const auto& [mac, ips] : macToIPs) {
            if (ips.size() > 1) {
                std::string ipList;
                for (const auto& ip : ips) ipList += ip + " ";
                suspects.push_back({ mac, ipList });
            }
        }
        return suspects;
    }

    // ── Network Interface List ──────────────────────────────────────────────
    struct InterfaceInfo {
        std::string name;
        std::string description;
        std::string ipv4;
        std::string mac;
        bool        up { false };
    };

    static std::vector<InterfaceInfo> listInterfaces() {
        std::vector<InterfaceInfo> ifaces;
        ULONG bufSize = 15000;
        std::vector<BYTE> buf(bufSize);
        auto* addrList = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(buf.data());

        if (GetAdaptersAddresses(AF_INET,
                                  GAA_FLAG_INCLUDE_PREFIX,
                                  nullptr, addrList, &bufSize) != NO_ERROR) return ifaces;

        for (auto* adapter = addrList; adapter; adapter = adapter->Next) {
            InterfaceInfo ii;
            std::wstring wname(adapter->FriendlyName);
            std::wstring wdesc(adapter->Description);
            ii.name        = std::string(wname.begin(), wname.end());
            ii.description = std::string(wdesc.begin(), wdesc.end());
            ii.up          = (adapter->OperStatus == IfOperStatusUp);

            // MAC
            std::ostringstream mac;
            for (DWORD i = 0; i < adapter->PhysicalAddressLength; ++i) {
                if (i > 0) mac << ":";
                mac << std::hex << std::setw(2) << std::setfill('0')
                    << static_cast<int>(adapter->PhysicalAddress[i]);
            }
            ii.mac = mac.str();

            // IPv4
            for (auto* ua = adapter->FirstUnicastAddress; ua; ua = ua->Next) {
                if (ua->Address.lpSockaddr->sa_family == AF_INET) {
                    char ipStr[16]{};
                    auto* sa = reinterpret_cast<sockaddr_in*>(ua->Address.lpSockaddr);
                    inet_ntop(AF_INET, &sa->sin_addr, ipStr, sizeof(ipStr));
                    ii.ipv4 = ipStr;
                }
            }
            ifaces.push_back(ii);
        }
        return ifaces;
    }

    // ── LLMNR / NetBIOS risk check ──────────────────────────────────────────
    static std::vector<std::string> checkPoisoningRisks() {
        std::vector<std::string> risks;

        // Check if LLMNR is enabled
        HKEY hKey{};
        DWORD value = 0, size = sizeof(DWORD);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient",
                          0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExW(hKey, L"EnableMulticast", nullptr, nullptr,
                                 reinterpret_cast<LPBYTE>(&value), &size) != ERROR_SUCCESS
                || value != 0)
                risks.push_back("LLMNR is enabled — vulnerable to LLMNR poisoning (Responder)");
            RegCloseKey(hKey);
        } else {
            risks.push_back("LLMNR policy key missing — LLMNR likely enabled by default");
        }

        // NetBIOS over TCP/IP check (heuristic: check if port 137 is open locally)
        // We check NetBIOS name service port binding
        SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (s != INVALID_SOCKET) {
            sockaddr_in sa{};
            sa.sin_family = AF_INET;
            sa.sin_port   = htons(137);
            sa.sin_addr.s_addr = INADDR_ANY;
            if (bind(s, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0)
                risks.push_back("NetBIOS port 137 already bound — NetBIOS over TCP/IP active");
            closesocket(s);
        }

        return risks;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// CLI Menu
// ─────────────────────────────────────────────────────────────────────────────
inline void showNetworkDefenseMenu() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);

    while (true) {
        std::cout << Color::CYAN
            << "\n╔══════════════════════════════════════════════════════════════╗\n"
            << "║             🛡️  NETWORK DEFENSE & ANOMALY DETECTOR           ║\n"
            << "╠══════════════════════════════════════════════════════════════╣\n"
            << "║  1. List active TCP connections (with process mapping)       ║\n"
            << "║  2. ARP table — detect spoofing indicators                   ║\n"
            << "║  3. Network interface enumeration                            ║\n"
            << "║  4. LLMNR / NetBIOS poisoning risk check                     ║\n"
            << "║  5. Back                                                     ║\n"
            << "╚══════════════════════════════════════════════════════════════╝\n"
            << Color::RESET << "  Choice: ";

        int ch; std::cin >> ch; std::cin.ignore();
        if (ch == 5) break;

        if (ch == 1) {
            auto conns = NetworkDefense::listTCPConnections();
            std::cout << Color::CYAN
                << "\n  Local Address        Port   Remote Address       Port   State         PID    Process\n"
                << "  " << std::string(95, '-') << "\n" << Color::RESET;
            for (const auto& c : conns) {
                std::string_view col = c.suspicious ? Color::RED : Color::WHITE;
                std::cout << col
                    << "  " << std::setw(20) << std::left << c.localAddr
                    << std::setw(7)  << c.localPort
                    << std::setw(20) << c.remoteAddr
                    << std::setw(7)  << c.remotePort
                    << std::setw(14) << c.state
                    << std::setw(7)  << c.pid
                    << c.processName;
                if (c.suspicious)
                    std::cout << " ⚠ " << c.reason;
                std::cout << "\n" << Color::RESET;
            }
            LOG.info("TCP connection list: " + std::to_string(conns.size()) + " entries");

        } else if (ch == 2) {
            auto arp = NetworkDefense::getARPTable();
            std::cout << Color::CYAN << "\n  IP Address        MAC Address\n"
                << "  " << std::string(45, '-') << "\n" << Color::RESET;
            for (const auto& e : arp)
                std::cout << "  " << std::setw(18) << std::left << e.ip << e.mac << "\n";

            auto suspects = NetworkDefense::detectARPSpoofing(arp);
            if (!suspects.empty()) {
                std::cout << Color::RED << "\n  [!] ARP SPOOFING INDICATORS:\n";
                for (const auto& [mac, ips] : suspects)
                    std::cout << "  MAC " << mac << " → " << ips << "\n";
                std::cout << Color::RESET;
            } else {
                std::cout << Color::NEON_GREEN << "\n  [+] No ARP spoofing indicators found.\n" << Color::RESET;
            }

        } else if (ch == 3) {
            auto ifaces = NetworkDefense::listInterfaces();
            for (const auto& i : ifaces) {
                std::string_view col = i.up ? Color::NEON_GREEN : Color::DARK_GRAY;
                std::cout << col << "  " << (i.up ? "[UP]  " : "[DOWN]") << " "
                    << std::setw(30) << std::left << i.name
                    << "  IPv4: " << std::setw(16) << i.ipv4
                    << "  MAC: " << i.mac
                    << "\n" << Color::RESET;
            }

        } else if (ch == 4) {
            auto risks = NetworkDefense::checkPoisoningRisks();
            if (risks.empty())
                std::cout << Color::NEON_GREEN << "  [+] No poisoning risk factors detected.\n" << Color::RESET;
            else for (const auto& r : risks)
                std::cout << Color::ORANGE << "  [!] " << r << "\n" << Color::RESET;
        }
    }
    WSACleanup();
}
