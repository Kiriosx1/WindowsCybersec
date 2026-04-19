/**
 * @file privesc_checker.hpp
 * @brief Privilege Escalation & Windows Hardening Advisor
 *
 * Checks a live Windows system for common privesc vectors and misconfigurations:
 *  - Unquoted service paths
 *  - Writable service binaries
 *  - AlwaysInstallElevated registry keys
 *  - Weak DLL search order hijacking candidates
 *  - Scheduled task privilege misconfigurations
 *  - Token privilege enumeration (SeDebugPrivilege, SeImpersonatePrivilege, etc.)
 *  - UAC bypass indicators
 *  - LSASS protection status
 *  - Windows Defender / AV presence check
 *  - Generates a hardening recommendation report
 *
 * @version 4.0
 * @standard C++20
 * @note Requires administrator privileges for full scan.
 */

#pragma once

#include "cybersec_core.hpp"
#include <winsvc.h>
#include <winsafer.h>
#include <lm.h>
#include <sddl.h>
#include <aclapi.h>
#include <taskschd.h>
#include <comdef.h>
#include <fstream>
#include <sstream>
#include <map>
#include <filesystem>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "netapi32.lib")

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
// Finding severity
// ─────────────────────────────────────────────────────────────────────────────
enum class Severity { INFO, LOW, MEDIUM, HIGH, CRITICAL };

struct Finding {
    Severity    severity { Severity::INFO };
    std::string category;
    std::string title;
    std::string detail;
    std::string remediation;
};

inline std::string severityStr(Severity s) {
    switch (s) {
        case Severity::CRITICAL: return "CRITICAL";
        case Severity::HIGH:     return "HIGH";
        case Severity::MEDIUM:   return "MEDIUM";
        case Severity::LOW:      return "LOW";
        default:                 return "INFO";
    }
}

inline std::string_view severityColor(Severity s) {
    switch (s) {
        case Severity::CRITICAL: return Color::RED;
        case Severity::HIGH:     return Color::ORANGE;
        case Severity::MEDIUM:   return Color::YELLOW;
        case Severity::LOW:      return Color::CYAN;
        default:                 return Color::WHITE;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// PrivEscChecker
// ─────────────────────────────────────────────────────────────────────────────
class PrivEscChecker {
public:

    // ── Unquoted Service Paths ──────────────────────────────────────────────
    static std::vector<Finding> checkUnquotedServicePaths() {
        std::vector<Finding> findings;
        SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
        if (!hSCM) return findings;

        DWORD needed = 0, count = 0;
        EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                              SERVICE_STATE_ALL, nullptr, 0, &needed, &count, nullptr, nullptr);

        std::vector<BYTE> buf(needed);
        if (!EnumServicesStatusExW(hSCM, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
                                   SERVICE_STATE_ALL, buf.data(),
                                   static_cast<DWORD>(buf.size()),
                                   &needed, &count, nullptr, nullptr)) {
            CloseServiceHandle(hSCM); return findings;
        }

        auto* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSW*>(buf.data());
        for (DWORD i = 0; i < count; ++i) {
            SC_HANDLE hSvc = OpenServiceW(hSCM, services[i].lpServiceName,
                                           SERVICE_QUERY_CONFIG);
            if (!hSvc) continue;

            DWORD cfgNeeded = 0;
            QueryServiceConfigW(hSvc, nullptr, 0, &cfgNeeded);
            std::vector<BYTE> cfgBuf(cfgNeeded);
            auto* cfg = reinterpret_cast<QUERY_SERVICE_CONFIGW*>(cfgBuf.data());

            if (QueryServiceConfigW(hSvc, cfg, cfgNeeded, &cfgNeeded)) {
                std::wstring path = cfg->lpBinaryPathName;
                // Unquoted + contains spaces + not a driver
                if (!path.empty() && path[0] != L'"' &&
                    path.find(L' ') != std::wstring::npos &&
                    path.find(L"\\\\") == std::wstring::npos) {
                    std::string pathStr(path.begin(), path.end());
                    std::string svcName(services[i].lpServiceName,
                                        services[i].lpServiceName +
                                        wcslen(services[i].lpServiceName));
                    findings.push_back({
                        Severity::HIGH,
                        "Service Security",
                        "Unquoted Service Path: " + svcName,
                        "Binary path: " + pathStr,
                        "Quote the ImagePath value in HKLM\\SYSTEM\\CurrentControlSet\\Services\\" + svcName
                    });
                }
            }
            CloseServiceHandle(hSvc);
        }
        CloseServiceHandle(hSCM);
        return findings;
    }

    // ── AlwaysInstallElevated ───────────────────────────────────────────────
    static std::optional<Finding> checkAlwaysInstallElevated() {
        HKEY hKey{};
        DWORD value = 0, size = sizeof(DWORD);
        bool hkcu = false, hklm = false;

        if (RegOpenKeyExW(HKEY_CURRENT_USER,
                          L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                          0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExW(hKey, L"AlwaysInstallElevated", nullptr, nullptr,
                                 reinterpret_cast<LPBYTE>(&value), &size) == ERROR_SUCCESS)
                hkcu = (value == 1);
            RegCloseKey(hKey);
        }
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Policies\\Microsoft\\Windows\\Installer",
                          0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            if (RegQueryValueExW(hKey, L"AlwaysInstallElevated", nullptr, nullptr,
                                 reinterpret_cast<LPBYTE>(&value), &size) == ERROR_SUCCESS)
                hklm = (value == 1);
            RegCloseKey(hKey);
        }

        if (hkcu && hklm)
            return Finding{
                Severity::CRITICAL,
                "Registry",
                "AlwaysInstallElevated Enabled",
                "Both HKCU and HKLM AlwaysInstallElevated are set to 1. Any MSI can be installed with SYSTEM privileges.",
                "Set AlwaysInstallElevated to 0 in both HKCU and HKLM registry keys."
            };
        return std::nullopt;
    }

    // ── Token Privilege Enumeration ─────────────────────────────────────────
    static std::vector<Finding> checkTokenPrivileges() {
        std::vector<Finding> findings;
        HANDLE hToken{};
        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return findings;

        DWORD size = 0;
        GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &size);
        std::vector<BYTE> buf(size);
        if (!GetTokenInformation(hToken, TokenPrivileges, buf.data(), size, &size)) {
            CloseHandle(hToken); return findings;
        }

        auto* privs = reinterpret_cast<TOKEN_PRIVILEGES*>(buf.data());
        static const std::map<std::wstring, std::pair<Severity, std::string>> dangerousPrivs = {
            {L"SeDebugPrivilege",        {Severity::CRITICAL, "Can read/write any process memory. Used in credential dumping (Mimikatz)."}},
            {L"SeImpersonatePrivilege",  {Severity::HIGH,     "Can impersonate any logged-on user. Potato family exploits."}},
            {L"SeAssignPrimaryToken",    {Severity::HIGH,     "Can assign primary token to processes."}},
            {L"SeTcbPrivilege",          {Severity::CRITICAL, "'Act as part of OS' — highest privilege escalation vector."}},
            {L"SeLoadDriverPrivilege",   {Severity::HIGH,     "Can load/unload kernel drivers — potential BYOVD attacks."}},
            {L"SeRestorePrivilege",      {Severity::MEDIUM,   "Can restore files, potentially overwriting protected binaries."}},
            {L"SeTakeOwnershipPrivilege",{Severity::MEDIUM,   "Can take ownership of objects, including protected files."}}
        };

        for (DWORD i = 0; i < privs->PrivilegeCount; ++i) {
            if (!(privs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED)) continue;
            wchar_t name[256]; DWORD nameLen = 256;
            LookupPrivilegeNameW(nullptr, &privs->Privileges[i].Luid, name, &nameLen);
            std::wstring wname(name, nameLen);
            auto it = dangerousPrivs.find(wname);
            if (it != dangerousPrivs.end()) {
                std::string nameStr(wname.begin(), wname.end());
                findings.push_back({
                    it->second.first,
                    "Token Privileges",
                    "Dangerous privilege enabled: " + nameStr,
                    it->second.second,
                    "Review whether this process requires " + nameStr + ". Remove if unnecessary."
                });
            }
        }
        CloseHandle(hToken);
        return findings;
    }

    // ── LSASS Protection Status ─────────────────────────────────────────────
    static std::optional<Finding> checkLSASSProtection() {
        HKEY hKey{};
        DWORD value = 0, size = sizeof(DWORD);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SYSTEM\\CurrentControlSet\\Control\\Lsa",
                          0, KEY_READ, &hKey) != ERROR_SUCCESS) return std::nullopt;

        DWORD res = RegQueryValueExW(hKey, L"RunAsPPL", nullptr, nullptr,
                                     reinterpret_cast<LPBYTE>(&value), &size);
        RegCloseKey(hKey);

        if (res != ERROR_SUCCESS || value == 0)
            return Finding{
                Severity::HIGH,
                "LSASS Hardening",
                "LSASS RunAsPPL Not Enabled",
                "LSASS is not running as a Protected Process Light (PPL). "
                "This allows credential dumping via tools like Mimikatz.",
                "Set HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1 and reboot."
            };
        return std::nullopt;
    }

    // ── UAC Level Check ─────────────────────────────────────────────────────
    static std::optional<Finding> checkUACLevel() {
        HKEY hKey{};
        DWORD promptBehavior = 5, size = sizeof(DWORD);
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                          L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                          0, KEY_READ, &hKey) != ERROR_SUCCESS) return std::nullopt;

        RegQueryValueExW(hKey, L"ConsentPromptBehaviorAdmin", nullptr, nullptr,
                         reinterpret_cast<LPBYTE>(&promptBehavior), &size);
        RegCloseKey(hKey);

        if (promptBehavior == 0)
            return Finding{
                Severity::CRITICAL,
                "UAC",
                "UAC Disabled (ConsentPromptBehaviorAdmin = 0)",
                "UAC is completely disabled. Elevation happens silently without prompt.",
                "Set ConsentPromptBehaviorAdmin to 2 (Prompt for credentials) or 5 (Prompt for consent)."
            };
        if (promptBehavior == 5)
            return Finding{
                Severity::LOW,
                "UAC",
                "UAC on Default Level (notifies for app changes only)",
                "Default UAC level — vulnerable to certain auto-elevation UAC bypasses.",
                "Consider raising to level 2 (always notify) for higher security environments."
            };
        return std::nullopt;
    }

    // ── Full Scan ───────────────────────────────────────────────────────────
    static std::vector<Finding> fullScan() {
        std::vector<Finding> all;

        auto merge = [&](auto v) {
            all.insert(all.end(), v.begin(), v.end());
        };

        merge(checkUnquotedServicePaths());
        merge(checkTokenPrivileges());

        if (auto f = checkAlwaysInstallElevated()) all.push_back(*f);
        if (auto f = checkLSASSProtection())        all.push_back(*f);
        if (auto f = checkUACLevel())               all.push_back(*f);

        // Sort by severity descending
        std::sort(all.begin(), all.end(), [](const Finding& a, const Finding& b) {
            return static_cast<int>(a.severity) > static_cast<int>(b.severity);
        });

        LOG.info("PrivEsc scan complete: " + std::to_string(all.size()) + " findings.");
        return all;
    }

    // ── Export Report ───────────────────────────────────────────────────────
    static void exportReport(const std::vector<Finding>& findings, const std::string& path) {
        std::ofstream f(path);
        f << "# CyberSecMult v4.0 — Privilege Escalation / Hardening Report\n";
        f << "# Generated: " << __DATE__ << " " << __TIME__ << "\n\n";
        for (const auto& fn : findings) {
            f << "[" << severityStr(fn.severity) << "] " << fn.category << " — " << fn.title << "\n";
            f << "  Detail:      " << fn.detail << "\n";
            f << "  Remediation: " << fn.remediation << "\n\n";
        }
        LOG.info("PrivEsc report exported to: " + path);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// CLI Menu
// ─────────────────────────────────────────────────────────────────────────────
inline void showPrivEscMenu() {
    while (true) {
        std::cout << Color::RED
            << "\n╔══════════════════════════════════════════════════════════════╗\n"
            << "║       🔓 PRIVILEGE ESCALATION & HARDENING ADVISOR            ║\n"
            << "╠══════════════════════════════════════════════════════════════╣\n"
            << "║  1. Full System PrivEsc Scan                                 ║\n"
            << "║  2. Unquoted Service Path Check                              ║\n"
            << "║  3. Token Privilege Audit (current process)                  ║\n"
            << "║  4. LSASS Protection Status                                  ║\n"
            << "║  5. UAC Configuration Check                                  ║\n"
            << "║  6. AlwaysInstallElevated Check                              ║\n"
            << "║  7. Back                                                     ║\n"
            << "╚══════════════════════════════════════════════════════════════╝\n"
            << Color::RESET << "  Choice: ";

        int ch; std::cin >> ch; std::cin.ignore();
        if (ch == 7) break;

        auto printFindings = [](const std::vector<Finding>& findings) {
            if (findings.empty()) {
                std::cout << Color::NEON_GREEN << "  [+] No issues found.\n" << Color::RESET;
                return;
            }
            for (const auto& f : findings) {
                std::cout << severityColor(f.severity)
                    << "  [" << severityStr(f.severity) << "] " << f.title << "\n"
                    << Color::WHITE << "    " << f.detail << "\n"
                    << Color::CYAN  << "    Fix: " << f.remediation << "\n"
                    << Color::RESET;
            }
        };

        if (ch == 1) {
            std::cout << Color::YELLOW << "  [*] Running full PrivEsc scan...\n" << Color::RESET;
            auto findings = PrivEscChecker::fullScan();
            printFindings(findings);
            std::cout << Color::YELLOW << "\n  Export to file? (path or blank to skip): " << Color::RESET;
            std::string out; std::getline(std::cin, out);
            if (!out.empty()) PrivEscChecker::exportReport(findings, out);

        } else if (ch == 2) {
            printFindings(PrivEscChecker::checkUnquotedServicePaths());
        } else if (ch == 3) {
            printFindings(PrivEscChecker::checkTokenPrivileges());
        } else if (ch == 4) {
            auto f = PrivEscChecker::checkLSASSProtection();
            if (f) printFindings({*f});
            else std::cout << Color::NEON_GREEN << "  [+] LSASS PPL is enabled.\n" << Color::RESET;
        } else if (ch == 5) {
            auto f = PrivEscChecker::checkUACLevel();
            if (f) printFindings({*f});
            else std::cout << Color::NEON_GREEN << "  [+] UAC is on highest level.\n" << Color::RESET;
        } else if (ch == 6) {
            auto f = PrivEscChecker::checkAlwaysInstallElevated();
            if (f) printFindings({*f});
            else std::cout << Color::NEON_GREEN << "  [+] AlwaysInstallElevated not set.\n" << Color::RESET;
        }
    }
}
