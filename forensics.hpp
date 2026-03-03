/**
 * @file    forensics.hpp
 * @brief   Advanced Windows process forensics engine.
 *
 * New capabilities vs v2.0:
 *  - Process OWNER (domain\\user) via OpenProcessToken + LookupAccountSid.
 *  - Parent PID    from PROCESSENTRY32W.th32ParentProcessID.
 *  - Loaded DLL enumeration via Module32First/Next.
 *  - UNSIGNED DLL detection via WinVerifyTrust (Authenticode).
 *  - Heuristic flag for processes with suspicious unsigned modules.
 *  - Rich table output with colour-coded threat indicators.
 *
 * @note Link with: psapi.lib, wintrust.lib
 *
 * @version 3.0
 * @standard C++20
 */
#pragma once

#include "cybersec_core.hpp"
#include <tlhelp32.h>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")

// =============================================================================
/// @class ProcessInspector
/// @brief  Enumerates running processes and performs forensic analysis.
// =============================================================================
class ProcessInspector {
public:
    // -------------------------------------------------------------------------
    /// @brief  Detailed snapshot of a single running process.
    // -------------------------------------------------------------------------
    struct ProcessInfo {
        DWORD       pid           = 0;
        DWORD       parentPid     = 0;          ///< From PROCESSENTRY32W.th32ParentProcessID
        std::string name;                       ///< Executable file name (UTF-8)
        std::string owner;                      ///< "DOMAIN\\User" — empty if query failed
        SIZE_T      workingSetMB  = 0;          ///< Working set in megabytes
        std::vector<std::string> dlls;          ///< All loaded DLL names (up to 64)
        std::vector<std::string> unsignedDlls;  ///< DLLs that failed Authenticode check
        bool        isSuspicious  = false;      ///< True if unsigned non-system DLLs present
    };

    // -------------------------------------------------------------------------
    /// @brief  Build a full forensic snapshot of all running processes.
    ///
    /// @return Vector of ProcessInfo sorted ascending by PID.
    /// @throws ForensicsException if the initial process snapshot fails.
    // -------------------------------------------------------------------------
    [[nodiscard]] static std::vector<ProcessInfo> enumerate() {
        std::vector<ProcessInfo> list;

        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE)
            throw ForensicsException("CreateToolhelp32Snapshot(PROCESS) failed — "
                                     "ensure you have SeDebugPrivilege.");

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        if (Process32FirstW(snap, &pe)) {
            do {
                ProcessInfo info;
                info.pid       = pe.th32ProcessID;
                info.parentPid = pe.th32ParentProcessID; // FREE from the snapshot struct
                info.name      = wideToUtf8(pe.szExeFile);

                // Open process with the minimum required access rights
                HANDLE hProc = OpenProcess(
                    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
                    FALSE, info.pid);

                if (hProc) {
                    // ── Memory stats ──────────────────────────────────────
                    PROCESS_MEMORY_COUNTERS pmc{};
                    if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc)))
                        info.workingSetMB = pmc.WorkingSetSize / (1024ULL * 1024ULL);

                    // ── Process owner ──────────────────────────────────────
                    info.owner = queryOwner(hProc);

                    // ── Loaded DLLs + signature analysis ──────────────────
                    enumerateDlls(info);

                    // ── Heuristic: mark suspicious if unsigned 3rd-party DLLs
                    info.isSuspicious = !info.unsignedDlls.empty();

                    CloseHandle(hProc);
                }
                list.push_back(std::move(info));

            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);

        // Sort by PID for deterministic output
        std::ranges::sort(list, {}, &ProcessInfo::pid);
        return list;
    }

    // -------------------------------------------------------------------------
    /// @brief  Print a colour-coded forensics table to stdout.
    ///
    /// @param minMemMB  Omit processes using fewer than this many MB of RAM.
    ///                  Set to 0 to show all.
    // -------------------------------------------------------------------------
    static void printReport(std::size_t minMemMB = 5) {
        auto processes = enumerate();

        // ── Table header ─────────────────────────────────────────────────────
        std::cout
            << Color::PURPLE
            << "\n╔═══════════════════════════════════════════════════════════════════════╗\n"
            << "║         PROCESS FORENSICS INSPECTOR  v3.0  — CyberSec Multitool    ║\n"
            << "╠════════╦════════╦══════════════════╦═══════╦═══════════════════════╣\n"
            << Color::CYAN
            << "║  PID   ║  PPID  ║  OWNER           ║  MEM  ║  PROCESS              ║\n"
            << Color::PURPLE
            << "╠════════╬════════╬══════════════════╬═══════╬═══════════════════════╣\n"
            << Color::RESET;

        int shown = 0;
        for (const auto& p : processes) {
            if (p.workingSetMB < minMemMB) continue;
            ++shown;

            // Colour the process name: red = suspicious, green = clean
            auto nameColor = p.isSuspicious ? Color::RED : Color::NEON_GREEN;

            // Truncate owner string to fit column
            std::string ownerStr = p.owner.empty() ? "SYSTEM" : p.owner;
            if (ownerStr.size() > 17) ownerStr = ownerStr.substr(0, 14) + "...";

            // Truncate process name
            std::string procName = p.name;
            if (procName.size() > 22) procName = procName.substr(0, 19) + "...";

            std::cout
                << Color::DARK_GRAY << "║ "
                << Color::WHITE     << std::right << std::setw(6) << p.pid         << " "
                << Color::DARK_GRAY << "║ "
                << Color::WHITE     << std::setw(6) << p.parentPid                 << " "
                << Color::DARK_GRAY << "║ "
                << Color::CYAN      << std::left << std::setw(17) << ownerStr      << " "
                << Color::DARK_GRAY << "║ "
                << Color::YELLOW    << std::right << std::setw(4) << p.workingSetMB << "MB"
                << Color::DARK_GRAY << "║ "
                << nameColor        << std::left << std::setw(22) << procName
                << Color::DARK_GRAY << "║\n"
                << Color::RESET;

            // ── Unsigned DLL warning lines ────────────────────────────────
            if (!p.unsignedDlls.empty()) {
                std::cout << Color::RED << "  ⚠ UNSIGNED DLL(s): ";
                std::size_t shown_dlls = 0;
                for (const auto& dll : p.unsignedDlls) {
                    if (shown_dlls++ > 0) std::cout << ", ";
                    std::cout << dll;
                    if (shown_dlls >= 4) { std::cout << " ..."; break; }
                }
                std::cout << Color::RESET << "\n";
            }
        }

        // ── Footer ───────────────────────────────────────────────────────────
        std::cout
            << Color::PURPLE
            << "╚════════╩════════╩══════════════════╩═══════╩═══════════════════════╝\n"
            << Color::CYAN
            << "  Showing " << shown << " process(es) (≥" << minMemMB << " MB RAM usage).\n"
            << Color::YELLOW
            << "  Red rows = unsigned non-system DLLs detected — investigate further.\n"
            << Color::RESET;

        LOG.info("Process forensics report generated — " +
                 std::to_string(shown) + " processes inspected.");
    }

private:
    // ─────────────────────────────────────────────────────────────────────────
    /// @brief  Enumerate all loaded modules for a process and check signatures.
    // ─────────────────────────────────────────────────────────────────────────
    static void enumerateDlls(ProcessInfo& info) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
                                               info.pid);
        if (snap == INVALID_HANDLE_VALUE) return; // may fail for protected processes

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);

        if (Module32FirstW(snap, &me)) {
            do {
                std::string dllName = wideToUtf8(me.szModule);
                std::wstring dllPath(me.szExePath);

                info.dlls.push_back(dllName);

                // Only verify signature for DLLs OUTSIDE of System32 / SysWOW64.
                // System DLLs may rely on catalog-based trust and would show false positives.
                if (!isUnderSystemDirectory(dllPath)) {
                    if (!isAuthenticodeSigned(dllPath))
                        info.unsignedDlls.push_back(dllName);
                }

            } while (Module32NextW(snap, &me) && info.dlls.size() < 64);
        }
        CloseHandle(snap);
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief  Query the owner of a process via its primary access token.
    ///
    /// @return "DOMAIN\\UserName" or empty string on failure.
    // ─────────────────────────────────────────────────────────────────────────
    static std::string queryOwner(HANDLE hProcess) {
        HANDLE hToken = nullptr;
        if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
            return "";

        // First call: determine buffer size
        DWORD dwSize = 0;
        GetTokenInformation(hToken, TokenUser, nullptr, 0, &dwSize);

        if (dwSize == 0) {
            CloseHandle(hToken);
            return "";
        }

        std::vector<BYTE> buf(dwSize);
        if (!GetTokenInformation(hToken, TokenUser, buf.data(), dwSize, &dwSize)) {
            CloseHandle(hToken);
            return "";
        }
        CloseHandle(hToken);

        auto* pTokenUser = reinterpret_cast<TOKEN_USER*>(buf.data());
        WCHAR  name[256]   = {};
        WCHAR  domain[256] = {};
        DWORD  nameLen     = 256;
        DWORD  domainLen   = 256;
        SID_NAME_USE sidType;

        if (!LookupAccountSidW(nullptr, pTokenUser->User.Sid,
                name, &nameLen, domain, &domainLen, &sidType))
            return "";

        return wideToUtf8(domain) + "\\" + wideToUtf8(name);
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief  Validate an Authenticode (PKCS#7) digital signature via WinVerifyTrust.
    ///
    /// @return true  — file has a valid, trusted Authenticode signature.
    ///         false — file is unsigned, expired, revoked, or otherwise invalid.
    // ─────────────────────────────────────────────────────────────────────────
    static bool isAuthenticodeSigned(const std::wstring& filePath) {
        WINTRUST_FILE_INFO fileInfo{};
        fileInfo.cbStruct      = sizeof(fileInfo);
        fileInfo.pcwszFilePath = filePath.c_str();

        WINTRUST_DATA trustData{};
        trustData.cbStruct            = sizeof(trustData);
        trustData.dwUIChoice          = WTD_UI_NONE;      // No UI prompts
        trustData.fdwRevocationChecks = WTD_REVOKE_NONE;  // Skip revocation (offline use)
        trustData.dwUnionChoice       = WTD_CHOICE_FILE;
        trustData.pFile               = &fileInfo;
        trustData.dwStateAction       = WTD_STATEACTION_VERIFY;

        GUID actionGUID = WINTRUST_ACTION_GENERIC_VERIFY_V2;
        LONG status = WinVerifyTrust(
            static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGUID, &trustData);

        // Release WinVerifyTrust state regardless of result
        trustData.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(
            static_cast<HWND>(INVALID_HANDLE_VALUE), &actionGUID, &trustData);

        return (status == ERROR_SUCCESS);
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief  Returns true if @p path is under %SystemRoot%\System32 or SysWOW64.
    // ─────────────────────────────────────────────────────────────────────────
    static bool isUnderSystemDirectory(const std::wstring& path) {
        WCHAR sysDir[MAX_PATH] = {};
        GetSystemDirectoryW(sysDir, MAX_PATH);
        std::wstring sys(sysDir);

        // Case-insensitive prefix comparison
        if (path.size() < sys.size()) return false;
        return _wcsnicmp(path.c_str(), sys.c_str(), sys.size()) == 0;
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief  Convert a null-terminated wide string to UTF-8.
    // ─────────────────────────────────────────────────────────────────────────
    static std::string wideToUtf8(const wchar_t* wide) {
        if (!wide || wide[0] == L'\0') return "";
        int n = WideCharToMultiByte(CP_UTF8, 0, wide, -1,
                                    nullptr, 0, nullptr, nullptr);
        if (n <= 0) return "";
        std::string s(static_cast<std::size_t>(n - 1), '\0');
        WideCharToMultiByte(CP_UTF8, 0, wide, -1,
                            s.data(), n, nullptr, nullptr);
        return s;
    }
    static std::string wideToUtf8(const std::wstring& wide) {
        return wideToUtf8(wide.c_str());
    }
};
