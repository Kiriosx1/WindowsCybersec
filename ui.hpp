/**
 * @file    ui.hpp
 * @brief   Terminal UI layer — banner, menu system, and tool wrapper functions.
 *
 * Architecture note:
 *   This file is the ONLY place that calls std::cout / std::cin for user
 *   interaction.  All core logic lives in the respective engine headers.
 *   This clean separation means the UI can be swapped for a Dear ImGui
 *   frontend without touching a single line of business logic.
 *
 * @version 3.0
 * @standard C++20
 */
#pragma once

#include "cybersec_core.hpp"
#include "crypto_engine.hpp"
#include "network_scanner.hpp"
#include "forensics.hpp"
#include "secure_file_ops.hpp"
#include "system_monitor.hpp"

// Forward declarations for UI functions (ensure dispatchMenu can use them)
inline void runCalculator();
inline void runTempConverter();
inline void runBMICalculator();
inline void runBaseConverter();
inline void runEntropyEstimator();
inline void runPortScanner();
inline void runFileHasher();
inline void runBase64Tool();
inline void runAesTool();
inline void runPasswordGenerator();
inline void runSecureDelete();
inline void runForensicsInspector();
inline void runDNSLookup();
inline void runDiskUsage();
inline void runCreateBaseline();
inline void runVerifyBaseline();

// =============================================================================
//  Utility helpers (UI-only)
// =============================================================================

/// Read a menu choice from stdin. Accepts number or 'b'/'B' to go back.
inline std::optional<int> readMenuChoice() {
    std::string token;
    if (!(std::cin >> token)) return std::nullopt;
    if (token == "b" || token == "B") return std::optional<int>{-1};
    try {
        int v = std::stoi(token);
        return std::optional<int>{v};
    } catch (...) {
        return std::nullopt;
    }
}

/// Consume the rest of the current input line to prepare for getline usage.
inline void discardLine() {
    std::cin.clear();
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
}

/// @brief Enable ANSI/VT100 escape codes on the Windows console.
inline void enableVirtualTerminal() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD  dwMode = 0;
    GetConsoleMode(hOut, &dwMode);
    SetConsoleMode(hOut, dwMode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    // Also set UTF-8 code page so box-drawing characters render correctly
    SetConsoleOutputCP(CP_UTF8);
}

/// @brief Clear the console screen.
inline void clearScreen() {
    // Preferred over system("cls"): avoids spawning a child process
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    COORD  coord{0, 0};
    DWORD  written;
    CONSOLE_SCREEN_BUFFER_INFO csbi{};
    if (GetConsoleScreenBufferInfo(h, &csbi)) {
        DWORD cells = csbi.dwSize.X * csbi.dwSize.Y;
        FillConsoleOutputCharacterW(h, L' ', cells, coord, &written);
        FillConsoleOutputAttribute(h, csbi.wAttributes, cells, coord, &written);
    }
    SetConsoleCursorPosition(h, coord);
}

/// @brief Pause until the user presses Enter.
inline void pause() {
    std::cout << Color::DARK_GRAY << "\n  Press ENTER to continue..." << Color::RESET;
    discardLine();
    std::cin.get();
    clearScreen();
}

// =============================================================================
/// @brief  Print the ASCII art banner.
// =============================================================================
inline void displayBanner() {
    std::cout << Color::PURPLE << R"(
  +------------------------------------------------------------------+
  |   ____      _                ____             __  __       _ _   |
  |  / ___|   _| |__   ___ _ __/ ___|  ___  ___  |  \/  |_   _| | |_ |
  | | |  | | | | '_ \ / _ \ '__\___ \ / _ \/ __| | |\/| | | | | | __|  |
  | | |__| |_| | |_) |  __/ |   ___) |  __/ (__  | |  | | |_| | | |_   |
  |  \____\__, |_.__/ \___|_|  |____/ \___|\___| |_|  |_|\__,_|_|\__|  |
  |       |___/                                                         |
  +------------------------------------------------------------------+)"
    << Color::NEON_GREEN
    << "\n  |   Professional Cybersecurity Utility  v3.0  (C++20 / Windows)   |\n"
    << Color::PURPLE
    << "  +------------------------------------------------------------------+\n"
    << Color::RESET;
}

// =============================================================================
//  Sub-menu helpers
// =============================================================================

static void menuOption(int num, std::string_view label,
                       std::string_view color = Color::CYAN) {
    std::cout << Color::NEON_GREEN << "  " << num << ". "
              << color << label << "\n";
}

// New helper: print back hint
static void printBackHint() {
    std::cout << Color::DARK_GRAY << "  (Enter 'b' to go back to main menu)" << Color::RESET << "\n";
}

// =============================================================================
/// @brief  Display the main menu and return the user's validated choice.
// =============================================================================
inline int showMainMenu(SystemMonitor& monitor) {
    clearScreen();
    displayBanner();
    monitor.printStatusBar();

    std::cout << Color::PURPLE
              << "\n  ╔══════════════════════ MAIN MENU ══════════════════════╗\n"
              << Color::RESET;
    menuOption(1, "Calculators & Converters");
    menuOption(2, "System Utilities");
    menuOption(3, "Network & Security Tools");
    menuOption(4, "File Operations");
    menuOption(5, "Cryptographic Tools");
    menuOption(6, "Forensics & Analysis");
    menuOption(7, "Exit", Color::RED);
    std::cout << Color::PURPLE
              << "  ╚═══════════════════════════════════════════════════════╝\n"
              << Color::YELLOW << "\n  Enter choice [1-7]: " << Color::RESET;

    int choice = 0;
    if (auto opt = readMenuChoice()) {
        if (*opt == -1) return 7; // treat 'b' at top as exit
        choice = *opt;
    }
    return choice;
}

// =============================================================================
//  New calculator utilities
// =============================================================================

inline void runBMICalculator() {
    try {
        std::cout << Color::PURPLE << "\n  ════════ BMI CALCULATOR ════════\n" << Color::RESET;
        std::cout << "  Weight in kg: "; double kg; std::cin >> kg;
        std::cout << "  Height in cm: "; double cm; std::cin >> cm;
        double m = cm / 100.0;
        if (m <= 0.0) throw std::invalid_argument("Invalid height");
        double bmi = kg / (m * m);
        std::cout << Color::NEON_GREEN << "\n  BMI: " << std::fixed << std::setprecision(1) << bmi << "\n" << Color::RESET;
        LOG.info("BMI calculated: " + std::to_string(bmi));
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
    }
    pause();
}

inline void runBaseConverter() {
    try {
        std::cout << Color::PURPLE << "\n  ════════ BASE CONVERTER (bin/dec/hex) ════════\n" << Color::RESET;
        std::cout << "  Enter value (prefix 0x for hex, 0b for binary) or decimal: ";
        std::string s; std::cin >> s;
        int base = 10;
        std::string work = s;
        if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) { base = 16; work = s.substr(2); }
        else if (s.rfind("0b", 0) == 0 || s.rfind("0B", 0) == 0) { base = 2; work = s.substr(2); }
        int64_t val = std::stoll(work, nullptr, base);
        std::ostringstream oss;
        oss << "Dec: " << val << "  Hex: 0x" << std::hex << val << std::dec << "  Bin: ";
        // to binary
        std::string bin;
        if (val == 0) bin = "0";
        else {
            uint64_t u = static_cast<uint64_t>(val);
            while (u) { bin.push_back((u & 1) ? '1' : '0'); u >>= 1; }
            std::reverse(bin.begin(), bin.end());
        }
        oss << bin;
        std::cout << Color::NEON_GREEN << "\n  " << oss.str() << "\n" << Color::RESET;
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
    }
    pause();
}

inline void runEntropyEstimator() {
    try {
        std::cout << Color::PURPLE << "\n  ════════ PASSWORD ENTROPY ESTIMATOR ════════\n" << Color::RESET;
        std::cout << "  Input password/text: ";
        discardLine();
        std::string s; std::getline(std::cin, s);
        if (s.empty()) throw std::invalid_argument("Empty input");
        bool hasLower=false, hasUpper=false, hasDigit=false, hasSymbol=false;
        for (unsigned char c : s) {
            if (std::islower(c)) hasLower = true;
            else if (std::isupper(c)) hasUpper = true;
            else if (std::isdigit(c)) hasDigit = true;
            else hasSymbol = true;
        }
        int pool = 0;
        if (hasLower) pool += 26;
        if (hasUpper) pool += 26;
        if (hasDigit) pool += 10;
        if (hasSymbol) pool += 32; // rough estimate
        double entropy = s.size() * (pool > 0 ? std::log2(pool) : 0.0);
        std::cout << Color::NEON_GREEN << "\n  Estimated entropy: " << std::fixed << std::setprecision(1)
                  << entropy << " bits\n" << Color::RESET;
        LOG.info("Entropy estimated: " + std::to_string(entropy));
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
    }
    pause();
}

// =============================================================================
//  Network utilities (safe, read-only helpers)
// =============================================================================

inline void runDNSLookup() {
    try {
        std::cout << Color::PURPLE << "\n  ════════ DNS LOOKUP / REVERSE LOOKUP ════════\n" << Color::RESET;
        std::cout << "  Hostname or IP: "; std::string host; std::cin >> host;
        // forward lookup
        addrinfo hints{}, *res = nullptr;
        hints.ai_family = AF_UNSPEC;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
            throw NetworkException("DNS resolution failed for: " + host);
        std::cout << Color::CYAN << "\n  Addresses:\n" << Color::RESET;
        for (addrinfo* p = res; p != nullptr; p = p->ai_next) {
            char buf[INET6_ADDRSTRLEN] = {};
            void* addrptr = nullptr;
            if (p->ai_family == AF_INET) addrptr = &reinterpret_cast<sockaddr_in*>(p->ai_addr)->sin_addr;
            else if (p->ai_family == AF_INET6) addrptr = &reinterpret_cast<sockaddr_in6*>(p->ai_addr)->sin6_addr;
            inet_ntop(p->ai_family, addrptr, buf, sizeof(buf));
            std::cout << "    " << buf << "\n";
        }
        freeaddrinfo(res);

        // reverse lookup if input was an IP
        in_addr in{};
        if (inet_pton(AF_INET, host.c_str(), &in) == 1) {
            sockaddr_in sa{}; sa.sin_family = AF_INET; sa.sin_addr = in;
            char name[NI_MAXHOST] = {};
            if (getnameinfo(reinterpret_cast<sockaddr*>(&sa), sizeof(sa), name, sizeof(name), nullptr, 0, 0) == 0)
                std::cout << Color::CYAN << "\n  Reverse name: " << Color::WHITE << name << "\n" << Color::RESET;
        }
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
    }
    pause();
}

// =============================================================================
//  System utilities
// =============================================================================

inline void runDiskUsage() {
    try {
        std::cout << Color::PURPLE << "\n  ════════ DISK USAGE (per drive) ════════\n" << Color::RESET;
        DWORD drives = GetLogicalDrives();
        for (char letter = 'A'; letter <= 'Z'; ++letter) {
            if (!(drives & 1)) { drives >>= 1; continue; }
            std::string root = std::string(1, letter) + ":\\";
            ULARGE_INTEGER freeBytesAvailable, totalNumberOfBytes, totalNumberOfFreeBytes;
            if (GetDiskFreeSpaceExA(root.c_str(), &freeBytesAvailable, &totalNumberOfBytes, &totalNumberOfFreeBytes)) {
                double totalGB = static_cast<double>(totalNumberOfBytes.QuadPart) / (1024.0*1024.0*1024.0);
                double freeGB  = static_cast<double>(totalNumberOfFreeBytes.QuadPart) / (1024.0*1024.0*1024.0);
                std::cout << Color::CYAN << "  " << root << Color::WHITE << " Total: " << std::fixed << std::setprecision(2) << totalGB << " GB "
                          << Color::CYAN << " Free: " << Color::WHITE << freeGB << " GB\n" << Color::RESET;
            }
            drives >>= 1;
        }
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
    }
    pause();
}

// =============================================================================
//  File operations: integrity baseline create & verify
// =============================================================================

inline void runCreateBaseline() {
    try {
        std::cout << Color::PURPLE << "\n  ════════ CREATE INTEGRITY BASELINE (SHA-256) ════════\n" << Color::RESET;
        std::cout << "  Directory to scan: "; discardLine();
        std::string dir; std::getline(std::cin, dir);
        if (dir.empty()) throw std::invalid_argument("Empty directory");
        std::cout << "  Baseline output file (csv): "; std::string out; std::getline(std::cin, out);
        if (out.empty()) throw std::invalid_argument("Empty output file");

        std::ofstream ofs(out, std::ios::binary);
        if (!ofs.is_open()) throw FileException("Cannot open baseline output file");

        // Recursive traversal using Win32 APIs to avoid std::filesystem portability issues
        std::vector<std::string> stack{dir};
        while (!stack.empty()) {
            std::string current = stack.back(); stack.pop_back();
            std::string pattern = current;
            if (!pattern.empty() && pattern.back() != '\\' && pattern.back() != '/') pattern += "\\";
            pattern += "*";

            WIN32_FIND_DATAA fd{};
            HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
            if (h == INVALID_HANDLE_VALUE) continue;
            do {
                std::string name = fd.cFileName;
                if (name == "." || name == "..") continue;
                std::string full = current;
                if (!full.empty() && full.back() != '\\' && full.back() != '/') full += "\\";
                full += name;
                if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
                    stack.push_back(full);
                } else {
                    // regular file
                    std::string hash = CryptoEngine::hashFileSHA256(full);
                    ofs << '\"' << full << '\"' << ',' << hash << '\n';
                }
            } while (FindNextFileA(h, &fd));
            FindClose(h);
        }

        ofs.close();
        std::cout << Color::NEON_GREEN << "  Baseline written to: " << out << "\n" << Color::RESET;
        LOG.info("Integrity baseline created: " + out);
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
        LOG.error(std::string("Create baseline failed: ") + e.what());
    }
    pause();
}

inline void runVerifyBaseline() {
    try {
        std::cout << Color::PURPLE << "\n  ════════ VERIFY INTEGRITY BASELINE (SHA-256) ════════\n" << Color::RESET;
        std::cout << "  Baseline file (csv): "; discardLine();
        std::string in; std::getline(std::cin, in);
        if (in.empty()) throw std::invalid_argument("Empty baseline file");
        std::ifstream ifs(in, std::ios::binary);
        if (!ifs.is_open()) throw FileException("Cannot open baseline file");
        std::string line;
        int total=0, changed=0, missing=0;
        while (std::getline(ifs, line)) {
            // simple CSV: "path",hash
            auto comma = line.rfind(',');
            if (comma==std::string::npos) continue;
            std::string path = line.substr(1, comma-2); // remove surrounding quotes
            std::string expected = line.substr(comma+1);
            ++total;
            DWORD attrs = GetFileAttributesA(path.c_str());
            if (attrs == INVALID_FILE_ATTRIBUTES) { ++missing; std::cout << Color::YELLOW << "  Missing: " << path << "\n" << Color::RESET; continue; }
            std::string actual = CryptoEngine::hashFileSHA256(path);
            if (actual != expected) { ++changed; std::cout << Color::RED << "  Modified: " << path << "\n" << Color::RESET; }
        }
        std::cout << Color::CYAN << "\n  Summary: " << total << " files checked, " << changed << " modified, " << missing << " missing\n" << Color::RESET;
        LOG.info("Integrity verify done: " + in);
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
        LOG.error(std::string("Verify baseline failed: ") + e.what());
    }
    pause();
}

// =============================================================================
//  Missing tool implementations copied from original UI: calculator, temp converter, port scanner, file hasher, base64, AES tool, password generator, secure delete, forensics inspector
// =============================================================================

// Basic calculator
inline void runCalculator() {
    try {
        char   op;
        double a, b;
        std::cout << Color::PURPLE << "\n  ════════ CALCULATOR ════════\n" << Color::RESET;
        std::cout << "  Operator (+ - * /): "; std::cin >> op;
        std::cout << "  Operand 1: ";          std::cin >> a;
        std::cout << "  Operand 2: ";          std::cin >> b;

        double result = 0.0;
        switch (op) {
            case '+': result = a + b;                                      break;
            case '-': result = a - b;                                      break;
            case '*': result = a * b;                                      break;
            case '/':
                if (b == 0.0) throw std::invalid_argument("Division by zero");
                result = a / b;
                break;
            default:  throw std::invalid_argument("Invalid operator");
        }
        std::cout << Color::NEON_GREEN << "\n  Result: " << result << "\n" << Color::RESET;
        LOG.info("Calculator: " + std::to_string(a) + " " + op +
                 " " + std::to_string(b) + " = " + std::to_string(result));
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
        LOG.error(std::string("Calculator error: ") + e.what());
    }
    pause();
}

// Temperature converter
inline void runTempConverter() {
    try {
        std::cout << Color::PURPLE << "\n  ════════ TEMPERATURE CONVERTER ════════\n"
                  << Color::RESET;
        std::cout << "  1. Celsius → Fahrenheit\n"
                  << "  2. Fahrenheit → Celsius\n"
                  << "  3. Celsius → Kelvin\n"
                  << "  Choice: ";
        int choice; std::cin >> choice;
        std::cout << "  Value: ";
        double val; std::cin >> val;

        double result = 0.0;
        std::string label;
        switch (choice) {
            case 1: result = val * 9.0 / 5.0 + 32.0;  label = "°F"; break;
            case 2: result = (val - 32.0) * 5.0 / 9.0; label = "°C"; break;
            case 3: result = val + 273.15;               label = "K";  break;
            default: throw std::invalid_argument("Invalid choice");
        }
        std::cout << Color::NEON_GREEN << "\n  Result: " << std::fixed
                  << std::setprecision(2) << result << " " << label << "\n"
                  << Color::RESET;
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
    }
    pause();
}

// Port scanner wrapper (uses NetworkScanner)
inline void runPortScanner() {
    try {
        std::string host;
        std::cout << Color::PURPLE << "\n  ════════ ASYNC PORT SCANNER ════════\n"
                  << Color::RESET;
        std::cout << "  Target hostname / IP: ";
        std::cin >> host;

        std::cout << "\n  1. Common ports (26 ports)\n"
                  << "  2. Extended scan (specify range)\n"
                  << "  Choice: ";
        int choice; std::cin >> choice;

        std::vector<int> ports;
        if (choice == 1) {
            ports = NetworkScanner::commonPorts();
        } else {
            int low, high;
            std::cout << "  Start port: "; std::cin >> low;
            std::cout << "  End port:   "; std::cin >> high;
            for (int p = low; p <= high && p <= 65535; ++p) ports.push_back(p);
        }

        std::cout << Color::CYAN << "\n  [*] Scanning " << ports.size()
                  << " port(s) on " << host << " — please wait...\n" << Color::RESET;

        auto scanner = std::make_unique<NetworkScanner>();
        std::stop_source stopSrc;
        auto results = scanner->scanPorts(host, ports, stopSrc.get_token());

        NetworkScanner::printResults(host, results);

        LOG.info("Port scan on " + host + " — " +
                 std::to_string(results.size()) + " open port(s)");
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
        LOG.error(std::string("Port scan failed: ") + e.what());
    }
    pause();
}

// File hasher UI wrapper
inline void runFileHasher() {
    try {
        std::string filepath;
        std::cout << Color::PURPLE << "\n  ════════ FILE HASH CALCULATOR ════════\n"
                  << Color::RESET;
        std::cout << "  File path: ";
        discardLine();
        std::getline(std::cin, filepath);

        std::cout << Color::CYAN << "\n  [*] Computing hashes via Windows CNG...\n"
                  << Color::RESET;

        const std::string md5    = CryptoEngine::hashFileMD5(filepath);
        const std::string sha256 = CryptoEngine::hashFileSHA256(filepath);

        std::cout << Color::NEON_GREEN << "\n  [+] MD5     : " << Color::WHITE << md5    << "\n"
                  << Color::NEON_GREEN << "  [+] SHA-256 : " << Color::WHITE << sha256 << "\n"
                  << Color::RESET;

        LOG.info("File hashed: " + filepath);
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
        LOG.error(std::string("Hash failed: ") + e.what());
    }
    pause();
}

// Base64 tool wrapper
inline void runBase64Tool() {
    try {
        std::cout << Color::PURPLE << "\n  ════════ BASE64 ENCODE / DECODE ════════\n"
                  << Color::RESET;
        std::cout << "  1. Encode  2. Decode\n  Choice: ";
        int choice; std::cin >> choice;
        std::cin.ignore();

        std::string input;
        std::cout << "  Input text: ";
        std::getline(std::cin, input);

        if (choice == 1) {
            std::cout << Color::NEON_GREEN << "\n  Encoded: "
                      << Color::WHITE << CryptoEngine::base64Encode(input)
                      << "\n" << Color::RESET;
        } else if (choice == 2) {
            std::cout << Color::NEON_GREEN << "\n  Decoded: "
                      << Color::WHITE << CryptoEngine::base64Decode(input)
                      << "\n" << Color::RESET;
        } else {
            throw std::invalid_argument("Invalid choice");
        }
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
    }
    pause();
}

// AES tool wrapper
inline void runAesTool() {
    try {
        std::cout << Color::PURPLE << "\n  ════════ AES-256-CBC ENCRYPT / DECRYPT ════════\n"
                  << Color::RESET;
        std::cout << "  1. Encrypt text  2. Decrypt hex\n  Choice: ";
        int choice; std::cin >> choice;
        std::cin.ignore();

        // Use a zeroed key + IV for the demo — in production derive via PBKDF2
        std::array<std::uint8_t, 32> key{};
        std::array<std::uint8_t, 16> iv{};

        std::cout << Color::YELLOW
                  << "  [!] Demo mode: using all-zero 256-bit key and IV.\n"
                  << "      In production, derive key via PBKDF2 / HKDF.\n"
                  << Color::RESET;

        if (choice == 1) {
            std::string plaintext;
            std::cout << "  Plaintext: ";
            std::getline(std::cin, plaintext);

            auto cipherBytes = CryptoEngine::aes256Encrypt(
                std::span<const std::uint8_t>(
                    reinterpret_cast<const std::uint8_t*>(plaintext.data()),
                    plaintext.size()),
                std::span<const std::uint8_t, 32>(key),
                std::span<const std::uint8_t, 16>(iv));

            std::cout << Color::NEON_GREEN << "\n  Ciphertext (hex): "
                      << Color::WHITE
                      << CryptoEngine::toHex(cipherBytes)
                      << "\n" << Color::RESET;

        } else if (choice == 2) {
            std::cout << "  Ciphertext (hex): ";
            std::string hexInput;
            std::getline(std::cin, hexInput);

            // Parse hex string to bytes
            std::vector<std::uint8_t> cipherBytes;
            for (std::size_t i = 0; i + 1 < hexInput.size(); i += 2) {
                cipherBytes.push_back(
                    static_cast<std::uint8_t>(
                        std::stoul(hexInput.substr(i, 2), nullptr, 16)));
            }

            auto plainBytes = CryptoEngine::aes256Decrypt(
                cipherBytes,
                std::span<const std::uint8_t, 32>(key),
                std::span<const std::uint8_t, 16>(iv));

            std::string plaintext(reinterpret_cast<const char*>(plainBytes.data()),
                                  plainBytes.size());
            std::cout << Color::NEON_GREEN << "\n  Plaintext: "
                      << Color::WHITE << plaintext << "\n" << Color::RESET;
        }
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
        LOG.error(std::string("AES tool error: ") + e.what());
    }
    pause();
}

// Password generator wrapper
inline void runPasswordGenerator() {
    try {
        std::cout << Color::PURPLE << "\n  ════════ SECURE PASSWORD GENERATOR ════════\n"
                  << Color::RESET;
        std::cout << "  Password length [8-128, default 24]: ";
        std::size_t len = 24;
        std::string input;
        std::cin.ignore();
        std::getline(std::cin, input);
        if (!input.empty()) len = std::clamp(static_cast<std::size_t>(std::stoul(input)),
                                             std::size_t{8}, std::size_t{128});

        std::cout << Color::CYAN
                  << "\n  [*] Generating " << len
                  << "-char password via CSPRNG (random_device → mt19937_64)...\n"
                  << Color::RESET;

        for (int i = 0; i < 5; ++i) {
            std::cout << Color::NEON_GREEN << "  [" << (i + 1) << "] "
                      << Color::WHITE << CryptoEngine::generatePassword(len)
                      << "\n" << Color::RESET;
        }
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
    }
    pause();
}

// Secure delete wrapper
inline void runSecureDelete() {
    try {
        std::cout << Color::PURPLE
                  << "\n  ════════ SECURE FILE DELETION (DoD 5220.22-M) ════════\n"
                  << Color::RED
                  << "  WARNING: This operation is IRREVERSIBLE.\n"
                  << Color::RESET;
        std::cout << "  File path: ";
        std::cin.ignore();
        std::string filepath;
        std::getline(std::cin, filepath);

        std::cout << "  Overwrite passes [3-7, default 3]: ";
        std::string passInput;
        std::getline(std::cin, passInput);
        int passes = passInput.empty() ? 3 : std::clamp(std::stoi(passInput), 3, 7);

        std::cout << Color::YELLOW << "\n  Confirm destruction of \"" << filepath
                  << "\"? (yes/no): " << Color::RESET;
        std::string confirm;
        std::cin >> confirm;

        if (confirm == "yes") {
            SecureFileOps::secureDelete(filepath, passes);
        } else {
            std::cout << Color::YELLOW << "  Operation cancelled.\n" << Color::RESET;
        }
    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
        LOG.error(std::string("Secure delete UI error: ") + e.what());
    }
    pause();
}

// Forensics inspector wrapper
inline void runForensicsInspector() {
    try {
        std::cout << Color::CYAN
                  << "\n  [*] Enumerating processes and checking DLL signatures...\n"
                  << "      (This may take a few seconds for WinVerifyTrust calls)\n"
                  << Color::RESET;

        std::cout << "  Minimum RAM threshold in MB [default 5]: ";
        std::cin.ignore();
        std::string threshold;
        std::getline(std::cin, threshold);
        std::size_t minMB = threshold.empty() ? 5 : static_cast<std::size_t>(std::stoul(threshold));

        ProcessInspector::printReport(minMB);

    } catch (const std::exception& e) {
        std::cout << Color::RED << "  Error: " << e.what() << "\n" << Color::RESET;
        LOG.error(std::string("Forensics inspector error: ") + e.what());
    }
    pause();
}

// =============================================================================
/// @brief  Top-level menu dispatcher.  Called in the main loop.
// =============================================================================
inline void dispatchMenu(int topChoice) {
    switch (topChoice) {

        // ── Calculators & Converters ────────────────────────────────────────
        case 1: {
            while (true) {
                clearScreen();
                std::cout << Color::PURPLE << "  ╔═══ CALCULATORS & CONVERTERS ═══╗\n" << Color::RESET;
                menuOption(1, "Basic Calculator");
                menuOption(2, "Temperature Converter");
                menuOption(3, "BMI Calculator");
                menuOption(4, "Base converter (bin/dec/hex)");
                menuOption(5, "Password entropy estimator");
                printBackHint();
                std::cout << "  Choice: ";
                auto opt = readMenuChoice();
                if (!opt) { pause(); break; }
                if (*opt == -1) break; // back
                int c = *opt;
                if (c == 1) runCalculator();
                else if (c == 2) runTempConverter();
                else if (c == 3) runBMICalculator();
                else if (c == 4) runBaseConverter();
                else if (c == 5) runEntropyEstimator();
                else pause();
            }
            break;
        }

        // ── System Utilities ────────────────────────────────────────────────
        case 2: {
            while (true) {
                clearScreen();
                std::cout << Color::PURPLE << "  ╔═══ SYSTEM UTILITIES ═══╗\n" << Color::RESET;
                menuOption(1, "System Info  (systeminfo)");
                menuOption(2, "List Processes  (tasklist)");
                menuOption(3, "Disk usage per drive");
                printBackHint();
                std::cout << "  Choice: ";
                auto opt = readMenuChoice(); if (!opt) { pause(); break; }
                if (*opt == -1) break;
                int c = *opt;
                if      (c == 1) { system("systeminfo"); pause(); }
                else if (c == 2) { system("tasklist");   pause(); }
                else if (c == 3) { runDiskUsage(); }
                else pause();
            }
            break;
        }

        // ── Network & Security Tools ─────────────────────────────────────────
        case 3: {
            while (true) {
                clearScreen();
                std::cout << Color::PURPLE << "  ╔═══ NETWORK & SECURITY TOOLS ═══╗\n" << Color::RESET;
                menuOption(1, "Async Port Scanner");
                menuOption(2, "Network Info  (ipconfig)");
                menuOption(3, "DNS lookup / reverse");
                printBackHint();
                std::cout << "  Choice: ";
                auto opt = readMenuChoice(); if (!opt) { pause(); break; }
                if (*opt == -1) break;
                int c = *opt;
                if      (c == 1) runPortScanner();
                else if (c == 2) { system("ipconfig /all"); pause(); }
                else if (c == 3) runDNSLookup();
                else pause();
            }
            break;
        }

        // ── File Operations ─────────────────────────────────────────────────
        case 4: {
            while (true) {
                clearScreen();
                std::cout << Color::PURPLE << "  ╔═══ FILE OPERATIONS ═══╗\n" << Color::RESET;
                menuOption(1, "File Hash Calculator");
                menuOption(2, "Secure Delete  (DoD 5220.22-M)");
                menuOption(3, "Create integrity baseline (SHA-256)");
                menuOption(4, "Verify integrity baseline");
                printBackHint();
                std::cout << "  Choice: ";
                auto opt = readMenuChoice(); if (!opt) { pause(); break; }
                if (*opt == -1) break;
                int c = *opt;
                if      (c == 1) runFileHasher();
                else if (c == 2) runSecureDelete();
                else if (c == 3) runCreateBaseline();
                else if (c == 4) runVerifyBaseline();
                else pause();
            }
            break;
        }

        // ── Cryptographic Tools ─────────────────────────────────────────────
        case 5: {
            while (true) {
                clearScreen();
                std::cout << Color::PURPLE << "  ╔═══ CRYPTOGRAPHIC TOOLS ═══╗\n" << Color::RESET;
                menuOption(1, "Base64 Encode / Decode");
                menuOption(2, "AES-256-CBC Encrypt / Decrypt");
                menuOption(3, "Secure Password Generator");
                printBackHint();
                std::cout << "  Choice: ";
                auto opt = readMenuChoice(); if (!opt) { pause(); break; }
                if (*opt == -1) break;
                int c = *opt;
                if      (c == 1) runBase64Tool();
                else if (c == 2) runAesTool();
                else if (c == 3) runPasswordGenerator();
                else pause();
            }
            break;
        }

        // ── Forensics & Analysis ─────────────────────────────────────────────
        case 6: {
            while (true) {
                clearScreen();
                std::cout << Color::PURPLE << "  ╔═══ FORENSICS & ANALYSIS ═════╗\n" << Color::RESET;
                menuOption(1, "Process Inspector  (owner + unsigned DLLs)");
                printBackHint();
                std::cout << "  Choice: ";
                auto opt = readMenuChoice(); if (!opt) { pause(); break; }
                if (*opt == -1) break;
                int c = *opt;
                if (c == 1) runForensicsInspector();
                else pause();
            }
            break;
        }

        default:
            std::cout << Color::RED << "  Invalid choice.\n" << Color::RESET;
            pause();
            break;
    }
}
