/**
 * @file main.cpp
 * @brief CyberSec Multitool v4.0 — entry point and application lifecycle.
 *
 * v4.0 additions:
 *  - Module 8:  🦉 Steganography Engine  (Glaux integration)
 *  - Module 9:  🕵️  Threat Intelligence & OSINT
 *  - Module 10: 🔑 Password Audit Module
 *  - Module 11: 🔓 Privilege Escalation & Hardening Advisor
 *  - Module 12: 🛡️  Network Defense & Anomaly Detection
 *
 * @version 4.0
 * @standard C++20
 */

#include "ui.hpp"               // Transitively includes all original engine headers
#include "steganography.hpp"    // Glaux integration — LSB steganography
#include "threat_intel.hpp"     // IOC manager, entropy, hollowing detection, OSINT
#include "password_auditor.hpp" // NIST password scoring, offline hash crack, passgen
#include "privesc_checker.hpp"  // PrivEsc vectors, hardening advisor
#include "network_defense.hpp"  // Connection monitor, ARP spoof, poisoning risks

// =============================================================================
/// @brief Extended menu — shows original 7 choices + 5 new modules
// =============================================================================
static int showMainMenuV4(SystemMonitor& monitor) {
    clearScreen();
    std::cout << Color::NEON_GREEN
        << " ╔═══════════════════════════════════════════════════════════════════════╗\n"
        << " ║                    🔐 CYBERSECMULT v4.0 🔐                          ║\n"
        << " ║           Professional Cybersecurity Utility (C++20/Windows)         ║\n"
        << " ╚═══════════════════════════════════════════════════════════════════════╝\n"
        << Color::RESET;

    // Show live system stats from original SystemMonitor
    try {
        auto stats = monitor.getSystemStats();
        std::cout << Color::DARK_GRAY
            << " CPU: " << std::fixed << std::setprecision(1) << stats.cpuUsage << "%  "
            << "RAM: " << stats.ramUsageMB << " MB  "
            << "Uptime: " << stats.uptimeSeconds / 3600 << "h\n"
            << Color::RESET;
    } catch (...) {}

    std::cout << Color::CYAN
        << "\n ╔════════════════════════════════════════════════════════════════════╗\n"
        << " ║                          MAIN MENU                                ║\n"
        << " ╠════════════════════════════════════════════════════════════════════╣\n"
        << " ║                                                                    ║\n"
        << " ║  1.  🧮  Calculators & Converters                                 ║\n"
        << " ║  2.  🖥️   System Utilities                                        ║\n"
        << " ║  3.  🌐  Network & Security Tools                                 ║\n"
        << " ║  4.  📁  File Operations                                          ║\n"
        << " ║  5.  🔑  Cryptographic Tools                                      ║\n"
        << " ║  6.  🔍  Forensics & Analysis                                     ║\n"
        << " ║                                                                    ║\n"
        << " ║  ─────────────────── NEW IN v4.0 ──────────────────────           ║\n"
        << " ║                                                                    ║\n"
        << " ║  8.  🦉  Steganography Engine (Glaux — image LSB encode/decode)   ║\n"
        << " ║  9.  🕵️   Threat Intelligence & OSINT                             ║\n"
        << " ║  10. 🔓  Password Audit & Hash Cracker                            ║\n"
        << " ║  11. 💀  PrivEsc Scanner & Hardening Advisor                      ║\n"
        << " ║  12. 🛡️   Network Defense & Anomaly Detector                      ║\n"
        << " ║                                                                    ║\n"
        << " ║  0.  ❌  Exit                                                     ║\n"
        << " ║                                                                    ║\n"
        << " ╚════════════════════════════════════════════════════════════════════╝\n"
        << Color::RESET
        << "  Enter choice: ";

    int choice = 0;
    std::cin >> choice;
    std::cin.ignore();
    return choice;
}

// =============================================================================
/// @brief Dispatch to the appropriate module (extends original dispatchMenu).
// =============================================================================
static void dispatchMenuV4(int choice, SystemMonitor& monitor) {
    // Choices 1-7 are handled by original dispatchMenu
    if (choice >= 1 && choice <= 7) {
        dispatchMenu(choice);   // from ui.hpp
        return;
    }

    switch (choice) {
        case 8:
            LOG.info("Entered Steganography module");
            showSteganographyMenu();
            break;
        case 9:
            LOG.info("Entered Threat Intelligence module");
            showThreatIntelMenu();
            break;
        case 10:
            LOG.info("Entered Password Auditor module");
            showPasswordAuditorMenu();
            break;
        case 11:
            LOG.info("Entered PrivEsc Checker module");
            showPrivEscMenu();
            break;
        case 12:
            LOG.info("Entered Network Defense module");
            showNetworkDefenseMenu();
            break;
        default:
            std::cout << Color::RED << "\n  [!] Invalid choice.\n" << Color::RESET;
            break;
    }
}

// =============================================================================
/// @brief Application entry point.
// =============================================================================
int main() {
    try {
        // ── Phase 1: Platform setup ───────────────────────────────────────
        enableVirtualTerminal();

        // ── Phase 2: Logger ───────────────────────────────────────────────
        LOG.info("=== CyberSec Multitool v4.0 Started ===");

        // ── Phase 3: System monitor ───────────────────────────────────────
        SystemMonitor monitor;

        // ── Phase 4: Main event loop ──────────────────────────────────────
        int choice = 0;
        do {
            choice = showMainMenuV4(monitor);

            if (choice == 0) {
                clearScreen();
                std::cout << Color::NEON_GREEN
                    << "\n  [*] Shutting down securely...\n"
                    << "  [*] Audit log written to: cybersec_audit.log\n"
                    << Color::RESET;
                LOG.info("=== CyberSec Multitool v4.0 Shutdown (clean) ===");
                break;
            }

            dispatchMenuV4(choice, monitor);

        } while (choice != 0);
    }
    catch (const CyberSecException& e) {
        std::cerr << Color::RED
            << "\n  [CRITICAL] Application error: " << e.what()
            << Color::RESET << "\n";
        try { LOG.critical(std::string("Unhandled CyberSecException: ") + e.what()); } catch (...) {}
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << Color::RED
            << "\n  [CRITICAL] Unexpected exception: " << e.what()
            << Color::RESET << "\n";
        try { LOG.critical(std::string("Unhandled std::exception: ") + e.what()); } catch (...) {}
        return 1;
    }
    catch (...) {
        std::cerr << Color::RED
            << "\n  [CRITICAL] Unknown exception — terminated.\n"
            << Color::RESET;
        try { LOG.critical("Unknown exception"); } catch (...) {}
        return 2;
    }
    return 0;
}
