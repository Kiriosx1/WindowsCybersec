/**
 * @file    main.cpp
 * @brief   CyberSec Multitool — entry point and application lifecycle.
 *
 * Responsibilities of main():
 *  1. Enable Windows virtual terminal (ANSI colours / UTF-8).
 *  2. Initialise the global SecureLogger singleton.
 *  3. Instantiate SystemMonitor (opens PDH session).
 *  4. Run the main event loop — dispatch to UI layer.
 *  5. Catch and log any unhandled exceptions before clean exit.
 *
 * @version 3.0
 * @standard C++20
 */

#include "ui.hpp"   // Transitively includes all engine headers

// =============================================================================
/// @brief  Application entry point.
// =============================================================================
int main() {
    try {
        // ── Phase 1: Platform setup ───────────────────────────────────────────
        enableVirtualTerminal();   // ANSI escape codes + UTF-8 output

        // ── Phase 2: Logger (singleton — first call initialises it) ───────────
        LOG.info("=== CyberSec Multitool v3.0 Started ===");

        // ── Phase 3: System monitor (PDH session) ─────────────────────────────
        SystemMonitor monitor;

        // ── Phase 4: Main event loop ──────────────────────────────────────────
        int choice = 0;
        do {
            choice = showMainMenu(monitor);

            if (choice == 7) {
                // Graceful exit path
                clearScreen();
                std::cout << Color::NEON_GREEN
                          << "\n  [*] Shutting down securely...\n"
                          << "  [*] Audit log written to: cybersec_audit.log\n"
                          << Color::RESET;
                LOG.info("=== CyberSec Multitool Shutdown (clean) ===");
                break;
            }

            dispatchMenu(choice);

        } while (choice != 7);

    }
    // ── Global exception safety net ──────────────────────────────────────────
    catch (const CyberSecException& e) {
        std::cerr << Color::RED
                  << "\n  [CRITICAL] Application error: " << e.what()
                  << Color::RESET << "\n";
        try { LOG.critical(std::string("Unhandled CyberSecException: ") + e.what()); }
        catch (...) {}
        return 1;
    }
    catch (const std::exception& e) {
        std::cerr << Color::RED
                  << "\n  [CRITICAL] Unexpected std::exception: " << e.what()
                  << Color::RESET << "\n";
        try { LOG.critical(std::string("Unhandled std::exception: ") + e.what()); }
        catch (...) {}
        return 1;
    }
    catch (...) {
        std::cerr << Color::RED
                  << "\n  [CRITICAL] Unknown exception — application terminated.\n"
                  << Color::RESET;
        try { LOG.critical("Unknown exception — abnormal termination"); }
        catch (...) {}
        return 2;
    }

    return 0;
}
