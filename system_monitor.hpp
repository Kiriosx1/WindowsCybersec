/**
 * @file    system_monitor.hpp
 * @brief   Real-time CPU and RAM monitoring via the Windows PDH API.
 *
 * @note Link with: pdh.lib
 *
 * @version 3.0
 * @standard C++20
 */
#pragma once

#include "cybersec_core.hpp"
#include <pdh.h>
#pragma comment(lib, "pdh.lib")

// =============================================================================
/// @class SystemMonitor
/// @brief  Polls CPU and RAM usage on demand.
///
/// Owns one PDH query session for its lifetime.  The first PdhCollectQueryData
/// call primes the counter; every subsequent getCpuPercent() call is accurate.
// =============================================================================
class SystemMonitor {
public:
    // -------------------------------------------------------------------------
    /// @brief  Opens a PDH query and primes the CPU counter.
    // -------------------------------------------------------------------------
    SystemMonitor() {
        m_memInfo.dwLength = sizeof(m_memInfo);

        PdhOpenQuery(nullptr, 0, &m_cpuQuery);
        PdhAddEnglishCounterW(
            m_cpuQuery,
            L"\\Processor(_Total)\\% Processor Time",
            0, &m_cpuCounter);

        // First collect is needed before any value is available
        PdhCollectQueryData(m_cpuQuery);
    }

    ~SystemMonitor() {
        PdhCloseQuery(m_cpuQuery);
    }

    // Non-copyable (owns PDH handles)
    SystemMonitor(const SystemMonitor&)            = delete;
    SystemMonitor& operator=(const SystemMonitor&) = delete;

    // -------------------------------------------------------------------------
    /// @brief  Returns current CPU utilisation [0.0, 100.0].
    // -------------------------------------------------------------------------
    [[nodiscard]] double getCpuPercent() {
        PDH_FMT_COUNTERVALUE val{};
        PdhCollectQueryData(m_cpuQuery);
        PdhGetFormattedCounterValue(m_cpuCounter, PDH_FMT_DOUBLE, nullptr, &val);
        return std::clamp(val.doubleValue, 0.0, 100.0);
    }

    // -------------------------------------------------------------------------
    /// @brief  Returns current physical RAM usage [0.0, 100.0].
    // -------------------------------------------------------------------------
    [[nodiscard]] double getRamPercent() {
        GlobalMemoryStatusEx(&m_memInfo);
        double used = static_cast<double>(
            m_memInfo.ullTotalPhys - m_memInfo.ullAvailPhys);
        return std::clamp(100.0 * used / m_memInfo.ullTotalPhys, 0.0, 100.0);
    }

    // -------------------------------------------------------------------------
    /// @brief  Returns total installed RAM in gigabytes.
    // -------------------------------------------------------------------------
    [[nodiscard]] double getRamTotalGB() {
        GlobalMemoryStatusEx(&m_memInfo);
        return static_cast<double>(m_memInfo.ullTotalPhys) /
               (1024.0 * 1024.0 * 1024.0);
    }

    // -------------------------------------------------------------------------
    /// @brief  Prints a compact live-stats bar to stdout.
    // -------------------------------------------------------------------------
    void printStatusBar() {
        double cpu = getCpuPercent();
        double ram = getRamPercent();

        std::string cpuBar = makeBar(cpu, 16);
        std::string ramBar = makeBar(ram, 16);

        // Colour the bar based on severity
        auto barColor = [](double pct) -> std::string_view {
            if (pct >= 90.0) return Color::RED;
            if (pct >= 70.0) return Color::YELLOW;
            return Color::NEON_GREEN;
        };

        std::cout
            << Color::DARK_GRAY
            << "╔══════════════════════════════════════════════════════════╗\n"
            << "║  "
            << Color::CYAN << "CPU  " << barColor(cpu) << cpuBar
            << Color::WHITE << std::fixed << std::setprecision(1)
            << std::setw(5) << cpu << "%"
            << Color::DARK_GRAY << "   │   "
            << Color::PURPLE << "RAM  " << barColor(ram) << ramBar
            << Color::WHITE << std::setw(5) << ram << "%"
            << Color::DARK_GRAY << "  ║\n"
            << "╚══════════════════════════════════════════════════════════╝\n"
            << Color::RESET;
    }

private:
    MEMORYSTATUSEX m_memInfo{};
    PDH_HQUERY     m_cpuQuery   = nullptr;
    PDH_HCOUNTER   m_cpuCounter = nullptr;

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief  Render a Unicode block-character progress bar.
    /// @param  pct    Value in [0, 100].
    /// @param  width  Total bar character width.
    // ─────────────────────────────────────────────────────────────────────────
    static std::string makeBar(double pct, int width) {
        int filled = static_cast<int>(std::clamp(pct / 100.0, 0.0, 1.0) * width);
        std::string bar = "[";
        for (int i = 0; i < width; ++i)
            bar += (i < filled) ? "\xe2\x96\x88" : "\xe2\x96\x91"; // UTF-8 █ and ░
        bar += "]";
        return bar;
    }
};
