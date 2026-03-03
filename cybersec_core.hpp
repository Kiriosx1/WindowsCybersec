/*
 * @file    cybersec_core.hpp
 * @brief   Foundational definitions shared across all modules.
 *
 * Contains:
 *  - ANSI colour namespace (cyberpunk palette)
 *  - Custom exception hierarchy (RAII-friendly)
 *  - SecureLogger  – thread-safe Meyers-singleton logger w/ XOR encryption
 *  - ThreadPool    – C++20 std::jthread / std::stop_token pool
 *
 * @version 3.0
 * @standard C++20
 */
#pragma once

// Note: avoid redefining platform macros here to prevent redefinition warnings

// ── C++20 Standard Library ───────────────────────────────────────────────────
#include <concepts>
#include <span>
#include <ranges>
#include <stop_token>
#include <string>
#include <string_view>
#include <vector>
#include <queue>
#include <array>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <future>
#include <chrono>
#include <sstream>
#include <fstream>
#include <stdexcept>
#include <iomanip>
#include <algorithm>
#include <random>
#include <optional>
#include <iostream>

// ── Windows Platform ─────────────────────────────────────────────────────────
#include <windows.h>

// =============================================================================
/// @namespace Color
/// @brief  Cyberpunk ANSI escape palette.  All values are constexpr string_view
///         so they add zero runtime cost.
// =============================================================================
namespace Color {
    inline constexpr std::string_view RESET       = "\033[0m";
    inline constexpr std::string_view NEON_GREEN  = "\033[38;2;57;255;20m";
    inline constexpr std::string_view PURPLE      = "\033[38;2;138;43;226m";
    inline constexpr std::string_view CYAN        = "\033[38;2;0;255;255m";
    inline constexpr std::string_view RED         = "\033[38;2;255;0;0m";
    inline constexpr std::string_view YELLOW      = "\033[38;2;255;255;0m";
    inline constexpr std::string_view DARK_GRAY   = "\033[38;2;80;80;80m";
    inline constexpr std::string_view ORANGE      = "\033[38;2;255;140;0m";
    inline constexpr std::string_view WHITE       = "\033[38;2;220;220;220m";
    inline constexpr std::string_view BOLD        = "\033[1m";
}

// =============================================================================
/// @defgroup Exceptions  Custom Exception Hierarchy
/// @{
// =============================================================================

/// @brief Root of all CyberSec Multitool exceptions — catch this for any error.
class CyberSecException : public std::runtime_error {
public:
    explicit CyberSecException(std::string_view msg)
        : std::runtime_error(std::string(msg)) {}
};

/// @brief Thrown when a cryptographic (BCrypt / CNG) operation fails.
class SecurityException : public CyberSecException {
public:
    explicit SecurityException(std::string_view msg) : CyberSecException(msg) {}
};

/// @brief Thrown on socket / DNS / Winsock failures.
class NetworkException : public CyberSecException {
public:
    explicit NetworkException(std::string_view msg) : CyberSecException(msg) {}
};

/// @brief Thrown on any file I/O failure.
class FileException : public CyberSecException {
public:
    explicit FileException(std::string_view msg) : CyberSecException(msg) {}
};

/// @brief Thrown when a forensics Win32 snapshot/token operation fails.
class ForensicsException : public CyberSecException {
public:
    explicit ForensicsException(std::string_view msg) : CyberSecException(msg) {}
};
/// @}

// =============================================================================
/// @class SecureLogger
/// @brief  Thread-safe, XOR-encrypted, append-only audit logger.
///
/// Implemented as a Meyers singleton — construction is guaranteed thread-safe
/// by the C++11 standard (and every version since).
///
/// @par Usage
/// @code
///   SecureLogger::instance().info("Scan started");
///   LOG.error("CNG hash failed");   // via convenience macro
/// @endcode
// =============================================================================
class SecureLogger {
public:
    // ── Singleton access ─────────────────────────────────────────────────────
    /// @brief Returns the unique SecureLogger instance.
    static SecureLogger& instance() {
        static SecureLogger logger("cybersec_audit.log");
        return logger;
    }

    // Non-copyable / non-movable (singleton semantics)
    SecureLogger(const SecureLogger&)            = delete;
    SecureLogger& operator=(const SecureLogger&) = delete;

    // ── Logging API ──────────────────────────────────────────────────────────
    void info    (std::string_view msg) { write("INFO    ", msg); }
    void warning (std::string_view msg) { write("WARNING ", msg); }
    void error   (std::string_view msg) { write("ERROR   ", msg); }
    void critical(std::string_view msg) { write("CRITICAL", msg); }

    ~SecureLogger() {
        if (m_file && m_file->is_open()) m_file->close();
    }

private:
    explicit SecureLogger(std::string_view path) {
        m_file = std::make_unique<std::ofstream>(
            std::string(path), std::ios::app | std::ios::binary);
        if (!m_file->is_open())
            throw FileException("SecureLogger: cannot open log file.");
    }

    /// @brief Simple XOR stream cipher.
    /// @note  Upgrade to AES-256-CBC (via CryptoEngine) for production use.
    static std::string xorCipher(std::string_view data, std::uint8_t key = 0x5A) {
        std::string out(data);
        for (char& c : out) c ^= static_cast<char>(key);
        return out;
    }

    void write(std::string_view level, std::string_view msg) {
        std::lock_guard lock(m_mutex);
        auto now  = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::ostringstream ss;
        ss << "[" << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S") << "]"
           << "[" << level << "] " << msg << "\n";
        *m_file << xorCipher(ss.str());
        m_file->flush();
    }

    std::unique_ptr<std::ofstream> m_file;
    std::mutex                     m_mutex;
};

/// @brief Convenience macro for global logger access — avoids `::instance()` boilerplate.
#define LOG SecureLogger::instance()

// =============================================================================
/// @class ThreadPool
/// @brief  Fixed-size thread pool.  Upgraded to C++20: uses std::jthread
///         (auto-join on destruction) and std::stop_token for cooperative
///         cancellation.
///
/// @par Usage
/// @code
///   ThreadPool pool(8);
///   auto f = pool.enqueue([] { return 42; });
///   int result = f.get(); // == 42
/// @endcode
// =============================================================================
class ThreadPool {
public:
    /// @param threads Number of worker threads to spawn.
    explicit ThreadPool(std::size_t threads) {
        for (std::size_t i = 0; i < threads; ++i) {
            // std::jthread automatically joins on destruction
            m_workers.emplace_back([this](std::stop_token st) {
                while (!st.stop_requested()) {
                    std::function<void()> task;
                    {
                        // condition_variable_any is required to interop with stop_token
                        std::unique_lock lock(m_mutex);
                        m_cv.wait(lock, st, [this] { return !m_tasks.empty(); });
                        if (st.stop_requested() && m_tasks.empty()) return;
                        task = std::move(m_tasks.front());
                        m_tasks.pop();
                    }
                    task();
                }
            });
        }
    }

    /// @brief  Submit a callable and return a std::future for its return value.
    /// @tparam F  Any callable satisfying std::invocable.
    template <std::invocable F>
    [[nodiscard]] auto enqueue(F&& f) -> std::future<std::invoke_result_t<F>> {
        using R = std::invoke_result_t<F>;
        auto task = std::make_shared<std::packaged_task<R()>>(std::forward<F>(f));
        std::future<R> future = task->get_future();
        {
            std::lock_guard lock(m_mutex);
            m_tasks.emplace([task] { (*task)(); });
        }
        m_cv.notify_one();
        return future;
    }

    /// @brief Signals all workers to stop (std::jthread joins automatically).
    ~ThreadPool() {
        for (auto& t : m_workers) t.request_stop();
        m_cv.notify_all();
        // jthreads join here implicitly
    }

private:
    std::vector<std::jthread>          m_workers;
    std::queue<std::function<void()>>  m_tasks;
    std::mutex                         m_mutex;
    std::condition_variable_any        m_cv;  ///< _any variant supports stop_token
};
