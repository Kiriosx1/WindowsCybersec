/**
 * @file    network_scanner.hpp
 * @brief   High-performance asynchronous TCP port scanner with banner grabbing.
 *
 * Key improvements over v2.0:
 *  - WSAStartup / WSACleanup called ONCE at object lifetime boundaries (not per port).
 *  - Non-blocking connect() + select() eliminates per-thread blocking.
 *  - connect timeout: 500 ms  |  banner recv timeout: 1 000 ms.
 *  - std::stop_token allows the caller to cancel an in-flight scan.
 *  - Worker pool is bounded to min(ports.size(), 64) to avoid socket exhaustion.
 *  - Hostname resolved once via getaddrinfo() before any port is touched.
 *  - Service name table included for human-readable output.
 *
 * @note Link with: ws2_32.lib
 *
 * @version 3.0
 * @standard C++20
 */
#pragma once

#include "cybersec_core.hpp"
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")

// =============================================================================
/// @class NetworkScanner
/// @brief  Parallel TCP port scanner — owns one Winsock session for its lifetime.
// =============================================================================
class NetworkScanner {
public:
    // -------------------------------------------------------------------------
    /// @brief  Describes the result of probing one TCP port.
    // -------------------------------------------------------------------------
    struct PortResult {
        int         port    = 0;
        bool        open    = false;
        std::string service;    ///< Human-readable service name (best-effort)
        std::string banner;     ///< First bytes received from the service
    };

    // ── Constructor/Destructor ────────────────────────────────────────────────

    /// @brief Initialises Winsock ONCE for the lifetime of this scanner object.
    NetworkScanner() {
        WSADATA wsaData{};
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
            throw NetworkException("WSAStartup failed — is Winsock 2 available?");
        m_wsaUp = true;
    }

    /// @brief Cleans up the single Winsock session.
    ~NetworkScanner() {
        if (m_wsaUp) WSACleanup();
    }

    // Winsock session is non-copyable
    NetworkScanner(const NetworkScanner&)            = delete;
    NetworkScanner& operator=(const NetworkScanner&) = delete;

    // -------------------------------------------------------------------------
    /// @brief  Scan a list of TCP ports on a remote host.
    ///
    /// @param  host      Target hostname or dotted-decimal IPv4 address.
    /// @param  ports     Ports to probe (order not guaranteed in output).
    /// @param  stopToken Optional cancellation token — stops dispatching new
    ///                   probes when a stop is requested.
    /// @return Vector containing one PortResult for every OPEN port found.
    // -------------------------------------------------------------------------
    [[nodiscard]] std::vector<PortResult>
    scanPorts(const std::string& host,
              const std::vector<int>& ports,
              std::stop_token stopToken = {}) {
        // Resolve hostname to IP once — reused for every probe
        const std::string resolvedIP = resolveHost(host);

        // Cap thread count: no point spawning 65 535 threads
        const std::size_t workers =
            std::min<std::size_t>(ports.size(), 64u);
        ThreadPool pool(workers);

        // Dispatch all probes as independent futures
        std::vector<std::future<PortResult>> futures;
        futures.reserve(ports.size());

        for (int port : ports) {
            if (stopToken.stop_requested()) break;
            futures.push_back(pool.enqueue([this, resolvedIP, port] {
                return probePort(resolvedIP, port);
            }));
        }

        // Collect results — only return OPEN ports
        std::vector<PortResult> openPorts;
        for (auto& f : futures) {
            PortResult r = f.get();
            if (r.open) openPorts.push_back(std::move(r));
        }
        // Sort by port number for consistent display
        std::ranges::sort(openPorts, {}, &PortResult::port);
        return openPorts;
    }

    // -------------------------------------------------------------------------
    /// @brief  Returns a curated list of the most security-relevant TCP ports.
    // -------------------------------------------------------------------------
    [[nodiscard]] static std::vector<int> commonPorts() {
        return {
            21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
            143, 443, 445, 587, 993, 995, 1433, 1521,
            3306, 3389, 5432, 5900, 5985, 8080, 8443, 9200
        };
    }

    // -------------------------------------------------------------------------
    /// @brief  Pretty-print a scan result table to stdout.
    // -------------------------------------------------------------------------
    static void printResults(const std::string& host,
                             const std::vector<PortResult>& results) {
        std::cout << Color::PURPLE
                  << "\n╔══════════════════════════════════════════════════════╗\n"
                  << "║  TARGET: " << Color::CYAN << std::left << std::setw(44)
                  << host << Color::PURPLE << "║\n"
                  << "╠══════╦══════════════╦═══════════════════════════════╣\n"
                  << Color::CYAN
                  << "║ PORT ║   SERVICE    ║  BANNER                       ║\n"
                  << Color::PURPLE
                  << "╠══════╬══════════════╬═══════════════════════════════╣\n"
                  << Color::RESET;

        if (results.empty()) {
            std::cout << Color::YELLOW
                      << "  No open ports found in the scanned range.\n"
                      << Color::RESET;
        }
        for (const auto& r : results) {
            std::string bannerShort = r.banner;
            if (bannerShort.size() > 31) bannerShort = bannerShort.substr(0, 28) + "...";

            std::cout << Color::DARK_GRAY << "║ "
                      << Color::NEON_GREEN << std::right << std::setw(4) << r.port << " "
                      << Color::DARK_GRAY << "║ "
                      << Color::YELLOW << std::left << std::setw(12) << r.service << " "
                      << Color::DARK_GRAY << "║ "
                      << Color::WHITE << std::setw(31) << bannerShort
                      << Color::DARK_GRAY << "║\n"
                      << Color::RESET;
        }
        std::cout << Color::PURPLE
                  << "╚══════╩══════════════╩═══════════════════════════════╝\n"
                  << Color::CYAN
                  << "  " << results.size() << " open port(s) found.\n"
                  << Color::RESET;
    }

private:
    bool m_wsaUp = false;

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief  Resolve a hostname to a dotted-decimal IPv4 string.
    /// @throws NetworkException on DNS failure.
    // ─────────────────────────────────────────────────────────────────────────
    static std::string resolveHost(const std::string& host) {
        addrinfo hints{}, *res = nullptr;
        hints.ai_family   = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
            throw NetworkException("DNS resolution failed for: " + host);

        char ipStr[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET,
            &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr,
            ipStr, INET_ADDRSTRLEN);
        freeaddrinfo(res);
        return std::string(ipStr);
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief  Probe a single TCP port using non-blocking connect + select().
    ///
    /// @details
    ///  1. Create socket, switch to non-blocking mode.
    ///  2. Call connect() — it returns immediately with WSAEWOULDBLOCK.
    ///  3. Use select() with 500ms timeout to wait for writability (= connected).
    ///  4. Verify SO_ERROR to confirm the connection is clean.
    ///  5. If open, call grabBanner().
    ///  6. Always close the socket before returning.
    // ─────────────────────────────────────────────────────────────────────────
    [[nodiscard]] static PortResult probePort(const std::string& ip, int port) {
        PortResult result{port, false, serviceHint(port), ""};

        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) return result;

        // Switch to non-blocking so connect() returns immediately
        u_long nonBlocking = 1;
        ioctlsocket(sock, FIONBIO, &nonBlocking);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port   = htons(static_cast<u_short>(port));
        inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

        // Expected to return SOCKET_ERROR / WSAEWOULDBLOCK for non-blocking socket
        connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

        // Wait up to 500ms for the connection to become writable (= TCP handshake done)
        fd_set writeFds, errorFds;
        FD_ZERO(&writeFds);  FD_SET(sock, &writeFds);
        FD_ZERO(&errorFds);  FD_SET(sock, &errorFds);
        timeval timeout{ 0, 500'000 }; // 0 seconds + 500 000 µs

        int sel = select(0, nullptr, &writeFds, &errorFds, &timeout);

        if (sel > 0 && FD_ISSET(sock, &writeFds)) {
            // Double-check: no latent SO_ERROR on the socket
            int soErr = 0, soLen = sizeof(soErr);
            getsockopt(sock, SOL_SOCKET, SO_ERROR,
                reinterpret_cast<char*>(&soErr), &soLen);
            if (soErr == 0) {
                result.open   = true;
                result.banner = grabBanner(sock, port);
            }
        }

        closesocket(sock);
        return result;
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief  Attempt to read a service banner from a connected socket.
    ///
    /// @param  sock  A connected socket (non-blocking mode will be reverted).
    /// @param  port  Used to decide whether to send a protocol probe first.
    /// @return Sanitised, printable banner string (max 80 chars).
    // ─────────────────────────────────────────────────────────────────────────
    static std::string grabBanner(SOCKET sock, int port) {
        // Switch back to blocking mode for a clean recv()
        u_long blocking = 0;
        ioctlsocket(sock, FIONBIO, &blocking);

        // Hard 1-second receive timeout — prevents hanging the thread pool
        DWORD recvTimeout = 1000;
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
            reinterpret_cast<const char*>(&recvTimeout), sizeof(recvTimeout));

        // Some protocols need a stimulus before they emit a banner
        if (port == 80 || port == 8080) {
            const char* req = "HEAD / HTTP/1.0\r\nHost: target\r\n\r\n";
            send(sock, req, static_cast<int>(strlen(req)), 0);
        } else if (port == 443 || port == 8443) {
            // TLS — banner grab won't yield plaintext without a TLS handshake
            return "[TLS — use ssl-scan for banner]";
        }
        // FTP (21), SSH (22), SMTP (25), POP3 (110) send banners automatically

        char buf[512] = {};
        int  n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n <= 0) return "";

        buf[n] = '\0';

        // Strip non-printable characters and condense whitespace
        std::string clean;
        clean.reserve(static_cast<std::size_t>(n));
        for (int i = 0; i < n; ++i) {
            unsigned char c = static_cast<unsigned char>(buf[i]);
            if (c >= 0x20 && c < 0x7F) clean.push_back(static_cast<char>(c));
            else if (c == '\n' || c == '\r') clean.push_back(' ');
        }

        // Truncate for display
        if (clean.size() > 80) clean = clean.substr(0, 77) + "...";
        return clean;
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief  Map common port numbers to IANA service names.
    // ─────────────────────────────────────────────────────────────────────────
    static std::string serviceHint(int port) {
        switch (port) {
            case 21:   return "FTP";
            case 22:   return "SSH";
            case 23:   return "Telnet";
            case 25:   return "SMTP";
            case 53:   return "DNS";
            case 80:   return "HTTP";
            case 110:  return "POP3";
            case 111:  return "RPC/portmap";
            case 135:  return "MS-RPC";
            case 139:  return "NetBIOS-SSN";
            case 143:  return "IMAP";
            case 443:  return "HTTPS";
            case 445:  return "SMB";
            case 587:  return "SMTP/STARTTLS";
            case 993:  return "IMAPS";
            case 995:  return "POP3S";
            case 1433: return "MSSQL";
            case 1521: return "Oracle";
            case 3306: return "MySQL";
            case 3389: return "RDP";
            case 5432: return "PostgreSQL";
            case 5900: return "VNC";
            case 5985: return "WinRM";
            case 8080: return "HTTP-Alt";
            case 8443: return "HTTPS-Alt";
            case 9200: return "Elasticsearch";
            default:   return "Unknown";
        }
    }
};
