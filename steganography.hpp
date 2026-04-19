/**
 * @file steganography.hpp
 * @brief Image Steganography Engine — integrates Glaux (github.com/Kiriosx1/Glaux-)
 *
 * Supports LSB (Least Significant Bit) encoding/decoding inside BMP images,
 * with optional XOR passphrase encryption of the hidden payload before embedding.
 *
 * Features:
 *  - Embed text/binary payloads into BMP images (LSB steganography)
 *  - Extract hidden payloads from stego-images
 *  - Passphrase-based XOR encryption of payload (pre-embed / post-extract)
 *  - Capacity analysis — tells you the max bytes a carrier image can hold
 *  - Pixel-level noise analysis to detect potential stego artifacts
 *  - CLI menu integration (showSteganographyMenu)
 *
 * @version 4.0
 * @standard C++20
 */

#pragma once

#include "cybersec_core.hpp"
#include <fstream>
#include <vector>
#include <string>
#include <iostream>
#include <filesystem>
#include <cstring>
#include <algorithm>
#include <numeric>
#include <cmath>

namespace fs = std::filesystem;

// ─────────────────────────────────────────────────────────────────────────────
// BMP file structures (packed — no alignment padding)
// ─────────────────────────────────────────────────────────────────────────────
#pragma pack(push, 1)
struct BMPFileHeader {
    uint16_t bfType       { 0x4D42 }; // 'BM'
    uint32_t bfSize       { 0 };
    uint16_t bfReserved1  { 0 };
    uint16_t bfReserved2  { 0 };
    uint32_t bfOffBits    { 0 };
};

struct BMPInfoHeader {
    uint32_t biSize          { 0 };
    int32_t  biWidth         { 0 };
    int32_t  biHeight        { 0 };
    uint16_t biPlanes        { 1 };
    uint16_t biBitCount      { 0 };
    uint32_t biCompression   { 0 };
    uint32_t biSizeImage     { 0 };
    int32_t  biXPelsPerMeter { 0 };
    int32_t  biYPelsPerMeter { 0 };
    uint32_t biClrUsed       { 0 };
    uint32_t biClrImportant  { 0 };
};
#pragma pack(pop)

// ─────────────────────────────────────────────────────────────────────────────
// SteganographyEngine
// ─────────────────────────────────────────────────────────────────────────────
class SteganographyEngine {
public:

    // ── Payload XOR cipher (same approach as SecureLogger) ───────────────────
    static std::vector<uint8_t> xorPayload(const std::vector<uint8_t>& data,
                                            const std::string& passphrase) {
        if (passphrase.empty()) return data;
        std::vector<uint8_t> out(data.size());
        for (size_t i = 0; i < data.size(); ++i)
            out[i] = data[i] ^ static_cast<uint8_t>(passphrase[i % passphrase.size()]);
        return out;
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief Load a BMP file from disk into raw pixel bytes.
    /// @returns {fileHeader, infoHeader, pixelData, rowStride}
    // ─────────────────────────────────────────────────────────────────────────
    struct BmpImage {
        BMPFileHeader fh;
        BMPInfoHeader ih;
        std::vector<uint8_t> pixels;
        size_t rowStride { 0 };
        bool valid { false };
    };

    static BmpImage loadBMP(const std::string& path) {
        BmpImage img;
        std::ifstream f(path, std::ios::binary);
        if (!f) { LOG.error("Stego: cannot open BMP: " + path); return img; }

        f.read(reinterpret_cast<char*>(&img.fh), sizeof(img.fh));
        f.read(reinterpret_cast<char*>(&img.ih), sizeof(img.ih));

        if (img.fh.bfType != 0x4D42) {
            LOG.error("Stego: not a BMP file: " + path);
            return img;
        }
        if (img.ih.biBitCount != 24) {
            LOG.error("Stego: only 24-bit BMP supported.");
            return img;
        }

        // Row stride = multiple of 4 bytes
        img.rowStride = ((img.ih.biWidth * 3 + 3) / 4) * 4;
        size_t pixelSize = img.rowStride * std::abs(img.ih.biHeight);
        img.pixels.resize(pixelSize);

        f.seekg(img.fh.bfOffBits);
        f.read(reinterpret_cast<char*>(img.pixels.data()), static_cast<std::streamsize>(pixelSize));
        img.valid = f.good();
        return img;
    }

    static bool saveBMP(const std::string& path, BmpImage& img) {
        std::ofstream f(path, std::ios::binary);
        if (!f) { LOG.error("Stego: cannot write BMP: " + path); return false; }
        f.write(reinterpret_cast<char*>(&img.fh), sizeof(img.fh));
        f.write(reinterpret_cast<char*>(&img.ih), sizeof(img.ih));
        // Write any gap between info header end and pixel data
        size_t headerEnd = sizeof(img.fh) + sizeof(img.ih);
        if (img.fh.bfOffBits > headerEnd) {
            std::vector<uint8_t> gap(img.fh.bfOffBits - headerEnd, 0);
            f.write(reinterpret_cast<char*>(gap.data()), static_cast<std::streamsize>(gap.size()));
        }
        f.write(reinterpret_cast<char*>(img.pixels.data()), static_cast<std::streamsize>(img.pixels.size()));
        return f.good();
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief Returns max bytes embeddable (using 1 LSB per colour channel).
    // ─────────────────────────────────────────────────────────────────────────
    static size_t capacity(const BmpImage& img) {
        // 3 channels per pixel, 1 bit per channel → 3 bits per pixel
        // We use 8 pixels per byte → capacity = total_pixels * 3 / 8
        size_t totalPixels = static_cast<size_t>(std::abs(img.ih.biWidth) *
                                                  std::abs(img.ih.biHeight));
        return (totalPixels * 3) / 8 - sizeof(uint32_t); // minus 4-byte length header
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief Embed payload bytes into BMP LSBs. Prepends a 4-byte length.
    // ─────────────────────────────────────────────────────────────────────────
    static bool embed(BmpImage& img,
                      const std::vector<uint8_t>& payload,
                      const std::string& passphrase = "") {
        auto data = passphrase.empty() ? payload : xorPayload(payload, passphrase);

        if (data.size() + sizeof(uint32_t) > capacity(img)) {
            LOG.error("Stego: payload too large for carrier image.");
            return false;
        }

        // Build full stream: [4-byte LE length][data]
        std::vector<uint8_t> stream;
        stream.reserve(4 + data.size());
        uint32_t len = static_cast<uint32_t>(data.size());
        stream.push_back(len & 0xFF);
        stream.push_back((len >> 8) & 0xFF);
        stream.push_back((len >> 16) & 0xFF);
        stream.push_back((len >> 24) & 0xFF);
        stream.insert(stream.end(), data.begin(), data.end());

        // LSB-embed: 1 bit per channel byte
        size_t bitIdx = 0;
        for (size_t byteIdx = 0; byteIdx < stream.size(); ++byteIdx) {
            for (int bit = 7; bit >= 0; --bit) {
                uint8_t b = (stream[byteIdx] >> bit) & 1;
                // Find the right pixel byte: we walk pixel bytes sequentially
                // skipping row padding bytes
                size_t pixelByte = findPixelByte(img, bitIdx);
                img.pixels[pixelByte] = (img.pixels[pixelByte] & 0xFE) | b;
                ++bitIdx;
            }
        }
        return true;
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief Extract a previously embedded payload from a BMP.
    // ─────────────────────────────────────────────────────────────────────────
    static std::vector<uint8_t> extract(const BmpImage& img,
                                         const std::string& passphrase = "") {
        // Read first 32 bits → payload length
        auto readBits = [&](size_t startBit, size_t numBits) -> std::vector<uint8_t> {
            size_t numBytes = (numBits + 7) / 8;
            std::vector<uint8_t> out(numBytes, 0);
            for (size_t i = 0; i < numBits; ++i) {
                size_t pixelByte = findPixelByte(img, startBit + i);
                uint8_t bit = img.pixels[pixelByte] & 1;
                size_t outByte = i / 8;
                size_t outBit  = 7 - (i % 8);
                out[outByte] |= (bit << outBit);
            }
            return out;
        };

        auto lenBytes = readBits(0, 32);
        uint32_t len = lenBytes[0]
                     | (static_cast<uint32_t>(lenBytes[1]) << 8)
                     | (static_cast<uint32_t>(lenBytes[2]) << 16)
                     | (static_cast<uint32_t>(lenBytes[3]) << 24);

        if (len == 0 || len > capacity(img)) {
            LOG.error("Stego: extracted length invalid — no hidden data or wrong passphrase.");
            return {};
        }

        auto data = readBits(32, static_cast<size_t>(len) * 8);
        if (!passphrase.empty())
            data = xorPayload(data, passphrase);
        return data;
    }

    // ─────────────────────────────────────────────────────────────────────────
    /// @brief Chi-square analysis — detects likely LSB steganography.
    ///        Returns a suspicion score 0.0 (clean) .. 1.0 (very suspicious).
    // ─────────────────────────────────────────────────────────────────────────
    static double analyzeForStego(const BmpImage& img) {
        // Pair the LSB frequency of each byte value with its complementary pair
        std::array<size_t, 256> freq{};
        for (uint8_t b : img.pixels) ++freq[b];

        double chi2 = 0.0;
        size_t pairs = 0;
        for (int i = 0; i < 256; i += 2) {
            double expected = (freq[i] + freq[i + 1]) / 2.0;
            if (expected < 1.0) continue;
            double diff = freq[i] - expected;
            chi2 += (diff * diff) / expected;
            ++pairs;
        }
        if (pairs == 0) return 0.0;
        // Normalise: chi2 / (2 * pairs) gives rough 0..1 suspicion
        return std::min(1.0, chi2 / (2.0 * static_cast<double>(pairs)));
    }

private:
    // Map a sequential bit index to a pixel byte index, skipping row padding.
    static size_t findPixelByte(const BmpImage& img, size_t bitIdx) {
        // Each pixel has 3 usable bytes (BGR). Row stride may add padding bytes.
        size_t width       = static_cast<size_t>(std::abs(img.ih.biWidth));
        size_t usablePerRow = width * 3;
        size_t pixelRow    = bitIdx / usablePerRow;
        size_t pixelCol    = bitIdx % usablePerRow;
        return pixelRow * img.rowStride + pixelCol;
    }
    // Const overload
    static size_t findPixelByte(const BmpImage& img, size_t bitIdx) noexcept {
        size_t width        = static_cast<size_t>(std::abs(img.ih.biWidth));
        size_t usablePerRow = width * 3;
        size_t pixelRow     = bitIdx / usablePerRow;
        size_t pixelCol     = bitIdx % usablePerRow;
        return pixelRow * img.rowStride + pixelCol;
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// CLI Menu
// ─────────────────────────────────────────────────────────────────────────────
inline void showSteganographyMenu() {
    while (true) {
        std::cout << Color::CYAN
            << "\n╔══════════════════════════════════════════════════════════════╗\n"
            << "║          🦉 GLAUX STEGANOGRAPHY ENGINE (Integrated)          ║\n"
            << "╠══════════════════════════════════════════════════════════════╣\n"
            << "║  1. Embed message/file into BMP image                        ║\n"
            << "║  2. Extract hidden payload from BMP image                    ║\n"
            << "║  3. Analyse image for steganography artifacts (chi-square)   ║\n"
            << "║  4. Check carrier capacity (max embeddable bytes)            ║\n"
            << "║  5. Back to main menu                                        ║\n"
            << "╚══════════════════════════════════════════════════════════════╝\n"
            << Color::RESET
            << "  Choice: ";

        int ch; std::cin >> ch; std::cin.ignore();

        if (ch == 5) break;

        std::string carrier, output, passphrase;

        if (ch == 1) {
            // ── Embed ──────────────────────────────────────────────────────
            std::cout << Color::YELLOW << "  Carrier BMP path: " << Color::RESET;
            std::getline(std::cin, carrier);
            std::cout << Color::YELLOW << "  Message or file path to embed: " << Color::RESET;
            std::string input; std::getline(std::cin, input);
            std::cout << Color::YELLOW << "  Output BMP path: " << Color::RESET;
            std::getline(std::cin, output);
            std::cout << Color::YELLOW << "  Passphrase (blank = none): " << Color::RESET;
            std::getline(std::cin, passphrase);

            auto img = SteganographyEngine::loadBMP(carrier);
            if (!img.valid) {
                std::cout << Color::RED << "  [!] Failed to load carrier BMP.\n" << Color::RESET;
                continue;
            }

            // Determine if input is a file path or raw text
            std::vector<uint8_t> payload;
            if (fs::exists(input)) {
                std::ifstream pf(input, std::ios::binary);
                payload.assign(std::istreambuf_iterator<char>(pf), {});
            } else {
                payload.assign(input.begin(), input.end());
            }

            std::cout << Color::NEON_GREEN
                << "  [*] Carrier capacity: " << SteganographyEngine::capacity(img)
                << " bytes | Payload: " << payload.size() << " bytes\n"
                << Color::RESET;

            if (SteganographyEngine::embed(img, payload, passphrase)) {
                if (SteganographyEngine::saveBMP(output, img))
                    std::cout << Color::NEON_GREEN << "  [+] Payload embedded → " << output << "\n" << Color::RESET;
                else
                    std::cout << Color::RED << "  [!] Failed to save output BMP.\n" << Color::RESET;
            } else {
                std::cout << Color::RED << "  [!] Embedding failed (payload too large?).\n" << Color::RESET;
            }
            LOG.info("Stego embed: carrier=" + carrier + " output=" + output);

        } else if (ch == 2) {
            // ── Extract ────────────────────────────────────────────────────
            std::cout << Color::YELLOW << "  Stego BMP path: " << Color::RESET;
            std::getline(std::cin, carrier);
            std::cout << Color::YELLOW << "  Save extracted payload to (blank = print text): " << Color::RESET;
            std::getline(std::cin, output);
            std::cout << Color::YELLOW << "  Passphrase (blank = none): " << Color::RESET;
            std::getline(std::cin, passphrase);

            auto img = SteganographyEngine::loadBMP(carrier);
            if (!img.valid) {
                std::cout << Color::RED << "  [!] Failed to load BMP.\n" << Color::RESET;
                continue;
            }

            auto data = SteganographyEngine::extract(img, passphrase);
            if (data.empty()) {
                std::cout << Color::RED << "  [!] No valid payload found.\n" << Color::RESET;
                continue;
            }

            if (output.empty()) {
                std::cout << Color::NEON_GREEN << "  [+] Extracted (" << data.size() << " bytes):\n  ";
                for (auto c : data) std::cout << static_cast<char>(c);
                std::cout << "\n" << Color::RESET;
            } else {
                std::ofstream of(output, std::ios::binary);
                of.write(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(data.size()));
                std::cout << Color::NEON_GREEN << "  [+] Extracted " << data.size()
                    << " bytes → " << output << "\n" << Color::RESET;
            }
            LOG.info("Stego extract: source=" + carrier);

        } else if (ch == 3) {
            // ── Chi-square analysis ────────────────────────────────────────
            std::cout << Color::YELLOW << "  BMP to analyse: " << Color::RESET;
            std::getline(std::cin, carrier);
            auto img = SteganographyEngine::loadBMP(carrier);
            if (!img.valid) {
                std::cout << Color::RED << "  [!] Failed to load BMP.\n" << Color::RESET;
                continue;
            }
            double score = SteganographyEngine::analyzeForStego(img);
            std::cout << Color::CYAN << "  [*] Chi-square suspicion score: "
                << Color::YELLOW << std::fixed << std::setprecision(4) << score << "\n";
            if (score > 0.7)
                std::cout << Color::RED    << "  [!] HIGH suspicion — likely contains hidden data.\n";
            else if (score > 0.3)
                std::cout << Color::ORANGE << "  [~] MODERATE suspicion — possible steganography.\n";
            else
                std::cout << Color::NEON_GREEN << "  [+] LOW suspicion — image appears clean.\n";
            std::cout << Color::RESET;
            LOG.info("Stego analysis: file=" + carrier + " score=" + std::to_string(score));

        } else if (ch == 4) {
            // ── Capacity ───────────────────────────────────────────────────
            std::cout << Color::YELLOW << "  BMP path: " << Color::RESET;
            std::getline(std::cin, carrier);
            auto img = SteganographyEngine::loadBMP(carrier);
            if (!img.valid) {
                std::cout << Color::RED << "  [!] Failed to load BMP.\n" << Color::RESET;
                continue;
            }
            size_t cap = SteganographyEngine::capacity(img);
            std::cout << Color::NEON_GREEN
                << "  [*] Image: " << img.ih.biWidth << "x" << std::abs(img.ih.biHeight) << " px | 24-bit\n"
                << "  [*] Max embeddable payload: " << cap << " bytes ("
                << cap / 1024 << " KB)\n"
                << Color::RESET;
        }
    }
}
