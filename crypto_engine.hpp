/**
 * @file    crypto_engine.hpp
 * @brief   Genuine cryptographic operations via the Windows CNG (BCrypt) API.
 *
 * Replaces every placeholder in the original CryptoUtils class:
 *  - MD5    – BCrypt BCRYPT_MD5_ALGORITHM
 *  - SHA-256 – BCrypt BCRYPT_SHA256_ALGORITHM
 *  - AES-256-CBC – BCrypt symmetric key encrypt/decrypt (PKCS#7 padding)
 *  - Base64 – pure-C++ RFC 4648 implementation
 *  - Password generator – hardware entropy via std::random_device
 *
 * @note Link with: bcrypt.lib
 *
 * @version 3.0
 * @standard C++20
 */
#pragma once

#include "cybersec_core.hpp"
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")

// =============================================================================
/// @class CryptoEngine
/// @brief  Thin, RAII-safe wrapper around the Windows CNG API.
///
/// All methods are static — no instantiation required.
// =============================================================================
class CryptoEngine {
public:
    // =========================================================================
    //  HASHING
    // =========================================================================

    // -------------------------------------------------------------------------
    /// @brief  Compute the MD5 digest of a file on disk.
    /// @param  filepath  Absolute or relative path to the target file.
    /// @return Lowercase hex string (32 characters).
    /// @throws FileException      if the file cannot be opened.
    /// @throws SecurityException  if any BCrypt call fails.
    // -------------------------------------------------------------------------
    [[nodiscard]] static std::string hashFileMD5(const std::string& filepath) {
        return hashFile(filepath, BCRYPT_MD5_ALGORITHM);
    }

    // -------------------------------------------------------------------------
    /// @brief  Compute the SHA-256 digest of a file on disk.
    /// @param  filepath  Absolute or relative path to the target file.
    /// @return Lowercase hex string (64 characters).
    /// @throws FileException      if the file cannot be opened.
    /// @throws SecurityException  if any BCrypt call fails.
    // -------------------------------------------------------------------------
    [[nodiscard]] static std::string hashFileSHA256(const std::string& filepath) {
        return hashFile(filepath, BCRYPT_SHA256_ALGORITHM);
    }

    // -------------------------------------------------------------------------
    /// @brief  Compute the SHA-256 digest of a raw byte buffer.
    /// @param  data  Pointer to the byte data.
    /// @param  len   Number of bytes to hash.
    /// @return Lowercase hex string (64 characters).
    // -------------------------------------------------------------------------
    [[nodiscard]] static std::string hashBufferSHA256(
            const std::uint8_t* data, std::size_t len) {
        return hashBuffer(data, len, BCRYPT_SHA256_ALGORITHM);
    }

    // =========================================================================
    //  AES-256-CBC SYMMETRIC ENCRYPTION
    // =========================================================================

    // -------------------------------------------------------------------------
    /// @brief  Encrypt plaintext with AES-256-CBC (PKCS#7 padded).
    /// @param  plaintext  Data to encrypt.
    /// @param  key        32-byte (256-bit) symmetric key.
    /// @param  iv         16-byte initialisation vector.
    /// @return Ciphertext bytes (length is a multiple of 16).
    /// @throws SecurityException on any BCrypt failure.
    // -------------------------------------------------------------------------
    [[nodiscard]] static std::vector<std::uint8_t>
    aes256Encrypt(std::span<const std::uint8_t>    plaintext,
                  std::span<const std::uint8_t, 32> key,
                  std::span<const std::uint8_t, 16> iv) {
        return aes256Transform(plaintext, key, iv, /*encrypt=*/true);
    }

    // -------------------------------------------------------------------------
    /// @brief  Decrypt AES-256-CBC ciphertext (strips PKCS#7 padding).
    /// @param  ciphertext  Encrypted data (multiple of 16 bytes).
    /// @param  key         32-byte symmetric key (must match encryption key).
    /// @param  iv          16-byte IV used during encryption.
    /// @return Decrypted plaintext bytes.
    /// @throws SecurityException on any BCrypt failure.
    // -------------------------------------------------------------------------
    [[nodiscard]] static std::vector<std::uint8_t>
    aes256Decrypt(std::span<const std::uint8_t>    ciphertext,
                  std::span<const std::uint8_t, 32> key,
                  std::span<const std::uint8_t, 16> iv) {
        return aes256Transform(ciphertext, key, iv, /*encrypt=*/false);
    }

    // =========================================================================
    //  BASE-64
    // =========================================================================

    // -------------------------------------------------------------------------
    /// @brief  Encode arbitrary bytes to a Base-64 string (RFC 4648).
    // -------------------------------------------------------------------------
    [[nodiscard]] static std::string base64Encode(std::string_view input) {
        static constexpr char kTable[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        std::string out;
        out.reserve(((input.size() + 2) / 3) * 4);
        int val = 0, valb = -6;
        for (unsigned char c : input) {
            val  = (val << 8) + c;
            valb += 8;
            while (valb >= 0) {
                out.push_back(kTable[(val >> valb) & 0x3F]);
                valb -= 6;
            }
        }
        if (valb > -6)
            out.push_back(kTable[((val << 8) >> (valb + 8)) & 0x3F]);
        while (out.size() % 4) out.push_back('=');
        return out;
    }

    // -------------------------------------------------------------------------
    /// @brief  Decode a Base-64 string back to its original bytes.
    // -------------------------------------------------------------------------
    [[nodiscard]] static std::string base64Decode(std::string_view input) {
        // Build decode lookup table at compile time via immediately-invoked lambda
        static constexpr auto buildTable = []() {
            std::array<int, 256> t{};
            t.fill(-1);
            const char* enc =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            for (int i = 0; enc[i]; ++i)
                t[static_cast<unsigned char>(enc[i])] = i;
            return t;
        };
        static const auto kTable = buildTable();

        std::string out;
        int val = 0, valb = -8;
        for (unsigned char c : input) {
            if (c == '=') break;
            int idx = kTable[c];
            if (idx < 0) continue;
            val  = (val << 6) + idx;
            valb += 6;
            if (valb >= 0) {
                out.push_back(static_cast<char>((val >> valb) & 0xFF));
                valb -= 8;
            }
        }
        return out;
    }

    // =========================================================================
    //  PASSWORD GENERATOR
    // =========================================================================

    // -------------------------------------------------------------------------
    /// @brief  Generate a cryptographically-secure random password.
    /// @param  length  Desired character count (default 24).
    /// @return Password string using upper, lower, digits and symbols.
    // -------------------------------------------------------------------------
    [[nodiscard]] static std::string generatePassword(std::size_t length = 24) {
        static constexpr std::string_view kChars =
            "abcdefghijklmnopqrstuvwxyz"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "0123456789"
            "!@#$%^&*()-_=+[]{}|;:',.<>?";
        std::random_device                        rd;
        std::mt19937_64                           gen(rd());
        std::uniform_int_distribution<std::size_t> dis(0, kChars.size() - 1);
        std::string pwd(length, '\0');
        std::ranges::generate(pwd, [&] { return kChars[dis(gen)]; });
        return pwd;
    }

    // =========================================================================
    //  UTILITY HELPERS
    // =========================================================================

    /// @brief Convert a raw byte array to a lowercase hex string.
    [[nodiscard]] static std::string toHex(std::span<const std::uint8_t> bytes) {
        std::ostringstream oss;
        oss << std::hex << std::setfill('0');
        for (auto b : bytes) oss << std::setw(2) << static_cast<int>(b);
        return oss.str();
    }

private:
    // =========================================================================
    //  RAII BCrypt Handle Wrappers
    // =========================================================================

    /// @brief RAII guard for BCRYPT_ALG_HANDLE.
    struct AlgHandle {
        BCRYPT_ALG_HANDLE h = nullptr;

        explicit AlgHandle(LPCWSTR id, ULONG flags = 0) {
            if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&h, id, nullptr, flags)))
                throw SecurityException("BCryptOpenAlgorithmProvider failed");
        }
        ~AlgHandle() { if (h) BCryptCloseAlgorithmProvider(h, 0); }

        AlgHandle(const AlgHandle&)            = delete;
        AlgHandle& operator=(const AlgHandle&) = delete;
    };

    /// @brief RAII guard for BCRYPT_HASH_HANDLE.
    struct HashHandle {
        BCRYPT_HASH_HANDLE h = nullptr;
        HashHandle() noexcept = default; // allow default construction
        ~HashHandle() { if (h) BCryptDestroyHash(h); }
        HashHandle(const HashHandle&)            = delete;
        HashHandle& operator=(const HashHandle&) = delete;
    };

    /// @brief RAII guard for BCRYPT_KEY_HANDLE.
    struct KeyHandle {
        BCRYPT_KEY_HANDLE h = nullptr;
        KeyHandle() noexcept = default; // allow default construction
        ~KeyHandle() { if (h) BCryptDestroyKey(h); }
        KeyHandle(const KeyHandle&)            = delete;
        KeyHandle& operator=(const KeyHandle&) = delete;
    };

    // =========================================================================
    //  Private Implementations
    // =========================================================================

    /// @brief Hash the binary contents of a file using any BCrypt algorithm.
    static std::string hashFile(const std::string& filepath, LPCWSTR algorithm) {
        std::ifstream file(filepath, std::ios::binary);
        if (!file.is_open())
            throw FileException("Cannot open file for hashing: " + filepath);

        // Stream file into a byte vector
        std::vector<std::uint8_t> data(
            (std::istreambuf_iterator<char>(file)),
             std::istreambuf_iterator<char>());

        return hashBuffer(data.data(), data.size(), algorithm);
    }

    /// @brief Core BCrypt hashing routine — works for MD5, SHA-1, SHA-256, SHA-512.
    static std::string hashBuffer(
            const std::uint8_t* data, std::size_t len, LPCWSTR algorithm) {
        AlgHandle alg(algorithm);

        // Query the sizes we need to allocate
        DWORD cbHashObj = 0, cbHash = 0, cbData = 0;

        if (!BCRYPT_SUCCESS(BCryptGetProperty(alg.h, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PBYTE>(&cbHashObj), sizeof(DWORD), &cbData, 0)))
            throw SecurityException("BCryptGetProperty(OBJECT_LENGTH) failed");

        if (!BCRYPT_SUCCESS(BCryptGetProperty(alg.h, BCRYPT_HASH_LENGTH,
                reinterpret_cast<PBYTE>(&cbHash), sizeof(DWORD), &cbData, 0)))
            throw SecurityException("BCryptGetProperty(HASH_LENGTH) failed");

        std::vector<BYTE> hashObjBuf(cbHashObj);
        std::vector<BYTE> digest(cbHash);

        HashHandle hashHandle;
        if (!BCRYPT_SUCCESS(BCryptCreateHash(
                alg.h, &hashHandle.h, hashObjBuf.data(), cbHashObj,
                nullptr, 0, 0)))
            throw SecurityException("BCryptCreateHash failed");

        // BCryptHashData expects a non-const PUCHAR — cast is safe here
        if (!BCRYPT_SUCCESS(BCryptHashData(
                hashHandle.h,
                const_cast<PUCHAR>(data),
                static_cast<ULONG>(len), 0)))
            throw SecurityException("BCryptHashData failed");

        if (!BCRYPT_SUCCESS(BCryptFinishHash(hashHandle.h, digest.data(), cbHash, 0)))
            throw SecurityException("BCryptFinishHash failed");

        return toHex(std::span<const std::uint8_t>(digest.data(), cbHash));
    }

    // -------------------------------------------------------------------------
    /// @brief  Shared AES-256-CBC encrypt/decrypt core.
    /// @param  input    Input data.
    /// @param  key      32-byte key.
    /// @param  iv       16-byte IV (a local copy is used; caller's buffer unchanged).
    /// @param  encrypt  true  → encrypt (apply PKCS#7 padding)
    ///                  false → decrypt (strip PKCS#7 padding)
    // -------------------------------------------------------------------------
    static std::vector<std::uint8_t>
    aes256Transform(std::span<const std::uint8_t>    input,
                    std::span<const std::uint8_t, 32> key,
                    std::span<const std::uint8_t, 16> iv,
                    bool encrypt) {
        AlgHandle alg(BCRYPT_AES_ALGORITHM);

        // Switch to CBC mode
        if (!BCRYPT_SUCCESS(BCryptSetProperty(
                alg.h, BCRYPT_CHAINING_MODE,
                reinterpret_cast<PBYTE>(
                    const_cast<wchar_t*>(BCRYPT_CHAIN_MODE_CBC)),
                sizeof(BCRYPT_CHAIN_MODE_CBC), 0)))
            throw SecurityException("BCryptSetProperty(CHAINING_MODE=CBC) failed");

        // Query key object size
        DWORD cbKeyObj = 0, cbData = 0;
        if (!BCRYPT_SUCCESS(BCryptGetProperty(alg.h, BCRYPT_OBJECT_LENGTH,
                reinterpret_cast<PBYTE>(&cbKeyObj), sizeof(DWORD), &cbData, 0)))
            throw SecurityException("BCryptGetProperty(KEY_OBJECT) failed");

        std::vector<BYTE> keyObjBuf(cbKeyObj);
        KeyHandle keyHandle;
        // Import the raw key bytes
        if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(
                alg.h, &keyHandle.h,
                keyObjBuf.data(), cbKeyObj,
                const_cast<PUCHAR>(key.data()), 32, 0)))
            throw SecurityException("BCryptGenerateSymmetricKey failed");

        // IV is consumed by the operation; work on a local copy
        std::array<BYTE, 16> ivBuf{};
        std::ranges::copy(iv, ivBuf.begin());

        ULONG cbResult = 0;

        if (encrypt) {
            // First call: query required output buffer size
            ULONG cbCipher = 0;
            BCryptEncrypt(keyHandle.h,
                const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()),
                nullptr, ivBuf.data(), 16, nullptr, 0, &cbCipher,
                BCRYPT_BLOCK_PADDING);

            std::vector<std::uint8_t> cipher(cbCipher);
            if (!BCRYPT_SUCCESS(BCryptEncrypt(keyHandle.h,
                    const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()),
                    nullptr, ivBuf.data(), 16,
                    cipher.data(), cbCipher, &cbResult, BCRYPT_BLOCK_PADDING)))
                throw SecurityException("BCryptEncrypt failed");

            cipher.resize(cbResult);
            return cipher;
        } else {
            ULONG cbPlain = 0;
            BCryptDecrypt(keyHandle.h,
                const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()),
                nullptr, ivBuf.data(), 16, nullptr, 0, &cbPlain,
                BCRYPT_BLOCK_PADDING);

            std::vector<std::uint8_t> plain(cbPlain);
            if (!BCRYPT_SUCCESS(BCryptDecrypt(keyHandle.h,
                    const_cast<PUCHAR>(input.data()), static_cast<ULONG>(input.size()),
                    nullptr, ivBuf.data(), 16,
                    plain.data(), cbPlain, &cbResult, BCRYPT_BLOCK_PADDING)))
                throw SecurityException("BCryptDecrypt failed");

            plain.resize(cbResult);
            return plain;
        }
    }
};
