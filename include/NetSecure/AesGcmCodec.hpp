#pragma once

// NetSecure - AesGcmCodec.hpp
// AES-256-GCM per-message codec implementing Network::ICodec. Holds ONE
// key: create two instances per session (one per direction) from the keys
// Handshake derives. The Network frame header is authenticated as AAD
// (authenticated but not encrypted), so a tampered message id breaks the
// tag.
//
// Wire body layout: [12-byte random nonce][ciphertext][16-byte tag]
// A fresh random nonce per message makes nonce reuse a non-issue.
//
// Thread-safe: the Crypto::Aes256 engine inside is stateless and the key is
// never mutated. Every method returns 0 on success or a negative error code
// on failure (Crypto convention; kErrAuth on tampering).

#ifndef NETSECURE_AESGCMCODEC_HPP
#define NETSECURE_AESGCMCODEC_HPP

#ifndef NETSECURE_API
    #ifdef NETSECURE_STATIC
        #define NETSECURE_API
    #elif defined(NETSECURE_EXPORTS)
        #define NETSECURE_API __declspec(dllexport)
    #else
        #define NETSECURE_API __declspec(dllimport)
    #endif
#endif

#include "Network/ICodec.hpp"
#include "Aes256.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace NetSecure {

class NETSECURE_API AesGcmCodec : public Network::ICodec {
public:
    static constexpr std::size_t kKeySize   = 32;  // bytes = AES-256
    static constexpr std::size_t kNonceSize = 12;  // bytes = GCM IV
    static constexpr std::size_t kTagSize   = 16;  // bytes = GCM tag
    static constexpr std::size_t kOverhead  = kNonceSize + kTagSize; // 28

    // Return codes (Crypto::Aes256 convention).
    static constexpr int kOk                 = 0;  // success
    static constexpr int kErrInvalidArgument = -1; // wrong key size / too short
    static constexpr int kErrOpenSsl         = -2; // underlying OpenSSL call failed
    static constexpr int kErrAuth            = -3; // tampered data / wrong key

    /// Copy the 32-byte AES-256 key into the codec. If the key size is not
    /// kKeySize, encode/decode fail with kErrInvalidArgument.
    explicit AesGcmCodec(const std::vector<uint8_t>& key);

    /// plaintext -> [nonce][ciphertext][tag]. The aad (Network frame header)
    /// is authenticated but not encrypted.
    int encode(const std::vector<uint8_t>& plaintext,
               const std::vector<uint8_t>& aad,
               std::vector<uint8_t>& wireBytes) noexcept override;

    /// [nonce][ciphertext][tag] -> plaintext. Fails with kErrAuth on any
    /// tampering (body, tag, nonce or aad).
    int decode(const std::vector<uint8_t>& wireBytes,
               const std::vector<uint8_t>& aad,
               std::vector<uint8_t>& plaintext) noexcept override;

private:
    std::vector<uint8_t> key;   // the only state; never mutated
    Crypto::Aes256 engine;      // stateless, thread-safe
};

} // namespace NetSecure

#endif // NETSECURE_AESGCMCODEC_HPP
