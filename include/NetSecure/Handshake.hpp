#pragma once

// NetSecure - Handshake.hpp
// Post-quantum session key establishment: ML-KEM-768 + HKDF-SHA256.
//
// Client calls initiate() to wrap a fresh shared secret to the server's
// public key; the envelope is sent to the server as one plaintext message
// (it contains no secret). Server calls respond() to unwrap it with its
// secret key. Both sides then derive two directional AES-256 keys:
//
//   clientSendKey    = HKDF(sharedSecret, info = "netsecure v1 client->server")
//   clientReceiveKey = HKDF(sharedSecret, info = "netsecure v1 server->client")
//   serverReceiveKey = clientSendKey, serverSendKey = clientReceiveKey
//
// Envelope layout (binary): [4-byte little-endian length][KEM ciphertext]
//
// Security note: ML-KEM's implicit rejection means respond() cannot detect
// a forged envelope - it derives different keys instead, so an active
// attacker can break the connection but never read it. Authenticate the
// handshake (e.g. echo a client nonce through the encrypted channel) before
// trusting the session in hostile environments.
//
// Stateless and thread-safe: all inputs and outputs are per-call.

#ifndef NETSECURE_HANDSHAKE_HPP
#define NETSECURE_HANDSHAKE_HPP

#ifndef NETSECURE_API
    #ifdef NETSECURE_STATIC
        #define NETSECURE_API
    #elif defined(NETSECURE_EXPORTS)
        #define NETSECURE_API __declspec(dllexport)
    #else
        #define NETSECURE_API __declspec(dllimport)
    #endif
#endif

#include "MlKem768.hpp"
#include "Hkdf.hpp"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace NetSecure {

class NETSECURE_API Handshake {
public:
    static constexpr std::size_t kKeySize = 32;          // derived AES-256 key
    static constexpr std::size_t kMaxEnvelopeSize = 8192; // sanity limit

    // Return codes (Crypto convention).
    static constexpr int kOk                 = 0;  // success
    static constexpr int kErrInvalidArgument = -1; // malformed envelope / bad key
    static constexpr int kErrOpenSsl         = -2; // underlying OpenSSL call failed
    static constexpr int kErrAuth            = -3; // key mismatch (reserved)
    static constexpr int kErrUnavailable     = -4; // ML-KEM missing in OpenSSL

    /// Human readable algorithm identifier
    /// ("ML-KEM-768 + HKDF-SHA256 + AES-256-GCM").
    const char* algorithmName() const noexcept;

    /// Client side. Wrap a fresh shared secret to the server's public key
    /// (DER, from MlKem768::generateKeyPair). envelope = the bytes to send
    /// to the server; the two derived keys are 32 bytes each.
    int initiate(const std::vector<uint8_t>& serverPublicKey,
                 std::vector<uint8_t>& envelope,
                 std::vector<uint8_t>& clientSendKey,
                 std::vector<uint8_t>& clientReceiveKey) noexcept;

    /// Server side. Unwrap the client's envelope with the server's secret
    /// key (DER) and derive the mirrored key pair.
    int respond(const std::vector<uint8_t>& serverSecretKey,
                const std::vector<uint8_t>& envelope,
                std::vector<uint8_t>& serverSendKey,
                std::vector<uint8_t>& serverReceiveKey) noexcept;

private:
    Crypto::MlKem768 kem;    // stateless, thread-safe
    Crypto::Hkdf     hkdf;   // stateless, thread-safe
};

} // namespace NetSecure

#endif // NETSECURE_HANDSHAKE_HPP
