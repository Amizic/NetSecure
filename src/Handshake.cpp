// NetSecure - Handshake.cpp
// Post-quantum session key establishment: ML-KEM-768 + HKDF-SHA256.
// Envelope: [4-byte little-endian KEM ciphertext length][ciphertext].

#include "NetSecure/Handshake.hpp"

#include <cstring>
#include <string>
#include <vector>

namespace NetSecure {
namespace {

// Directional HKDF labels; the server mirrors the client's derivation, so
// clientSendKey == serverReceiveKey and vice versa.
constexpr char kInfoClientToServer[] = "netsecure v1 client->server";
constexpr char kInfoServerToClient[] = "netsecure v1 server->client";

std::vector<uint8_t> infoBytes(const char* text) {
    return std::vector<uint8_t>(text, text + std::strlen(text));
}

} // namespace

const char* Handshake::algorithmName() const noexcept {
    return "ML-KEM-768 + HKDF-SHA256 + AES-256-GCM";
}

int Handshake::initiate(const std::vector<uint8_t>& serverPublicKey,
                        std::vector<uint8_t>& envelope,
                        std::vector<uint8_t>& clientSendKey,
                        std::vector<uint8_t>& clientReceiveKey) noexcept {
    std::vector<uint8_t> kemCiphertext;
    std::vector<uint8_t> sharedSecret;
    int rc = kem.encapsulate(serverPublicKey, kemCiphertext, sharedSecret);
    if (rc != Crypto::MlKem768::kOk) {
        return rc;
    }

    const uint32_t length = static_cast<uint32_t>(kemCiphertext.size());
    envelope.resize(sizeof(length) + kemCiphertext.size());
    std::memcpy(envelope.data(), &length, sizeof(length));
    std::memcpy(envelope.data() + sizeof(length), kemCiphertext.data(), kemCiphertext.size());

    rc = hkdf.derive(sharedSecret, {}, infoBytes(kInfoClientToServer), kKeySize, clientSendKey);
    if (rc != Crypto::Hkdf::kOk) {
        return rc;
    }
    return hkdf.derive(sharedSecret, {}, infoBytes(kInfoServerToClient), kKeySize, clientReceiveKey);
}

int Handshake::respond(const std::vector<uint8_t>& serverSecretKey,
                       const std::vector<uint8_t>& envelope,
                       std::vector<uint8_t>& serverSendKey,
                       std::vector<uint8_t>& serverReceiveKey) noexcept {
    if (envelope.size() < sizeof(uint32_t)) {
        return kErrInvalidArgument;
    }
    uint32_t length = 0;
    std::memcpy(&length, envelope.data(), sizeof(length));
    if (length == 0 || length > kMaxEnvelopeSize) {
        return kErrInvalidArgument;
    }
    if (envelope.size() < sizeof(length) + length) {
        return kErrInvalidArgument;
    }

    const std::vector<uint8_t> kemCiphertext(envelope.begin() + sizeof(length),
                                             envelope.begin() + sizeof(length) + length);
    std::vector<uint8_t> sharedSecret;
    int rc = kem.decapsulate(kemCiphertext, serverSecretKey, sharedSecret);
    if (rc != Crypto::MlKem768::kOk) {
        return rc;
    }

    // Mirror the client's derivation (the labels are directional).
    rc = hkdf.derive(sharedSecret, {}, infoBytes(kInfoServerToClient), kKeySize, serverSendKey);
    if (rc != Crypto::Hkdf::kOk) {
        return rc;
    }
    return hkdf.derive(sharedSecret, {}, infoBytes(kInfoClientToServer), kKeySize, serverReceiveKey);
}

} // namespace NetSecure
