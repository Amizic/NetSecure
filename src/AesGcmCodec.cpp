// NetSecure - AesGcmCodec.cpp
// AES-256-GCM per-message codec. Wire layout: [12-byte nonce][ciphertext]
// [16-byte tag]; the Network frame header is authenticated as AAD.

#include "NetSecure/AesGcmCodec.hpp"

#include <array>
#include <cstring>

namespace NetSecure {

AesGcmCodec::AesGcmCodec(const std::vector<uint8_t>& key) : key(key) {}

int AesGcmCodec::encode(const std::vector<uint8_t>& plaintext,
                        const std::vector<uint8_t>& aad,
                        std::vector<uint8_t>& wireBytes) noexcept {
    if (key.size() != kKeySize) {
        return kErrInvalidArgument;
    }
    std::vector<uint8_t> nonce;
    int rc = engine.generateIv(nonce);
    if (rc != Crypto::Aes256::kOk) {
        return rc;
    }
    std::vector<uint8_t> ciphertext;
    std::array<uint8_t, kTagSize> tag{};
    rc = engine.encrypt(plaintext, key, nonce, aad, ciphertext, tag);
    if (rc != Crypto::Aes256::kOk) {
        return rc;
    }

    wireBytes.resize(kNonceSize + ciphertext.size() + kTagSize);
    std::memcpy(wireBytes.data(), nonce.data(), kNonceSize);
    if (!ciphertext.empty()) {
        std::memcpy(wireBytes.data() + kNonceSize, ciphertext.data(), ciphertext.size());
    }
    std::memcpy(wireBytes.data() + kNonceSize + ciphertext.size(), tag.data(), kTagSize);
    return kOk;
}

int AesGcmCodec::decode(const std::vector<uint8_t>& wireBytes,
                        const std::vector<uint8_t>& aad,
                        std::vector<uint8_t>& plaintext) noexcept {
    if (key.size() != kKeySize) {
        return kErrInvalidArgument;
    }
    if (wireBytes.size() < kOverhead) {
        return kErrInvalidArgument;
    }
    const std::vector<uint8_t> nonce(wireBytes.begin(), wireBytes.begin() + kNonceSize);
    const std::vector<uint8_t> tag(wireBytes.end() - kTagSize, wireBytes.end());
    const std::vector<uint8_t> ciphertext(wireBytes.begin() + kNonceSize,
                                          wireBytes.end() - kTagSize);
    return engine.decrypt(ciphertext, key, nonce, aad, tag, plaintext);
}

} // namespace NetSecure
