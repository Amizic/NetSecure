// NetSecure - test_netsecure.cpp
// Codec + handshake unit tests, then a full loopback encrypted echo:
// server sends its ML-KEM-768 public key (id 0), client handshakes (id 1),
// then chat messages (id 2) travel AES-256-GCM encrypted both ways.

#include "Network/Network.hpp"
#include "NetSecure/NetSecure.hpp"
#include "Crypto.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

int gFailures = 0;

void check(bool condition, const std::string& what) {
    if (condition) {
        std::cout << "  [PASS] " << what << std::endl;
    } else {
        std::cout << "  [FAIL] " << what << std::endl;
        ++gFailures;
    }
}

std::vector<uint8_t> bytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

std::vector<uint8_t> fillerKey(uint8_t seed) {
    return std::vector<uint8_t>(32, seed);
}

// Message ids of the demo protocol.
constexpr uint16_t kMsgPublicKey = 0;
constexpr uint16_t kMsgHandshake = 1;
constexpr uint16_t kMsgChat      = 2;
constexpr uint16_t kMsgConfirm   = 3;

// ---- codec unit tests -----------------------------------------------------

void testCodec() {
    std::cout << "AesGcmCodec tests" << std::endl;
    const std::vector<uint8_t> key = fillerKey(0x11);
    const std::vector<uint8_t> aad{0x02, 0x00};   // message id 2, little-endian
    const std::vector<uint8_t> plaintext = bytes("attack at dawn");
    NetSecure::AesGcmCodec codec(key);

    std::vector<uint8_t> wire;
    check(codec.encode(plaintext, aad, wire) == 0, "encode succeeds");
    check(wire.size() == plaintext.size() + NetSecure::AesGcmCodec::kOverhead,
          "wire size = plaintext + 28 (nonce + tag)");

    std::vector<uint8_t> decoded;
    check(codec.decode(wire, aad, decoded) == 0 && decoded == plaintext, "decode round-trips");

    std::vector<uint8_t> tampered = wire;
    tampered[12] ^= 0x01;                            // flip a ciphertext byte
    std::vector<uint8_t> out;
    check(codec.decode(tampered, aad, out) == NetSecure::AesGcmCodec::kErrAuth,
          "tampered ciphertext rejected with kErrAuth (-3)");

    NetSecure::AesGcmCodec wrongKeyCodec(fillerKey(0x22));
    check(wrongKeyCodec.decode(wire, aad, out) == NetSecure::AesGcmCodec::kErrAuth,
          "wrong key rejected with kErrAuth (-3)");

    const std::vector<uint8_t> wrongAad{0x03, 0x00};
    check(codec.decode(wire, wrongAad, out) == NetSecure::AesGcmCodec::kErrAuth,
          "wrong aad (message id) rejected with kErrAuth (-3)");

    std::vector<uint8_t> tooShort(10, 0);
    check(codec.decode(tooShort, aad, out) == NetSecure::AesGcmCodec::kErrInvalidArgument,
          "truncated wire rejected with kErrInvalidArgument (-1)");
}

// ---- handshake unit tests --------------------------------------------------

void testHandshake() {
    std::cout << "Handshake tests" << std::endl;
    Crypto::MlKem768 kem;
    std::vector<uint8_t> publicKey, secretKey;
    check(kem.generateKeyPair(publicKey, secretKey) == 0, "ML-KEM-768 keypair generated");

    NetSecure::Handshake handshake;
    std::vector<uint8_t> envelope, clientSend, clientRecv, serverSend, serverRecv;
    check(handshake.initiate(publicKey, envelope, clientSend, clientRecv) == 0, "client initiate");
    check(handshake.respond(secretKey, envelope, serverSend, serverRecv) == 0, "server respond");
    check(clientSend.size() == NetSecure::Handshake::kKeySize &&
          clientRecv.size() == NetSecure::Handshake::kKeySize, "derived keys are 32 bytes");
    check(clientSend == serverRecv && clientRecv == serverSend,
          "clientSend == serverReceive and clientReceive == serverSend");
    check(std::string(handshake.algorithmName()).find("ML-KEM-768") != std::string::npos,
          "algorithmName identifies ML-KEM-768");

    // Forged envelope: ML-KEM implicit rejection means respond() may succeed
    // with a different shared secret - but it must NEVER produce the same
    // keys as the client's.
    std::vector<uint8_t> forged = envelope;
    forged[4] ^= 0x01;
    std::vector<uint8_t> forgedSend, forgedRecv;
    int rc = handshake.respond(secretKey, forged, forgedSend, forgedRecv);
    check(rc != 0 || forgedSend != clientRecv || forgedRecv != clientSend,
          "tampered envelope never yields the client's keys");

    std::vector<uint8_t> garbage;
    check(handshake.respond(secretKey, bytes("short"), garbage, garbage) ==
              NetSecure::Handshake::kErrInvalidArgument,
          "malformed envelope rejected with kErrInvalidArgument (-1)");
}

// ---- end-to-end encrypted echo ---------------------------------------------

struct SessionCrypto {
    NetSecure::AesGcmCodec sendCodec;
    NetSecure::AesGcmCodec receiveCodec;
    SessionCrypto(const std::vector<uint8_t>& sendKey, const std::vector<uint8_t>& receiveKey)
        : sendCodec(sendKey), receiveCodec(receiveKey) {}
};

class SecureServerHandler : public Network::IServerHandler {
public:
    SecureServerHandler(std::vector<uint8_t> publicKey, std::vector<uint8_t> secretKey)
        : publicKey(std::move(publicKey)), secretKey(std::move(secretKey)) {}

    void onClientConnected(Network::Session& session) override {
        session.sendMessage(kMsgPublicKey, publicKey);
        ++connected;
    }

    void onMessage(Network::Session& session, const Network::Message& message) override {
        if (message.id == kMsgHandshake) {
            NetSecure::Handshake handshake;
            std::vector<uint8_t> sendKey, receiveKey;
            int rc = handshake.respond(secretKey, message.payload, sendKey, receiveKey);
            if (rc != 0) {
                session.close();
                return;
            }
            SessionCrypto* crypto = new SessionCrypto(sendKey, receiveKey);
            session.setCodecs(&crypto->sendCodec, &crypto->receiveCodec);
            session.setUserData(crypto);
            ++handshakes;
            return;
        }
        if (message.id == kMsgConfirm) {
            session.sendMessage(kMsgConfirm, message.payload);   // encrypted nonce echo
            ++confirms;
            return;
        }
        if (message.id == kMsgChat) {
            session.sendMessage(kMsgChat, message.payload);
            ++echoes;
        }
    }

    void onClientDisconnected(Network::Session& session, int reason) override {
        delete static_cast<SessionCrypto*>(session.userData());
        ++disconnected;
        if (reason > 0) {
            ++badReasons;
        }
    }

    std::atomic<int> connected{0};
    std::atomic<int> handshakes{0};
    std::atomic<int> confirms{0};
    std::atomic<int> echoes{0};
    std::atomic<int> disconnected{0};
    std::atomic<int> badReasons{0};

private:
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
};

class SecureClientHandler : public Network::IClientHandler {
public:
    void onMessage(const Network::Message& message) override {
        if (message.id == kMsgPublicKey) {
            NetSecure::Handshake handshake;
            std::vector<uint8_t> envelope, sendKey, receiveKey;
            int rc = handshake.initiate(message.payload, envelope, sendKey, receiveKey);
            if (rc != 0) {
                client->disconnect();
                return;
            }
            if (client->sendMessage(kMsgHandshake, envelope) != 0) {
                client->disconnect();
                return;
            }
            sendCodec = std::make_unique<NetSecure::AesGcmCodec>(sendKey);
            receiveCodec = std::make_unique<NetSecure::AesGcmCodec>(receiveKey);
            client->setCodecs(sendCodec.get(), receiveCodec.get());
            secured = true;

            // Handshake confirmation: encrypted nonce echo.
            Crypto::Aes256 aes;
            if (aes.generateKey(confirmNonce) == 0) {
                client->sendMessage(kMsgConfirm, confirmNonce);
            }
            return;
        }
        if (message.id == kMsgConfirm) {
            confirmed = message.payload == confirmNonce && !confirmNonce.empty();
            return;
        }
        if (message.id == kMsgChat) {
            std::lock_guard<std::mutex> guard(mutex);
            received.push_back(message);
            condition.notify_all();
        }
    }
    bool waitFor(std::size_t count, int timeoutMs = 15000) {
        std::unique_lock<std::mutex> lock(mutex);
        return condition.wait_for(lock, std::chrono::milliseconds(timeoutMs),
                                  [&] { return received.size() >= count; });
    }
    Network::Client* client = nullptr;
    std::atomic<bool> secured{false};
    std::atomic<bool> confirmed{false};
    std::vector<Network::Message> received;
    std::mutex mutex;
    std::condition_variable condition;
    std::vector<uint8_t> confirmNonce;   // written on the I/O thread before any other use
    std::unique_ptr<NetSecure::AesGcmCodec> sendCodec;
    std::unique_ptr<NetSecure::AesGcmCodec> receiveCodec;
};

void testEndToEnd() {
    std::cout << "End-to-end encrypted echo" << std::endl;

    Crypto::MlKem768 kem;
    std::vector<uint8_t> publicKey, secretKey;
    if (kem.generateKeyPair(publicKey, secretKey) != 0) {
        check(false, "server keypair generated");
        return;
    }

    Network::Server server;
    SecureServerHandler serverHandler(publicKey, secretKey);
    server.setHandler(&serverHandler);
    if (server.start("127.0.0.1", 0) != 0) {
        check(false, "server start");
        return;
    }

    Network::Client client;
    SecureClientHandler clientHandler;
    clientHandler.client = &client;
    client.setHandler(&clientHandler);
    check(client.connect("127.0.0.1", server.boundPort()) == 0, "client connected");

    // Wait for the handshake to finish on the client side.
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!clientHandler.secured.load() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    check(clientHandler.secured.load(), "client completed the handshake and attached codecs");

    const auto confirmDeadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!clientHandler.confirmed.load() && std::chrono::steady_clock::now() < confirmDeadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    check(clientHandler.confirmed.load(), "client confirmed the handshake (nonce echoed)");
    check(serverHandler.confirms.load() == 1, "server echoed the confirm nonce");

    const std::vector<uint8_t> small = bytes("encrypted hello");
    check(client.sendMessage(kMsgChat, small) == 0, "small encrypted message sent");
    const std::vector<uint8_t> big(200000, 0xC7);
    check(client.sendMessage(kMsgChat, big) == 0, "200 KB encrypted message sent");

    check(clientHandler.waitFor(2), "two encrypted echoes received");
    if (clientHandler.received.size() >= 2) {
        check(clientHandler.received[0].id == kMsgChat && clientHandler.received[0].payload == small,
              "small echo matches after decryption");
        check(clientHandler.received[1].id == kMsgChat && clientHandler.received[1].payload == big,
              "200 KB echo matches after decryption");
    }

    const auto deadline2 = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (serverHandler.handshakes.load() < 1 && std::chrono::steady_clock::now() < deadline2) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    check(serverHandler.handshakes.load() == 1, "server completed the handshake");
    check(serverHandler.echoes.load() >= 2, "server echoed the encrypted messages");

    client.disconnect();
    const auto deadline3 = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (serverHandler.disconnected.load() < 1 && std::chrono::steady_clock::now() < deadline3) {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    check(serverHandler.disconnected.load() == 1, "server saw the disconnect");
    check(serverHandler.badReasons.load() == 0, "disconnect reason <= 0");

    server.stop();
}

} // namespace

int main() {
    std::cout << "NetSecure tests" << std::endl;
    testCodec();
    testHandshake();
    testEndToEnd();
    std::cout << (gFailures == 0 ? "ALL TESTS PASSED" : "FAILURES: " + std::to_string(gFailures)) << std::endl;
    return gFailures == 0 ? 0 : 1;
}
