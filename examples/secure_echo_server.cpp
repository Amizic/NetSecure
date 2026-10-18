// NetSecure example - secure_echo_server.cpp
// Console server with a post-quantum handshake. On connect the server sends
// its ML-KEM-768 public key (id 0, plaintext). The client answers with an
// encapsulated shared secret (id 1, plaintext - it contains no secret).
// Both sides derive AES-256 keys and from then on every message (id 2) is
// AES-256-GCM encrypted. Watch the console: plaintext before the handshake,
// encrypted after.
//
// Usage: secure_echo_server.exe [port] [bindAddress]   (defaults: 6001, 127.0.0.1)

#include "Network/Network.hpp"
#include "NetSecure/NetSecure.hpp"
#include "Crypto.hpp"

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

std::string timestamp() {
    std::time_t t = std::time(nullptr);
    std::tm tm{};
    localtime_s(&tm, &t);
    char buffer[16] = {0};
    std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &tm);
    return buffer;
}

// Message ids of the demo protocol.
constexpr uint16_t kMsgPublicKey = 0;   // server -> client: ML-KEM public key (plaintext)
constexpr uint16_t kMsgHandshake = 1;   // client -> server: KEM envelope (plaintext)
constexpr uint16_t kMsgChat      = 2;   // chat / demo text (AES-256-GCM encrypted)
constexpr uint16_t kMsgConfirm   = 3;   // handshake confirmation: encrypted nonce echo

// Per-session crypto state, owned by the application through Session::userData.
struct SessionCrypto {
    NetSecure::AesGcmCodec sendCodec;
    NetSecure::AesGcmCodec receiveCodec;
    SessionCrypto(const std::vector<uint8_t>& sendKey, const std::vector<uint8_t>& receiveKey)
        : sendCodec(sendKey), receiveCodec(receiveKey) {}
};

class SecureEchoHandler : public Network::IServerHandler {
public:
    SecureEchoHandler(std::vector<uint8_t> publicKey, std::vector<uint8_t> secretKey)
        : publicKey(std::move(publicKey)), secretKey(std::move(secretKey)) {}

    void onClientConnected(Network::Session& session) override {
        std::cout << "[" << timestamp() << "] [server] client connected: #" << session.id()
                  << " from " << session.remoteAddress() << std::endl;
        std::cout << "[" << timestamp() << "] [server] sending public key ("
                  << publicKey.size() << " bytes, plaintext) to #" << session.id() << std::endl;
        session.sendMessage(kMsgPublicKey, publicKey);
    }

    void onMessage(Network::Session& session, const Network::Message& message) override {
        if (message.id == kMsgHandshake) {
            NetSecure::Handshake handshake;
            std::vector<uint8_t> sendKey, receiveKey;
            int rc = handshake.respond(secretKey, message.payload, sendKey, receiveKey);
            if (rc != 0) {
                std::cout << "[" << timestamp() << "] [server] handshake FAILED for #"
                          << session.id() << ": " << rc << std::endl;
                session.close();
                return;
            }
            SessionCrypto* crypto = new SessionCrypto(sendKey, receiveKey);
            session.setCodecs(&crypto->sendCodec, &crypto->receiveCodec);
            session.setUserData(crypto);
            std::cout << "[" << timestamp() << "] [server] handshake complete ("
                      << handshake.algorithmName() << "): session #" << session.id()
                      << " is now ENCRYPTED" << std::endl;
            return;
        }
        if (message.id == kMsgConfirm) {
            // Handshake confirmation: echo the client's nonce back through
            // the encrypted channel. If it decrypts here, our keys match.
            session.sendMessage(kMsgConfirm, message.payload);
            std::cout << "[" << timestamp() << "] [server] handshake CONFIRMED for #"
                      << session.id() << " (encrypted nonce echoed)" << std::endl;
            return;
        }
        if (message.id == kMsgChat) {
            std::cout << "[" << timestamp() << "] [server] decrypted #" << session.id()
                      << ": " << message.payload.size() << " bytes";
            if (!message.payload.empty() && message.payload.size() <= 64) {
                std::cout << ", text=\"" << std::string(message.payload.begin(), message.payload.end()) << "\"";
            }
            std::cout << std::endl;
            int rc = session.sendMessage(kMsgChat, message.payload);
            if (rc != 0) {
                std::cout << "[" << timestamp() << "] [server] echo failed: " << rc << std::endl;
            }
        }
    }

    void onClientDisconnected(Network::Session& session, int reason) override {
        std::cout << "[" << timestamp() << "] [server] client disconnected: #" << session.id()
                  << ", reason=" << reason << std::endl;
        delete static_cast<SessionCrypto*>(session.userData());
    }

private:
    std::vector<uint8_t> publicKey;
    std::vector<uint8_t> secretKey;
};

} // namespace

int main(int argc, char* argv[]) {
    uint16_t port = 6001;
    std::string bindAddress = "127.0.0.1";
    if (argc > 1) {
        port = static_cast<uint16_t>(std::atoi(argv[1]));
    }
    if (argc > 2) {
        bindAddress = argv[2];
    }

    Crypto::MlKem768 kem;
    std::vector<uint8_t> publicKey, secretKey;
    int rc = kem.generateKeyPair(publicKey, secretKey);
    if (rc != 0) {
        std::cout << "[" << timestamp() << "] [server] key generation failed: " << rc << std::endl;
        return 1;
    }
    std::cout << "[" << timestamp() << "] [server] " << kem.algorithmName()
              << " keypair generated (public: " << publicKey.size()
              << " bytes, secret: " << secretKey.size() << " bytes)" << std::endl;

    std::cout << "[" << timestamp() << "] [server] Secure echo server - starting on "
              << bindAddress << ":" << port << std::endl;

    Network::Server server;
    SecureEchoHandler handler(publicKey, secretKey);
    server.setHandler(&handler);

    rc = server.start(bindAddress, port);
    if (rc != 0) {
        std::cout << "[" << timestamp() << "] [server] start failed: " << rc << std::endl;
        return 1;
    }
    std::cout << "[" << timestamp() << "] [server] running on " << bindAddress << ":"
              << server.boundPort() << " - type 'quit' to stop" << std::endl;

    std::string line;
    while (server.isRunning()) {
        if (std::cin.peek() != EOF) {
            if (!std::getline(std::cin, line)) {
                break;
            }
            if (line == "quit" || line == "exit") {
                break;
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    std::cout << "[" << timestamp() << "] [server] stopping..." << std::endl;
    server.stop();
    std::cout << "[" << timestamp() << "] [server] stopped." << std::endl;
    return 0;
}
