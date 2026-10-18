// NetSecure example - secure_echo_client.cpp
// Console client with a post-quantum handshake:
//   1. connect and receive the server's ML-KEM-768 public key (id 0)
//   2. encapsulate a fresh shared secret, send the envelope (id 1) while
//      the connection is still plaintext
//   3. attach the AES-256-GCM codecs - everything after is encrypted
//   4. send demo messages (id 2), then act as a chat terminal; the server
//      echoes every line back encrypted. Type 'quit' to disconnect.
//
// Usage: secure_echo_client.exe [host] [port]   (defaults: 127.0.0.1, 6001)

#include "Network/Network.hpp"
#include "NetSecure/NetSecure.hpp"
#include "Crypto.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <memory>
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

std::vector<uint8_t> toBytes(const std::string& text) {
    return std::vector<uint8_t>(text.begin(), text.end());
}

// Message ids of the demo protocol.
constexpr uint16_t kMsgPublicKey = 0;
constexpr uint16_t kMsgHandshake = 1;
constexpr uint16_t kMsgChat      = 2;
constexpr uint16_t kMsgConfirm   = 3;   // handshake confirmation: encrypted nonce echo

class SecureClientHandler : public Network::IClientHandler {
public:
    void onConnected() override {
        std::cout << "[" << timestamp() << "] [client] connected - waiting for the server's public key" << std::endl;
    }

    void onMessage(const Network::Message& message) override {
        if (message.id == kMsgPublicKey) {
            std::cout << "[" << timestamp() << "] [client] received public key ("
                      << message.payload.size() << " bytes, plaintext)" << std::endl;

            NetSecure::Handshake handshake;
            std::vector<uint8_t> envelope, sendKey, receiveKey;
            int rc = handshake.initiate(message.payload, envelope, sendKey, receiveKey);
            if (rc != 0) {
                std::cout << "[" << timestamp() << "] [client] handshake failed: " << rc << std::endl;
                client->disconnect();
                return;
            }
            // Send the envelope FIRST (plaintext), then encrypt everything after.
            rc = client->sendMessage(kMsgHandshake, envelope);
            if (rc != 0) {
                std::cout << "[" << timestamp() << "] [client] sending the envelope failed: " << rc << std::endl;
                client->disconnect();
                return;
            }
            sendCodec = std::make_unique<NetSecure::AesGcmCodec>(sendKey);
            receiveCodec = std::make_unique<NetSecure::AesGcmCodec>(receiveKey);
            client->setCodecs(sendCodec.get(), receiveCodec.get());
            handshakeDone = true;
            std::cout << "[" << timestamp() << "] [client] handshake sent ("
                      << handshake.algorithmName() << ") - session is now ENCRYPTED" << std::endl;

            // Handshake confirmation: send a fresh random nonce through the
            // encrypted channel; the server echoes it back. When it comes
            // back identical, both sides provably derived the same keys.
            Crypto::Aes256 aes;
            aes.generateKey(confirmNonce);                       // 32 random bytes
            client->sendMessage(kMsgConfirm, confirmNonce);

            client->sendMessage(kMsgChat, toBytes("Hello from the secure client!"));
            client->sendMessage(kMsgChat, toBytes("Second encrypted message"));
            client->sendMessage(kMsgChat, std::vector<uint8_t>(100000, 'x'));
            std::cout << "[" << timestamp() << "] [client] sent 3 encrypted demo messages" << std::endl;
            return;
        }
        if (message.id == kMsgConfirm) {
            if (message.payload == confirmNonce) {
                confirmed = true;
                std::cout << "[" << timestamp() << "] [client] handshake CONFIRMED - keys match on both sides" << std::endl;
            } else {
                std::cout << "[" << timestamp() << "] [client] handshake FAILED - nonce mismatch, disconnecting" << std::endl;
                client->disconnect();
            }
            return;
        }
        if (message.id == kMsgChat) {
            std::cout << "[" << timestamp() << "] [client] decrypted echo: "
                      << message.payload.size() << " bytes";
            if (!message.payload.empty() && message.payload.size() <= 64) {
                std::cout << ", text=\"" << std::string(message.payload.begin(), message.payload.end()) << "\"";
            }
            std::cout << std::endl;
            ++receivedCount;
        }
    }

    void onDisconnected(int reason) override {
        std::cout << "[" << timestamp() << "] [client] disconnected, reason=" << reason << std::endl;
    }

    Network::Client* client = nullptr;
    std::atomic<int> receivedCount{0};
    bool handshakeDone = false;
    std::atomic<bool> confirmed{false};
    std::vector<uint8_t> confirmNonce;   // written on the I/O thread before any other use
    std::unique_ptr<NetSecure::AesGcmCodec> sendCodec;
    std::unique_ptr<NetSecure::AesGcmCodec> receiveCodec;
};

} // namespace

int main(int argc, char* argv[]) {
    std::string host = "127.0.0.1";
    uint16_t port = 6001;
    if (argc > 1) {
        host = argv[1];
    }
    if (argc > 2) {
        port = static_cast<uint16_t>(std::atoi(argv[2]));
    }

    std::cout << "[" << timestamp() << "] [client] connecting to " << host << ":" << port << std::endl;

    Network::Client client;
    SecureClientHandler handler;
    handler.client = &client;
    client.setHandler(&handler);

    int rc = client.connect(host, port);
    if (rc != 0) {
        std::cout << "[" << timestamp() << "] [client] connect failed: " << rc << std::endl;
        return 1;
    }

    const bool stdinClosed = std::cin.peek() == EOF;
    if (!stdinClosed) {
        std::cout << "[" << timestamp() << "] [client] type a line to send it encrypted, 'quit' to leave" << std::endl;
    } else {
        std::cout << "[" << timestamp() << "] [client] no console input - leaving after the echoes arrive" << std::endl;
    }

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    std::string line;
    while (client.isConnected()) {
        if (!stdinClosed && std::cin.peek() != EOF) {
            if (!std::getline(std::cin, line)) {
                break;
            }
            if (line == "quit" || line == "exit") {
                break;
            }
            if (handler.handshakeDone && client.sendMessage(kMsgChat, toBytes(line)) != 0) {
                break;
            }
        }
        if (stdinClosed &&
            (handler.receivedCount.load() >= 3 || std::chrono::steady_clock::now() >= deadline)) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1500));
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    client.disconnect();
    std::cout << "[" << timestamp() << "] [client] bye." << std::endl;
    return 0;
}
