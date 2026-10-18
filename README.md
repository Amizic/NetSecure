# NetSecure

Post-quantum session security for the `Network` library:
**ML-KEM-768 + HKDF-SHA256 + AES-256-GCM**. NetSecure is the only library
that links both `Network` (transport) and `Crypto` (engines) — `Network`
itself stays crypto-free. One include brings in everything:

```cpp
#include "NetSecure/NetSecure.hpp"   // namespace NetSecure
```

## Design (the short version)

* **`AesGcmCodec`** implements `Network::ICodec`: one AES-256 key per
  direction, a fresh random nonce per message, the Network frame header
  (message id + sequence number) authenticated as AAD. Wire body:
  `[12B nonce][ciphertext][16B tag]`. Any tampering fails authentication
  with `kErrAuth` (-3).
* **`Handshake`** establishes the session keys: the client encapsulates a
  fresh shared secret to the server's ML-KEM-768 public key; both sides
  derive two directional AES-256 keys with HKDF-SHA256. Stateless and
  thread-safe, Crypto conventions (int return codes, `noexcept`).
* Envelope layout: `[4-byte little-endian length][KEM ciphertext]` — sent as
  one plaintext message, it contains no secret.

## Return codes

| Constant | Value | Meaning |
|---|---|---|
| `kOk` | `0` | success |
| `kErrInvalidArgument` | `-1` | bad input (wrong key size, malformed envelope) |
| `kErrOpenSsl` | `-2` | underlying OpenSSL call failed |
| `kErrAuth` | `-3` | tampered data / wrong key |
| `kErrUnavailable` | `-4` | ML-KEM missing in this OpenSSL build |

## API reference

### AesGcmCodec

Constants: `kKeySize = 32`, `kNonceSize = 12`, `kTagSize = 16`,
`kOverhead = 28` (nonce + tag added to every message).

#### `AesGcmCodec::AesGcmCodec(key)`
Copies the AES-256 key into the codec. Create **two** instances per session
(one per direction) from the keys `Handshake` derives.
- **In:** `key` — 32 bytes. A wrong size makes `encode()`/`decode()` fail with `kErrInvalidArgument`.
- **Returns:** nothing (constructor).

#### `AesGcmCodec::encode(plaintext, aad, wireBytes)`
Encrypts one message: random 12-byte nonce + AES-256-GCM. The `aad` (the
Network frame's message id) is authenticated but not encrypted.
- **In:** `plaintext` — the message; `aad` — the frame header (id).
- **Out:** `wireBytes` — `[nonce][ciphertext][tag]`, i.e. plaintext + 28 bytes.
- **Returns:** `kOk` (0), `kErrInvalidArgument` (-1), `kErrOpenSsl` (-2).

#### `AesGcmCodec::decode(wireBytes, aad, plaintext)`
Decrypts and authenticates. Fails with `kErrAuth` (-3) if the body, tag,
nonce or aad was tampered with, or if the key does not match.
- **In:** `wireBytes` — `[nonce][ciphertext][tag]`; `aad` — the frame header (id).
- **Out:** `plaintext` — the original message.
- **Returns:** `kOk` (0), `kErrInvalidArgument` (-1, shorter than 28 bytes), `kErrAuth` (-3).

### Handshake

Constants: `kKeySize = 32` (derived AES-256 keys),
`kMaxEnvelopeSize = 8192` (sanity limit for the envelope).

#### `Handshake::algorithmName()`
- **Returns:** `"ML-KEM-768 + HKDF-SHA256 + AES-256-GCM"` (for logging).

#### `Handshake::initiate(serverPublicKey, envelope, clientSendKey, clientReceiveKey)`
Client side: encapsulates a fresh shared secret to the server's public key
and derives the two session keys. Call this, **send the envelope while the
connection is still plaintext**, then attach the codecs.
- **In:** `serverPublicKey` — the server's DER-encoded ML-KEM-768 public key (from `Crypto::MlKem768::generateKeyPair`).
- **Out:** `envelope` — the bytes to send to the server (contains no secret); `clientSendKey` / `clientReceiveKey` — two 32-byte AES keys.
- **Returns:** `kOk` (0), `kErrInvalidArgument` (-1), `kErrOpenSsl` (-2), `kErrUnavailable` (-4).

#### `Handshake::respond(serverSecretKey, envelope, serverSendKey, serverReceiveKey)`
Server side: unwraps the client's envelope with the secret key and derives
the mirrored key pair (`serverSendKey == clientReceiveKey` and
`serverReceiveKey == clientSendKey`).
- **In:** `serverSecretKey` — the server's DER-encoded secret key; `envelope` — the bytes the client sent.
- **Out:** `serverSendKey` / `serverReceiveKey` — two 32-byte AES keys.
- **Returns:** `kOk` (0), `kErrInvalidArgument` (-1, malformed envelope), `kErrOpenSsl` (-2), `kErrUnavailable` (-4).

## Demo protocol (examples)

| id | direction | content | protection |
|---|---|---|---|
| 0 | server -> client | ML-KEM-768 public key | plaintext |
| 1 | client -> server | KEM envelope | plaintext |
| 3 | client -> server, echoed back | handshake confirmation nonce | AES-256-GCM encrypted |
| 2+ | both ways | application data | AES-256-GCM encrypted |

**Handshake confirmation (why id 3 exists):** ML-KEM's implicit rejection
means the server cannot detect a forged envelope — it would just derive
different keys. So right after attaching the codecs the client sends a
fresh random nonce through the *encrypted* channel and the server echoes it
back. When the client receives its own nonce back, both sides have provably
derived the same keys; a mismatch means an attacker interfered and the
client disconnects loudly.

## Wiring it up

Server side (inside `IServerHandler::onMessage` for id 1):

```cpp
NetSecure::Handshake handshake;
std::vector<uint8_t> sendKey, receiveKey;
if (handshake.respond(serverSecretKey, message.payload, sendKey, receiveKey) == 0) {
    SessionCrypto* crypto = new SessionCrypto(sendKey, receiveKey);   // app-owned
    session.setCodecs(&crypto->sendCodec, &crypto->receiveCodec);
    session.setUserData(crypto);                                      // delete on disconnect
}
```

Client side (inside `IClientHandler::onMessage` for id 0):

```cpp
std::vector<uint8_t> envelope, sendKey, receiveKey;
handshake.initiate(message.payload, envelope, sendKey, receiveKey);
client.sendMessage(1, envelope);            // plaintext FIRST ...
client.setCodecs(new AesGcmCodec(sendKey), new AesGcmCodec(receiveKey)); // ... then encrypt

// ... and confirm the handshake through the encrypted channel:
std::vector<uint8_t> nonce;
Crypto::Aes256 aes; aes.generateKey(nonce);      // 32 fresh random bytes
client.sendMessage(3, nonce);                    // server echoes it back (id 3);
// compare the echo to `nonce` - a match proves both sides share the keys.
```

After that, every message travels AES-256-GCM encrypted without `Network`
knowing anything about it.

## Security notes (be honest about what this is)

* **Confidentiality + integrity** for every message after the handshake:
  AES-256-GCM with a fresh random nonce; a forged envelope or tampered
  message breaks the connection or fails authentication — data cannot be
  read or modified silently.
* **Replay protection** — provided by the Network layer: every frame carries
  a sequence number authenticated as AAD, and replayed frames drop the
  connection with `kErrReplay` (-7). Nothing to configure.
* **Handshake confirmation** — the encrypted nonce echo (id 3) proves both
  sides derived the same keys, which neutralizes the ML-KEM implicit
  rejection issue below: an attacker who swaps the envelope breaks the
  confirmation instead of silently impersonating a side.
* **No forward secrecy** with a static server key (steal the key later,
  decrypt recorded traffic). Mitigation: hybrid X25519 + ML-KEM, or key
  rotation — not implemented.
* **ML-KEM implicit rejection**: `respond()` cannot detect a forged
  envelope — it derives different keys instead (an attacker can break the
  connection, never read it). The handshake confirmation above makes this
  visible: mismatched keys fail the nonce echo.

## Building

Requirements: CMake >= 3.20, C++17 (MinGW-w64 GCC or MSVC), Windows, the
sibling `Network` and `Crypto` projects, OpenSSL >= 3.5 (default: the
in-workspace `tools/openssl-install`).

```bash
cmake -S . -B build-shared -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release \
      -DOPENSSL_ROOT_DIR=D:/DeepSeekHarnesWorkspace/tools/openssl-install
cmake --build build-shared
# or: pwsh -ExecutionPolicy Bypass -File scripts/build.ps1 -Linkage shared -Test
```

Static build — same sources, one switch (`libNetSecure.a`, with Network, Crypto
and OpenSSL linked in statically):

```bash
cmake -S . -B build-static -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_SHARED_LIBS=OFF \
      -DOPENSSL_ROOT_DIR=D:/DeepSeekHarnesWorkspace/tools/openssl-install
cmake --build build-static
# or: pwsh -ExecutionPolicy Bypass -File scripts/build.ps1 -Linkage static -Test
```

Run the demo (two consoles):

```bash
build-shared/bin/secure_echo_server.exe 6001 127.0.0.1
build-shared/bin/secure_echo_client.exe 127.0.0.1 6001
```

Watch the handshake in the console: key exchange travels plaintext, then
every chat message is decrypted AES-256-GCM payload.

## Tests

`ctest --test-dir build-shared --output-on-failure` runs codec round-trip /
tamper / wrong-key / wrong-AAD tests, handshake key-agreement tests, a full
encrypted loopback echo (200 KB message included) and the handshake
confirmation (nonce echo verified on both sides).
