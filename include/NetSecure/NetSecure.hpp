#pragma once

// NetSecure - NetSecure.hpp
// Single-include convenience header: everything the library exposes.
//   #include "NetSecure/NetSecure.hpp"
// brings in the AES-256-GCM codec and the ML-KEM-768 handshake. NetSecure
// is the only library that links both Network and Crypto.

#include "AesGcmCodec.hpp"
#include "Handshake.hpp"
