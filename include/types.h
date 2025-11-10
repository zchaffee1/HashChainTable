#ifndef HASHCHAINTABLE_TYPES_H_
#define HASHCHAINTABLE_TYPES_H_

#include <array>
#include <cstdint>
#include <cstring>

#include "config.h"

namespace hashchain {

// Fixed-size nonce type
using Nonce = std::array<uint8_t, Config::nonceSize>;

// Hash prefix type for bucketing (first N bytes of hash)
using HashPrefix = std::array<uint8_t, Config::bucketPrefixSize>;

// Bucket ID type (uint32_t can handle up to 4 bytes of prefix)
using BucketId = uint32_t;

// Convert hash prefix to bucket ID
inline BucketId hashPrefixToBucketId(const HashPrefix& prefix) {
  BucketId id = 0;
  for (size_t i = 0; i < Config::bucketPrefixSize; ++i) {
    id = (id << 8) | prefix[i];
  }
  return id;
}

// Convert nonce counter to nonce bytes
inline Nonce counterToNonce(uint64_t counter) {
  Nonce nonce;
  for (size_t i = 0; i < Config::nonceSize; ++i) {
    nonce[Config::nonceSize - 1 - i] = static_cast<uint8_t>(counter & 0xFF);
    counter >>= 8;
  }
  return nonce;
}

// Entry for worker buffer (nonce + bucket ID)
struct BufferEntry {
  Nonce nonce;
  BucketId bucketId;

  // Comparison operator for sorting
  bool operator<(const BufferEntry& other) const { return bucketId < other.bucketId; }
};

// Bucket statistics
struct BucketStats {
  uint64_t entriesWritten = 0;
  uint64_t overflowEntries = 0;
  bool isFull = false;
};

}  // namespace hashchain

#endif  // HASHCHAINTABLE_TYPES_H_
