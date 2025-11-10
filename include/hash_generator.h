#ifndef HASHCHAINTABLE_HASH_GENERATOR_H_
#define HASHCHAINTABLE_HASH_GENERATOR_H_

#include <vector>

#include "blake3.h"
#include "config.h"
#include "types.h"

namespace hashchain {

// Hash generator class for computing BLAKE3 hash prefixes
class HashGenerator {
 public:
  HashGenerator();
  ~HashGenerator();

  // Compute hash prefix for a nonce (only first bucketPrefixSize bytes)
  // This is optimized to only compute what we need for bucketing
  HashPrefix computeHashPrefix(const Nonce& nonce);

  // Batch process nonces and fill buffer with entries
  // Returns number of entries processed
  size_t processNonceBatch(uint64_t startCounter, size_t count,
                           std::vector<BufferEntry>& buffer);

 private:
  blake3_hasher hasher_;
};

}  // namespace hashchain

#endif  // HASHCHAINTABLE_HASH_GENERATOR_H_
