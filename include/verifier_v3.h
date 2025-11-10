#ifndef HASHCHAIN_VERIFIER_V3_H_
#define HASHCHAIN_VERIFIER_V3_H_

#include <array>
#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "config.h"

namespace hashchain {

using Nonce = std::array<uint8_t, Config::nonceSize>;

// Verifier for Implementation 3: In-Memory with Dynamic Nonce Size
class VerifierV3 {
 public:
  explicit VerifierV3(const std::string& bucketDir);
  ~VerifierV3();

  // Display functions
  void displayFirstEntries(size_t count);
  void displayFirstFromEachBucket(size_t maxBuckets);

  // Search for matches with given difficulty
  size_t findMatches(const std::array<uint8_t, Config::hashSize>& targetHash, size_t difficulty,
                     size_t maxMatches);

  // Get the effective nonce size from metadata
  size_t getEffectiveNonceSize() const { return effectiveNonceSize_; }

 private:
  struct BucketMetadata {
    uint64_t entryCount = 0;
    uint64_t fileOffset = 0;
  };

  // Load metadata file
  bool loadMetadata();

  // Read bucket from data file (returns partial nonces of effectiveNonceSize_)
  std::vector<Nonce> readBucket(size_t bucketId);

  // Compute full hash from nonce
  std::array<uint8_t, Config::hashSize> computeFullHash(const Nonce& nonce);

  // Check if two hashes match up to given difficulty
  bool hashesMatchDifficulty(const std::array<uint8_t, Config::hashSize>& hash1,
                             const std::array<uint8_t, Config::hashSize>& hash2,
                             size_t difficulty) const;

  // Get bucket ID from hash
  size_t getBucketIdFromHash(const std::array<uint8_t, Config::hashSize>& hash) const;

  // Utility functions
  std::string nonceToHex(const Nonce& nonce) const;
  std::string hashToHex(const std::array<uint8_t, Config::hashSize>& hash) const;

  std::string bucketDir_;
  std::string dataFilePath_;
  std::string metadataFilePath_;

  size_t effectiveNonceSize_;  // Actual nonce size stored (may be < Config::nonceSize)
  std::vector<BucketMetadata> metadata_;
};

}  // namespace hashchain

#endif  // HASHCHAIN_VERIFIER_V3_H_
