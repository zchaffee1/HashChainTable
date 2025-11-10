#ifndef HASHCHAINTABLE_VERIFIER_V2_H_
#define HASHCHAINTABLE_VERIFIER_V2_H_

#include <fstream>
#include <string>
#include <vector>

#include "config.h"
#include "types.h"

namespace hashchain {

// Verifier for Implementation 2 (single-file with offsets)
class VerifierV2 {
 public:
  explicit VerifierV2(const std::string& bucketDir);
  ~VerifierV2();

  // Display first N entries from the entire table
  void displayFirstEntries(size_t count);

  // Display first entry from each bucket
  void displayFirstFromEachBucket(size_t maxBuckets = 100);

  // Find matches for a target hash with specified difficulty
  size_t findMatches(const std::array<uint8_t, Config::hashSize>& targetHash, size_t difficulty,
                     size_t maxMatches = 10);

  // Compute full hash for a nonce (for verification)
  std::array<uint8_t, Config::hashSize> computeFullHash(const Nonce& nonce);

 private:
  struct BucketMetadata {
    uint16_t entryCount = 0;
    uint64_t fileOffset = 0;
  };

  std::string bucketDir_;
  std::string dataFilePath_;
  std::string metadataFilePath_;
  std::vector<BucketMetadata> metadata_;

  // Load metadata
  bool loadMetadata();

  // Read nonces from a specific bucket
  std::vector<Nonce> readBucket(size_t bucketId);

  // Helper functions
  std::string nonceToHex(const Nonce& nonce) const;
  std::string hashToHex(const std::array<uint8_t, Config::hashSize>& hash) const;
  bool hashesMatchDifficulty(const std::array<uint8_t, Config::hashSize>& hash1,
                             const std::array<uint8_t, Config::hashSize>& hash2,
                             size_t difficulty) const;
  size_t getBucketIdFromHash(const std::array<uint8_t, Config::hashSize>& hash) const;
};

}  // namespace hashchain

#endif  // HASHCHAINTABLE_VERIFIER_V2_H_
