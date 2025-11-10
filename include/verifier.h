#ifndef HASHCHAINTABLE_VERIFIER_H_
#define HASHCHAINTABLE_VERIFIER_H_

#include <string>
#include <vector>

#include "config.h"
#include "types.h"

namespace hashchain {

// Structure to hold a nonce-hash pair for display
struct NonceHashPair {
  Nonce nonce;
  std::array<uint8_t, Config::hashSize> fullHash;
};

// Verifier class for reading and searching hash chain tables
class Verifier {
 public:
  explicit Verifier(const std::string& bucketDir);
  ~Verifier();

  // Display first N entries from the entire table
  // Reads entries sequentially from buckets
  void displayFirstEntries(size_t count);

  // Display first entry from each bucket
  // Shows distribution across buckets
  void displayFirstFromEachBucket(size_t maxBuckets = 100);

  // Find matches for a target hash with specified difficulty
  // Difficulty is the number of most significant bits that must match
  // Returns the number of matches found
  size_t findMatches(const std::array<uint8_t, Config::hashSize>& targetHash,
                     size_t difficulty,
                     size_t maxMatches = 10);

  // Compute full hash for a nonce (for verification)
  std::array<uint8_t, Config::hashSize> computeFullHash(const Nonce& nonce);

 private:
  std::string bucketDir_;

  // Helper to read nonces from a bucket file
  std::vector<Nonce> readBucket(size_t bucketId);

  // Helper to format nonce as hex string
  std::string nonceToHex(const Nonce& nonce) const;

  // Helper to format hash as hex string
  std::string hashToHex(const std::array<uint8_t, Config::hashSize>& hash) const;

  // Helper to check if two hashes match for N most significant bits
  bool hashesMatchDifficulty(const std::array<uint8_t, Config::hashSize>& hash1,
                             const std::array<uint8_t, Config::hashSize>& hash2,
                             size_t difficulty) const;

  // Get bucket ID from target hash
  size_t getBucketIdFromHash(const std::array<uint8_t, Config::hashSize>& hash) const;
};

}  // namespace hashchain

#endif  // HASHCHAINTABLE_VERIFIER_H_
