#ifndef HASHCHAIN_RAINBOW_VERIFIER_H_
#define HASHCHAIN_RAINBOW_VERIFIER_H_

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "config.h"
#include "rainbow_table_generator.h"

namespace hashchain {

// Rainbow table verifier for hash lookup
class RainbowVerifier {
 public:
  explicit RainbowVerifier(const std::string& rainbowDir);
  ~RainbowVerifier();

  // Load all rainbow tables from directory
  bool loadTables();

  // Search for a hash in the rainbow tables
  // Returns true if found, fills in the nonce
  bool findHash(const std::array<uint8_t, Config::hashSize>& targetHash, Nonce& foundNonce);

  // Display table statistics
  void displayStatistics() const;

  // Display some sample chains
  void displaySampleChains(size_t count) const;

  // Compute hash of nonce (public for testing)
  std::array<uint8_t, Config::hashSize> computeHash(const Nonce& nonce) const;

 private:
  struct TableMetadata {
    size_t tableId;
    size_t numChains;
    size_t chainLength;
  };

  // Load a single table file
  bool loadTable(size_t tableId, const std::string& filename);

  // Reduction function (must match generator)
  Nonce reduce(const std::array<uint8_t, Config::hashSize>& hash, size_t tableId,
               size_t position) const;

  // Search for target in a specific table
  bool searchTable(size_t tableId, const std::array<uint8_t, Config::hashSize>& targetHash,
                   Nonce& foundNonce);

  // Generate chain endpoint from position in chain
  Nonce generatePartialChain(const Nonce& startNonce, size_t tableId, size_t startPos,
                             size_t endPos);

  // Utility functions
  std::string nonceToHex(const Nonce& nonce) const;
  std::string hashToHex(const std::array<uint8_t, Config::hashSize>& hash) const;

  std::string rainbowDir_;
  std::vector<TableMetadata> metadata_;
  std::vector<std::vector<RainbowChain>> tables_;
  size_t chainLength_;
};

}  // namespace hashchain

#endif  // HASHCHAIN_RAINBOW_VERIFIER_H_
