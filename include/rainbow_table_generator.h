#ifndef HASHCHAIN_RAINBOW_TABLE_GENERATOR_H_
#define HASHCHAIN_RAINBOW_TABLE_GENERATOR_H_

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "config.h"
#include "types.h"

namespace hashchain {

// Rainbow table chain entry (only store start and end)
struct RainbowChain {
  Nonce startNonce;
  Nonce endNonce;

  bool operator<(const RainbowChain& other) const {
    // Sort by end nonce for lookup
    return endNonce < other.endNonce;
  }
};

// Implementation 4: Rainbow Table Generator
// Uses chain-based storage with reduction functions for massive space savings
class RainbowTableGenerator {
 public:
  RainbowTableGenerator(const std::string& outputDir, size_t memoryLimitMB, size_t numTables = 4);
  ~RainbowTableGenerator();

  // Initialize: calculate optimal chain parameters
  bool initialize();

  // Generate all rainbow tables
  void generateTables();

  // Write tables to disk
  bool writeTables();

  // Statistics
  void printStatistics() const;

  // Get calculated parameters
  size_t getChainLength() const { return chainLength_; }
  size_t getChainsPerTable() const { return chainsPerTable_; }
  size_t getNumTables() const { return numTables_; }
  uint64_t getTotalCoverage() const;

 private:
  // Reduction function: hash -> nonce (different per table and position)
  Nonce reduce(const std::array<uint8_t, Config::hashSize>& hash, size_t tableId,
               size_t position) const;

  // Generate a single chain from start nonce
  Nonce generateChain(const Nonce& startNonce, size_t tableId);

  // Generate one complete table
  void generateTable(size_t tableId);

  // Calculate optimal chain length based on memory and coverage
  size_t calculateOptimalChainLength() const;

  std::string outputDir_;
  size_t memoryLimitBytes_;
  size_t numTables_;

  // Calculated parameters
  size_t chainLength_;
  size_t chainsPerTable_;

  // In-memory storage: one vector per table
  std::vector<std::vector<RainbowChain>> tables_;

  // Statistics
  uint64_t totalChainsGenerated_;
  uint64_t mergedChains_;  // Chains that merged with others
};

}  // namespace hashchain

#endif  // HASHCHAIN_RAINBOW_TABLE_GENERATOR_H_
