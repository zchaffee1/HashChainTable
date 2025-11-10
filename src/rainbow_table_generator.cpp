#include "rainbow_table_generator.h"

#include <sys/stat.h>

#include <algorithm>
#include <cmath>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>

#include "blake3.h"
#include "benchmark.h"

namespace hashchain {

RainbowTableGenerator::RainbowTableGenerator(const std::string& outputDir,
                                             size_t memoryLimitMB, size_t numTables)
    : outputDir_(outputDir),
      memoryLimitBytes_(memoryLimitMB * 1024 * 1024),
      numTables_(numTables),
      chainLength_(0),
      chainsPerTable_(0),
      totalChainsGenerated_(0),
      mergedChains_(0) {
  tables_.resize(numTables_);
}

RainbowTableGenerator::~RainbowTableGenerator() {}

size_t RainbowTableGenerator::calculateOptimalChainLength() const {
  // Calculate number of chains we can store in memory
  size_t bytesPerChain = 2 * Config::nonceSize;  // start + end nonce
  size_t totalChains = memoryLimitBytes_ / bytesPerChain;

  // Optimal chain length: balance between coverage and collision probability
  // Rule of thumb: L = sqrt(coverage_target / num_chains)
  // We want to cover 2^K nonces with total chains
  double coverageTarget = static_cast<double>(Config::tableSize);
  double totalChains_d = static_cast<double>(totalChains);

  size_t optimalLength = static_cast<size_t>(std::sqrt(coverageTarget / totalChains_d));

  // Clamp to reasonable range [100, 100000]
  optimalLength = std::max(size_t(100), std::min(size_t(100000), optimalLength));

  return optimalLength;
}

bool RainbowTableGenerator::initialize() {
  mkdir(outputDir_.c_str(), 0755);

  std::cout << "\n=== Implementation 4: Rainbow Table Generator ===" << std::endl;
  std::cout << "Memory limit: " << (memoryLimitBytes_ / 1024.0 / 1024.0) << " MB" << std::endl;
  std::cout << "Number of tables: " << numTables_ << std::endl;
  std::cout << "Nonce size: " << Config::nonceSize << " bytes" << std::endl;

  // Calculate parameters
  size_t bytesPerChain = 2 * Config::nonceSize;
  chainsPerTable_ = memoryLimitBytes_ / (numTables_ * bytesPerChain);
  chainLength_ = calculateOptimalChainLength();

  std::cout << "\nCalculated Parameters:" << std::endl;
  std::cout << "  Chain length: " << chainLength_ << std::endl;
  std::cout << "  Chains per table: " << chainsPerTable_ << std::endl;
  std::cout << "  Total chains: " << (chainsPerTable_ * numTables_) << std::endl;

  uint64_t idealCoverage = static_cast<uint64_t>(chainsPerTable_) * chainLength_ * numTables_;
  std::cout << "  Ideal coverage: " << idealCoverage << " nonces";
  if (idealCoverage < Config::tableSize) {
    double coveragePercent = (idealCoverage * 100.0) / Config::tableSize;
    std::cout << " (" << std::fixed << std::setprecision(2) << coveragePercent << "% of 2^"
              << Config::kValue << ")";
  }
  std::cout << std::endl;

  // Allocate memory for tables
  for (size_t i = 0; i < numTables_; ++i) {
    tables_[i].reserve(chainsPerTable_);
  }

  std::cout << "  Memory allocated: " << (memoryLimitBytes_ / 1024.0 / 1024.0) << " MB\n"
            << std::endl;

  return true;
}

Nonce RainbowTableGenerator::reduce(const std::array<uint8_t, Config::hashSize>& hash,
                                    size_t tableId, size_t position) const {
  // Reduction function: hash -> nonce
  // Must be different for each table and position to prevent chain merging
  // Simple but effective: XOR hash bytes with table and position salts

  Nonce result;
  result.fill(0);

  // Mix in table ID and position to make reduction unique
  uint64_t salt = (static_cast<uint64_t>(tableId) << 32) | (position & 0xFFFFFFFF);

  // XOR hash bytes with salt to create nonce
  for (size_t i = 0; i < Config::nonceSize; ++i) {
    uint8_t hashByte = (i < Config::hashSize) ? hash[i] : 0;
    uint8_t saltByte = static_cast<uint8_t>((salt >> (i * 8)) & 0xFF);
    result[i] = hashByte ^ saltByte;
  }

  // If hash is longer than nonce, fold remaining bytes in
  for (size_t i = Config::nonceSize; i < Config::hashSize; ++i) {
    result[i % Config::nonceSize] ^= hash[i];
  }

  return result;
}

Nonce RainbowTableGenerator::generateChain(const Nonce& startNonce, size_t tableId) {
  Nonce current = startNonce;
  blake3_hasher hasher;

  for (size_t pos = 0; pos < chainLength_; ++pos) {
    // Hash current nonce
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, current.data(), current.size());

    std::array<uint8_t, Config::hashSize> hash;
    blake3_hasher_finalize(&hasher, hash.data(), Config::hashSize);

    // Reduce hash to next nonce
    current = reduce(hash, tableId, pos);
  }

  return current;  // Return end point
}

void RainbowTableGenerator::generateTable(size_t tableId) {
  std::cout << "Generating table " << (tableId + 1) << "/" << numTables_ << "..." << std::endl;

  BENCHMARK_TIMER(tableTimer);

  // Generate chains with sequential start nonces
  uint64_t startCounter = tableId * chainsPerTable_;

  for (size_t i = 0; i < chainsPerTable_; ++i) {
    uint64_t counter = startCounter + i;

    // Create start nonce from counter
    Nonce startNonce = counterToNonce(counter);

    // Generate chain
    Nonce endNonce = generateChain(startNonce, tableId);

    // Store chain
    tables_[tableId].push_back({startNonce, endNonce});

    totalChainsGenerated_++;

    if (i % 100000 == 0 && i > 0) {
      std::cout << "\r  Generated " << i << " / " << chainsPerTable_ << " chains" << std::flush;
    }
  }

  std::cout << "\r  Generated " << chainsPerTable_ << " / " << chainsPerTable_ << " chains"
            << std::endl;

  // Sort by end nonce for efficient lookup
  std::cout << "  Sorting chains by end point..." << std::endl;
  std::sort(tables_[tableId].begin(), tables_[tableId].end());

  // Detect merged chains (duplicate end points)
  size_t duplicates = 0;
  for (size_t i = 1; i < tables_[tableId].size(); ++i) {
    if (tables_[tableId][i].endNonce == tables_[tableId][i - 1].endNonce) {
      duplicates++;
    }
  }
  if (duplicates > 0) {
    mergedChains_ += duplicates;
    std::cout << "  Warning: " << duplicates << " merged chains detected (duplicates)" << std::endl;
  }

#ifdef ENABLE_BENCHMARKING
  double tableTime = tableTimer.elapsed();
  std::cout << "  Table generated in " << std::fixed << std::setprecision(2) << tableTime
            << " seconds (" << static_cast<int>(chainsPerTable_ * chainLength_ / tableTime)
            << " hashes/sec)" << std::endl;
#endif
}

void RainbowTableGenerator::generateTables() {
  std::cout << "\nGenerating " << numTables_ << " rainbow tables..." << std::endl;

  BENCHMARK_TIMER(totalTimer);

  for (size_t i = 0; i < numTables_; ++i) {
    generateTable(i);
    std::cout << std::endl;
  }

#ifdef ENABLE_BENCHMARKING
  double totalTime = totalTimer.elapsed();
  uint64_t totalHashes = totalChainsGenerated_ * chainLength_;
  std::cout << "All tables generated in " << std::fixed << std::setprecision(2) << totalTime
            << " seconds" << std::endl;
  std::cout << "Total hashes computed: " << totalHashes << " (" << (totalHashes / totalTime)
            << " hashes/sec)" << std::endl;
#endif
}

bool RainbowTableGenerator::writeTables() {
  std::cout << "\nWriting rainbow tables to disk..." << std::endl;

  BENCHMARK_TIMER(writeTimer);

  uint64_t totalBytes = 0;

  for (size_t tableId = 0; tableId < numTables_; ++tableId) {
    std::string filename =
        outputDir_ + "/rainbow_table_" + std::to_string(tableId) + ".bin";

    std::ofstream outFile(filename, std::ios::binary | std::ios::trunc);
    if (!outFile.is_open()) {
      std::cerr << "Failed to create file: " << filename << std::endl;
      return false;
    }

    // Write header
    uint32_t version = 4;  // Implementation version
    outFile.write(reinterpret_cast<const char*>(&version), sizeof(version));

    uint64_t numChains = tables_[tableId].size();
    outFile.write(reinterpret_cast<const char*>(&numChains), sizeof(numChains));

    uint32_t chainLen = static_cast<uint32_t>(chainLength_);
    outFile.write(reinterpret_cast<const char*>(&chainLen), sizeof(chainLen));

    // Write chains (start, end) pairs
    for (const auto& chain : tables_[tableId]) {
      outFile.write(reinterpret_cast<const char*>(chain.startNonce.data()), Config::nonceSize);
      outFile.write(reinterpret_cast<const char*>(chain.endNonce.data()), Config::nonceSize);
    }

    uint64_t fileSize = outFile.tellp();
    totalBytes += fileSize;

    outFile.close();

    std::cout << "  Wrote " << filename << " (" << (fileSize / 1024.0 / 1024.0) << " MB)"
              << std::endl;
  }

  // Write metadata
  std::string metaFile = outputDir_ + "/rainbow_meta.txt";
  std::ofstream meta(metaFile);
  if (meta.is_open()) {
    meta << "Rainbow Table Metadata\n";
    meta << "Implementation: 4\n";
    meta << "K Value: " << Config::kValue << "\n";
    meta << "Nonce Size: " << Config::nonceSize << " bytes\n";
    meta << "Hash Size: " << Config::hashSize << " bytes\n";
    meta << "Number of Tables: " << numTables_ << "\n";
    meta << "Chain Length: " << chainLength_ << "\n";
    meta << "Chains per Table: " << chainsPerTable_ << "\n";
    meta << "Total Chains: " << totalChainsGenerated_ << "\n";
    meta << "Merged Chains: " << mergedChains_ << "\n";
    meta << "Ideal Coverage: " << getTotalCoverage() << " nonces\n";
    meta.close();
  }

#ifdef ENABLE_BENCHMARKING
  double writeTime = writeTimer.elapsed();
  std::cout << "\nWrite complete in " << std::fixed << std::setprecision(2) << writeTime
            << " seconds" << std::endl;
  std::cout << "Total size: " << (totalBytes / 1024.0 / 1024.0) << " MB" << std::endl;
  std::cout << "Write throughput: " << (totalBytes / 1024.0 / 1024.0 / writeTime) << " MB/s"
            << std::endl;
#endif

  return true;
}

uint64_t RainbowTableGenerator::getTotalCoverage() const {
  // Ideal coverage (ignoring chain collisions and merges)
  return static_cast<uint64_t>(totalChainsGenerated_) * chainLength_;
}

void RainbowTableGenerator::printStatistics() const {
  std::cout << "\n=== Rainbow Table Statistics ===" << std::endl;
  std::cout << "Tables generated: " << numTables_ << std::endl;
  std::cout << "Chain length: " << chainLength_ << std::endl;
  std::cout << "Chains per table: " << chainsPerTable_ << std::endl;
  std::cout << "Total chains: " << totalChainsGenerated_ << std::endl;
  std::cout << "Merged chains: " << mergedChains_;
  if (totalChainsGenerated_ > 0) {
    double mergeRate = (mergedChains_ * 100.0) / totalChainsGenerated_;
    std::cout << " (" << std::fixed << std::setprecision(2) << mergeRate << "%)";
  }
  std::cout << std::endl;

  uint64_t idealCoverage = getTotalCoverage();
  std::cout << "Ideal coverage: " << idealCoverage << " nonces";
  if (idealCoverage < Config::tableSize) {
    double percent = (idealCoverage * 100.0) / Config::tableSize;
    std::cout << " (" << std::fixed << std::setprecision(1) << percent << "% of 2^"
              << Config::kValue << ")";
  }
  std::cout << std::endl;

  // Space efficiency vs naive approach
  uint64_t naiveStorage = Config::tableSize * Config::nonceSize;
  uint64_t rainbowStorage = totalChainsGenerated_ * 2 * Config::nonceSize;
  double spaceSavings = 100.0 * (1.0 - (static_cast<double>(rainbowStorage) / naiveStorage));

  std::cout << "Space efficiency: " << (rainbowStorage / 1024.0 / 1024.0) << " MB vs "
            << (naiveStorage / 1024.0 / 1024.0) << " MB naive (savings: " << std::fixed
            << std::setprecision(1) << spaceSavings << "%)" << std::endl;
  std::cout << "================================\n" << std::endl;
}

}  // namespace hashchain
