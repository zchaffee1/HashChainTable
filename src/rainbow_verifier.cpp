#include "rainbow_verifier.h"

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "blake3.h"

namespace hashchain {

RainbowVerifier::RainbowVerifier(const std::string& rainbowDir)
    : rainbowDir_(rainbowDir), chainLength_(0) {}

RainbowVerifier::~RainbowVerifier() {}

bool RainbowVerifier::loadTable(size_t tableId, const std::string& filename) {
  std::ifstream inFile(filename, std::ios::binary);
  if (!inFile.is_open()) {
    std::cerr << "Failed to open file: " << filename << std::endl;
    return false;
  }

  // Read header
  uint32_t version;
  inFile.read(reinterpret_cast<char*>(&version), sizeof(version));
  if (version != 4) {
    std::cerr << "Invalid version: " << version << " (expected 4)" << std::endl;
    return false;
  }

  uint64_t numChains;
  inFile.read(reinterpret_cast<char*>(&numChains), sizeof(numChains));

  uint32_t chainLen;
  inFile.read(reinterpret_cast<char*>(&chainLen), sizeof(chainLen));

  if (chainLength_ == 0) {
    chainLength_ = chainLen;
  } else if (chainLength_ != chainLen) {
    std::cerr << "Chain length mismatch!" << std::endl;
    return false;
  }

  // Store metadata
  metadata_.push_back({tableId, numChains, chainLen});

  // Read chains
  std::vector<RainbowChain> chains;
  chains.reserve(numChains);

  for (size_t i = 0; i < numChains; ++i) {
    RainbowChain chain;
    inFile.read(reinterpret_cast<char*>(chain.startNonce.data()), Config::nonceSize);
    inFile.read(reinterpret_cast<char*>(chain.endNonce.data()), Config::nonceSize);
    chains.push_back(chain);
  }

  tables_.push_back(std::move(chains));

  std::cout << "Loaded table " << tableId << ": " << numChains << " chains, length " << chainLen
            << std::endl;

  return true;
}

bool RainbowVerifier::loadTables() {
  std::cout << "Loading rainbow tables from: " << rainbowDir_ << std::endl;

  size_t tableId = 0;
  while (true) {
    std::string filename =
        rainbowDir_ + "/rainbow_table_" + std::to_string(tableId) + ".bin";

    std::ifstream test(filename);
    if (!test.good()) {
      break;  // No more tables
    }
    test.close();

    if (!loadTable(tableId, filename)) {
      return false;
    }

    tableId++;
  }

  if (tables_.empty()) {
    std::cerr << "No rainbow tables found in: " << rainbowDir_ << std::endl;
    return false;
  }

  std::cout << "Loaded " << tables_.size() << " rainbow tables\n" << std::endl;
  return true;
}

Nonce RainbowVerifier::reduce(const std::array<uint8_t, Config::hashSize>& hash, size_t tableId,
                              size_t position) const {
  // Must match generator's reduction function exactly!
  Nonce result;
  result.fill(0);

  uint64_t salt = (static_cast<uint64_t>(tableId) << 32) | (position & 0xFFFFFFFF);

  for (size_t i = 0; i < Config::nonceSize; ++i) {
    uint8_t hashByte = (i < Config::hashSize) ? hash[i] : 0;
    uint8_t saltByte = static_cast<uint8_t>((salt >> (i * 8)) & 0xFF);
    result[i] = hashByte ^ saltByte;
  }

  for (size_t i = Config::nonceSize; i < Config::hashSize; ++i) {
    result[i % Config::nonceSize] ^= hash[i];
  }

  return result;
}

std::array<uint8_t, Config::hashSize> RainbowVerifier::computeHash(const Nonce& nonce) const {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, nonce.data(), nonce.size());

  std::array<uint8_t, Config::hashSize> hash;
  blake3_hasher_finalize(&hasher, hash.data(), Config::hashSize);

  return hash;
}

Nonce RainbowVerifier::generatePartialChain(const Nonce& startNonce, size_t tableId,
                                            size_t startPos, size_t endPos) {
  Nonce current = startNonce;

  for (size_t pos = startPos; pos < endPos; ++pos) {
    auto hash = computeHash(current);
    current = reduce(hash, tableId, pos);
  }

  return current;
}

bool RainbowVerifier::searchTable(size_t tableId,
                                  const std::array<uint8_t, Config::hashSize>& targetHash,
                                  Nonce& foundNonce) {
  const auto& table = tables_[tableId];

  // Try each possible position in the chain
  for (int pos = chainLength_ - 1; pos >= 0; --pos) {
    // Generate what the endpoint would be if target is at position 'pos'
    Nonce candidate = reduce(targetHash, tableId, pos);

    // Continue chain from pos+1 to end
    Nonce endpoint = generatePartialChain(candidate, tableId, pos + 1, chainLength_);

    // Binary search for this endpoint in the sorted table
    RainbowChain searchChain;
    searchChain.endNonce = endpoint;

    auto it = std::lower_bound(table.begin(), table.end(), searchChain,
                              [](const RainbowChain& a, const RainbowChain& b) {
                                return a.endNonce < b.endNonce;
                              });

    // Check if we found a matching endpoint
    if (it != table.end() && it->endNonce == endpoint) {
      // Found a candidate chain! Regenerate from start and check each position
      Nonce current = it->startNonce;

      for (size_t checkPos = 0; checkPos < chainLength_; ++checkPos) {
        auto hash = computeHash(current);

        // Check if this hash matches target
        if (hash == targetHash) {
          foundNonce = current;
          return true;
        }

        // Continue to next position
        current = reduce(hash, tableId, checkPos);
      }
    }
  }

  return false;
}

bool RainbowVerifier::findHash(const std::array<uint8_t, Config::hashSize>& targetHash,
                               Nonce& foundNonce) {
  std::cout << "Searching for hash: " << hashToHex(targetHash) << std::endl;

  auto startTime = std::chrono::high_resolution_clock::now();

  // Try each table
  for (size_t tableId = 0; tableId < tables_.size(); ++tableId) {
    std::cout << "Searching table " << (tableId + 1) << "/" << tables_.size() << "..."
              << std::endl;

    if (searchTable(tableId, targetHash, foundNonce)) {
      auto endTime = std::chrono::high_resolution_clock::now();
      std::chrono::duration<double> duration = endTime - startTime;

      std::cout << "\nFOUND! Nonce: " << nonceToHex(foundNonce) << std::endl;
      std::cout << "Search time: " << std::fixed << std::setprecision(3) << duration.count()
                << " seconds" << std::endl;

      // Verify by recomputing hash
      auto verifyHash = computeHash(foundNonce);
      if (verifyHash == targetHash) {
        std::cout << "Verification: SUCCESS\n" << std::endl;
      } else {
        std::cout << "Verification: FAILED (hash mismatch!)\n" << std::endl;
      }

      return true;
    }
  }

  auto endTime = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = endTime - startTime;

  std::cout << "\nNOT FOUND in any table" << std::endl;
  std::cout << "Search time: " << std::fixed << std::setprecision(3) << duration.count()
            << " seconds\n" << std::endl;

  return false;
}

std::string RainbowVerifier::nonceToHex(const Nonce& nonce) const {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (const auto& byte : nonce) {
    oss << std::setw(2) << static_cast<int>(byte);
  }
  return oss.str();
}

std::string RainbowVerifier::hashToHex(const std::array<uint8_t, Config::hashSize>& hash) const {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (const auto& byte : hash) {
    oss << std::setw(2) << static_cast<int>(byte);
  }
  return oss.str();
}

void RainbowVerifier::displayStatistics() const {
  std::cout << "\n=== Rainbow Table Statistics ===" << std::endl;
  std::cout << "Number of tables: " << tables_.size() << std::endl;
  std::cout << "Chain length: " << chainLength_ << std::endl;

  uint64_t totalChains = 0;
  for (const auto& meta : metadata_) {
    totalChains += meta.numChains;
  }
  std::cout << "Total chains: " << totalChains << std::endl;

  uint64_t idealCoverage = totalChains * chainLength_;
  std::cout << "Ideal coverage: " << idealCoverage << " nonces";
  if (idealCoverage < Config::tableSize) {
    double percent = (idealCoverage * 100.0) / Config::tableSize;
    std::cout << " (" << std::fixed << std::setprecision(1) << percent << "% of 2^"
              << Config::kValue << ")";
  }
  std::cout << "\n================================\n" << std::endl;
}

void RainbowVerifier::displaySampleChains(size_t count) const {
  std::cout << "\n=== Sample Chains (first " << count << " from table 0) ===" << std::endl;
  std::cout << "Format: Start -> End\n" << std::endl;

  if (tables_.empty()) {
    std::cout << "No tables loaded\n" << std::endl;
    return;
  }

  const auto& table = tables_[0];
  size_t numToShow = std::min(count, table.size());

  for (size_t i = 0; i < numToShow; ++i) {
    const auto& chain = table[i];
    std::cout << nonceToHex(chain.startNonce) << " -> " << nonceToHex(chain.endNonce) << std::endl;
  }

  std::cout << std::endl;
}

}  // namespace hashchain
