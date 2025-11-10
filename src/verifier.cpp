#include "verifier.h"

#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "blake3.h"

namespace hashchain {

Verifier::Verifier(const std::string& bucketDir) : bucketDir_(bucketDir) {}

Verifier::~Verifier() {}

std::array<uint8_t, Config::hashSize> Verifier::computeFullHash(const Nonce& nonce) {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, nonce.data(), nonce.size());

  std::array<uint8_t, Config::hashSize> hash;
  blake3_hasher_finalize(&hasher, hash.data(), Config::hashSize);
  return hash;
}

std::vector<Nonce> Verifier::readBucket(size_t bucketId) {
  std::vector<Nonce> nonces;

  // Construct bucket file path
  std::ostringstream oss;
  oss << bucketDir_ << "/bucket_" << std::setfill('0') << std::setw(6) << bucketId << ".bin";
  std::string filePath = oss.str();

  std::ifstream file(filePath, std::ios::binary);
  if (!file.is_open()) {
    return nonces;  // Return empty if file doesn't exist
  }

  // Read all nonces from file
  Nonce nonce;
  while (file.read(reinterpret_cast<char*>(nonce.data()), Config::nonceSize)) {
    nonces.push_back(nonce);
  }

  file.close();
  return nonces;
}

std::string Verifier::nonceToHex(const Nonce& nonce) const {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < Config::nonceSize; ++i) {
    oss << std::setw(2) << static_cast<int>(nonce[i]);
  }
  return oss.str();
}

std::string Verifier::hashToHex(const std::array<uint8_t, Config::hashSize>& hash) const {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < Config::hashSize; ++i) {
    oss << std::setw(2) << static_cast<int>(hash[i]);
  }
  return oss.str();
}

bool Verifier::hashesMatchDifficulty(const std::array<uint8_t, Config::hashSize>& hash1,
                                     const std::array<uint8_t, Config::hashSize>& hash2,
                                     size_t difficulty) const {
  size_t bitsToMatch = difficulty;
  size_t bytesToMatch = bitsToMatch / 8;
  size_t remainingBits = bitsToMatch % 8;

  // Check full bytes
  for (size_t i = 0; i < bytesToMatch && i < Config::hashSize; ++i) {
    if (hash1[i] != hash2[i]) {
      return false;
    }
  }

  // Check remaining bits in the next byte
  if (remainingBits > 0 && bytesToMatch < Config::hashSize) {
    uint8_t mask = static_cast<uint8_t>(0xFF << (8 - remainingBits));
    if ((hash1[bytesToMatch] & mask) != (hash2[bytesToMatch] & mask)) {
      return false;
    }
  }

  return true;
}

size_t Verifier::getBucketIdFromHash(const std::array<uint8_t, Config::hashSize>& hash) const {
  size_t bucketId = 0;
  for (size_t i = 0; i < Config::bucketPrefixSize && i < Config::hashSize; ++i) {
    bucketId = (bucketId << 8) | hash[i];
  }
  return bucketId;
}

void Verifier::displayFirstEntries(size_t count) {
  std::cout << "\n=== Displaying First " << count << " Entries ===" << std::endl;
  std::cout << "Format: Nonce (hex) -> Hash (hex)\n" << std::endl;

  auto startTime = std::chrono::high_resolution_clock::now();

  size_t displayed = 0;
  for (size_t bucketId = 0; bucketId < Config::numBuckets && displayed < count; ++bucketId) {
    std::vector<Nonce> nonces = readBucket(bucketId);

    for (const auto& nonce : nonces) {
      if (displayed >= count) break;

      auto hash = computeFullHash(nonce);
      std::cout << nonceToHex(nonce) << " -> " << hashToHex(hash) << std::endl;
      displayed++;
    }
  }

  auto endTime = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = endTime - startTime;

  std::cout << "\nDisplayed " << displayed << " entries in " << std::fixed
            << std::setprecision(3) << duration.count() << " seconds" << std::endl;
  std::cout << "Rate: " << std::fixed << std::setprecision(0)
            << (displayed / duration.count()) << " entries/second\n" << std::endl;
}

void Verifier::displayFirstFromEachBucket(size_t maxBuckets) {
  std::cout << "\n=== Displaying First Entry From Each Bucket ===" << std::endl;
  std::cout << "Format: [Bucket ID] Nonce (hex) -> Hash (hex)\n" << std::endl;

  auto startTime = std::chrono::high_resolution_clock::now();

  size_t bucketsWithData = 0;
  size_t maxToDisplay = std::min(maxBuckets, Config::numBuckets);

  for (size_t bucketId = 0; bucketId < maxToDisplay; ++bucketId) {
    std::vector<Nonce> nonces = readBucket(bucketId);

    if (!nonces.empty()) {
      const auto& nonce = nonces[0];
      auto hash = computeFullHash(nonce);
      std::cout << "[" << std::setw(6) << std::setfill('0') << bucketId << "] "
                << nonceToHex(nonce) << " -> " << hashToHex(hash) << std::endl;
      bucketsWithData++;
    }
  }

  auto endTime = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = endTime - startTime;

  std::cout << "\nDisplayed " << bucketsWithData << " buckets with data (checked "
            << maxToDisplay << " buckets)" << std::endl;
  std::cout << "Time: " << std::fixed << std::setprecision(3) << duration.count()
            << " seconds\n" << std::endl;
}

size_t Verifier::findMatches(const std::array<uint8_t, Config::hashSize>& targetHash,
                             size_t difficulty, size_t maxMatches) {
  std::cout << "\n=== Finding Matches for Target Hash ===" << std::endl;
  std::cout << "Target Hash: " << hashToHex(targetHash) << std::endl;
  std::cout << "Difficulty: " << difficulty << " bits" << std::endl;
  std::cout << "Max Matches: " << maxMatches << "\n" << std::endl;

  auto startTime = std::chrono::high_resolution_clock::now();

  // Determine which bucket to search based on target hash
  size_t targetBucket = getBucketIdFromHash(targetHash);
  std::cout << "Searching in bucket: " << targetBucket << std::endl;

  // Read all nonces from the target bucket
  std::vector<Nonce> nonces = readBucket(targetBucket);
  std::cout << "Bucket contains " << nonces.size() << " nonces" << std::endl;

  size_t matchesFound = 0;
  size_t noncesChecked = 0;

  std::cout << "\nMatches found:" << std::endl;

  for (const auto& nonce : nonces) {
    noncesChecked++;

    // Compute full hash for this nonce
    auto hash = computeFullHash(nonce);

    // Check if it matches the difficulty
    if (hashesMatchDifficulty(hash, targetHash, difficulty)) {
      std::cout << "  [" << matchesFound + 1 << "] Nonce: " << nonceToHex(nonce)
                << " -> Hash: " << hashToHex(hash) << std::endl;
      matchesFound++;

      if (matchesFound >= maxMatches) {
        break;
      }
    }
  }

  auto endTime = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = endTime - startTime;

  std::cout << "\nSearch Results:" << std::endl;
  std::cout << "  Matches Found: " << matchesFound << std::endl;
  std::cout << "  Nonces Checked: " << noncesChecked << std::endl;
  std::cout << "  Search Time: " << std::fixed << std::setprecision(3) << duration.count()
            << " seconds" << std::endl;
  std::cout << "  Hash Rate: " << std::fixed << std::setprecision(0)
            << (noncesChecked / duration.count()) << " hashes/second\n" << std::endl;

  return matchesFound;
}

}  // namespace hashchain
