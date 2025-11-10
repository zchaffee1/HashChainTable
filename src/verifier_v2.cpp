#include "verifier_v2.h"

#include <chrono>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "blake3.h"

namespace hashchain {

VerifierV2::VerifierV2(const std::string& bucketDir) : bucketDir_(bucketDir) {
  dataFilePath_ = bucketDir_ + "/buckets.dat";
  metadataFilePath_ = bucketDir_ + "/buckets.meta";
  metadata_.resize(Config::numBuckets);

  if (!loadMetadata()) {
    std::cerr << "Warning: Could not load metadata file" << std::endl;
  }
}

VerifierV2::~VerifierV2() {}

bool VerifierV2::loadMetadata() {
  std::ifstream metaFile(metadataFilePath_, std::ios::binary);
  if (!metaFile.is_open()) {
    return false;
  }

  // Read header
  uint32_t version;
  metaFile.read(reinterpret_cast<char*>(&version), sizeof(version));

  uint64_t numBuckets;
  metaFile.read(reinterpret_cast<char*>(&numBuckets), sizeof(numBuckets));

  if (numBuckets != Config::numBuckets) {
    std::cerr << "Metadata bucket count mismatch!" << std::endl;
    return false;
  }

  // Read metadata
  for (auto& meta : metadata_) {
    metaFile.read(reinterpret_cast<char*>(&meta.entryCount), sizeof(meta.entryCount));
    metaFile.read(reinterpret_cast<char*>(&meta.fileOffset), sizeof(meta.fileOffset));
  }

  metaFile.close();
  return true;
}

std::array<uint8_t, Config::hashSize> VerifierV2::computeFullHash(const Nonce& nonce) {
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);
  blake3_hasher_update(&hasher, nonce.data(), nonce.size());

  std::array<uint8_t, Config::hashSize> hash;
  blake3_hasher_finalize(&hasher, hash.data(), Config::hashSize);
  return hash;
}

std::vector<Nonce> VerifierV2::readBucket(size_t bucketId) {
  std::vector<Nonce> nonces;

  if (bucketId >= Config::numBuckets) {
    return nonces;
  }

  const auto& meta = metadata_[bucketId];
  if (meta.entryCount == 0) {
    return nonces;
  }

  // Open data file
  std::ifstream dataFile(dataFilePath_, std::ios::binary);
  if (!dataFile.is_open()) {
    return nonces;
  }

  // Seek to bucket offset
  dataFile.seekg(meta.fileOffset, std::ios::beg);

  // Read all nonces from this bucket
  nonces.resize(meta.entryCount);
  for (size_t i = 0; i < meta.entryCount; ++i) {
    dataFile.read(reinterpret_cast<char*>(nonces[i].data()), Config::nonceSize);
  }

  dataFile.close();
  return nonces;
}

std::string VerifierV2::nonceToHex(const Nonce& nonce) const {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < Config::nonceSize; ++i) {
    oss << std::setw(2) << static_cast<int>(nonce[i]);
  }
  return oss.str();
}

std::string VerifierV2::hashToHex(const std::array<uint8_t, Config::hashSize>& hash) const {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0');
  for (size_t i = 0; i < Config::hashSize; ++i) {
    oss << std::setw(2) << static_cast<int>(hash[i]);
  }
  return oss.str();
}

bool VerifierV2::hashesMatchDifficulty(const std::array<uint8_t, Config::hashSize>& hash1,
                                       const std::array<uint8_t, Config::hashSize>& hash2,
                                       size_t difficulty) const {
  size_t bitsToMatch = difficulty;
  size_t bytesToMatch = bitsToMatch / 8;
  size_t remainingBits = bitsToMatch % 8;

  for (size_t i = 0; i < bytesToMatch && i < Config::hashSize; ++i) {
    if (hash1[i] != hash2[i]) {
      return false;
    }
  }

  if (remainingBits > 0 && bytesToMatch < Config::hashSize) {
    uint8_t mask = static_cast<uint8_t>(0xFF << (8 - remainingBits));
    if ((hash1[bytesToMatch] & mask) != (hash2[bytesToMatch] & mask)) {
      return false;
    }
  }

  return true;
}

size_t VerifierV2::getBucketIdFromHash(const std::array<uint8_t, Config::hashSize>& hash) const {
  size_t bucketId = 0;
  for (size_t i = 0; i < Config::bucketPrefixSize && i < Config::hashSize; ++i) {
    bucketId = (bucketId << 8) | hash[i];
  }
  return bucketId;
}

void VerifierV2::displayFirstEntries(size_t count) {
  std::cout << "\n=== Displaying First " << count << " Entries (Implementation 2) ===" << std::endl;
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

  std::cout << "\nDisplayed " << displayed << " entries in " << std::fixed << std::setprecision(3)
            << duration.count() << " seconds" << std::endl;
  std::cout << "Rate: " << std::fixed << std::setprecision(0) << (displayed / duration.count())
            << " entries/second\n"
            << std::endl;
}

void VerifierV2::displayFirstFromEachBucket(size_t maxBuckets) {
  std::cout << "\n=== Displaying First Entry From Each Bucket (Implementation 2) ==="
            << std::endl;
  std::cout << "Format: [Bucket ID] Nonce (hex) -> Hash (hex)\n" << std::endl;

  auto startTime = std::chrono::high_resolution_clock::now();

  size_t bucketsWithData = 0;
  size_t maxToDisplay = std::min(maxBuckets, Config::numBuckets);

  for (size_t bucketId = 0; bucketId < maxToDisplay; ++bucketId) {
    if (metadata_[bucketId].entryCount == 0) {
      continue;
    }

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

  std::cout << "\nDisplayed " << bucketsWithData << " buckets with data (checked " << maxToDisplay
            << " buckets)" << std::endl;
  std::cout << "Time: " << std::fixed << std::setprecision(3) << duration.count() << " seconds\n"
            << std::endl;
}

size_t VerifierV2::findMatches(const std::array<uint8_t, Config::hashSize>& targetHash,
                               size_t difficulty, size_t maxMatches) {
  std::cout << "\n=== Finding Matches for Target Hash (Implementation 2) ===" << std::endl;
  std::cout << "Target Hash: " << hashToHex(targetHash) << std::endl;
  std::cout << "Difficulty: " << difficulty << " bits" << std::endl;
  std::cout << "Max Matches: " << maxMatches << "\n" << std::endl;

  auto startTime = std::chrono::high_resolution_clock::now();

  size_t targetBucket = getBucketIdFromHash(targetHash);
  std::cout << "Searching in bucket: " << targetBucket << std::endl;

  std::vector<Nonce> nonces = readBucket(targetBucket);
  std::cout << "Bucket contains " << nonces.size() << " nonces" << std::endl;

  size_t matchesFound = 0;
  size_t noncesChecked = 0;

  std::cout << "\nMatches found:" << std::endl;

  for (const auto& nonce : nonces) {
    noncesChecked++;

    auto hash = computeFullHash(nonce);

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
