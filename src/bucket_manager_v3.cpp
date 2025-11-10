#include "bucket_manager_v3.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <map>

#include "benchmark.h"
#include "blake3.h"

namespace hashchain {

BucketManagerV3::BucketManagerV3(const std::string& outputDir, size_t memoryLimitMB)
    : outputDir_(outputDir), memoryLimitBytes_(memoryLimitMB * 1024 * 1024) {
  dataFilePath_ = outputDir_ + "/buckets.dat";
  metadataFilePath_ = outputDir_ + "/buckets.meta";
  metadata_.resize(Config::numBuckets);
}

BucketManagerV3::~BucketManagerV3() {
  finalize();
}

size_t BucketManagerV3::calculateEffectiveNonceSize() const {
  // Calculate how many bytes we can store per entry given memory limit
  // Total entries = 2^K
  // Available memory = memoryLimitBytes_
  // Effective nonce size = floor(memoryLimitBytes_ / tableSize)

  uint64_t totalEntries = Config::tableSize;
  uint64_t bytesPerEntry = memoryLimitBytes_ / totalEntries;

  // Cap at configured nonce size (we can't store more than the nonce itself)
  size_t effectiveSize = std::min(static_cast<size_t>(bytesPerEntry), Config::nonceSize);

  // Must be at least 1 byte
  if (effectiveSize < 1) {
    std::cerr << "Error: Memory limit too small! Need at least " << totalEntries
              << " bytes for 1 byte per entry" << std::endl;
    return 0;
  }

  return effectiveSize;
}

uint64_t BucketManagerV3::calculateMemoryOffset(uint64_t entryCounter) const {
  // Linear layout: entry at index = counter value
  // This avoids the bucket-based offset issue
  return entryCounter * effectiveNonceSize_;
}

// Helper: Extract counter from nonce (reverse of counterToNonce in types.h)
static uint64_t nonceToCounter(const Nonce& nonce) {
  uint64_t counter = 0;
  for (size_t i = 0; i < Config::nonceSize && i < 8; ++i) {
    counter = (counter << 8) | nonce[i];
  }
  return counter;
}

bool BucketManagerV3::initialize() {
  // Create output directory
  mkdir(outputDir_.c_str(), 0755);

  std::cout << "\n=== Implementation 3: In-Memory with Dynamic Nonce Size ===" << std::endl;
  std::cout << "Memory limit: " << (memoryLimitBytes_ / 1024.0 / 1024.0) << " MB" << std::endl;
  std::cout << "Configured nonce size: " << Config::nonceSize << " bytes" << std::endl;

  // Calculate effective nonce size
  effectiveNonceSize_ = calculateEffectiveNonceSize();
  if (effectiveNonceSize_ == 0) {
    return false;
  }

  std::cout << "Effective nonce size: " << effectiveNonceSize_ << " bytes" << std::endl;

  if (effectiveNonceSize_ < Config::nonceSize) {
    std::cout << "WARNING: Reduced nonce size from " << Config::nonceSize << " to "
              << effectiveNonceSize_ << " bytes to fit in memory" << std::endl;
    std::cout << "Only the first " << effectiveNonceSize_ << " bytes of each nonce will be stored"
              << std::endl;
  }

  // Calculate total memory needed
  uint64_t totalMemoryNeeded = Config::tableSize * effectiveNonceSize_;
  std::cout << "Total memory allocated: " << (totalMemoryNeeded / 1024.0 / 1024.0) << " MB"
            << std::endl;
  std::cout << "Table size: " << Config::tableSize << " entries (2^" << Config::kValue << ")"
            << std::endl;
  std::cout << "Bucket count: " << Config::numBuckets << std::endl;
  std::cout << "Bucket capacity: " << Config::bucketCapacity << " entries" << std::endl;

  // Allocate memory for entire table
  std::cout << "\nAllocating memory for entire table..." << std::endl;
  try {
    memoryTable_ = std::make_unique<uint8_t[]>(totalMemoryNeeded);
    // Initialize to zero
    std::memset(memoryTable_.get(), 0, totalMemoryNeeded);
  } catch (const std::bad_alloc& e) {
    std::cerr << "Failed to allocate " << (totalMemoryNeeded / 1024.0 / 1024.0)
              << " MB of memory: " << e.what() << std::endl;
    return false;
  }

  // Initialize bucket metadata
  for (size_t i = 0; i < Config::numBuckets; ++i) {
    metadata_[i].fileOffset = static_cast<uint64_t>(i) * Config::bucketCapacity * effectiveNonceSize_;
    metadata_[i].entryCount = 0;
  }

  std::cout << "Memory allocation complete\n" << std::endl;
  return true;
}

void BucketManagerV3::writeSortedEntries(const std::vector<BufferEntry>& entries) {
  if (entries.empty()) {
    return;
  }

  std::lock_guard<std::mutex> lock(writeMutex_);

  // Write entries directly to memory using linear layout
  // Store at position = nonce counter (extracted from nonce)
  for (const auto& entry : entries) {
    // Extract counter from nonce to determine position in linear array
    uint64_t counter = nonceToCounter(entry.nonce);

    // Check bounds
    if (counter >= Config::tableSize) {
      droppedEntries_.fetch_add(1, std::memory_order_relaxed);
      continue;
    }

    // Calculate memory offset based on counter
    uint64_t offset = calculateMemoryOffset(counter);

    // Copy nonce data (only effectiveNonceSize_ bytes)
    std::memcpy(memoryTable_.get() + offset, entry.nonce.data(), effectiveNonceSize_);

    // Track per-bucket statistics for metadata
    metadata_[entry.bucketId].entryCount++;

    totalEntriesWritten_.fetch_add(1, std::memory_order_relaxed);
    BENCHMARK_ADD(g_benchmarkStats.totalEntriesWritten, 1);
  }
}

bool BucketManagerV3::writeTableToFile() {
  std::cout << "\nWriting table to disk (reorganizing by bucket)..." << std::endl;

  BENCHMARK_TIMER(writeTimer);

  // Step 1: Scan through memory once and group entries by bucket
  std::cout << "Scanning entries and grouping by bucket..." << std::endl;
  std::map<BucketId, std::vector<uint8_t>> bucketData;

  for (uint64_t counter = 0; counter < Config::tableSize; ++counter) {
    uint64_t offset = calculateMemoryOffset(counter);

    // Check if this entry is non-zero (was written)
    bool isEmpty = true;
    for (size_t i = 0; i < effectiveNonceSize_; ++i) {
      if (memoryTable_[offset + i] != 0) {
        isEmpty = false;
        break;
      }
    }

    if (isEmpty) continue;

    // Reconstruct nonce from memory
    Nonce nonce;
    nonce.fill(0);
    std::memcpy(nonce.data(), memoryTable_.get() + offset, effectiveNonceSize_);

    // Compute hash prefix to determine bucket
    blake3_hasher hasher;
    blake3_hasher_init(&hasher);
    blake3_hasher_update(&hasher, nonce.data(), nonce.size());
    uint8_t hashPrefix[Config::bucketPrefixSize];
    blake3_hasher_finalize(&hasher, hashPrefix, Config::bucketPrefixSize);

    // Convert to bucket ID
    BucketId entryBucket = 0;
    for (size_t i = 0; i < Config::bucketPrefixSize; ++i) {
      entryBucket = (entryBucket << 8) | hashPrefix[i];
    }

    // Add to bucket's data
    bucketData[entryBucket].insert(bucketData[entryBucket].end(),
                                     memoryTable_.get() + offset,
                                     memoryTable_.get() + offset + effectiveNonceSize_);

    if (counter % 10000 == 0) {
      std::cout << "\r  Processed " << counter << " / " << Config::tableSize << " entries" << std::flush;
    }
  }
  std::cout << std::endl;
  std::cout << "Found " << bucketData.size() << " non-empty buckets" << std::endl;

  // Step 2: Write to file in bucket order
  std::cout << "Writing buckets to file..." << std::endl;
  std::ofstream outFile(dataFilePath_, std::ios::binary | std::ios::trunc);
  if (!outFile.is_open()) {
    std::cerr << "Failed to create output file: " << dataFilePath_ << std::endl;
    return false;
  }

  uint64_t totalBytesWritten = 0;
  size_t bucketsWritten = 0;

  for (const auto& [bucketId, data] : bucketData) {
    // Calculate bucket offset
    uint64_t bucketOffset = static_cast<uint64_t>(bucketId) * Config::bucketCapacity * effectiveNonceSize_;
    outFile.seekp(bucketOffset, std::ios::beg);

    // Write bucket data
    size_t entriesInBucket = data.size() / effectiveNonceSize_;
    outFile.write(reinterpret_cast<const char*>(data.data()), data.size());
    totalBytesWritten += data.size();

    // Update metadata
    metadata_[bucketId].entryCount = entriesInBucket;
    metadata_[bucketId].fileOffset = bucketOffset;

    bucketsWritten++;
    if (bucketsWritten % 1000 == 0) {
      std::cout << "\r  Written " << bucketsWritten << " / " << bucketData.size() << " buckets" << std::flush;
    }
  }
  std::cout << std::endl;

  outFile.close();

#ifdef ENABLE_BENCHMARKING
  double writeTime = writeTimer.elapsed();
  BENCHMARK_RECORD(g_benchmarkStats.writeTime, writeTime);
  BENCHMARK_ADD(g_benchmarkStats.totalBytesWritten, totalBytesWritten);
  BENCHMARK_INCREMENT(g_benchmarkStats.totalWriteOperations);
#endif

  std::cout << "Table written successfully (" << (totalBytesWritten / 1024.0 / 1024.0) << " MB actual data)" << std::endl;
  return true;
}

bool BucketManagerV3::saveMetadata() {
  std::ofstream metaFile(metadataFilePath_, std::ios::binary | std::ios::trunc);
  if (!metaFile.is_open()) {
    std::cerr << "Failed to create metadata file: " << metadataFilePath_ << std::endl;
    return false;
  }

  // Write header
  uint32_t version = 3;  // Implementation version
  metaFile.write(reinterpret_cast<const char*>(&version), sizeof(version));

  uint64_t numBuckets = Config::numBuckets;
  metaFile.write(reinterpret_cast<const char*>(&numBuckets), sizeof(numBuckets));

  // Write effective nonce size (IMPORTANT: verifier needs this!)
  uint32_t effectiveNonce = static_cast<uint32_t>(effectiveNonceSize_);
  metaFile.write(reinterpret_cast<const char*>(&effectiveNonce), sizeof(effectiveNonce));

  // Write metadata for each bucket
  for (const auto& meta : metadata_) {
    metaFile.write(reinterpret_cast<const char*>(&meta.entryCount), sizeof(meta.entryCount));
    metaFile.write(reinterpret_cast<const char*>(&meta.fileOffset), sizeof(meta.fileOffset));
  }

  metaFile.close();
  return true;
}

void BucketManagerV3::finalize() {
  std::cout << "\nFinalizing..." << std::endl;

  // Write entire table to disk
  if (memoryTable_) {
    writeTableToFile();
  }

  // Save metadata
  saveMetadata();

  // Free memory
  memoryTable_.reset();

  std::cout << "Finalization complete" << std::endl;
}

uint64_t BucketManagerV3::getTotalEntriesWritten() const {
  return totalEntriesWritten_.load(std::memory_order_relaxed);
}

void BucketManagerV3::printStatistics() const {
  std::cout << "\n=== Bucket Statistics (Implementation 3) ===" << std::endl;
  std::cout << "Effective nonce size: " << effectiveNonceSize_ << " bytes" << std::endl;
  std::cout << "Total entries written: " << getTotalEntriesWritten() << std::endl;

  uint64_t dropped = droppedEntries_.load(std::memory_order_relaxed);
  if (dropped > 0) {
    std::cout << "Dropped entries (bucket full): " << dropped << std::endl;
  }

  uint64_t fullBuckets = 0;
  for (const auto& meta : metadata_) {
    if (meta.entryCount >= Config::bucketCapacity) {
      fullBuckets++;
    }
  }

  std::cout << "Full buckets: " << fullBuckets << " / " << Config::numBuckets << std::endl;
  std::cout << "========================\n" << std::endl;
}

}  // namespace hashchain
