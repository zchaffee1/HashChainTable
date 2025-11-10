#include "bucket_manager_v2.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "benchmark.h"

namespace hashchain {

BucketManagerV2::BucketManagerV2(const std::string& outputDir, size_t memoryLimitMB)
    : outputDir_(outputDir), memoryLimitBytes_(memoryLimitMB * 1024 * 1024) {
  dataFilePath_ = outputDir_ + "/buckets.dat";
  metadataFilePath_ = outputDir_ + "/buckets.meta";
  metadata_.resize(Config::numBuckets);
}

BucketManagerV2::~BucketManagerV2() {
  finalize();
}

uint64_t BucketManagerV2::calculateBucketOffset(BucketId id) const {
  return static_cast<uint64_t>(id) * Config::bucketCapacity * Config::nonceSize;
}

bool BucketManagerV2::preallocateDataFile() {
  // Calculate total file size needed
  uint64_t totalSize =
      static_cast<uint64_t>(Config::numBuckets) * Config::bucketCapacity * Config::nonceSize;

  std::cout << "Pre-allocating bucket file: " << dataFilePath_ << std::endl;
  std::cout << "Total size: " << (totalSize / 1024.0 / 1024.0 / 1024.0) << " GB" << std::endl;

  // Open file for writing
  dataFile_ = std::make_unique<std::fstream>(dataFilePath_,
                                              std::ios::binary | std::ios::in | std::ios::out |
                                                  std::ios::trunc);

  if (!dataFile_->is_open()) {
    std::cerr << "Failed to create bucket file: " << dataFilePath_ << std::endl;
    return false;
  }

  // Try to use posix_fallocate for efficient preallocation
#ifdef __linux__
  dataFile_->close();

  // Use system call directly for efficient allocation
  int file_fd = open(dataFilePath_.c_str(), O_RDWR | O_CREAT, 0644);
  if (file_fd >= 0) {
    std::cout << "Using posix_fallocate for fast allocation..." << std::endl;
    int result = posix_fallocate(file_fd, 0, totalSize);
    close(file_fd);

    if (result == 0) {
      // Reopen as fstream
      dataFile_ = std::make_unique<std::fstream>(dataFilePath_,
                                                  std::ios::binary | std::ios::in | std::ios::out);
      std::cout << "File pre-allocated successfully" << std::endl;
      return dataFile_->is_open();
    } else {
      std::cout << "posix_fallocate failed (error " << result
                << "), falling back to manual write..." << std::endl;
    }
  }
#endif

  // Fallback: Write zeros in chunks to create dense file
  dataFile_ = std::make_unique<std::fstream>(dataFilePath_,
                                              std::ios::binary | std::ios::in | std::ios::out |
                                                  std::ios::trunc);

  std::cout << "Writing zeros to create dense file (this may take a while)..." << std::endl;

  const size_t chunkSize = 64 * 1024 * 1024;  // 64MB chunks
  std::vector<uint8_t> zeroChunk(chunkSize, 0);

  uint64_t written = 0;
  while (written < totalSize) {
    size_t toWrite = std::min(chunkSize, static_cast<size_t>(totalSize - written));
    dataFile_->write(reinterpret_cast<const char*>(zeroChunk.data()), toWrite);

    if (!dataFile_->good()) {
      std::cerr << "Failed to write to bucket file" << std::endl;
      return false;
    }

    written += toWrite;

    // Progress indicator
    if (written % (1024ULL * 1024 * 1024) == 0) {
      std::cout << "  Written: " << (written / 1024.0 / 1024.0 / 1024.0) << " GB" << std::endl;
    }
  }

  dataFile_->flush();
  std::cout << "File pre-allocation complete" << std::endl;

  return true;
}

bool BucketManagerV2::initialize() {
  // Create output directory
  mkdir(outputDir_.c_str(), 0755);

  std::cout << "\n=== Implementation 2: Single-File Offset-Based Buckets ===" << std::endl;
  std::cout << "Memory limit: " << (memoryLimitBytes_ / 1024.0 / 1024.0) << " MB" << std::endl;
  std::cout << "Bucket count: " << Config::numBuckets << std::endl;
  std::cout << "Bucket capacity: " << Config::bucketCapacity << " entries" << std::endl;

  // Initialize all bucket offsets
  for (size_t i = 0; i < Config::numBuckets; ++i) {
    metadata_[i].fileOffset = calculateBucketOffset(i);
    metadata_[i].entryCount = 0;
  }

  // Pre-allocate the data file
  if (!preallocateDataFile()) {
    return false;
  }

  std::cout << "Initialization complete\n" << std::endl;
  return true;
}

BucketManagerV2::BucketBuffer* BucketManagerV2::getBucketBuffer(BucketId id) {
  std::lock_guard<std::mutex> lock(cacheMutex_);

  // Check if already in cache
  auto it = bucketCache_.find(id);
  if (it != bucketCache_.end()) {
    BENCHMARK_INCREMENT(cacheHits_);
    it->second->lastAccessTime = accessCounter_.fetch_add(1, std::memory_order_relaxed);
    return it->second.get();
  }

  BENCHMARK_INCREMENT(cacheMisses_);

  // Check if we need to evict
  while (currentMemoryUsage_ + (Config::bucketCapacity * Config::nonceSize) > memoryLimitBytes_) {
    evictLRUBucket();
  }

  // Create new buffer
  auto buffer = std::make_unique<BucketBuffer>();
  buffer->lastAccessTime = accessCounter_.fetch_add(1, std::memory_order_relaxed);

  // If bucket has existing data, load it (we'll only write new data)
  // For now, we start fresh since we're generating

  currentMemoryUsage_ += Config::bucketCapacity * Config::nonceSize;

  auto* bufferPtr = buffer.get();
  bucketCache_[id] = std::move(buffer);

  return bufferPtr;
}

void BucketManagerV2::evictLRUBucket() {
  if (bucketCache_.empty()) {
    return;
  }

  // Find LRU bucket
  BucketId lruId = 0;
  uint64_t lruTime = UINT64_MAX;

  for (const auto& [id, buffer] : bucketCache_) {
    if (buffer->lastAccessTime < lruTime) {
      lruTime = buffer->lastAccessTime;
      lruId = id;
    }
  }

  // Flush if dirty
  auto& buffer = bucketCache_[lruId];
  if (buffer->dirty) {
    flushBucket(lruId, buffer.get());
  }

  // Remove from cache
  currentMemoryUsage_ -= Config::bucketCapacity * Config::nonceSize;
  bucketCache_.erase(lruId);

  BENCHMARK_INCREMENT(cacheEvictions_);
}

void BucketManagerV2::flushBucket(BucketId id, BucketBuffer* buffer) {
  if (!buffer->dirty || buffer->entryCount == 0) {
    return;
  }

  BENCHMARK_TIMER(writeTimer);

  // Seek to bucket offset
  uint64_t offset = metadata_[id].fileOffset;
  dataFile_->seekp(offset, std::ios::beg);

  // Write bucket data
  size_t bytesToWrite = buffer->entryCount * Config::nonceSize;
  dataFile_->write(reinterpret_cast<const char*>(buffer->data.data()), bytesToWrite);

  if (!dataFile_->good()) {
    std::cerr << "Failed to write to bucket file at offset " << offset << std::endl;
  }

#ifdef ENABLE_BENCHMARKING
  BENCHMARK_RECORD(g_benchmarkStats.writeTime, writeTimer.elapsed());
  BENCHMARK_ADD(g_benchmarkStats.totalBytesWritten, bytesToWrite);
  BENCHMARK_INCREMENT(g_benchmarkStats.totalWriteOperations);
#endif

  // Update metadata
  metadata_[id].entryCount = buffer->entryCount;

  buffer->dirty = false;
}

void BucketManagerV2::writeSortedEntries(const std::vector<BufferEntry>& entries) {
  if (entries.empty()) {
    return;
  }

  std::lock_guard<std::mutex> lock(cacheMutex_);

  // Process entries (they're already sorted by bucket ID)
  for (const auto& entry : entries) {
    BucketId bucketId = entry.bucketId;

    // Skip if bucket is full
    if (metadata_[bucketId].entryCount >= Config::bucketCapacity) {
      continue;
    }

    // Get buffer for this bucket
    BucketBuffer* buffer = getBucketBuffer(bucketId);

    // Add nonce to buffer
    size_t offset = buffer->entryCount * Config::nonceSize;
    std::memcpy(buffer->data.data() + offset, entry.nonce.data(), Config::nonceSize);

    buffer->entryCount++;
    buffer->dirty = true;

    totalEntriesWritten_.fetch_add(1, std::memory_order_relaxed);
    BENCHMARK_ADD(g_benchmarkStats.totalEntriesWritten, 1);

    // Check if buffer should be flushed (full or hitting memory limit)
    if (buffer->entryCount >= Config::bucketCapacity) {
      flushBucket(bucketId, buffer);
    }
  }
}

void BucketManagerV2::finalize() {
  std::cout << "Finalizing buckets..." << std::endl;

  // Flush all cached buckets
  std::lock_guard<std::mutex> lock(cacheMutex_);
  for (auto& [id, buffer] : bucketCache_) {
    if (buffer->dirty) {
      flushBucket(id, buffer.get());
    }
  }

  // Flush file
  if (dataFile_ && dataFile_->is_open()) {
    dataFile_->flush();
    dataFile_->close();
  }

  // Save metadata
  saveMetadata();

  std::cout << "Finalization complete" << std::endl;
}

bool BucketManagerV2::saveMetadata() {
  std::ofstream metaFile(metadataFilePath_, std::ios::binary | std::ios::trunc);
  if (!metaFile.is_open()) {
    std::cerr << "Failed to create metadata file: " << metadataFilePath_ << std::endl;
    return false;
  }

  // Write header
  uint32_t version = 2;  // Implementation version
  metaFile.write(reinterpret_cast<const char*>(&version), sizeof(version));

  uint64_t numBuckets = Config::numBuckets;
  metaFile.write(reinterpret_cast<const char*>(&numBuckets), sizeof(numBuckets));

  // Write metadata for each bucket
  for (const auto& meta : metadata_) {
    metaFile.write(reinterpret_cast<const char*>(&meta.entryCount), sizeof(meta.entryCount));
    metaFile.write(reinterpret_cast<const char*>(&meta.fileOffset), sizeof(meta.fileOffset));
  }

  metaFile.close();
  return true;
}

bool BucketManagerV2::loadMetadata() {
  std::ifstream metaFile(metadataFilePath_, std::ios::binary);
  if (!metaFile.is_open()) {
    return false;  // File doesn't exist yet
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

uint64_t BucketManagerV2::getTotalEntriesWritten() const {
  return totalEntriesWritten_.load(std::memory_order_relaxed);
}

void BucketManagerV2::printStatistics() const {
  std::cout << "\n=== Bucket Statistics (Implementation 2) ===" << std::endl;
  std::cout << "Total entries written: " << getTotalEntriesWritten() << std::endl;

  uint64_t fullBuckets = 0;
  for (const auto& meta : metadata_) {
    if (meta.entryCount >= Config::bucketCapacity) {
      fullBuckets++;
    }
  }

  std::cout << "Full buckets: " << fullBuckets << " / " << Config::numBuckets << std::endl;

#ifdef ENABLE_BENCHMARKING
  std::cout << "Cache hits: " << cacheHits_.load(std::memory_order_relaxed) << std::endl;
  std::cout << "Cache misses: " << cacheMisses_.load(std::memory_order_relaxed) << std::endl;
  std::cout << "Cache evictions: " << cacheEvictions_.load(std::memory_order_relaxed) << std::endl;

  uint64_t totalAccess = cacheHits_.load(std::memory_order_relaxed) +
                         cacheMisses_.load(std::memory_order_relaxed);
  if (totalAccess > 0) {
    double hitRate = (cacheHits_.load(std::memory_order_relaxed) * 100.0) / totalAccess;
    std::cout << "Cache hit rate: " << std::fixed << std::setprecision(2) << hitRate << "%"
              << std::endl;
  }
#endif

  std::cout << "========================\n" << std::endl;
}

}  // namespace hashchain
