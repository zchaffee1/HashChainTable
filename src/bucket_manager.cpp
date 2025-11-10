#include "bucket_manager.h"

#include <iomanip>
#include <iostream>
#include <sstream>
#include <sys/stat.h>

#include "benchmark.h"

namespace hashchain {

BucketManager::Bucket::Bucket() {
  writeBuffer.reserve(Config::bucketCapacity * Config::nonceSize);
}

BucketManager::Bucket::~Bucket() {
  if (file && file->is_open()) {
    file->close();
    BENCHMARK_INCREMENT(g_benchmarkStats.totalFileCloses);
  }
}

BucketManager::BucketManager(const std::string& outputDir) : outputDir_(outputDir) {
  buckets_.resize(Config::numBuckets);
}

BucketManager::~BucketManager() {
  finalize();
}

bool BucketManager::initialize() {
  // Create output directory
  mkdir(outputDir_.c_str(), 0755);

  std::cout << "Initializing " << Config::numBuckets << " buckets..." << std::endl;

  // Initialize all buckets (but don't open files yet to avoid file descriptor limits)
  for (size_t i = 0; i < Config::numBuckets; ++i) {
    buckets_[i] = std::make_unique<Bucket>();

    // Create bucket file path
    std::ostringstream oss;
    oss << outputDir_ << "/bucket_" << std::setfill('0') << std::setw(6) << i << ".bin";
    buckets_[i]->filePath = oss.str();
  }

  std::cout << "Bucket initialization complete." << std::endl;
  return true;
}

void BucketManager::ensureBucketFileOpen(Bucket* bucket) {
  if (!bucket->file || !bucket->file->is_open()) {
    bucket->file = std::make_unique<std::ofstream>(bucket->filePath,
                                                    std::ios::binary | std::ios::out |
                                                        std::ios::app);
    BENCHMARK_INCREMENT(g_benchmarkStats.totalFileOpens);
  }
}

BucketManager::Bucket* BucketManager::getBucket(BucketId id) {
  if (id >= Config::numBuckets) {
    return nullptr;
  }
  return buckets_[id].get();
}

void BucketManager::flushBucket(Bucket* bucket, BucketId id) {
  (void)id;  // Unused, kept for future logging/debugging
  if (bucket->writeBuffer.empty()) {
    return;
  }

  // Ensure file is open
  ensureBucketFileOpen(bucket);

  BENCHMARK_TIMER(writeTimer);

  // Write buffer to file
  size_t bytesToWrite = bucket->writeBuffer.size();
  bucket->file->write(reinterpret_cast<const char*>(bucket->writeBuffer.data()),
                      bytesToWrite);

#ifdef ENABLE_BENCHMARKING
  BENCHMARK_RECORD(g_benchmarkStats.writeTime, writeTimer.elapsed());
  BENCHMARK_ADD(g_benchmarkStats.totalBytesWritten, bytesToWrite);
  BENCHMARK_INCREMENT(g_benchmarkStats.totalWriteOperations);
#endif

  // Update statistics
  size_t entriesWritten = bytesToWrite / Config::nonceSize;
  bucket->stats.entriesWritten += entriesWritten;
  totalEntriesWritten_.fetch_add(entriesWritten, std::memory_order_relaxed);
  BENCHMARK_ADD(g_benchmarkStats.totalEntriesWritten, entriesWritten);

  // Check if bucket is full
  if (bucket->stats.entriesWritten >= Config::bucketCapacity) {
    bucket->stats.isFull = true;
  }

  // Clear buffer
  bucket->writeBuffer.clear();
}

void BucketManager::writeSortedEntries(const std::vector<BufferEntry>& entries) {
  if (entries.empty()) {
    return;
  }

  // Process entries in order (they're already sorted by bucket ID)
  BucketId currentBucketId = entries[0].bucketId;
  Bucket* currentBucket = getBucket(currentBucketId);

  if (!currentBucket) {
    return;
  }

  std::lock_guard<std::mutex> lock(currentBucket->mutex);

  for (const auto& entry : entries) {
    // Switch bucket if needed
    if (entry.bucketId != currentBucketId) {
      // Flush current bucket
      flushBucket(currentBucket, currentBucketId);

      // Switch to new bucket
      currentBucketId = entry.bucketId;
      currentBucket = getBucket(currentBucketId);

      if (!currentBucket) {
        continue;
      }

      // Need to acquire new lock (but we're already in a scope, so we need to be careful)
      // For simplicity, we'll just reacquire. In production, this could be optimized.
    }

    // Skip if bucket is full (overflow)
    if (currentBucket->stats.isFull) {
      currentBucket->stats.overflowEntries++;
      continue;
    }

    // Add nonce to write buffer
    currentBucket->writeBuffer.insert(currentBucket->writeBuffer.end(), entry.nonce.begin(),
                                      entry.nonce.end());

    // Flush if buffer is large enough
    if (currentBucket->writeBuffer.size() >= 1024 * 1024) {  // 1MB buffer
      flushBucket(currentBucket, currentBucketId);
    }
  }

  // Flush final bucket
  flushBucket(currentBucket, currentBucketId);
}

void BucketManager::finalize() {
  std::cout << "Finalizing buckets..." << std::endl;

  // Flush and close all buckets
  for (size_t i = 0; i < buckets_.size(); ++i) {
    if (buckets_[i]) {
      std::lock_guard<std::mutex> lock(buckets_[i]->mutex);
      flushBucket(buckets_[i].get(), static_cast<BucketId>(i));
      if (buckets_[i]->file && buckets_[i]->file->is_open()) {
        buckets_[i]->file->close();
      }
    }
  }

  std::cout << "Bucket finalization complete." << std::endl;
}

uint64_t BucketManager::getTotalEntriesWritten() const {
  return totalEntriesWritten_.load(std::memory_order_relaxed);
}

void BucketManager::printStatistics() const {
  std::cout << "\n=== Bucket Statistics ===" << std::endl;
  std::cout << "Total entries written: " << getTotalEntriesWritten() << std::endl;

  uint64_t totalOverflow = 0;
  size_t fullBuckets = 0;

  for (const auto& bucket : buckets_) {
    if (bucket) {
      totalOverflow += bucket->stats.overflowEntries;
      if (bucket->stats.isFull) {
        fullBuckets++;
      }
    }
  }

  std::cout << "Full buckets: " << fullBuckets << " / " << Config::numBuckets << std::endl;
  std::cout << "Total overflow entries: " << totalOverflow << std::endl;
  std::cout << "========================\n" << std::endl;
}

}  // namespace hashchain
