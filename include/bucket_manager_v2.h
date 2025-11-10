#ifndef HASHCHAINTABLE_BUCKET_MANAGER_V2_H_
#define HASHCHAINTABLE_BUCKET_MANAGER_V2_H_

#include <atomic>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "config.h"
#include "types.h"

namespace hashchain {

// Single-file bucket manager with offset-based storage
// Implementation 2: All buckets in one file, memory-limited caching
class BucketManagerV2 {
 public:
  BucketManagerV2(const std::string& outputDir, size_t memoryLimitMB);
  ~BucketManagerV2();

  // Initialize the single bucket file and metadata
  bool initialize();

  // Write sorted entries to buckets (same interface as V1)
  void writeSortedEntries(const std::vector<BufferEntry>& entries);

  // Finalize and close bucket file
  void finalize();

  // Get statistics
  uint64_t getTotalEntriesWritten() const;
  void printStatistics() const;

 private:
  struct BucketBuffer {
    std::vector<uint8_t> data;
    uint16_t entryCount = 0;
    bool dirty = false;
    uint64_t lastAccessTime = 0;

    BucketBuffer() { data.reserve(Config::bucketCapacity * Config::nonceSize); }
  };

  struct BucketMetadata {
    uint16_t entryCount = 0;
    uint64_t fileOffset = 0;
  };

  std::string outputDir_;
  std::string dataFilePath_;
  std::string metadataFilePath_;

  // Single data file for all buckets
  std::unique_ptr<std::fstream> dataFile_;

  // Bucket metadata (entry counts and offsets)
  std::vector<BucketMetadata> metadata_;

  // In-memory cache of bucket buffers (LRU)
  std::map<BucketId, std::unique_ptr<BucketBuffer>> bucketCache_;
  std::mutex cacheMutex_;

  // Memory management
  size_t memoryLimitBytes_;
  size_t currentMemoryUsage_ = 0;
  std::atomic<uint64_t> accessCounter_{0};

  // Statistics
  std::atomic<uint64_t> totalEntriesWritten_{0};
  std::atomic<uint64_t> cacheHits_{0};
  std::atomic<uint64_t> cacheMisses_{0};
  std::atomic<uint64_t> cacheEvictions_{0};

  // Pre-allocate the entire data file
  bool preallocateDataFile();

  // Get or load bucket buffer from cache
  BucketBuffer* getBucketBuffer(BucketId id);

  // Flush a bucket buffer to disk at its offset
  void flushBucket(BucketId id, BucketBuffer* buffer);

  // Evict least-recently-used bucket from cache
  void evictLRUBucket();

  // Calculate file offset for a bucket
  uint64_t calculateBucketOffset(BucketId id) const;

  // Load metadata from file
  bool loadMetadata();

  // Save metadata to file
  bool saveMetadata();
};

}  // namespace hashchain

#endif  // HASHCHAINTABLE_BUCKET_MANAGER_V2_H_
