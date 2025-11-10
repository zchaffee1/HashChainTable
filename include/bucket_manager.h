#ifndef HASHCHAINTABLE_BUCKET_MANAGER_H_
#define HASHCHAINTABLE_BUCKET_MANAGER_H_

#include <atomic>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "config.h"
#include "types.h"

namespace hashchain {

// Manages bucket files and writes nonces to appropriate buckets
class BucketManager {
 public:
  explicit BucketManager(const std::string& outputDir);
  ~BucketManager();

  // Initialize bucket files
  bool initialize();

  // Write a batch of sorted entries to their respective buckets
  // This is called by I/O threads after worker threads sort their buffers
  void writeSortedEntries(const std::vector<BufferEntry>& entries);

  // Finalize and close all buckets
  void finalize();

  // Get statistics
  uint64_t getTotalEntriesWritten() const;
  void printStatistics() const;

 private:
  struct Bucket {
    std::unique_ptr<std::ofstream> file;
    std::mutex mutex;
    BucketStats stats;
    std::vector<uint8_t> writeBuffer;
    std::string filePath;

    Bucket();
    ~Bucket();
  };

  std::string outputDir_;
  std::vector<std::unique_ptr<Bucket>> buckets_;
  std::atomic<uint64_t> totalEntriesWritten_{0};

  // Get bucket for a given ID
  Bucket* getBucket(BucketId id);

  // Ensure bucket file is open
  void ensureBucketFileOpen(Bucket* bucket);

  // Flush a bucket's write buffer to disk
  void flushBucket(Bucket* bucket, BucketId id);
};

}  // namespace hashchain

#endif  // HASHCHAINTABLE_BUCKET_MANAGER_H_
