#ifndef HASHCHAIN_BUCKET_MANAGER_V3_H_
#define HASHCHAIN_BUCKET_MANAGER_V3_H_

#include <atomic>
#include <cstdint>
#include <fstream>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "config.h"
#include "types.h"

namespace hashchain {

// Implementation 3: In-Memory with Dynamic Nonce Size
// Calculates optimal nonce size based on memory limit and stores entire table in memory
class BucketManagerV3 {
 public:
  BucketManagerV3(const std::string& outputDir, size_t memoryLimitMB);
  ~BucketManagerV3();

  // Initialize storage and calculate effective nonce size
  bool initialize();

  // Write sorted entries directly to memory
  void writeSortedEntries(const std::vector<BufferEntry>& entries);

  // Finalize: write entire table to disk
  void finalize();

  // Statistics
  uint64_t getTotalEntriesWritten() const;
  void printStatistics() const;

  // Get the effective nonce size being used (may be less than Config::nonceSize)
  size_t getEffectiveNonceSize() const { return effectiveNonceSize_; }

 private:
  struct BucketMetadata {
    uint64_t entryCount = 0;
    uint64_t fileOffset = 0;  // For final file write
  };

  // Calculate effective nonce size that fits in memory
  size_t calculateEffectiveNonceSize() const;

  // Calculate memory offset for an entry by counter (linear layout)
  uint64_t calculateMemoryOffset(uint64_t entryCounter) const;

  // Write final table to disk
  bool writeTableToFile();

  // Save metadata file
  bool saveMetadata();

  std::string outputDir_;
  std::string dataFilePath_;
  std::string metadataFilePath_;

  size_t memoryLimitBytes_;
  size_t effectiveNonceSize_;  // Actual nonce size used (may be < Config::nonceSize)

  // In-memory storage
  std::unique_ptr<uint8_t[]> memoryTable_;
  std::vector<BucketMetadata> metadata_;

  // Thread safety
  std::mutex writeMutex_;

  // Statistics
  std::atomic<uint64_t> totalEntriesWritten_{0};
  std::atomic<uint64_t> droppedEntries_{0};  // Entries that didn't fit
};

}  // namespace hashchain

#endif  // HASHCHAIN_BUCKET_MANAGER_V3_H_
