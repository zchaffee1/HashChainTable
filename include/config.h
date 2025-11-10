#ifndef HASHCHAINTABLE_CONFIG_H_
#define HASHCHAINTABLE_CONFIG_H_

#include <cstddef>
#include <cstdint>

namespace hashchain {

// Compile-time configuration constants
// These are defined by CMake during compilation for maximum efficiency
struct Config {
  // Table generation parameters
  static constexpr uint32_t kValue = K_VALUE;
  static constexpr uint64_t tableSize = 1ULL << K_VALUE;

  // Data sizes
  static constexpr size_t nonceSize = NONCE_SIZE;
  static constexpr size_t hashSize = HASH_SIZE;
  static constexpr size_t bucketPrefixSize = BUCKET_PREFIX_SIZE;

  // Bucket configuration
  static constexpr size_t bucketCapacity = BUCKET_CAPACITY;
  static constexpr size_t numBuckets = 1ULL << (BUCKET_PREFIX_SIZE * 8);

  // Threading configuration
  static constexpr size_t numWorkerThreads = NUM_WORKER_THREADS;
  static constexpr size_t numIoThreads = NUM_IO_THREADS;
  static constexpr size_t workerBufferSize = WORKER_BUFFER_SIZE;

  // Calculated constants
  static constexpr size_t entriesPerWorker = tableSize / numWorkerThreads;
  static constexpr size_t bufferEntries = workerBufferSize / nonceSize;

  // Verify configuration sanity at compile time
  static_assert(nonceSize >= 1 && nonceSize <= 8, "Nonce size must be 1-8 bytes");
  static_assert(hashSize >= 1 && hashSize <= 32, "Hash size must be 1-32 bytes");
  static_assert(bucketPrefixSize <= hashSize, "Bucket prefix must fit in hash");
  static_assert(bucketPrefixSize >= 1 && bucketPrefixSize <= 4,
                "Bucket prefix must be 1-4 bytes");
  static_assert(numWorkerThreads > 0, "Must have at least 1 worker thread");
  static_assert(numIoThreads > 0, "Must have at least 1 I/O thread");
};

}  // namespace hashchain

#endif  // HASHCHAINTABLE_CONFIG_H_
