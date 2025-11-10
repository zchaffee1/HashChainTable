#include "hash_generator.h"

#include <algorithm>
#include <cstring>

#include "benchmark.h"

namespace hashchain {

HashGenerator::HashGenerator() {
  blake3_hasher_init(&hasher_);
}

HashGenerator::~HashGenerator() {}

HashPrefix HashGenerator::computeHashPrefix(const Nonce& nonce) {
  // Reset hasher for new computation
  blake3_hasher_init(&hasher_);

  // Hash the nonce
  blake3_hasher_update(&hasher_, nonce.data(), nonce.size());

  // Only extract the prefix we need (optimization)
  uint8_t output[Config::bucketPrefixSize];
  blake3_hasher_finalize(&hasher_, output, Config::bucketPrefixSize);

  // Copy to HashPrefix
  HashPrefix prefix;
  std::memcpy(prefix.data(), output, Config::bucketPrefixSize);

  return prefix;
}

size_t HashGenerator::processNonceBatch(uint64_t startCounter, size_t count,
                                        std::vector<BufferEntry>& buffer) {
  BENCHMARK_TIMER(hashTimer);
  BENCHMARK_TIMER(sortTimer);

  // Pre-allocate buffer space
  buffer.clear();
  buffer.reserve(count);

  // Process each nonce in the batch
  for (size_t i = 0; i < count; ++i) {
    uint64_t counter = startCounter + i;

    // Convert counter to nonce
    Nonce nonce = counterToNonce(counter);

    // Compute hash prefix
    HashPrefix prefix = computeHashPrefix(nonce);

    // Convert to bucket ID
    BucketId bucketId = hashPrefixToBucketId(prefix);

    // Add to buffer
    buffer.push_back({nonce, bucketId});
  }

#ifdef ENABLE_BENCHMARKING
  double hashTime = hashTimer.elapsed();
  BENCHMARK_RECORD(g_benchmarkStats.hashGenerationTime, hashTime);
  BENCHMARK_ADD(g_benchmarkStats.totalEntriesProcessed, count);
#endif

  // Sort buffer by bucket ID for better locality during writes
  // This is a critical optimization for reducing random I/O
  std::sort(buffer.begin(), buffer.end());

#ifdef ENABLE_BENCHMARKING
  double sortTime = sortTimer.elapsed() - hashTime;
  BENCHMARK_RECORD(g_benchmarkStats.sortingTime, sortTime);
  BENCHMARK_INCREMENT(g_benchmarkStats.totalBuffersSorted);
#endif

  return buffer.size();
}

}  // namespace hashchain
