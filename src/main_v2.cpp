#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include "benchmark.h"
#include "bucket_manager_v2.h"
#include "config.h"
#include "hash_generator.h"
#include "thread_pool.h"

int main(int argc, char* argv[]) {
  // Parse command line arguments
  std::string outputDir = "buckets";
  std::string csvFile = "";

  if (argc > 1) {
    outputDir = argv[1];
  }
  if (argc > 2) {
    csvFile = argv[2];
  }

  std::cout << "HashChainTable Generator (Implementation 2)" << std::endl;
  std::cout << "Output directory: " << outputDir << std::endl;
  std::cout << "Memory limit: " << MEMORY_LIMIT_MB << " MB" << std::endl;
  if (!csvFile.empty()) {
    std::cout << "CSV output: " << csvFile << std::endl;
  }
  std::cout << std::endl;

  // Create work coordinator with Implementation 2
  // We need to modify WorkCoordinator to accept BucketManagerV2
  // For now, let's create a simple inline version

  std::cout << "\n=== HashChainTable Generator ===" << std::endl;
  std::cout << "Configuration:" << std::endl;
  std::cout << "  K Value:               " << hashchain::Config::kValue << " (2^"
            << hashchain::Config::kValue << " = " << hashchain::Config::tableSize << " entries)"
            << std::endl;
  std::cout << "  Nonce Size:            " << hashchain::Config::nonceSize << " bytes"
            << std::endl;
  std::cout << "  Hash Prefix Size:      " << hashchain::Config::bucketPrefixSize << " bytes"
            << std::endl;
  std::cout << "  Number of Buckets:     " << hashchain::Config::numBuckets << std::endl;
  std::cout << "  Worker Threads:        " << hashchain::Config::numWorkerThreads << std::endl;
  std::cout << "  I/O Threads:           " << hashchain::Config::numIoThreads << std::endl;
  std::cout << "  Buffer Size:           " << hashchain::Config::workerBufferSize << " bytes\n"
            << std::endl;

  // Create bucket manager V2
  hashchain::BucketManagerV2 bucketManager(outputDir, MEMORY_LIMIT_MB);
  if (!bucketManager.initialize()) {
    std::cerr << "Failed to initialize bucket manager" << std::endl;
    return 1;
  }

  // Create thread pools
  hashchain::ThreadPool workerPool(hashchain::Config::numWorkerThreads);
  hashchain::ThreadPool ioPool(hashchain::Config::numIoThreads);

  auto startTime = std::chrono::high_resolution_clock::now();

  std::cout << "Starting generation..." << std::endl;

  const uint64_t entriesPerWorker = hashchain::Config::entriesPerWorker;
  const uint64_t totalEntries = hashchain::Config::tableSize;
  std::atomic<uint64_t> processedEntries{0};

  // Distribute work among worker threads
  for (size_t i = 0; i < hashchain::Config::numWorkerThreads; ++i) {
    uint64_t startCounter = i * entriesPerWorker;
    uint64_t count = entriesPerWorker;

    if (i == hashchain::Config::numWorkerThreads - 1) {
      count = totalEntries - startCounter;
    }

    workerPool.submit([&, startCounter, count]() {
      hashchain::HashGenerator generator;
      const size_t chunkSize = hashchain::Config::bufferEntries;
      uint64_t remaining = count;
      uint64_t current = startCounter;

      while (remaining > 0) {
        size_t batchSize = std::min(static_cast<size_t>(remaining), chunkSize);
        std::vector<hashchain::BufferEntry> buffer;
        buffer.reserve(batchSize);

        generator.processNonceBatch(current, batchSize, buffer);

        ioPool.submit([&bucketManager, buffer = std::move(buffer)]() mutable {
          bucketManager.writeSortedEntries(buffer);
        });

        processedEntries.fetch_add(batchSize, std::memory_order_relaxed);
        current += batchSize;
        remaining -= batchSize;
      }
    });
  }

  // Monitor progress
  std::cout << "Processing entries..." << std::endl;
  while (processedEntries.load(std::memory_order_relaxed) < totalEntries) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    double progress = static_cast<double>(processedEntries.load(std::memory_order_relaxed)) /
                      static_cast<double>(totalEntries);
    std::cout << "\rProgress: " << std::fixed << std::setprecision(2) << (progress * 100.0)
              << "% (" << processedEntries.load(std::memory_order_relaxed) << " / " << totalEntries
              << " entries)" << std::flush;
  }
  std::cout << std::endl;

  // Wait for all work to complete
  std::cout << "Waiting for workers to complete..." << std::endl;
  workerPool.waitAll();

  std::cout << "Waiting for I/O operations to complete..." << std::endl;
  hashchain::Timer ioWaitTimer;
  ioPool.waitAll();
  BENCHMARK_RECORD(hashchain::g_benchmarkStats.ioWaitTime, ioWaitTimer.elapsed());

  bucketManager.finalize();

  auto endTime = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = endTime - startTime;

#ifdef ENABLE_BENCHMARKING
  hashchain::g_benchmarkStats.totalTime = duration.count();
#endif

  std::cout << "\nGeneration complete!" << std::endl;
  std::cout << "Total time: " << std::fixed << std::setprecision(3) << duration.count()
            << " seconds" << std::endl;
  std::cout << "Entries per second: " << std::fixed << std::setprecision(0)
            << (totalEntries / std::max(0.001, duration.count())) << std::endl;

  bucketManager.printStatistics();

#ifdef ENABLE_BENCHMARKING
  hashchain::g_benchmarkStats.printReport();
#endif

  // Export CSV if requested
  if (!csvFile.empty()) {
#ifdef ENABLE_BENCHMARKING
    hashchain::g_benchmarkStats.printCSV(csvFile);
#else
    std::cerr << "Warning: Benchmarking disabled, CSV output not available" << std::endl;
#endif
  }

  std::cout << "\nSuccess! Hash chain table generated in: " << outputDir << std::endl;

  return 0;
}
