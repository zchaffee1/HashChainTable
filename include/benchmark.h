#ifndef HASHCHAINTABLE_BENCHMARK_H_
#define HASHCHAINTABLE_BENCHMARK_H_

#include <atomic>
#include <chrono>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

#include "config.h"

namespace hashchain {

// High-resolution timer for benchmarking
class Timer {
 public:
  using Clock = std::chrono::high_resolution_clock;
  using TimePoint = Clock::time_point;
  using Duration = std::chrono::duration<double>;

  Timer() : start_(Clock::now()) {}

  void reset() { start_ = Clock::now(); }

  double elapsed() const {
    auto end = Clock::now();
    Duration duration = end - start_;
    return duration.count();
  }

 private:
  TimePoint start_;
};

// Benchmarking statistics
struct BenchmarkStats {
  // Timing statistics (in seconds)
  double totalTime = 0.0;
  double hashGenerationTime = 0.0;
  double sortingTime = 0.0;
  double ioWaitTime = 0.0;
  double writeTime = 0.0;

  // I/O statistics
  std::atomic<uint64_t> totalBytesWritten{0};
  std::atomic<uint64_t> totalWriteOperations{0};
  std::atomic<uint64_t> totalFileOpens{0};
  std::atomic<uint64_t> totalFileCloses{0};

  // Processing statistics
  std::atomic<uint64_t> totalEntriesProcessed{0};
  std::atomic<uint64_t> totalEntriesWritten{0};
  std::atomic<uint64_t> totalBuffersSorted{0};

  // Memory statistics
  size_t peakMemoryUsage = 0;

  void printCSV(const std::string& filename) const {
#ifdef ENABLE_BENCHMARKING
    std::ofstream csv(filename);
    if (!csv.is_open()) {
      std::cerr << "Failed to open CSV file: " << filename << std::endl;
      return;
    }

    // Header
    csv << "metric,value,unit\n";

    // Configuration
    csv << "k_value," << Config::kValue << ",\n";
    csv << "table_size," << Config::tableSize << ",entries\n";
    csv << "nonce_size," << Config::nonceSize << ",bytes\n";
    csv << "bucket_prefix_size," << Config::bucketPrefixSize << ",bytes\n";
    csv << "num_buckets," << Config::numBuckets << ",\n";
    csv << "worker_threads," << Config::numWorkerThreads << ",\n";
    csv << "io_threads," << Config::numIoThreads << ",\n";
    csv << "buffer_size," << Config::workerBufferSize << ",bytes\n";

    // Timing
    csv << "total_time," << totalTime << ",seconds\n";
    csv << "hash_generation_time," << hashGenerationTime << ",seconds\n";
    csv << "sorting_time," << sortingTime << ",seconds\n";
    csv << "io_wait_time," << ioWaitTime << ",seconds\n";
    csv << "write_time," << writeTime << ",seconds\n";

    // I/O Statistics
    csv << "bytes_written," << totalBytesWritten.load(std::memory_order_relaxed) << ",bytes\n";
    csv << "write_operations," << totalWriteOperations.load(std::memory_order_relaxed) << ",\n";
    csv << "file_opens," << totalFileOpens.load(std::memory_order_relaxed) << ",\n";
    csv << "file_closes," << totalFileCloses.load(std::memory_order_relaxed) << ",\n";

    // Processing Statistics
    csv << "entries_processed," << totalEntriesProcessed.load(std::memory_order_relaxed) << ",\n";
    csv << "entries_written," << totalEntriesWritten.load(std::memory_order_relaxed) << ",\n";
    csv << "buffers_sorted," << totalBuffersSorted.load(std::memory_order_relaxed) << ",\n";

    // Derived Metrics
    csv << "entries_per_second," << (totalEntriesProcessed.load(std::memory_order_relaxed) / totalTime) << ",entries/s\n";
    csv << "hash_rate," << (totalEntriesProcessed.load(std::memory_order_relaxed) / hashGenerationTime) << ",hashes/s\n";
    csv << "sort_rate," << (totalEntriesProcessed.load(std::memory_order_relaxed) / sortingTime) << ",entries/s\n";
    csv << "write_throughput_mb," << (totalBytesWritten.load(std::memory_order_relaxed) / 1024.0 / 1024.0 / writeTime) << ",MB/s\n";
    csv << "avg_bytes_per_write," << (totalBytesWritten.load(std::memory_order_relaxed) / (double)totalWriteOperations.load(std::memory_order_relaxed)) << ",bytes\n";

    csv.close();
    std::cout << "Benchmark results written to: " << filename << std::endl;
#endif
  }

  void printReport() const {
#ifdef ENABLE_BENCHMARKING
    std::cout << "\n╔════════════════════════════════════════════════════════════╗"
              << std::endl;
    std::cout << "║          IMPLEMENTATION 1 - BENCHMARK REPORT              ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝\n"
              << std::endl;

    std::cout << "Configuration:" << std::endl;
    std::cout << "  K Value:               " << Config::kValue << " (2^" << Config::kValue
              << " = " << Config::tableSize << " entries)" << std::endl;
    std::cout << "  Nonce Size:            " << Config::nonceSize << " bytes" << std::endl;
    std::cout << "  Hash Prefix Size:      " << Config::bucketPrefixSize << " bytes"
              << std::endl;
    std::cout << "  Number of Buckets:     " << Config::numBuckets << std::endl;
    std::cout << "  Worker Threads:        " << Config::numWorkerThreads << std::endl;
    std::cout << "  I/O Threads:           " << Config::numIoThreads << std::endl;
    std::cout << "  Buffer Size:           " << Config::workerBufferSize << " bytes\n"
              << std::endl;

    std::cout << "Timing Statistics:" << std::endl;
    std::cout << "  Total Time:            " << std::fixed << std::setprecision(3) << totalTime
              << " seconds" << std::endl;
    std::cout << "  Hash Generation:       " << std::fixed << std::setprecision(3)
              << hashGenerationTime << " seconds (" << std::fixed << std::setprecision(1)
              << (hashGenerationTime / totalTime * 100.0) << "%)" << std::endl;
    std::cout << "  Sorting:               " << std::fixed << std::setprecision(3)
              << sortingTime << " seconds (" << std::fixed << std::setprecision(1)
              << (sortingTime / totalTime * 100.0) << "%)" << std::endl;
    std::cout << "  I/O Wait:              " << std::fixed << std::setprecision(3)
              << ioWaitTime << " seconds (" << std::fixed << std::setprecision(1)
              << (ioWaitTime / totalTime * 100.0) << "%)" << std::endl;
    std::cout << "  Disk Write:            " << std::fixed << std::setprecision(3) << writeTime
              << " seconds (" << std::fixed << std::setprecision(1)
              << (writeTime / totalTime * 100.0) << "%)\n" << std::endl;

    std::cout << "Processing Statistics:" << std::endl;
    std::cout << "  Entries Processed:     "
              << totalEntriesProcessed.load(std::memory_order_relaxed) << std::endl;
    std::cout << "  Entries Written:       "
              << totalEntriesWritten.load(std::memory_order_relaxed) << std::endl;
    std::cout << "  Buffers Sorted:        "
              << totalBuffersSorted.load(std::memory_order_relaxed) << std::endl;
    std::cout << "  Entries/Second:        " << std::fixed << std::setprecision(0)
              << (totalEntriesProcessed.load(std::memory_order_relaxed) / totalTime) << "\n"
              << std::endl;

    std::cout << "I/O Statistics:" << std::endl;
    uint64_t bytesWritten = totalBytesWritten.load(std::memory_order_relaxed);
    std::cout << "  Bytes Written:         " << bytesWritten << " bytes ("
              << std::fixed << std::setprecision(2) << (bytesWritten / 1024.0 / 1024.0)
              << " MB)" << std::endl;
    std::cout << "  Write Operations:      "
              << totalWriteOperations.load(std::memory_order_relaxed) << std::endl;
    std::cout << "  Files Opened:          " << totalFileOpens.load(std::memory_order_relaxed)
              << std::endl;
    std::cout << "  Files Closed:          "
              << totalFileCloses.load(std::memory_order_relaxed) << std::endl;
    std::cout << "  Write Throughput:      " << std::fixed << std::setprecision(2)
              << (bytesWritten / 1024.0 / 1024.0 / writeTime) << " MB/s\n" << std::endl;

    std::cout << "Efficiency Metrics:" << std::endl;
    std::cout << "  Avg Bytes/Write Op:    " << std::fixed << std::setprecision(0)
              << (bytesWritten /
                  (double)totalWriteOperations.load(std::memory_order_relaxed))
              << " bytes" << std::endl;
    std::cout << "  Hash Rate:             " << std::fixed << std::setprecision(0)
              << (totalEntriesProcessed.load(std::memory_order_relaxed) /
                  hashGenerationTime)
              << " hashes/second" << std::endl;
    std::cout << "  Sort Rate:             " << std::fixed << std::setprecision(0)
              << (totalEntriesProcessed.load(std::memory_order_relaxed) / sortingTime)
              << " entries/second\n" << std::endl;

    std::cout << "════════════════════════════════════════════════════════════\n"
              << std::endl;
#endif
  }
};

// Global benchmark stats
extern BenchmarkStats g_benchmarkStats;

// Scoped timer that automatically records to a stat
class ScopedTimer {
 public:
  ScopedTimer(double& statRef) : statRef_(statRef), timer_() {}

  ~ScopedTimer() { statRef_ += timer_.elapsed(); }

 private:
  double& statRef_;
  Timer timer_;
};

// Macros for optional benchmarking
#ifdef ENABLE_BENCHMARKING
#define BENCHMARK_TIMER(var) hashchain::Timer var
#define BENCHMARK_SCOPED_TIMER(stat) hashchain::ScopedTimer _scopedTimer(stat)
#define BENCHMARK_RECORD(stat, value) (stat) += (value)
#define BENCHMARK_INCREMENT(atomic_stat) \
  (atomic_stat).fetch_add(1, std::memory_order_relaxed)
#define BENCHMARK_ADD(atomic_stat, value) \
  (atomic_stat).fetch_add((value), std::memory_order_relaxed)
#else
#define BENCHMARK_TIMER(var)
#define BENCHMARK_SCOPED_TIMER(stat)
#define BENCHMARK_RECORD(stat, value)
#define BENCHMARK_INCREMENT(atomic_stat)
#define BENCHMARK_ADD(atomic_stat, value)
#endif

}  // namespace hashchain

#endif  // HASHCHAINTABLE_BENCHMARK_H_
