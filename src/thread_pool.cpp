#include "thread_pool.h"

#include <chrono>
#include <iomanip>
#include <iostream>

#include "benchmark.h"
#include "bucket_manager.h"
#include "hash_generator.h"

namespace hashchain {

// ============================================================================
// ThreadPool Implementation
// ============================================================================

ThreadPool::ThreadPool(size_t numThreads) {
  threads_.reserve(numThreads);
  for (size_t i = 0; i < numThreads; ++i) {
    threads_.emplace_back(&ThreadPool::workerThread, this);
  }
}

ThreadPool::~ThreadPool() {
  stop_.store(true, std::memory_order_release);
  condition_.notify_all();

  for (auto& thread : threads_) {
    if (thread.joinable()) {
      thread.join();
    }
  }
}

void ThreadPool::submit(std::function<void()> task) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    tasks_.push(std::move(task));
    activeTasks_.fetch_add(1, std::memory_order_relaxed);
  }
  condition_.notify_one();
}

void ThreadPool::waitAll() {
  std::unique_lock<std::mutex> lock(mutex_);
  completionCondition_.wait(lock, [this] {
    return tasks_.empty() && activeTasks_.load(std::memory_order_relaxed) == 0;
  });
}

void ThreadPool::workerThread() {
  while (true) {
    std::function<void()> task;

    {
      std::unique_lock<std::mutex> lock(mutex_);
      condition_.wait(lock, [this] {
        return stop_.load(std::memory_order_acquire) || !tasks_.empty();
      });

      if (stop_.load(std::memory_order_acquire) && tasks_.empty()) {
        return;
      }

      if (!tasks_.empty()) {
        task = std::move(tasks_.front());
        tasks_.pop();
      }
    }

    if (task) {
      task();
      size_t remaining = activeTasks_.fetch_sub(1, std::memory_order_relaxed) - 1;
      if (remaining == 0) {
        completionCondition_.notify_all();
      }
    }
  }
}

// ============================================================================
// WorkCoordinator Implementation
// ============================================================================

WorkCoordinator::WorkCoordinator() {}

WorkCoordinator::~WorkCoordinator() {}

bool WorkCoordinator::initialize(const std::string& outputDir) {
  std::cout << "\n=== HashChainTable Generator ===" << std::endl;
  std::cout << "Configuration:" << std::endl;
  std::cout << "  K Value: " << Config::kValue << " (2^" << Config::kValue << " = "
            << Config::tableSize << " entries)" << std::endl;
  std::cout << "  Nonce Size: " << Config::nonceSize << " bytes" << std::endl;
  std::cout << "  Hash Size: " << Config::hashSize << " bytes" << std::endl;
  std::cout << "  Bucket Prefix: " << Config::bucketPrefixSize << " bytes" << std::endl;
  std::cout << "  Number of Buckets: " << Config::numBuckets << std::endl;
  std::cout << "  Bucket Capacity: " << Config::bucketCapacity << " entries" << std::endl;
  std::cout << "  Worker Threads: " << Config::numWorkerThreads << std::endl;
  std::cout << "  I/O Threads: " << Config::numIoThreads << std::endl;
  std::cout << "  Buffer Size: " << Config::workerBufferSize << " bytes" << std::endl;
  std::cout << "=================================\n" << std::endl;

  // Create thread pools
  workerPool_ = std::make_unique<ThreadPool>(Config::numWorkerThreads);
  ioPool_ = std::make_unique<ThreadPool>(Config::numIoThreads);

  // Create bucket manager
  bucketManager_ = std::make_unique<BucketManager>(outputDir);
  if (!bucketManager_->initialize()) {
    std::cerr << "Failed to initialize bucket manager" << std::endl;
    return false;
  }

  return true;
}

void WorkCoordinator::workerTask(uint64_t startCounter, uint64_t count) {
  // Create hash generator for this thread (thread-local)
  HashGenerator generator;

  // Process in chunks to maintain good buffer sizes
  const size_t chunkSize = Config::bufferEntries;
  uint64_t remaining = count;
  uint64_t current = startCounter;

  while (remaining > 0) {
    size_t batchSize = std::min(static_cast<size_t>(remaining), chunkSize);

    // Create buffer for this batch
    std::vector<BufferEntry> buffer;
    buffer.reserve(batchSize);

    // Process batch
    generator.processNonceBatch(current, batchSize, buffer);

    // Submit to I/O thread (move buffer to avoid copy)
    ioPool_->submit([this, buffer = std::move(buffer)]() mutable {
      bucketManager_->writeSortedEntries(buffer);
    });

    // Update progress
    processedEntries_.fetch_add(batchSize, std::memory_order_relaxed);

    current += batchSize;
    remaining -= batchSize;
  }
}

bool WorkCoordinator::generate() {
  auto startTime = std::chrono::high_resolution_clock::now();

  std::cout << "Starting generation..." << std::endl;

  // Distribute work among worker threads
  const uint64_t entriesPerWorker = Config::entriesPerWorker;
  const uint64_t totalEntries = Config::tableSize;

  for (size_t i = 0; i < Config::numWorkerThreads; ++i) {
    uint64_t startCounter = i * entriesPerWorker;
    uint64_t count = entriesPerWorker;

    // Handle the last worker if there's a remainder
    if (i == Config::numWorkerThreads - 1) {
      count = totalEntries - startCounter;
    }

    workerPool_->submit([this, startCounter, count]() { workerTask(startCounter, count); });
  }

  // Monitor progress
  std::cout << "Processing entries..." << std::endl;
  while (processedEntries_.load(std::memory_order_relaxed) < totalEntries) {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    double progress = getProgress();
    std::cout << "\rProgress: " << std::fixed << std::setprecision(2) << (progress * 100.0)
              << "% (" << processedEntries_.load(std::memory_order_relaxed) << " / "
              << totalEntries << " entries)" << std::flush;
  }
  std::cout << std::endl;

  // Wait for all workers to complete
  std::cout << "Waiting for workers to complete..." << std::endl;
  workerPool_->waitAll();

  // Wait for all I/O operations to complete
  std::cout << "Waiting for I/O operations to complete..." << std::endl;
  Timer ioWaitTimer;
  ioPool_->waitAll();
  BENCHMARK_RECORD(g_benchmarkStats.ioWaitTime, ioWaitTimer.elapsed());

  // Finalize buckets
  bucketManager_->finalize();

  auto endTime = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = endTime - startTime;

#ifdef ENABLE_BENCHMARKING
  g_benchmarkStats.totalTime = duration.count();
#endif

  std::cout << "\nGeneration complete!" << std::endl;
  std::cout << "Total time: " << std::fixed << std::setprecision(3) << duration.count()
            << " seconds" << std::endl;
  std::cout << "Entries per second: " << std::fixed << std::setprecision(0)
            << (totalEntries / std::max(0.001, duration.count())) << std::endl;

  bucketManager_->printStatistics();

#ifdef ENABLE_BENCHMARKING
  g_benchmarkStats.printReport();
#endif

  generationComplete_.store(true, std::memory_order_release);
  return true;
}

double WorkCoordinator::getProgress() const {
  return static_cast<double>(processedEntries_.load(std::memory_order_relaxed)) /
         static_cast<double>(Config::tableSize);
}

}  // namespace hashchain
