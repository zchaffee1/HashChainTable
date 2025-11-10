#ifndef HASHCHAINTABLE_THREAD_POOL_H_
#define HASHCHAINTABLE_THREAD_POOL_H_

#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <vector>

namespace hashchain {

// Thread pool for managing worker and I/O threads
class ThreadPool {
 public:
  explicit ThreadPool(size_t numThreads);
  ~ThreadPool();

  // Submit a task to the thread pool
  void submit(std::function<void()> task);

  // Wait for all tasks to complete
  void waitAll();

  // Get number of threads
  size_t getNumThreads() const { return threads_.size(); }

 private:
  std::vector<std::thread> threads_;
  std::queue<std::function<void()>> tasks_;
  std::mutex mutex_;
  std::condition_variable condition_;
  std::atomic<bool> stop_{false};
  std::atomic<size_t> activeTasks_{0};
  std::condition_variable completionCondition_;

  void workerThread();
};

// Coordinator class for managing work distribution and I/O
class WorkCoordinator {
 public:
  WorkCoordinator();
  ~WorkCoordinator();

  // Initialize the coordinator
  bool initialize(const std::string& outputDir);

  // Generate the complete hash chain table
  bool generate();

  // Get progress information
  double getProgress() const;

 private:
  std::unique_ptr<ThreadPool> workerPool_;
  std::unique_ptr<ThreadPool> ioPool_;
  std::unique_ptr<class BucketManager> bucketManager_;

  std::atomic<uint64_t> processedEntries_{0};
  std::atomic<bool> generationComplete_{false};

  // Worker thread function
  void workerTask(uint64_t startCounter, uint64_t count);

  // I/O thread function
  void ioTask(std::vector<class BufferEntry> entries);
};

}  // namespace hashchain

#endif  // HASHCHAINTABLE_THREAD_POOL_H_
