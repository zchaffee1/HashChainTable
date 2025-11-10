// Thread pool implementation for Implementation 2
// This is a simplified version - main_v2.cpp contains the inline coordinator

#include "thread_pool.h"

#include <iostream>

namespace hashchain {

// ThreadPool implementation (same for both versions)
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

}  // namespace hashchain
