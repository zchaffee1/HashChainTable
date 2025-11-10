#include <iostream>
#include <string>

#include "benchmark.h"
#include "config.h"
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

  std::cout << "HashChainTable Generator" << std::endl;
  std::cout << "Output directory: " << outputDir << std::endl;
  if (!csvFile.empty()) {
    std::cout << "CSV output: " << csvFile << std::endl;
  }
  std::cout << std::endl;

  // Create work coordinator
  hashchain::WorkCoordinator coordinator;

  // Initialize
  if (!coordinator.initialize(outputDir)) {
    std::cerr << "Failed to initialize coordinator" << std::endl;
    return 1;
  }

  // Generate table
  if (!coordinator.generate()) {
    std::cerr << "Failed to generate table" << std::endl;
    return 1;
  }

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
