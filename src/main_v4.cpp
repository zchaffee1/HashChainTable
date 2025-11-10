#include <chrono>
#include <iomanip>
#include <iostream>
#include <string>

#include "benchmark.h"
#include "config.h"
#include "rainbow_table_generator.h"

int main(int argc, char* argv[]) {
  // Parse command line arguments
  std::string outputDir = "rainbow_tables";
  std::string csvFile = "";
  size_t numTables = 4;  // Default: 4 tables

  if (argc > 1) {
    outputDir = argv[1];
  }
  if (argc > 2) {
    csvFile = argv[2];
  }
  if (argc > 3) {
    numTables = std::stoull(argv[3]);
  }

  std::cout << "Rainbow Table Generator (Implementation 4)" << std::endl;
  std::cout << "Output directory: " << outputDir << std::endl;
  std::cout << "Memory limit: " << MEMORY_LIMIT_MB << " MB" << std::endl;
  std::cout << "Number of tables: " << numTables << std::endl;
  if (!csvFile.empty()) {
    std::cout << "CSV output: " << csvFile << std::endl;
  }
  std::cout << std::endl;

  std::cout << "Configuration:" << std::endl;
  std::cout << "  K Value:               " << hashchain::Config::kValue << " (2^"
            << hashchain::Config::kValue << " = " << hashchain::Config::tableSize << " entries)"
            << std::endl;
  std::cout << "  Nonce Size:            " << hashchain::Config::nonceSize << " bytes"
            << std::endl;
  std::cout << "  Hash Size:             " << hashchain::Config::hashSize << " bytes" << std::endl;
  std::cout << std::endl;

  // Create rainbow table generator
  hashchain::RainbowTableGenerator generator(outputDir, MEMORY_LIMIT_MB, numTables);

  if (!generator.initialize()) {
    std::cerr << "Failed to initialize rainbow table generator" << std::endl;
    return 1;
  }

  auto startTime = std::chrono::high_resolution_clock::now();

  // Generate all tables
  generator.generateTables();

  // Write to disk
  if (!generator.writeTables()) {
    std::cerr << "Failed to write rainbow tables" << std::endl;
    return 1;
  }

  auto endTime = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = endTime - startTime;

  std::cout << "\nGeneration complete!" << std::endl;
  std::cout << "Total time: " << std::fixed << std::setprecision(3) << duration.count()
            << " seconds" << std::endl;

  uint64_t totalHashes = generator.getChainsPerTable() * generator.getChainLength() *
                         generator.getNumTables();
  std::cout << "Hash rate: " << std::fixed << std::setprecision(0)
            << (totalHashes / duration.count()) << " hashes/second" << std::endl;

  generator.printStatistics();

#ifdef ENABLE_BENCHMARKING
  hashchain::g_benchmarkStats.totalTime = duration.count();

  if (!csvFile.empty()) {
    hashchain::g_benchmarkStats.printCSV(csvFile);
  }
#endif

  std::cout << "Success! Rainbow tables generated in: " << outputDir << std::endl;

  return 0;
}
