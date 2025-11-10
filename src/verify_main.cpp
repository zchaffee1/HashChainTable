#include <iostream>
#include <string>
#include <cstring>

#include "config.h"
#include "verifier.h"

void printUsage(const char* progName) {
  std::cout << "Usage: " << progName << " <bucket_dir> <command> [options]\n" << std::endl;
  std::cout << "Commands:" << std::endl;
  std::cout << "  display <count>              Display first N entries from the table" << std::endl;
  std::cout << "  display-buckets [max]        Display first entry from each bucket" << std::endl;
  std::cout << "  find <target_hash> <difficulty> <max_matches>" << std::endl;
  std::cout << "                               Find matches for target hash\n" << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  " << progName << " buckets display 100" << std::endl;
  std::cout << "  " << progName << " buckets display-buckets 50" << std::endl;
  std::cout << "  " << progName << " buckets find 0a1b2c3d4e5f6789 24 10" << std::endl;
}

std::array<uint8_t, hashchain::Config::hashSize> parseHexHash(const std::string& hexStr) {
  std::array<uint8_t, hashchain::Config::hashSize> hash = {};

  // Remove any "0x" prefix
  std::string hex = hexStr;
  if (hex.substr(0, 2) == "0x" || hex.substr(0, 2) == "0X") {
    hex = hex.substr(2);
  }

  // Parse hex string to bytes
  for (size_t i = 0; i < hashchain::Config::hashSize && i * 2 < hex.length(); ++i) {
    std::string byteStr = hex.substr(i * 2, 2);
    hash[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
  }

  return hash;
}

int main(int argc, char* argv[]) {
  if (argc < 3) {
    printUsage(argv[0]);
    return 1;
  }

  std::string bucketDir = argv[1];
  std::string command = argv[2];

  std::cout << "HashChainTable Verifier" << std::endl;
  std::cout << "Bucket directory: " << bucketDir << std::endl;
  std::cout << "Configuration: K=" << hashchain::Config::kValue
            << ", Nonce=" << hashchain::Config::nonceSize << "B"
            << ", Hash=" << hashchain::Config::hashSize << "B"
            << ", Buckets=" << hashchain::Config::numBuckets << "\n" << std::endl;

  hashchain::Verifier verifier(bucketDir);

  if (command == "display") {
    if (argc < 4) {
      std::cerr << "Error: display command requires count parameter" << std::endl;
      printUsage(argv[0]);
      return 1;
    }
    size_t count = std::stoull(argv[3]);
    verifier.displayFirstEntries(count);

  } else if (command == "display-buckets") {
    size_t maxBuckets = 100;
    if (argc >= 4) {
      maxBuckets = std::stoull(argv[3]);
    }
    verifier.displayFirstFromEachBucket(maxBuckets);

  } else if (command == "find") {
    if (argc < 6) {
      std::cerr << "Error: find command requires target_hash, difficulty, and max_matches" << std::endl;
      printUsage(argv[0]);
      return 1;
    }

    std::string targetHashStr = argv[3];
    size_t difficulty = std::stoull(argv[4]);
    size_t maxMatches = std::stoull(argv[5]);

    auto targetHash = parseHexHash(targetHashStr);
    verifier.findMatches(targetHash, difficulty, maxMatches);

  } else {
    std::cerr << "Error: Unknown command '" << command << "'" << std::endl;
    printUsage(argv[0]);
    return 1;
  }

  return 0;
}
