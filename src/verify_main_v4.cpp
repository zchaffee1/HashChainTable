#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

#include "config.h"
#include "rainbow_verifier.h"

void printUsage(const char* progName) {
  std::cout << "Usage: " << progName << " <rainbow_dir> <command> [options]\n" << std::endl;
  std::cout << "Commands:" << std::endl;
  std::cout << "  stats                        Display rainbow table statistics" << std::endl;
  std::cout << "  sample <count>               Display sample chains from first table" << std::endl;
  std::cout << "  find <target_hash>           Search for a hash in the rainbow tables"
            << std::endl;
  std::cout << "  test <nonce_hex>             Generate hash from nonce and test lookup\n"
            << std::endl;
  std::cout << "Examples:" << std::endl;
  std::cout << "  " << progName << " rainbow_tables stats" << std::endl;
  std::cout << "  " << progName << " rainbow_tables sample 10" << std::endl;
  std::cout << "  " << progName << " rainbow_tables find 0a1b2c3d4e5f6789abcd" << std::endl;
  std::cout << "  " << progName << " rainbow_tables test 000000001234" << std::endl;
}

std::array<uint8_t, hashchain::Config::hashSize> parseHexHash(const std::string& hexStr) {
  std::array<uint8_t, hashchain::Config::hashSize> hash = {};

  std::string hex = hexStr;
  if (hex.substr(0, 2) == "0x" || hex.substr(0, 2) == "0X") {
    hex = hex.substr(2);
  }

  for (size_t i = 0; i < hashchain::Config::hashSize && i * 2 < hex.length(); ++i) {
    std::string byteStr = hex.substr(i * 2, 2);
    hash[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
  }

  return hash;
}

hashchain::Nonce parseHexNonce(const std::string& hexStr) {
  hashchain::Nonce nonce = {};

  std::string hex = hexStr;
  if (hex.substr(0, 2) == "0x" || hex.substr(0, 2) == "0X") {
    hex = hex.substr(2);
  }

  for (size_t i = 0; i < hashchain::Config::nonceSize && i * 2 < hex.length(); ++i) {
    std::string byteStr = hex.substr(i * 2, 2);
    nonce[i] = static_cast<uint8_t>(std::stoi(byteStr, nullptr, 16));
  }

  return nonce;
}

int main(int argc, char* argv[]) {
  if (argc < 3) {
    printUsage(argv[0]);
    return 1;
  }

  std::string rainbowDir = argv[1];
  std::string command = argv[2];

  std::cout << "Rainbow Table Verifier (Implementation 4)" << std::endl;
  std::cout << "Rainbow directory: " << rainbowDir << std::endl;
  std::cout << "Configuration: K=" << hashchain::Config::kValue
            << ", Nonce=" << hashchain::Config::nonceSize << "B"
            << ", Hash=" << hashchain::Config::hashSize << "B\n"
            << std::endl;

  hashchain::RainbowVerifier verifier(rainbowDir);

  if (!verifier.loadTables()) {
    std::cerr << "Failed to load rainbow tables" << std::endl;
    return 1;
  }

  if (command == "stats") {
    verifier.displayStatistics();

  } else if (command == "sample") {
    size_t count = 10;
    if (argc >= 4) {
      count = std::stoull(argv[3]);
    }
    verifier.displaySampleChains(count);

  } else if (command == "find") {
    if (argc < 4) {
      std::cerr << "Error: find command requires target_hash" << std::endl;
      printUsage(argv[0]);
      return 1;
    }

    std::string targetHashStr = argv[3];
    auto targetHash = parseHexHash(targetHashStr);

    hashchain::Nonce foundNonce;
    verifier.findHash(targetHash, foundNonce);

  } else if (command == "test") {
    if (argc < 4) {
      std::cerr << "Error: test command requires nonce in hex" << std::endl;
      printUsage(argv[0]);
      return 1;
    }

    std::string nonceStr = argv[3];
    auto testNonce = parseHexNonce(nonceStr);

    // Compute hash from nonce
    auto hash = verifier.computeHash(testNonce);

    std::cout << "Test nonce: ";
    for (auto byte : testNonce) {
      std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::endl;

    std::cout << "Computed hash: ";
    for (auto byte : hash) {
      std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
    }
    std::cout << std::dec << "\n" << std::endl;

    // Now try to find it
    hashchain::Nonce foundNonce;
    verifier.findHash(hash, foundNonce);

  } else {
    std::cerr << "Error: Unknown command '" << command << "'" << std::endl;
    printUsage(argv[0]);
    return 1;
  }

  return 0;
}
