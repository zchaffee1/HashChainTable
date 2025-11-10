# HashChainTable Generator

A high-performance, memory-efficient hash chain table generator using BLAKE3 and C++17. This project implements multiple approaches for generating large-scale nonce-hash lookup tables optimized for different performance characteristics.

## Overview

### What is a Hash Chain Table?

A hash chain table is a data structure that stores mappings between nonces (random numbers used once) and their cryptographic hash values. These tables are useful for:
- Proof-of-work systems
- Rainbow table generation
- Cryptographic research
- Hash collision studies

In our implementation, we generate 2^K nonce-hash pairs where:
- **Nonce**: A fixed-size value (default: 6 bytes)
- **Hash**: BLAKE3 cryptographic hash output (variable size, default: 10 bytes)
- **Bucket**: Storage partition based on hash prefix for memory efficiency

### BLAKE3 Hash Function

BLAKE3 is a cryptographic hash function that is:
- **Fast**: Much faster than SHA-2 and SHA-3
- **Secure**: Based on the BLAKE2 design, with improved security
- **Parallel**: Designed for modern multi-core processors
- **Flexible**: Supports arbitrary output lengths

We use BLAKE3 because it provides excellent performance for generating billions of hashes while maintaining cryptographic security.

### Bucketing Strategy

To efficiently handle large-scale hash generation without loading everything into memory:

1. **Hash Prefix Bucketing**: The first N bytes of each hash determine which bucket (file) the nonce belongs to
2. **Space Efficiency**: Only nonces are stored in buckets (not full hashes), as the hash can be recomputed
3. **Distribution**: BLAKE3's uniform distribution ensures even bucket filling
4. **Bucket Capacity**: Each bucket has a logical limit (default: 512 entries) to prevent overflow

Example with 3-byte prefix:
- Creates 2^24 = 16,777,216 buckets
- Each bucket contains ~2^(K-24) entries for K-value table
- For K=32: ~256 entries per bucket on average

## Building

### Prerequisites
- CMake 3.15+
- C++17 compatible compiler (GCC 7+, Clang 5+)
- BLAKE3 library (included)
- Linux/Unix environment

### Quick Start

```bash
# Default build (K=32, benchmarking enabled)
mkdir build && cd build
cmake ..
make -j$(nproc)

# Test build (K=24 for faster testing)
mkdir build_test && cd build_test
cmake .. -DK_VALUE=24
make -j$(nproc)
./hashchaintable test_output
```

### Configuration Parameters

All parameters are compile-time constants for maximum efficiency:

| Parameter | Default | Description |
|-----------|---------|-------------|
| K_VALUE | 32 | Generate 2^K nonce-hash pairs (e.g., 32 = 4.3 billion) |
| NONCE_SIZE | 6 | Size of each nonce in bytes |
| HASH_SIZE | 10 | Size of hash in bytes (only prefix is computed) |
| BUCKET_PREFIX_SIZE | 3 | Bytes of hash used for bucketing (determines bucket count) |
| BUCKET_CAPACITY | 512 | Logical capacity per bucket |
| NUM_WORKER_THREADS | 8 | Number of hash generation threads |
| NUM_IO_THREADS | 2 | Number of I/O threads |
| WORKER_BUFFER_SIZE | 65536 | Buffer size per worker in bytes |
| ENABLE_BENCHMARKING | ON | Enable detailed performance statistics |

### Custom Configuration

```bash
mkdir build && cd build
cmake .. \
  -DK_VALUE=24 \
  -DNONCE_SIZE=6 \
  -DBUCKET_PREFIX_SIZE=3 \
  -DNUM_WORKER_THREADS=16 \
  -DNUM_IO_THREADS=4 \
  -DENABLE_BENCHMARKING=ON
make -j$(nproc)
```

### Disabling Benchmarking

For maximum performance in production:

```bash
cmake .. -DENABLE_BENCHMARKING=OFF
```

This removes all benchmarking overhead at compile time.

## Usage

### Generating Hash Chain Tables

```bash
./hashchaintable [output_directory] [csv_output_file]
```

Arguments:
- `output_directory`: Directory to store bucket files (default: "buckets")
- `csv_output_file`: Optional CSV file for benchmark statistics

Examples:
```bash
# Basic generation
./hashchaintable buckets

# With CSV output for benchmarking
./hashchaintable buckets results.csv
```

Output structure:
```
buckets/
├── bucket_000000.bin
├── bucket_000001.bin
├── bucket_000002.bin
...
└── bucket_16777215.bin  (for 3-byte prefix)
```

Each bucket file is a binary file containing concatenated nonces (6 bytes each).

### Verifying and Searching Tables

The `verify` tool allows you to inspect generated tables and search for hash matches:

```bash
./verify <bucket_dir> <command> [options]
```

**Commands:**

1. **Display first N entries:**
   ```bash
   ./verify buckets display 100
   ```
   Shows the first 100 nonce-hash pairs from the table in human-readable hex format.

2. **Display first entry from each bucket:**
   ```bash
   ./verify buckets display-buckets 50
   ```
   Shows the first nonce-hash pair from the first 50 buckets to verify distribution.

3. **Find matches by difficulty:**
   ```bash
   ./verify buckets find 0a1b2c3d4e5f6789 24 10
   ```
   Finds up to 10 nonces whose hashes match the first 24 bits of the target hash.

   - `target_hash`: Target hash in hex (without 0x prefix)
   - `difficulty`: Number of most significant bits that must match
   - `max_matches`: Maximum number of matches to return

**How matching works:**
- The target hash determines which bucket to search (based on first N bytes)
- All nonces in that bucket are hashed and compared
- Matches are found when the specified number of most significant bits align
- Example: difficulty=24 means the first 3 bytes must match exactly

## Benchmarking

When `ENABLE_BENCHMARKING=ON`, the program outputs detailed performance metrics:

### Console Output

The program prints a detailed report to the console with the following statistics:

**Timing Statistics:**
- **Total Time**: End-to-end execution time
- **Hash Generation**: Time spent computing BLAKE3 hashes
- **Sorting**: Time spent sorting buffers by bucket ID
- **I/O Wait**: Time waiting for I/O operations to complete
- **Disk Write**: Actual disk write time

**I/O Statistics:**
- **Bytes Written**: Total data written to disk
- **Write Operations**: Number of disk write calls
- **Files Opened/Closed**: File descriptor operations
- **Write Throughput**: MB/s write speed

**Processing Statistics:**
- **Entries Processed**: Total nonces hashed
- **Entries Written**: Total nonces written to buckets
- **Buffers Sorted**: Number of sort operations
- **Hash Rate**: Hashes per second
- **Sort Rate**: Entries sorted per second

### CSV Export

Specify a CSV filename as the second argument to export all metrics:

```bash
./hashchaintable buckets benchmark_results.csv
```

The CSV file contains all configuration parameters and performance metrics in a format suitable for plotting and analysis. This is ideal for:
- Comparing different implementations
- Analyzing performance across different configurations
- Creating performance graphs
- Benchmarking different hardware setups

## Performance Tips

1. **Testing**: Use K=24 (16.7M entries) for quick testing, K=32 (4.3B entries) for production
2. **Thread Count**: Match worker threads to your CPU core count
3. **I/O Threads**: 1-2 threads sufficient for most systems, 4+ for high-speed NVMe
4. **Buffer Size**: Larger buffers (128KB-1MB) reduce overhead but increase memory
5. **Bucket Prefix**: Balance between bucket count and filesystem limits:
   - 2 bytes = 65,536 buckets
   - 3 bytes = 16,777,216 buckets (may hit filesystem limits)
   - 4 bytes = 4,294,967,296 buckets (requires lazy file opening)

## Code Standards

- Google C++ Style Guide
- clang-format configuration included
- C++17 standard features
- RAII resource management
- Zero-copy optimizations where possible

---

# Implementation 1: In-Memory Sort with Bucket Streaming

## Approach

Implementation 1 uses a **worker-pool architecture** with **in-memory sorting** and **lazy file I/O** to generate hash chain tables efficiently.

### Key Design Decisions

1. **Worker Thread Pool**: Multiple threads generate nonces and compute BLAKE3 hash prefixes in parallel
2. **I/O Thread Pool**: Dedicated threads handle disk writes to avoid blocking workers
3. **In-Memory Sorting**: Each worker sorts its buffer by bucket ID before submitting to I/O
4. **Lazy File Opening**: Bucket files are opened on-demand to avoid file descriptor limits
5. **Sequential Writes**: Sorted buffers enable sequential writes within each bucket

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                     WorkCoordinator                          │
│  - Manages worker and I/O thread pools                      │
│  - Tracks overall progress                                   │
└─────────────────────────────────────────────────────────────┘
                          │
         ┌────────────────┴────────────────┐
         │                                  │
         ▼                                  ▼
┌──────────────────┐              ┌──────────────────┐
│  Worker Pool     │              │   I/O Pool       │
│  (N threads)     │              │  (M threads)     │
└──────────────────┘              └──────────────────┘
         │                                  │
         │ Each worker:                     │ Each I/O thread:
         │  1. Generate nonces              │  1. Receives sorted buffer
         │  2. Compute BLAKE3 prefix        │  2. Writes to bucket files
         │  3. Build buffer                 │  3. Manages file handles
         │  4. Sort by bucket ID            │
         │  5. Submit to I/O pool           │
         │                                  │
         └──────────────────────────────────┘
                          │
                          ▼
              ┌───────────────────────┐
              │   BucketManager       │
              │  - Lazy file opening  │
              │  - Write buffering    │
              │  - Statistics         │
              └───────────────────────┘
                          │
                          ▼
                  ┌──────────────┐
                  │  Bucket Files │
                  │  (on disk)    │
                  └──────────────┘
```

### Detailed Workflow

#### Phase 1: Initialization
```cpp
1. Create output directory
2. Initialize worker thread pool (N threads)
3. Initialize I/O thread pool (M threads)
4. Allocate bucket metadata (but don't open files yet)
```

#### Phase 2: Work Distribution
```cpp
1. Divide 2^K nonces among N worker threads
2. Each worker gets entriesPerWorker = 2^K / N nonces
3. Workers process nonces in chunks of bufferSize
```

#### Phase 3: Worker Processing
```cpp
For each chunk in worker's range:
  1. Generate nonces (counter → 6-byte value)
  2. Hash each nonce with BLAKE3
  3. Extract first 3 bytes of hash as bucket ID
  4. Build buffer: [(nonce, bucketID), ...]
  5. Sort buffer by bucketID (std::sort)
  6. Submit sorted buffer to I/O pool
```

**Optimization**: Only compute 3 bytes of BLAKE3 output instead of full 32 bytes.

#### Phase 4: I/O Processing
```cpp
For each sorted buffer from workers:
  1. Iterate through entries (already sorted)
  2. For each bucket ID:
     a. Get bucket handle (open file if needed)
     b. Append nonce to bucket's write buffer
     c. Flush to disk when buffer reaches 1MB
  3. Update statistics
```

**Optimization**: Sorted input means sequential bucket access, reducing file open/close operations.

#### Phase 5: Finalization
```cpp
1. Wait for all workers to complete
2. Wait for all I/O operations to finish
3. Flush remaining buffers to disk
4. Close all open file handles
5. Print statistics
```

### Memory Management

**Per-Worker Memory**:
- Hash generator state: ~1KB (BLAKE3 context)
- Buffer: 65,536 bytes (default) = ~10,922 entries
- Total per worker: ~66KB

**Global Memory**:
- Bucket metadata: numBuckets × ~128 bytes = 2GB for 3-byte prefix
- File handles: Only opened files kept in memory (lazy opening)
- Thread stacks: ~8MB × (N + M) threads

**Total Memory**: ~2GB + (N × 66KB) + ((N+M) × 8MB)
- For N=8, M=2: ~2.6GB

### I/O Optimization Strategies

1. **Sorting Before Write**:
   - Random bucket access → Sequential bucket access
   - Reduces file opens from O(buffer_size) to O(buckets_accessed)

2. **Write Buffering**:
   - Accumulate writes up to 1MB per bucket
   - Reduces system call overhead
   - Better filesystem block alignment

3. **Lazy File Opening**:
   - Only open bucket files when needed
   - Avoids hitting OS file descriptor limits
   - Close files after period of inactivity

4. **Append-Only Writes**:
   - Simple sequential writes within each file
   - Filesystem-friendly access pattern
   - No seeks required

### Performance Characteristics

**Time Complexity**:
- Hash generation: O(2^K × H) where H = BLAKE3 time per hash
- Sorting: O(2^K × log(buffer_size)) distributed across workers
- I/O: O(2^K × W) where W = write time per nonce

**Space Complexity**:
- Memory: O(workers × buffer_size + buckets × metadata)
- Disk: O(2^K × nonce_size)

**Bottlenecks**:
1. **BLAKE3 Computation**: Usually the primary bottleneck (CPU-bound)
2. **Disk Write Bandwidth**: Secondary bottleneck for fast CPUs
3. **Sorting**: Minimal overhead with small buffers (<1%)

### Benchmark Results

Example configuration (K=24, 16.7M entries):
```
Configuration:
  K Value:               24 (2^24 = 16777216 entries)
  Worker Threads:        8
  I/O Threads:           2
  Buffer Size:           65536 bytes

Timing Statistics:
  Total Time:            ~25 seconds
  Hash Generation:       ~20 seconds (80%)
  Sorting:              ~1 second (4%)
  I/O Wait:             ~3 seconds (12%)
  Disk Write:           ~2 seconds (8%)

I/O Statistics:
  Bytes Written:         100 MB
  Write Operations:      ~1500
  Write Throughput:      50 MB/s

Processing Statistics:
  Hash Rate:             ~840,000 hashes/second
  Sort Rate:             ~16.7M entries/second
```

### Advantages

1. **Simple and Reliable**: Straightforward architecture, easy to debug
2. **Good CPU Utilization**: Worker threads keep all cores busy
3. **Predictable Memory Usage**: Fixed buffer sizes, no dynamic allocation in hot path
4. **Filesystem Friendly**: Sequential writes, append-only access
5. **Scalable**: Add more workers for more CPU, more I/O threads for faster disks

### Limitations

1. **File Descriptor Pressure**: Large bucket counts may require many open files
2. **Sorting Overhead**: Small but non-zero cost per buffer
3. **Write Amplification**: Small writes to many buckets may not be optimal for all filesystems
4. **No Write Coalescing**: Multiple workers may write to same bucket without coordination

### Potential Improvements

These would be explored in future implementations:
- **Temporary Files**: Use larger temp files, merge-sort into final buckets
- **Write Coalescing**: Coordinate writes to same bucket across workers
- **Memory-Mapped I/O**: Reduce system call overhead
- **Compression**: Compress buckets on the fly
- **Distribution**: Spread generation across multiple machines

---

## License

This is a custom implementation for educational and research purposes.
