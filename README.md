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
# Implementation 1: Multi-file (default)
mkdir build && cd build
cmake .. -DIMPLEMENTATION=1
make -j$(nproc)

# Implementation 2: Single-file with memory limit
mkdir build && cd build
cmake .. -DIMPLEMENTATION=2 -DMEMORY_LIMIT_MB=2048
make -j$(nproc)

# Implementation 3: In-memory with dynamic nonce size
mkdir build && cd build
cmake .. -DIMPLEMENTATION=3 -DK_VALUE=20 -DMEMORY_LIMIT_MB=512
make -j$(nproc)

# Test build (K=16 for faster testing)
cmake .. -DIMPLEMENTATION=3 -DK_VALUE=16 -DMEMORY_LIMIT_MB=128
make -j$(nproc)
./hashchaintable test_output
```

### Configuration Parameters

All parameters are compile-time constants for maximum efficiency:

| Parameter | Default | Description |
|-----------|---------|-------------|
| IMPLEMENTATION | 1 | Implementation version (1=multi-file, 2=single-file, 3=in-memory) |
| K_VALUE | 32 | Generate 2^K nonce-hash pairs (e.g., 32 = 4.3 billion) |
| NONCE_SIZE | 6 | Size of each nonce in bytes |
| HASH_SIZE | 10 | Size of hash in bytes (only prefix is computed) |
| BUCKET_PREFIX_SIZE | 3 | Bytes of hash used for bucketing (determines bucket count) |
| BUCKET_CAPACITY | 512 | Logical capacity per bucket |
| NUM_WORKER_THREADS | 8 | Number of hash generation threads |
| NUM_IO_THREADS | 2 | Number of I/O threads |
| WORKER_BUFFER_SIZE | 65536 | Buffer size per worker in bytes |
| MEMORY_LIMIT_MB | 2048 | Memory limit for Implementations 2 and 3 (in MB) |
| ENABLE_BENCHMARKING | ON | Enable detailed performance statistics |

### Custom Configuration

```bash
# Implementation 1 with custom settings
mkdir build && cd build
cmake .. \
  -DIMPLEMENTATION=1 \
  -DK_VALUE=24 \
  -DNONCE_SIZE=6 \
  -DBUCKET_PREFIX_SIZE=3 \
  -DNUM_WORKER_THREADS=16 \
  -DNUM_IO_THREADS=4 \
  -DENABLE_BENCHMARKING=ON
make -j$(nproc)

# Implementation 2 with memory limit
cmake .. \
  -DIMPLEMENTATION=2 \
  -DK_VALUE=24 \
  -DMEMORY_LIMIT_MB=4096 \
  -DNUM_WORKER_THREADS=16
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

# Implementation 2: Single-File with Offset-Based Storage

## Approach

Implementation 2 addresses the file descriptor limitations of Implementation 1 by storing all buckets in a **single dense file** with **fixed offsets** and **memory-limited caching**.

### Key Design Decisions

1. **Single Data File**: All buckets stored in one contiguous file
2. **Fixed Offsets**: Each bucket at offset = bucketId × bucketCapacity × nonceSize
3. **Dense Allocation**: File pre-allocated (not sparse) for guaranteed space
4. **LRU Cache**: Memory-limited cache evicts least-recently-used buckets
5. **Metadata File**: Separate file tracks entry counts per bucket

### Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                    Main Program (V2)                         │
│  - Similar worker/IO threading model                        │
│  - Memory limit parameter                                    │
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
         │ Process & sort                   │ Write sorted entries
         └──────────────────┬───────────────┘
                            ▼
              ┌─────────────────────────────┐
              │   BucketManagerV2          │
              │  - LRU cache (memory limit) │
              │  - Lazy bucket loading      │
              │  - Offset-based writes      │
              └─────────────────────────────┘
                            │
         ┌──────────────────┴──────────────────┐
         ▼                                      ▼
┌──────────────────┐                  ┌──────────────────┐
│  buckets.dat     │                  │  buckets.meta    │
│  Single file:    │                  │  Binary metadata:│
│  [Bucket 0 data] │                  │  - Entry counts  │
│  [Bucket 1 data] │                  │  - File offsets  │
│  [Bucket 2 data] │                  │  - Version info  │
│  ...             │                  └──────────────────┘
│  [Bucket N data] │
└──────────────────┘
```

### Detailed Workflow

#### Phase 1: Initialization & Preallocation
```cpp
1. Create output directory
2. Calculate total file size: numBuckets × bucketCapacity × nonceSize
   For K=32, 3-byte prefix: 16.7M × 512 × 6 = ~51 GB
3. Pre-allocate dense file:
   a. Try posix_fallocate on Linux (fast, instant)
   b. Fallback: Write zeros in 64MB chunks (slower but portable)
4. Initialize metadata structure (in memory)
5. Calculate fixed offset for each bucket
```

#### Phase 2: Worker Processing (Same as V1)
```cpp
For each chunk in worker's range:
  1. Generate nonces
  2. Hash with BLAKE3 (3-byte prefix only)
  3. Build buffer: [(nonce, bucketID), ...]
  4. Sort buffer by bucketID
  5. Submit to I/O pool
```

#### Phase 3: I/O Processing with LRU Cache
```cpp
For each sorted buffer from workers:
  For each entry:
    1. Get bucket buffer from cache (or load if not cached)
    2. If cache full and need new bucket:
       a. Find LRU bucket (lowest access time)
       b. Flush LRU bucket if dirty
       c. Evict LRU bucket from cache
    3. Add nonce to bucket buffer
    4. Mark buffer as dirty
    5. Update access time
    6. If bucket full: flush immediately
```

#### Phase 4: Bucket Flushing
```cpp
To flush a bucket:
  1. Calculate file offset: bucketId × bucketCapacity × nonceSize
  2. Seek to offset in data file
  3. Write entryCount × nonceSize bytes
  4. Update metadata (entry count)
  5. Mark buffer as clean
```

#### Phase 5: Finalization
```cpp
1. Wait for all workers to complete
2. Wait for all I/O operations
3. Flush all cached buckets (dirty or not)
4. Write metadata file:
   - Version number
   - Bucket count
   - For each bucket: entry count, file offset
5. Close data file
```

### File Formats

**buckets.dat** (Dense Binary File):
```
Offset 0:              [Bucket 0: up to 512 nonces, 6 bytes each]
Offset 3072:           [Bucket 1: up to 512 nonces, 6 bytes each]
Offset 6144:           [Bucket 2: up to 512 nonces, 6 bytes each]
...
Offset (N×3072):       [Bucket N: up to 512 nonces, 6 bytes each]

Total size for K=32, 3-byte prefix: ~51 GB
```

**buckets.meta** (Binary Metadata):
```
[4 bytes] Version (2 for Implementation 2)
[8 bytes] Number of buckets
For each bucket:
  [2 bytes] Entry count (0-512)
  [8 bytes] File offset

Total size for 16.7M buckets: ~167 MB
```

### Memory Management

**LRU Cache Strategy:**
- Each bucket buffer occupies: bucketCapacity × nonceSize bytes
- Default: 512 × 6 = 3KB per bucket
- With 2GB memory limit: ~680,000 buckets can be cached
- Access counter tracks recency (atomic uint64_t)
- When limit reached: evict bucket with lowest access time

**Memory Usage:**
```
Per-bucket buffer:     3 KB (512 × 6 bytes)
Cached buckets:        memoryLimit / 3KB
Metadata (all):        ~167 MB (16.7M × 10 bytes)
Thread stacks:         ~80 MB (10 threads × 8MB)
Total with 2GB limit:  ~2.25 GB
```

### Performance Characteristics

**Time Complexity:**
- Hash generation: O(2^K × H) - same as V1
- Sorting: O(2^K × log(buffer_size)) - same as V1
- I/O: O(2^K × (W + C)) where W = write time, C = cache miss penalty

**Space Complexity:**
- Memory: O(memoryLimit + metadata_size)
- Disk: O(2^K × nonce_size) - same as V1

**Bottlenecks:**
1. **File Preallocation**: Can take minutes for 50+ GB (if posix_fallocate unavailable)
2. **Cache Thrashing**: If working set > memory limit, frequent evictions
3. **Seek Overhead**: Random seeks when bucket not cached (SSD recommended)

### Benchmark Results

Example configuration (K=24, 16.7M entries, 2GB memory):
```
Configuration:
  K Value:               24 (2^24 = 16777216 entries)
  Implementation:        2 (Single-file)
  Memory Limit:          2048 MB
  File Size:             ~97 MB (actual data used)
  Worker Threads:        8
  I/O Threads:           2

Timing Statistics:
  Total Time:            ~30 seconds
  Preallocation:         ~5 seconds (posix_fallocate)
  Hash Generation:       ~20 seconds (67%)
  Sorting:               ~1 second (3%)
  I/O Wait:              ~4 seconds (13%)

Cache Statistics:
  Cache Hits:            ~15.5M (92%)
  Cache Misses:          ~1.2M (8%)
  Cache Evictions:       ~500K
  Hit Rate:              92%
```

### Advantages

1. **No File Descriptor Limits**: Single file regardless of bucket count
2. **Predictable Disk Usage**: Pre-allocated, no sparse files
3. **Memory Control**: Explicit memory limit prevents OOM
4. **Good for SSDs**: Seeks are cheap, single file reduces metadata overhead
5. **Portable File Format**: Easy to transfer, verify, or distribute

### Limitations

1. **Preallocation Time**: Large files take time to allocate (K=32 = ~51GB)
2. **Cache Sensitivity**: Performance degrades if working set > memory limit
3. **Write Amplification**: Bucket writes may not align with filesystem blocks
4. **Single File Risk**: Corruption affects entire table (vs isolated buckets in V1)
5. **Not Incremental**: Must pre-allocate entire file upfront

# Implementation 3: In-Memory with Dynamic Nonce Size

## Overview

Implementation 3 takes a fundamentally different approach by **generating the entire hash table in memory** with a **dynamically calculated nonce size** based on available memory.

### Key Features

- **Full In-Memory Generation**: Entire table stored in RAM during generation
- **Dynamic Nonce Size**: Automatically reduces nonce bytes to fit memory limit
- **Single Write**: All disk I/O happens at finalization
- **Reorganization**: Entries reorganized by bucket when writing to disk

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Worker Threads                        │
├─────────────────────────────────────────────────────────┤
│  Generate nonces → Compute hashes → Write to linear     │
│                                      memory array       │
└─────────────────────────────────────────────────────────┘
                         ↓
┌─────────────────────────────────────────────────────────┐
│              Linear Memory Layout                       │
│  [Entry 0][Entry 1][Entry 2]...[Entry 2^K-1]          │
│   Position = Nonce Counter Value                        │
└─────────────────────────────────────────────────────────┘
                         ↓
              On Finalize: Reorganize
                         ↓
┌─────────────────────────────────────────────────────────┐
│           Bucket-Organized File                         │
│  [Bucket 0 entries...][Bucket 1 entries...]...         │
└─────────────────────────────────────────────────────────┘
```

### Dynamic Nonce Size Calculation

Implementation 3 automatically calculates the maximum nonce size that fits in the configured memory limit:

```
Effective Nonce Size = min(NONCE_SIZE, MEMORY_LIMIT / 2^K)
```

**Example calculations:**

| K Value | Table Size | Memory Limit | Effective Nonce Size |
|---------|------------|--------------|---------------------|
| 16 | 65,536 | 128 MB | 6 bytes (full) |
| 20 | 1,048,576 | 512 MB | 6 bytes (full) |
| 24 | 16,777,216 | 512 MB | 30 bytes → 6 bytes (capped) |
| 28 | 268,435,456 | 2048 MB | 7 bytes → 6 bytes (capped) |
| 32 | 4,294,967,296 | 4096 MB | 0.95 bytes → 0 bytes (error!) |

If the calculated size is less than 1 byte, generation fails with an error.

### Workflow

1. **Initialization**
   - Calculate effective nonce size based on memory limit and K value
   - Allocate linear memory array: `tableSize * effectiveNonceSize` bytes
   - Initialize metadata for all buckets

2. **Generation Phase**
   - Worker threads generate nonces sequentially (counter-based)
   - Compute BLAKE3 hash for each nonce
   - Store nonce at linear position = counter value
   - Track bucket statistics but don't organize by bucket yet

3. **Finalization Phase**
   - Scan through linear memory once
   - Group entries by bucket ID (recompute hash prefix)
   - Write to disk in bucket-organized format
   - Create metadata file with bucket counts and offsets

### Build Example

```bash
# Implementation 3: In-memory with dynamic nonce size
mkdir build && cd build
cmake .. -DIMPLEMENTATION=3 -DK_VALUE=20 -DMEMORY_LIMIT_MB=1024
make -j$(nproc)
```

### File Format

Same as Implementation 2 - single `buckets.dat` file with bucket-based offsets and `buckets.meta` metadata file.

**Metadata Differences:**
```
[4 bytes] Version (3 for Implementation 3)
[8 bytes] Bucket count
[4 bytes] Effective nonce size (IMPORTANT: may be < configured size!)
For each bucket:
  [8 bytes] Entry count
  [8 bytes] File offset
```

### Performance Characteristics

**Advantages:**
- ✅ Zero disk I/O during generation (fastest generation phase)
- ✅ Automatically adapts nonce size to memory
- ✅ Simple linear memory layout
- ✅ Single write operation at end
- ✅ No file descriptor limits

**Disadvantages:**
- ❌ Requires all data to fit in RAM
- ❌ May reduce nonce size (less preimage space)
- ❌ Reorganization overhead at finalization
- ❌ Not suitable for extremely large K values
- ❌ File still requires full bucket space (can be large)

### Memory Requirements

Total memory needed:
```
Memory = 2^K × effectiveNonceSize + overhead
```

**Examples:**

- K=20, 6 bytes: ~6 MB
- K=24, 6 bytes: ~96 MB
- K=28, 6 bytes: ~1.5 GB
- K=32, 4 bytes: ~16 GB (reduced from 6 bytes)

### Comparison of All Implementations

| Aspect | Implementation 1 | Implementation 2 | Implementation 3 |
|--------|------------------|------------------|------------------|
| **Storage** |
| Files Created | 16.7M files | 2 files | 2 files |
| File Descriptors | Up to 16.7M | 1 | 1 |
| Disk Format | Many small files | One large file | One large file |
| Preallocation | None | Required (~51GB) | None (sparse write) |
| **Memory** |
| Memory Usage | ~2.6GB fixed | Configurable LRU cache | Full table in RAM |
| Memory Model | Buffer-based | Cache-based | Full in-memory |
| Nonce Size | Fixed | Fixed | Dynamic (adapts) |
| **Performance** |
| Write Speed | Fast (parallel) | Medium (cached) | Fastest (deferred) |
| Seek Operations | Minimal | Many | None during gen |
| Disk I/O Pattern | Many small writes | Cached writes | Single bulk write |
| Finalization | Instant | Fast | Medium (reorganize) |
| **Best For** |
| Use Case | Rotating disks | SSDs, large K | Small K, max speed |
| Storage Type | HDD-friendly | SSD-friendly | RAM-friendly |
| Scale | Small K (<28) | Large K | Limited by RAM |

### When to Use Implementation 3

Choose Implementation 3 when:
- ✅ K value is small enough to fit in RAM (K ≤ 28)
- ✅ Want absolute fastest generation phase
- ✅ Have abundant RAM available
- ✅ Don't mind reduced nonce size
- ✅ Can tolerate reorganization time at end

Choose Implementation 2 when:
- ✅ K value too large for RAM but need single file
- ✅ Need full nonce size preserved
- ✅ Using SSD storage
- ✅ Want predictable memory usage

Choose Implementation 1 when:
- ✅ Using rotating disks
- ✅ Need maximum write throughput
- ✅ Filesystem handles many files well
- ✅ Want incremental generation

---

## License

This is a custom implementation for educational and research purposes.
