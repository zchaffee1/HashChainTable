cmake_minimum_required(VERSION 3.15)
project(HashChainTable VERSION 1.0 LANGUAGES CXX)

# Set C++17 as the standard
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Compile-time configuration options
set(K_VALUE "32" CACHE STRING "K value for table size (2^K entries)")
set(NONCE_SIZE "6" CACHE STRING "Size of nonce in bytes")
set(HASH_SIZE "10" CACHE STRING "Size of hash in bytes")
set(BUCKET_PREFIX_SIZE "3" CACHE STRING "Size of hash prefix for bucketing")
set(BUCKET_CAPACITY "512" CACHE STRING "Logical capacity per bucket")
set(NUM_WORKER_THREADS "8" CACHE STRING "Number of worker threads")
set(NUM_IO_THREADS "2" CACHE STRING "Number of I/O threads")
set(WORKER_BUFFER_SIZE "65536" CACHE STRING "Buffer size per worker thread")
option(ENABLE_BENCHMARKING "Enable detailed benchmarking and statistics" ON)

# Build type optimization
if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

# Compiler optimizations
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3 -march=native -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g -O0")

# Add compile definitions for all parameters
add_compile_definitions(
    K_VALUE=${K_VALUE}
    NONCE_SIZE=${NONCE_SIZE}
    HASH_SIZE=${HASH_SIZE}
    BUCKET_PREFIX_SIZE=${BUCKET_PREFIX_SIZE}
    BUCKET_CAPACITY=${BUCKET_CAPACITY}
    NUM_WORKER_THREADS=${NUM_WORKER_THREADS}
    NUM_IO_THREADS=${NUM_IO_THREADS}
    WORKER_BUFFER_SIZE=${WORKER_BUFFER_SIZE}
)

if(ENABLE_BENCHMARKING)
    add_compile_definitions(ENABLE_BENCHMARKING=1)
    message(STATUS "Benchmarking: Enabled")
else()
    message(STATUS "Benchmarking: Disabled")
endif()

# Include directories
include_directories(${CMAKE_SOURCE_DIR}/include)
include_directories(${CMAKE_SOURCE_DIR}/external)
include_directories(${CMAKE_SOURCE_DIR}/external/blake3)

# BLAKE3 library
add_subdirectory(external/blake3)

# Source files
set(SOURCES
    src/main.cpp
    src/hash_generator.cpp
    src/bucket_manager.cpp
    src/thread_pool.cpp
    src/benchmark.cpp
)

# Main executable
add_executable(hashchaintable ${SOURCES})
target_link_libraries(hashchaintable PRIVATE blake3 pthread)

# Verifier executable
set(VERIFIER_SOURCES
    src/verify_main.cpp
    src/verifier.cpp
)
add_executable(verify ${VERIFIER_SOURCES})
target_link_libraries(verify PRIVATE blake3)

# Enable link-time optimization for release builds
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    include(CheckIPOSupported)
    check_ipo_supported(RESULT ipo_supported)
    if(ipo_supported)
        set_property(TARGET hashchaintable PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
        set_property(TARGET verify PROPERTY INTERPROCEDURAL_OPTIMIZATION TRUE)
    endif()
endif()

# Installation
install(TARGETS hashchaintable verify DESTINATION bin)

# Print configuration
message(STATUS "HashChainTable Configuration:")
message(STATUS "  K Value: ${K_VALUE} (2^${K_VALUE} = ${TABLE_SIZE} entries)")
message(STATUS "  Nonce Size: ${NONCE_SIZE} bytes")
message(STATUS "  Hash Size: ${HASH_SIZE} bytes")
message(STATUS "  Bucket Prefix Size: ${BUCKET_PREFIX_SIZE} bytes")
message(STATUS "  Bucket Capacity: ${BUCKET_CAPACITY} entries")
message(STATUS "  Worker Threads: ${NUM_WORKER_THREADS}")
message(STATUS "  I/O Threads: ${NUM_IO_THREADS}")
message(STATUS "  Worker Buffer Size: ${WORKER_BUFFER_SIZE} bytes")
message(STATUS "  Build Type: ${CMAKE_BUILD_TYPE}")
