cmake_minimum_required(VERSION 2.8)

# Pick a compiler
set(CMAKE_CXX_COMPILER g++)

add_definitions(-std=c++11)

add_definitions(-Wall -Wextra -Werror -pedantic)
add_definitions(-Wsign-conversion)
add_definitions(-Wold-style-cast)

add_definitions(-Wno-unused-function)
add_definitions(-Wno-nested-anon-types)
add_definitions(-Wno-keyword-macro)
add_definitions(-Wno-keyword-macro)
add_definitions(-Wno-deprecated-declarations)
add_definitions(-march=native)
add_definitions(-g)
set(LIBRARIES ${LIBRARIES} -Wl,--whole-archive rt pthread gflags dpdk numa dl -Wl,--no-whole-archive)

# Options exposed to the user
option(PERF "Compile for performance" OFF)

# Parse the user-exposed options
if(PERF)
  MESSAGE(STATUS "Compilation optimized for performance.")
  add_definitions(-DNDEBUG)
  add_definitions(-O2)
else(PERF)
  MESSAGE(STATUS "Compilation not optimized for performance.")
  add_definitions(-g)
endif(PERF)

# DPDK include directory. Locating rte_config.h does not work on some systems.
# Example: it may be kept in /usr/include/x86_64-linux-gnu/, and symlinked
# from the real DPDK include directory (/usr/include/dpdk/).
find_path(DPDK_INCLUDE_DIR NAMES rte_ethdev.h PATH_SUFFIXES dpdk)
if (DPDK_INCLUDE_DIR)
  message(STATUS "DPDK include directory = ${DPDK_INCLUDE_DIR}")
else()
  message(FATAL_ERROR "DPDK include directory not found. Please install DPDK.")
endif()
include_directories(SYSTEM ${DPDK_INCLUDE_DIR})

add_executable(example example.cc)
target_link_libraries(example ${LIBRARIES})
