cmake_minimum_required(VERSION 3.5)

# Pick a compiler
set(CMAKE_CXX_COMPILER g++-7)

add_definitions(-std=c++11)

add_definitions(-Wall -Wextra -Werror -pedantic)
add_definitions(-Wsign-conversion)
add_definitions(-Wold-style-cast)

add_definitions(-Wno-unused-function)
add_definitions(-Wno-nested-anon-types)
add_definitions(-Wno-keyword-macro)
add_definitions(-march=native)
add_definitions(-g)

set(LIBRARIES ${LIBRARIES} rt numa pthread gflags)

# Options exposed to the user
option(PERF "Compile for performance" OFF)

# Parse the user-exposed options
if(PERF)
  MESSAGE(STATUS "Compilation optimized for performance.")
  add_definitions(-g)
else(PERF)
  MESSAGE(STATUS "Compilation not optimized for performance.")
  add_definitions(-DNDEBUG)
  add_definitions(-O2)
endif(PERF)

set(DPDK_HOME "/users/akalia/dpdk")
include_directories(SYSTEM ${DPDK_HOME}/x86_64-native-linuxapp-gcc/include)
add_definitions(-include rte_config.h)
link_directories(${LINK_DIRECTORIES} ${DPDK_HOME}/x86_64-native-linuxapp-gcc/lib)
set(LIBRARIES ${LIBRARIES} -Wl,--whole-archive)
set(LIBRARIES ${LIBRARIES} rte_kvargs rte_mbuf rte_ethdev rte_mempool rte_mempool_ring rte_ring rte_eal rte_hash rte_pci rte_bus_pci rte_bus_vdev)
set(LIBRARIES ${LIBRARIES} rte_pmd_i40e rte_pmd_ixgbe rte_pmd_ring)
set(LIBRARIES ${LIBRARIES} -Wl,--no-whole-archive)
set(LIBRARIES ${LIBRARIES} rt dl)

add_executable(example example.cc)
target_link_libraries(example ${LIBRARIES})
