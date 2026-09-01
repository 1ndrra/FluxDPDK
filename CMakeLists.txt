cmake_minimum_required(VERSION 3.20)
project(MicroServer CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)

# Extreme CPU tuning, LTO, and stripping C++ runtime overhead
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O3 -march=native -mtune=native -flto -Wall -Wextra -Werror -fno-rtti -fno-exceptions")

find_package(PkgConfig REQUIRED)
pkg_check_modules(DPDK REQUIRED libdpdk)

file(GLOB_RECURSE SOURCES
     "src/*.cpp" 
     "src/core/*.cpp"
     "src/edge/*.cpp"    
      "src/tenant/*.cpp"
    )
      
      
add_executable(server ${SOURCES})

target_include_directories(server PRIVATE src)
target_include_directories(server PRIVATE ${DPDK_INCLUDE_DIRS})
target_link_directories(server PRIVATE ${DPDK_LIBRARY_DIRS})
target_link_libraries(server PRIVATE ${DPDK_LIBRARIES})