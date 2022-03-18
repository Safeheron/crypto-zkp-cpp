cmake_minimum_required(VERSION 3.10)
project(test)

find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for opencv.pc file

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
#SET(CMAKE_BUILD_TYPE "Debug")
#set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
#set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

include_directories(
        "../src"
        ${PROTOBUF_INCLUDE_DIRS})

add_executable(zkp-test zkp-test.cpp)
target_link_libraries(zkp-test
        CryptoZKP
        ${GTEST_BOTH_LIBRARIES}
        pthread )
add_test(NAME test-zkp COMMAND zkp-test)


