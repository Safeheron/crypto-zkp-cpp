cmake_minimum_required(VERSION 3.10)
project(test)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
include_directories(${PROTOBUF_INCLUDE_DIRS})

find_package(GTest REQUIRED)
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoBN REQUIRED)
find_package(CryptoEncode REQUIRED)
find_package(CryptoHash REQUIRED)
find_package(CryptoCurve REQUIRED)
find_package(CryptoCommitment REQUIRED)
find_package(CryptoZKP REQUIRED)

add_executable(zkp-test zkp-test.cpp)
target_include_directories(zkp-test PUBLIC
        ${CryptoBN_INCLUDE_DIRS}
        ${CryptoEncode_INCLUDE_DIRS}
        ${CryptoHash_INCLUDE_DIRS}
        ${CryptoCommitment_INCLUDE_DIRS}
        ${CryptoZKP_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        ${GTEST_INCLUDE_DIRS}
)

target_link_libraries(zkp-test
        CryptoBN
        CryptoEncode
        CryptoHash
        CryptoCurve
        CryptoCommitment
        CryptoZKP
        ${GTEST_BOTH_LIBRARIES}
        ${PROTOBUF_LINK_LIBRARIES}
        pthread )


