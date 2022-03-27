find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # depend on pkg-config, this looks for opencv.pc file

#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoBN REQUIRED)
find_package(CryptoEncode REQUIRED)
find_package(CryptoCurve REQUIRED)
find_package(CryptoHash REQUIRED)
find_package(CryptoPaillier REQUIRED)

add_library(${PROJECT_NAME} SHARED
        crypto-zkp/dln_proof.cpp
        crypto-zkp/dlog_proof.cpp
        crypto-zkp/heg_proof.cpp
        crypto-zkp/pail_proof.cpp
        crypto-zkp/range_proof.cpp
        crypto-zkp/zkp.pb.cc
        )

target_include_directories(${PROJECT_NAME} PUBLIC
        ${CryptoBN_INCLUDE_DIRS}
        ${CryptoEncode_INCLUDE_DIRS}
        ${CryptoHash_INCLUDE_DIRS}
        ${CryptoCurve_INCLUDE_DIRS}
        ${CryptoPaillier_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        ${OPENSSL_INCLUDE_DIR}
        )

TARGET_LINK_LIBRARIES(${PROJECT_NAME} ${PROTOBUF_LIBRARIES}
        CryptoBN
        CryptoEncode
        CryptoCurve
        CryptoHash
        CryptoPaillier
        OpenSSL::Crypto
        -ldl
        )
