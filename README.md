# crypto-zkp-cpp

![img](doc/logo.png)

This software implements a library for several zero knowledge protocols.
- A Schnorr proof.
- A proof of knowledge that a pair of group elements {D, E}
- A proof of strong RSA modulus.
- A range proof in GG18.
- Non-interactive proof of correct paillier keypair generation.

The library comes with serialize/deserialize support to be used in higher level code to implement networking.

# Prerequisites

- [OpenSSL](https://github.com/openssl/openssl#documentation). See the [OpenSSL Installation Instructions](./doc/OpenSSL-Installation.md)
- [Protocol Buffers](https://github.com/protocolbuffers/protobuf.git). See the [Protocol Buffers Installation Instructions](./doc/Protocol-Buffers-Installation.md)
- [GoogleTest](https://github.com/google/googletest). **You need it to compile and run test cases**. See the [GoogleTest Installation Instructions](./doc/GoogleTest-Installation.md)
- [crypto-bn-cpp](https://github.com/safeheron/crypto-bn-cpp.git). See the [crypto-bn-cpp Installation Instructions](https://github.com/safeheron/crypto-bn-cpp/blob/main/README.md#build-and-install)
- [crypto-hash-cpp](https://github.com/safeheron/crypto-hash-cpp.git). See the [crypto-hash-cpp Installation Instructions](https://github.com/safeheron/crypto-hash-cpp/blob/main/README.md#build-and-install)
- [crypto-encode-cpp](https://github.com/safeheron/crypto-encode-cpp.git). See the [crypto-encode-cpp Installation Instructions](https://github.com/safeheron/crypto-encode-cpp/blob/main/README.md#build-and-install)
- [crypto-curve-cpp](https://github.com/safeheron/crypto-curve-cpp.git). See the [crypto-curve-cpp Installation Instructions](https://github.com/safeheron/crypto-curve-cpp/blob/main/README.md#build-and-install)
- [crypto-paillier-cpp](https://github.com/safeheron/crypto-paillier-cpp.git). See the [crypto-paillier-cpp Installation Instructions](https://github.com/safeheron/crypto-paillier-cpp/blob/main/README.md#build-and-install)

# Build and Install

Linux and Mac are supported now.  After obtaining the Source, have a look at the installation script.

```shell
git clone https://github.com/safeheron/crypto-zkp-cpp.git
cd crypto-zkp-cpp
mkdir build && cd build
# Run "cmake .. -DOPENSSL_ROOT_DIR=Your-Root-Directory-of-OPENSSL" instead of the command below on Mac OS.
# Turn on the switcher to enable tests; by default, turn off it if you don't wanna to build the test cases.
cmake .. -DENABLE_TESTS=ON
# Add the path to the LD_LIBRARY_PATH environment variable on Mac OS; Ignore it on Linux
export LIBRARY_PATH=$LIBRARY_PATH:/usr/local/lib/
make
make test # If you set ENABLE_TESTS ON
sudo make install
```

More platforms such as Windows would be supported soon.


# To start using crypto-sss-cpp

## CMake

CMake is your best option. It supports building on Linux, MacOS and Windows (soon) but also has a good chance of working on other platforms (no promises!). cmake has good support for crosscompiling and can be used for targeting the Android platform.

To build crypto-zkp-cpp from source, follow the BUILDING guide.

The canonical way to discover dependencies in CMake is the find_package command.

```shell
project(XXXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_BUILD_TYPE "Release")

find_package(PkgConfig REQUIRED)
pkg_search_module(PROTOBUF REQUIRED protobuf)  # this looks for *.pc file
#set(OPENSSL_USE_STATIC_LIBS TRUE)
find_package(OpenSSL REQUIRED)
find_package(CryptoZKP REQUIRED)

add_executable(${PROJECT_NAME} XXXX.cpp)
target_include_directories(${PROJECT_NAME} PUBLIC
        ${CryptoZKP_INCLUDE_DIRS}
        ${PROTOBUF_INCLUDE_DIRS}
        )

target_link_libraries(${PROJECT_NAME} PUBLIC
        CryptoZKP
        OpenSSL::Crypto
        ${PROTOBUF_LINK_LIBRARIES}
        pthread )
```

# Usage
## A Schnorr Proof
```c++
using safeheron::zkp::dlog::DLogProof;

const Curve * curv = GetCurveParam(CurveType::SECP256K1);
BN r = RandomBNLt(curv->n);
BN sk = RandomBNLt(curv->n);
DLogProof proof(CurveType::SECP256K1);
proof.ProveWithR(sk, r);
EXPECT_TRUE(proof.Verify());
```

## A Non-interactive proof of correct paillier keypair generation
```c++
using safeheron::zkp::pail::PailProof;
using safeheron::pail::PailPubKey;
using safeheron::pail::PailPrivKey;
using safeheron::pail::CreatePailPubKey;

PailPubKey pail_pub;
PailPrivKey pail_priv;
CreateKeyPair2048(pail_priv, pail_pub);

const Curve * curv = GetCurveParam(CurveType::SECP256K1);
BN r = RandomBNLt(curv->n);
CurvePoint point = curv->g * r;
BN index = RandomBNLtGcd(curv->n);

PailProof proof;
proof.Prove(pail_priv, index, point.x(), point.y());
ASSERT_TRUE(proof.Verify(pail_pub, index, point.x(), point.y()));
```

## A proof of knowledge that a pair of group elements {D, E}
```c++
using safeheron::zkp::heg::HegProof;

const Curve * curv = GetCurveParam(CurveType::SECP256K1);
// Witness
BN r = RandomBNLt(curv->n);
BN x = RandomBNLt(curv->n);
heg::HomoElGamalWitness witness(r, x);

// Statement
BN h = RandomBNLt(curv->n);
CurvePoint H = curv->g * h;
BN y = RandomBNLt(curv->n);
CurvePoint Y = curv->g * y;
CurvePoint D = H * x + Y * r;
CurvePoint E = curv->g * r;
heg::HomoElGamalStatement statement(curv->g, H, Y, D, E);

// Prove
heg::HegProof proof;
proof.Prove(statement, witness);

// Verify
EXPECT_TRUE(proof.Verify(statement));
```

## A range Proof
```c++
std::string n_hex = "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794611";
std::string g_hex = "a346603c869f5b159fde34715551985ab2fbb2254bf828801b750e422f22d652403e9258aeb65b983070e32dc1b439a91c6593ec8c93896dbf421b5d7d86f7e620bef3010560d29f377257afc2e1d6d396197f2ae80f70fd6741bc2282db8dc38947785e31e23ba0706340ee38f995241e222e92db89c47b0889b44797aae93ebba20d55770b1418b5815595db9c07a7682ab9a0125e54357ab76919eb7ce2818d702729fc28f130b4eb28de0dd5bd4c8d7030945856335a1bf9d3d29d923bde4692b6481ef549bd22b5c2010aecd98efb1fbe895ce4d5212728c9815ce4eae36c4b514b53b01657f29d2010e750526ef9bba5c7d011a6ed82e87fa166794612";
std::string n_tilde_hex = "C11A2F1A0EA592008BAFCAE756038DE028BA195E73B60F773F7399B4B94E26F8F90C488DEEA7ADB6910BCBCA8BA558E527B67B0B098420D4282411863B3FF39049C420CEB61D4C3683D2264957E583066F9C08C71E7A2A9E8E628E7853C962C4240E2E6FDB1F0F547A33EF0C31BD2B9739E0191AAF948AADE86519CD01A7B944A37C7150DF78A6E6FF4E5B8598F06334374BA068316C73484A07C2A0DF96DFE25931D0C67CE3A8B0E14635F0B34C1937F376EAB077281553F9F81E563DE7111136D95C8A5F9B87D91681AB412A8B62409CD2A2C3386E9B3E2FA3A7B7BE75368415315C1F905B7F38F4ED6758AD88563C41F28B717C7C13573062E6A6D4AA2A8D";
PailPubKey pail_pub = CreatePailPubKey(n_hex, g_hex);

BN N_tilde = BN::FromHexStr(n_tilde_hex);

const Curve * curv = GetCurveParam(CurveType::SECP256K1);
BN m = RandomBNLt(curv->n);
BN r = RandomBNLtGcd(pail_pub.n());
BN c = pail_pub.EncryptWithR(m, r);

BN h1 = RandomBNLtGcd(N_tilde);
h1 = ( h1 * h1 ) % N_tilde;

BN h2 = RandomBNLtGcd(N_tilde);
h2 = ( h2 * h2 ) % N_tilde;
std::cout << "tag3 " << std::endl;

range_proof::AliceRangeProof range_proof;
range_proof.Prove(curv->n, pail_pub.n(), pail_pub.g(), N_tilde, h1, h2, c, m , r);
ASSERT_TRUE(range_proof.Verify(curv->n, pail_pub.n(), pail_pub.g(), N_tilde, h1, h2, c));
```

## A proof of strong RSA modulus
```c++
int PRIME_BYTE_LEN = 1024 / 8;
BN P = RandomSafePrime(PRIME_BYTE_LEN);
BN Q = RandomSafePrime(PRIME_BYTE_LEN);
BN N_tilde = P * Q;

BN p = (P-1)/2;
BN q = (Q-1)/2;
BN pq = p * q;
BN f = RandomBNLtGcd(N_tilde);
BN alpha = RandomBNLtGcd(N_tilde);
BN beta = alpha.InvM(pq);

BN h1 = ( f * f ) % N_tilde;
BN h2 = h1.PowM(alpha, N_tilde);

dln_proof::DLNProof dln_proof;
dln_proof.Prove(N_tilde, h1, h2, p, q , alpha);
ASSERT_TRUE(dln_proof.Verify(N_tilde, h1, h2));
```

# Development Process & Contact
This library is maintained by Safeheron. Contributions are highly welcomed! Besides GitHub issues and PRs, feel free to reach out by mail.
