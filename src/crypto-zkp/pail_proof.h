//
// Created by Sword03 on 2021/6/8.
//

#ifndef CPP_MPC_PAIL_PROOF_H
#define CPP_MPC_PAIL_PROOF_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "zkp.pb.h"
#include "crypto-paillier/pail.h"

namespace safeheron{
namespace zkp {
namespace pail {

class PailProof {
private:
    void GenerateXs(std::vector<safeheron::bignum::BN> &x_arr, const safeheron::bignum::BN &index, const safeheron::bignum::BN &point_x, const safeheron::bignum::BN &point_y, const safeheron::bignum::BN &N, uint proof_iters = 13) const;
public:
    // List of y^N mod N
    std::vector<safeheron::bignum::BN> y_N_arr_;

    PailProof(){};

    void Prove(const safeheron::pail::PailPrivKey &pail_priv, const safeheron::bignum::BN &index, const safeheron::bignum::BN &point_x, const safeheron::bignum::BN &point_y, uint proof_iters = 13);
    bool Verify(const safeheron::pail::PailPubKey &pail_pub, const safeheron::bignum::BN &index, const safeheron::bignum::BN &point_x, const safeheron::bignum::BN &point_y, uint proof_iters = 13) const;

    bool ToProtoObject(safeheron::proto::PailProof &pail_proof) const;
    bool FromProtoObject(const safeheron::proto::PailProof &pail_proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //CPP_MPC_PAIL_PROOF_H
