//
// Created by Sword03 on 2021/6/8.
//

#ifndef CPP_MPC_DLOG_PROOF_H
#define CPP_MPC_DLOG_PROOF_H

#include <string>
#include "crypto-bn/bn.h"
#include "crypto-curve/curve.h"
#include "zkp.pb.h"

namespace safeheron{
namespace zkp {
namespace dlog {

class DLogProof {
private:
    void InternalProve(const safeheron::bignum::BN &sk, const curve::CurvePoint &g, const safeheron::bignum::BN &order);
    void InternalProveWithR(const safeheron::bignum::BN &sk, const curve::CurvePoint &g, const safeheron::bignum::BN &order, const safeheron::bignum::BN &r);
    bool InternalVerify(const curve::CurvePoint &g) const;

public:
    curve::CurvePoint pk_;
    curve::CurvePoint g_r_;
    safeheron::bignum::BN res_;

    const curve::Curve *curv_;

    DLogProof(){curv_ = nullptr;};
    DLogProof(curve::CurveType c_type);

    void Prove(const safeheron::bignum::BN &sk);
    void ProveWithR(const safeheron::bignum::BN &sk, const safeheron::bignum::BN &r);
    bool Verify() const;

    bool ToProtoObject(safeheron::proto::DLogProof &dlog_proof) const;
    bool FromProtoObject(const safeheron::proto::DLogProof &dlog_proof);

    bool ToBase64(std::string& base64) const;
    bool FromBase64(const std::string& base64);

    bool ToJsonString(std::string &json_str) const;
    bool FromJsonString(const std::string &json_str);
};

}
}
}
#endif //CPP_MPC_DLOG_PROOF_H
