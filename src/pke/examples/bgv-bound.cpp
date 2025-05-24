//==================================================================================
// BSD 2-Clause License
//
// Copyright (c) 2014-2022, NJIT, Duality Technologies Inc. and other contributors
//
// All rights reserved.
//
// Author TPOC: contact@openfhe.org
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
// FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
// DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
// SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
// CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//==================================================================================

/*
  Simple example for BGVrns (integer arithmetic)
 */

#include "openfhe.h"

using namespace lbcrypto;

using CiphertextT        = ConstCiphertext<DCRTPoly>;
using MutableCiphertextT = Ciphertext<DCRTPoly>;
using CCParamsT          = CCParams<CryptoContextBFVRNS>;
using CryptoContextT     = CryptoContext<DCRTPoly>;
using EvalKeyT           = EvalKey<DCRTPoly>;
using PlaintextT         = Plaintext;
using PrivateKeyT        = PrivateKey<DCRTPoly>;
using PublicKeyT         = PublicKey<DCRTPoly>;

// DecryptCore not accessible from CryptoContext
// so copy from @openfhe//src/pke/lib/schemerns/rns-pke.cpp
DCRTPoly DecryptCore(const std::vector<DCRTPoly>& cv, const PrivateKey<DCRTPoly> privateKey) {
    const DCRTPoly& s = privateKey->GetPrivateElement();

    size_t sizeQ  = s.GetParams()->GetParams().size();
    size_t sizeQl = cv[0].GetParams()->GetParams().size();

    size_t diffQl = sizeQ - sizeQl;

    auto scopy(s);
    scopy.DropLastElements(diffQl);

    DCRTPoly sPower(scopy);

    DCRTPoly b(cv[0]);
    b.SetFormat(Format::EVALUATION);

    DCRTPoly ci;
    for (size_t i = 1; i < cv.size(); i++) {
        ci = cv[i];
        ci.SetFormat(Format::EVALUATION);

        b += sPower * ci;
        sPower *= scopy;
    }
    return b;
}

//#define OP
//#define DECRYPT
#define NOISE

void __heir_debug(CryptoContextT cc, PrivateKeyT sk, CiphertextT ct,
                  const std::map<std::string, std::string>& debugAttrMap) {
#ifdef OP
    auto isBlockArgument = debugAttrMap.at("asm.is_block_arg");
    if (isBlockArgument == "1") {
        std::cout << "Input" << std::endl;
    }
    else {
        std::cout << debugAttrMap.at("asm.op_name") << std::endl;
    }
#endif

#ifdef DECRYPT
    PlaintextT ptxt;
    cc->Decrypt(sk, ct, &ptxt);
    ptxt->SetLength(std::stod(debugAttrMap.at("message.size")));
    std::cout << "  " << ptxt << std::endl;
#endif

#ifdef NOISE
    auto cv       = ct->GetElements();
    size_t sizeQl = cv[0].GetParams()->GetParams().size();

    auto b = DecryptCore(cv, sk);
    b.SetFormat(Format::COEFFICIENT);

    auto poly = b.CRTInterpolate();

    // auto values  = poly.GetValues();
    // auto modulus = poly.GetParams()->GetModulus();
    // for (size_t i = 0; i < values.GetLength(); i++) {
    //     if (values[i] != 0) {
    //         auto value = values[i];
    //         bool neg   = false;
    //         if (value > modulus / 2) {
    //             neg   = true;
    //             value = modulus - value;
    //         }
    //         std::cout << "big[" << i << "] = " << (neg ? "-" : "") << value << std::endl;
    //     }
    // }

    double noise = (log2(b.Norm()));

    double logQ = 0;
    std::vector<double> logqi_v;
    for (usint i = 0; i < sizeQl; i++) {
        double logqi = log2(cv[0].GetParams()->GetParams()[i]->GetModulus().ConvertToInt());
        logqi_v.push_back(logqi);
        logQ += logqi;
    }

    std::cout << "  cv " << cv.size() << " Ql " << sizeQl << " logQ: " << logQ << " logqi: " << logqi_v << " budget "
              << logQ - noise - 1 << " noise: " << noise << std::endl;

    auto ringDim = cv[0].GetParams()->GetRingDimension();
    auto delta   = [](uint32_t n) -> double {
        return (2. * std::sqrt(n));
    };
    auto Bkey = 1;
    auto ptm  = cc->GetCryptoParameters()->GetPlaintextModulus();

    auto bound = ptm * (1. + delta(ringDim) * Bkey) / 2.;

    std::cout << "  noise bound: " << log2(bound) << "  gap: " << log2(bound) - noise << std::endl;

    if (log2(bound) < noise) {
        std::cout << "exceeded!" << std::endl;
    }

    // print the predicted bound by analysis
    if (debugAttrMap.find("noise.bound") != debugAttrMap.end()) {
        double noiseBound = std::stod(debugAttrMap.at("noise.bound"));

        std::cout << "  noise bound: " << noiseBound << "  gap: " << noiseBound - noise << std::endl;
    }
#endif
}

int main() {
    // Sample Program: Step 1 - Set CryptoContext
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(10);
    parameters.SetPlaintextModulus(65537);
    parameters.SetScalingModSize(50);
    parameters.SetScalingModSize(50);
    //parameters.SetSecurityLevel(lbcrypto::HEStd_NotSet);
    // parameters.SetRingDim(8192);
    //parameters.SetSecretKeyDist(SecretKeyDist::GAUSSIAN);
    parameters.SetSecretKeyDist(SecretKeyDist::UNIFORM_TERNARY);
    parameters.SetScalingTechnique(FIXEDMANUAL);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    std::cout << *(cryptoContext->GetCryptoParameters()) << std::endl;

    // Sample Program: Step 2 - Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    // Generate the relinearization key
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);

    // Generate the rotation evaluation keys
    cryptoContext->EvalRotateKeyGen(keyPair.secretKey, {1, 2, -1, -2});

    // Sample Program: Step 3 - Encryption

    // First plaintext vector is encoded
    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);
    // Second plaintext vector is encoded
    std::vector<int64_t> vectorOfInts2 = {3, 2, 1, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext2               = cryptoContext->MakePackedPlaintext(vectorOfInts2);
    // Third plaintext vector is encoded
    std::vector<int64_t> vectorOfInts3 = {1, 2, 5, 2, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext3               = cryptoContext->MakePackedPlaintext(vectorOfInts3);

    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    ciphertext1      = cryptoContext->ModReduce(ciphertext1);

    __heir_debug(cryptoContext, keyPair.secretKey, ciphertext1, {});

    // auto ciphertextMul12   = cryptoContext->EvalMult(ciphertext1, ciphertext2);
    // auto ciphertextMultResult = cryptoContext->EvalMult(ciphertextMul12, ciphertext3);
    // // Homomorphic rotations
    // auto ciphertextRot1 = cryptoContext->EvalRotate(ciphertext1, 1);
    // auto ciphertextRot2 = cryptoContext->EvalRotate(ciphertext1, 2);
    // auto ciphertextRot3 = cryptoContext->EvalRotate(ciphertext1, -1);
    // auto ciphertextRot4 = cryptoContext->EvalRotate(ciphertext1, -2);

    // // Sample Program: Step 5 - Decryption

    // // Decrypt the result of additions
    // Plaintext plaintextAddResult;
    // cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult, &plaintextAddResult);

    // // Decrypt the result of multiplications
    // Plaintext plaintextMultResult;
    // cryptoContext->Decrypt(keyPair.secretKey, ciphertextMultResult, &plaintextMultResult);

    // // Decrypt the result of rotations
    // Plaintext plaintextRot1;
    // cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot1, &plaintextRot1);
    // Plaintext plaintextRot2;
    // cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot2, &plaintextRot2);
    // Plaintext plaintextRot3;
    // cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot3, &plaintextRot3);
    // Plaintext plaintextRot4;
    // cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot4, &plaintextRot4);

    // plaintextRot1->SetLength(vectorOfInts1.size());
    // plaintextRot2->SetLength(vectorOfInts1.size());
    // plaintextRot3->SetLength(vectorOfInts1.size());
    // plaintextRot4->SetLength(vectorOfInts1.size());

    // std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    // std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    // std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    // // Output results
    // std::cout << "\nResults of homomorphic computations" << std::endl;
    // std::cout << "#1 + #2 + #3: " << plaintextAddResult << std::endl;
    // std::cout << "#1 * #2 * #3: " << plaintextMultResult << std::endl;
    // std::cout << "Left rotation of #1 by 1: " << plaintextRot1 << std::endl;
    // std::cout << "Left rotation of #1 by 2: " << plaintextRot2 << std::endl;
    // std::cout << "Right rotation of #1 by 1: " << plaintextRot3 << std::endl;
    // std::cout << "Right rotation of #1 by 2: " << plaintextRot4 << std::endl;

    return 0;
}
