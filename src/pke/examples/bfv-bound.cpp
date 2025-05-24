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
  Simple example for BFVrns (integer arithmetic)
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

    // B/FV specific
    // from @openfhe//src/pke/extras/bfv-mult-bug.cpp
    const auto cryptoParams = std::static_pointer_cast<CryptoParametersBFVRNS>(sk->GetCryptoParameters());

    const auto encParams                = cryptoParams->GetElementParams();
    NativeInteger NegQModt              = cryptoParams->GetNegQModt();
    NativeInteger NegQModtPrecon        = cryptoParams->GetNegQModtPrecon();
    const NativeInteger t               = cryptoParams->GetPlaintextModulus();
    std::vector<NativeInteger> tInvModq = cryptoParams->GettInvModq();

    // Get a new plaintext with full slots
    // SetLength(8) above will truncate the plaintext
    PlaintextT newPtxt;
    cc->Decrypt(sk, ct, &newPtxt);
    // Repack to convert from NativePoly to DCRTPoly
    std::vector<int64_t> value = newPtxt->GetPackedValue();
    Plaintext repack           = cc->MakePackedPlaintext(value);
    DCRTPoly plain             = repack->GetElement<DCRTPoly>();
    plain.SetFormat(Format::COEFFICIENT);
    plain.TimesQovert(encParams, tInvModq, t, NegQModt, NegQModtPrecon);

    // remove the message, leave only the noise
    DCRTPoly res;
    res = b - plain;

    double noise = (log2(res.Norm()));

    double logQ = 0;
    std::vector<double> logqi_v;
    for (usint i = 0; i < sizeQl; i++) {
        double logqi = log2(cv[0].GetParams()->GetParams()[i]->GetModulus().ConvertToInt());
        logqi_v.push_back(logqi);
        logQ += logqi;
    }

    auto logT = log2(t.ConvertToInt());

    std::cout << "  cv " << cv.size() << " Ql " << sizeQl << " log(Q/2T): " << logQ - logT - 1 << " logqi: " << logqi_v
              << " budget " << logQ - logT - 1 - noise << " noise: " << noise << std::endl;

    auto ringDim = cv[0].GetParams()->GetRingDimension();
    // expansion factor delta
    auto delta = [](uint32_t n) -> double {
        return (2. * std::sqrt(n));
    };

    auto Bkey = 1;

    auto bound = (1. + delta(ringDim) * Bkey) / 2.;
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
    // Sample Program: Step 1: Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(2);
    parameters.SetEncryptionTechnique(lbcrypto::EXTENDED);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);

    // Sample Program: Step 2: Key Generation

    // Initialize Public Key Containers
    KeyPair<DCRTPoly> keyPair;

    // Generate a public/private key pair
    keyPair = cryptoContext->KeyGen();

    std::vector<int64_t> vectorOfInts1 = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    Plaintext plaintext1               = cryptoContext->MakePackedPlaintext(vectorOfInts1);

    // The encoded vectors are encrypted
    auto ciphertext1 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);

    __heir_debug(cryptoContext, keyPair.secretKey, ciphertext1, {});

    return 0;
}
