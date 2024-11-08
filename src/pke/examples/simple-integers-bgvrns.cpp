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

void EvalNoiseBGV(CryptoContext<DCRTPoly> &cryptoContext, PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, std::string tag);

int main() {
    // Sample Program: Step 1 - Set CryptoContext
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetMultiplicativeDepth(2);
    parameters.SetPlaintextModulus(65537);
    parameters.SetScalingTechnique(FIXEDMANUAL);
    parameters.SetKeySwitchTechnique(HYBRID);
    //parameters.SetDigitSize(30);
    parameters.SetNumLargeDigits(3);
    parameters.SetScalingModSize(51);

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
    auto ciphertext2 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
    auto ciphertext3 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
    auto ciphertext4 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext5 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    auto ciphertext6 = cryptoContext->Encrypt(keyPair.publicKey, plaintext2);
    auto ciphertext7 = cryptoContext->Encrypt(keyPair.publicKey, plaintext3);
    auto ciphertext8 = cryptoContext->Encrypt(keyPair.publicKey, plaintext1);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertext1, "fresh1");
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertext2, "fresh2");
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertext3, "fresh3");
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertext4, "fresh4");
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertext5, "fresh5");
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertext6, "fresh6");
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertext7, "fresh7");
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertext8, "fresh8");

    auto ciphertextMul12 = cryptoContext->EvalMult(ciphertext1, ciphertext2);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul12, "Mul12");
    cryptoContext->ModReduceInPlace(ciphertextMul12);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul12, "Mul12r");
    auto ciphertextMul34 = cryptoContext->EvalMult(ciphertext3, ciphertext4);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul34, "Mul34");
    cryptoContext->ModReduceInPlace(ciphertextMul34);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul34, "Mul34r");
    auto ciphertextMul1234 = cryptoContext->EvalMult(ciphertextMul12, ciphertextMul34);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul1234, "Mul1234");
    cryptoContext->ModReduceInPlace(ciphertextMul1234);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul1234, "Mul1234r");

    auto ciphertextMul56 = cryptoContext->EvalMult(ciphertext5, ciphertext6);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul56, "Mul56");
    cryptoContext->ModReduceInPlace(ciphertextMul56);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul56, "Mul56r");
    auto ciphertextMul78 = cryptoContext->EvalMult(ciphertext7, ciphertext8);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul78, "Mul78");
    cryptoContext->ModReduceInPlace(ciphertextMul78);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul78, "Mul78r");
    auto ciphertextMul5678 = cryptoContext->EvalMult(ciphertextMul56, ciphertextMul78);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul5678, "Mul5678");
    cryptoContext->ModReduceInPlace(ciphertextMul5678);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul5678, "Mul5678r");

    auto ciphertextMul12345678 = cryptoContext->EvalMult(ciphertextMul1234, ciphertextMul5678);
    EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMul12345678, "Mul");

    Plaintext plaintextMultResult;
    cryptoContext->Decrypt(keyPair.secretKey, ciphertextMul12345678, &plaintextMultResult);

    std::cout << "mult result: " << plaintextMultResult << std::endl;

    //// Sample Program: Step 4 - Evaluation

    //// Homomorphic additions
    //auto ciphertextAdd12     = cryptoContext->EvalAdd(ciphertext1, ciphertext2);
    //auto ciphertextAddResult = cryptoContext->EvalAdd(ciphertextAdd12, ciphertext3);

    //// Homomorphic multiplications
    //// modulus switching is done automatically because by default the modulus
    //// switching method is set to AUTO (rather than MANUAL)
    //auto ciphertextMul12      = cryptoContext->EvalMult(ciphertext1, ciphertext2);
    //auto ciphertextMultResult = cryptoContext->EvalMult(ciphertextMul12, ciphertext3);
    //// Homomorphic rotations
    //auto ciphertextRot1 = cryptoContext->EvalRotate(ciphertext1, 1);
    //auto ciphertextRot2 = cryptoContext->EvalRotate(ciphertext1, 2);
    //auto ciphertextRot3 = cryptoContext->EvalRotate(ciphertext1, -1);
    //auto ciphertextRot4 = cryptoContext->EvalRotate(ciphertext1, -2);

    //// Sample Program: Step 5 - Decryption

    //// Decrypt the result of additions
    //Plaintext plaintextAddResult;
    //cryptoContext->Decrypt(keyPair.secretKey, ciphertextAddResult, &plaintextAddResult);

    //std::cout << "#1 + #2 + #3: " << plaintextAddResult << std::endl;
    //EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextAddResult, "add");

    //// Decrypt the result of multiplications
    //Plaintext plaintextMultResult;
    //cryptoContext->Decrypt(keyPair.secretKey, ciphertextMultResult, &plaintextMultResult);

    //EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextMultResult, "mult");

    //// Decrypt the result of rotations
    //Plaintext plaintextRot1;
    //cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot1, &plaintextRot1);
    //Plaintext plaintextRot2;
    //cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot2, &plaintextRot2);
    //Plaintext plaintextRot3;
    //cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot3, &plaintextRot3);
    //Plaintext plaintextRot4;
    //cryptoContext->Decrypt(keyPair.secretKey, ciphertextRot4, &plaintextRot4);

    //plaintextRot1->SetLength(vectorOfInts1.size());
    //plaintextRot2->SetLength(vectorOfInts1.size());
    //plaintextRot3->SetLength(vectorOfInts1.size());
    //plaintextRot4->SetLength(vectorOfInts1.size());

    //EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextRot1, "rot1");
    //EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextRot2, "rot2");
    //EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextRot3, "rot-1");
    //EvalNoiseBGV(cryptoContext, keyPair.secretKey, ciphertextRot4, "rot-2");

    //std::cout << "Plaintext #1: " << plaintext1 << std::endl;
    //std::cout << "Plaintext #2: " << plaintext2 << std::endl;
    //std::cout << "Plaintext #3: " << plaintext3 << std::endl;

    //// Output results
    //std::cout << "\nResults of homomorphic computations" << std::endl;
    //std::cout << "#1 + #2 + #3: " << plaintextAddResult << std::endl;
    //std::cout << "#1 * #2 * #3: " << plaintextMultResult << std::endl;
    //std::cout << "Left rotation of #1 by 1: " << plaintextRot1 << std::endl;
    //std::cout << "Left rotation of #1 by 2: " << plaintextRot2 << std::endl;
    //std::cout << "Right rotation of #1 by 1: " << plaintextRot3 << std::endl;
    //std::cout << "Right rotation of #1 by 2: " << plaintextRot4 << std::endl;

    return 0;
}

void EvalNoiseBGV(CryptoContext<DCRTPoly> &cryptoContext, PrivateKey<DCRTPoly> privateKey, ConstCiphertext<DCRTPoly> ciphertext, std::string tag) {
    Plaintext ptxt;
    cryptoContext->Decrypt(privateKey, ciphertext, &ptxt);
    //const auto ptm = cryptoContext->GetCryptoParameters()->GetPlaintextModulus();

    const std::vector<DCRTPoly>& cv = ciphertext->GetElements();
    DCRTPoly s                      = privateKey->GetPrivateElement();

    size_t sizeQl = cv[0].GetParams()->GetParams().size();
    size_t sizeQs = s.GetParams()->GetParams().size();

    size_t diffQl = sizeQs - sizeQl;

    auto scopy(s);
    scopy.DropLastElements(diffQl);

    DCRTPoly sPower(scopy);

    DCRTPoly b = cv[0];
    b.SetFormat(Format::EVALUATION);

    DCRTPoly ci;
    for (size_t i = 1; i < cv.size(); i++) {
        ci = cv[i];
        ci.SetFormat(Format::EVALUATION);

        b += sPower * ci;
        sPower *= scopy;
    }

    b.SetFormat(Format::COEFFICIENT);
    Poly b_big = b.CRTInterpolate();

    Poly plain_big;

    DCRTPoly plain_dcrt = ptxt->GetElement<DCRTPoly>();
    auto plain_dcrt_size = plain_dcrt.GetNumOfElements();

    if (plain_dcrt_size > 0) {
        plain_dcrt.SetFormat(Format::COEFFICIENT);
        plain_big = plain_dcrt.CRTInterpolate();
    } else {
        std::vector<int64_t> value = ptxt->GetPackedValue();
        Plaintext repack = cryptoContext->MakePackedPlaintext(value);
        DCRTPoly plain_repack = repack->GetElement<DCRTPoly>();
        plain_repack.SetFormat(Format::COEFFICIENT);
        plain_big = plain_repack.CRTInterpolate();
    }

    auto plain_modulus = plain_big.GetModulus();
    auto b_modulus = b_big.GetModulus();
    plain_big.SwitchModulus(b_big.GetModulus(), b_big.GetRootOfUnity(), 0, 0);

    Poly res = b_big - plain_big;

    double noise = (log2(res.Norm()));

    double logQ = 0;
    for (usint i = 0; i < sizeQl; i++) {
        double logqi = log2(cv[0].GetParams()->GetParams()[i]->GetModulus().ConvertToInt());
        logQ += logqi;
    }

    std::cout << tag << '\t' << " logQ: " << logQ << " noise: " << noise << " budget " << logQ - noise - 1 << std::endl;
}
