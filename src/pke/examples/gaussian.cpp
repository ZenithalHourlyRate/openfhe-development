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
  Gaussian Noise Multiplication
 */

#include "openfhe.h"

using namespace lbcrypto;

template <int depth, int ringDim, int mulDepth, int numTests>
int gaussian_mult() {
    std::cout << "Depth: " << depth << ", RingDim: " << ringDim << ", MulDepth: " << mulDepth
              << ", NumTests: " << numTests << std::endl;
    CCParams<CryptoContextBFVRNS> parameters;
    // ptm is not important, just for making sure Q is large enough
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(mulDepth);
    parameters.SetSecurityLevel(HEStd_NotSet);

    // this set N
    parameters.SetRingDim(ringDim);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    cryptoContext->Enable(PKE);

    auto cryptoParams  = std::dynamic_pointer_cast<CryptoParametersRNS>(cryptoContext->GetCryptoParameters());
    auto elementParams = cryptoContext->GetCryptoParameters()->GetElementParams();

    // dump logQ
    double logQ = 0;
    std::vector<double> logqi_v;
    auto Qsize = elementParams->GetParams().size();
    for (usint i = 0; i < Qsize; i++) {
        double logqi = log2(elementParams->GetParams()[i]->GetModulus().ConvertToInt());
        logqi_v.push_back(logqi);
        logQ += logqi;
    }
    std::cout << "logQ : " << logQ << std::endl;
    // std::cout << *(cryptoContext->GetCryptoParameters()) << std::endl;

    // Get Discrete Gaussian
    const DCRTPoly::DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();

    auto getNorm = [&](DCRTPoly e) {
        e.SetFormat(Format::COEFFICIENT);
        return log2(e.Norm());
    };

    auto indepExpr = [&]() {
        std::vector<double> norms;
        DCRTPoly e(dgg, elementParams, Format::EVALUATION);
        norms.push_back(getNorm(e));
        for (auto i = 0; i != depth - 1; ++i) {
            DCRTPoly newE(dgg, elementParams, Format::EVALUATION);
            e *= newE;
            norms.push_back(getNorm(e));
        }
        return norms;
    };

    auto depExpr = [&]() {
        std::vector<double> norms;
        DCRTPoly e(dgg, elementParams, Format::EVALUATION);
        norms.push_back(getNorm(e));
        DCRTPoly oldE = e;
        for (auto i = 0; i != depth - 1; ++i) {
            e *= oldE;
            norms.push_back(getNorm(e));
        }
        return norms;
    };

    std::array<std::vector<double>, depth> indepNormsExprs;
    std::array<std::vector<double>, depth> depNormsExprs;

    for (auto i = 0; i != numTests; ++i) {
        auto indepNorms = indepExpr();
        auto depNorms   = depExpr();
        for (unsigned j = 0; j != indepNorms.size(); ++j) {
            indepNormsExprs[j].push_back(indepNorms[j]);
            depNormsExprs[j].push_back(depNorms[j]);
        }
    }

    std::array<double, depth> indepMedians;
    std::array<double, depth> indepMaxs;
    std::array<double, depth> depMedians;
    std::array<double, depth> depMaxs;

    // calculate the median and max
    for (auto i = 0; i != depth; ++i) {
        std::sort(indepNormsExprs[i].begin(), indepNormsExprs[i].end());
        std::sort(depNormsExprs[i].begin(), depNormsExprs[i].end());
        auto indepMedian = indepNormsExprs[i][numTests / 2];
        auto indepMax    = indepNormsExprs[i].back();
        auto depMedian   = depNormsExprs[i][numTests / 2];
        auto depMax      = depNormsExprs[i].back();
        indepMedians[i]  = indepMedian;
        indepMaxs[i]     = indepMax;
        depMedians[i]    = depMedian;
        depMaxs[i]       = depMax;
    }

    // print the results
    std::cout << "Independent expression norms: " << std::endl;
    for (unsigned i = 0; i != indepMedians.size(); ++i) {
        std::cout << "Median: " << indepMedians[i] << ", Max: " << indepMaxs[i] << std::endl;
    }
    std::cout << "Dependent expression norms: " << std::endl;
    for (unsigned i = 0; i != depMedians.size(); ++i) {
        std::cout << "Median: " << depMedians[i] << ", Max: " << depMaxs[i] << std::endl;
    }
    return 0;
}

int main() {
    // gaussian_mult</*depth*/ 64, /*ringDim*/ 64, /*mulDepth*/ 15, /*numTests*/ 10>();
    gaussian_mult</*depth*/ 32, /*ringDim*/ 65536, /*mulDepth*/ 15, /*numTests*/ 1000>();
    // gaussian_mult</*depth*/ 64, /*ringDim*/ 65536, /*mulDepth*/ 20, /*numTests*/ 10>();
    return 0;
}