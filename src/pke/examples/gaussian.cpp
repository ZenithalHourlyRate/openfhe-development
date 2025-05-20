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

#include <cassert>

using namespace lbcrypto;

int gaussian_mult(unsigned depth, int ringDim, int mulDepth, int numTests, int isKey) {
    // open file gaussian_depth_ringdim_muldepth_numtests.txt
    std::ofstream out_indep("gaussian_" + std::to_string(depth) + "_" + std::to_string(ringDim) + "_" +
                            std::to_string(mulDepth) + "_" + std::to_string(numTests) + "_" + std::to_string(isKey) +
                            "_indep.txt");
    std::ofstream out_dep("gaussian_" + std::to_string(depth) + "_" + std::to_string(ringDim) + "_" +
                          std::to_string(mulDepth) + "_" + std::to_string(numTests) + "_" + std::to_string(isKey) +
                          "_dep.txt");

    out_indep << "Depth: " << depth << ", RingDim: " << ringDim << ", MulDepth: " << mulDepth
              << ", NumTests: " << numTests << ", isKey: " << isKey << std::endl;
    out_dep << "Depth: " << depth << ", RingDim: " << ringDim << ", MulDepth: " << mulDepth
            << ", NumTests: " << numTests << ", isKey: " << isKey << std::endl;

    constexpr int ARRAY_LEN = 256;
    assert(depth < ARRAY_LEN);

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
    out_indep << "logQ : " << logQ << std::endl;
    out_dep << "logQ : " << logQ << std::endl;
    out_indep << *(cryptoContext->GetCryptoParameters()) << std::endl;
    out_dep << *(cryptoContext->GetCryptoParameters()) << std::endl;

    // Get Discrete Gaussian
    [[maybe_unused]] const DCRTPoly::DggType& dgg = cryptoParams->GetDiscreteGaussianGenerator();
    [[maybe_unused]] DCRTPoly::TugType tug;

    auto getNorm = [&](DCRTPoly e) {
        e.SetFormat(Format::COEFFICIENT);
        return log2(e.Norm());
    };

    auto indepExpr = [&]() {
        std::vector<double> norms;
        auto e =
            isKey ? DCRTPoly(tug, elementParams, Format::EVALUATION) : DCRTPoly(dgg, elementParams, Format::EVALUATION);
        norms.push_back(getNorm(e));
        for (unsigned i = 0; i != depth - 1; ++i) {
            auto newE = isKey ? DCRTPoly(tug, elementParams, Format::EVALUATION) :
                                DCRTPoly(dgg, elementParams, Format::EVALUATION);
            e *= newE;
            norms.push_back(getNorm(e));
        }
        return norms;
    };

    auto depExpr = [&]() {
        std::vector<double> norms;
        auto e =
            isKey ? DCRTPoly(tug, elementParams, Format::EVALUATION) : DCRTPoly(dgg, elementParams, Format::EVALUATION);
        norms.push_back(getNorm(e));
        DCRTPoly oldE = e;
        for (unsigned i = 0; i != depth - 1; ++i) {
            e *= oldE;
            norms.push_back(getNorm(e));
        }
        return norms;
    };

    std::array<std::vector<double>, ARRAY_LEN> indepNormsExprs;
    std::array<std::vector<double>, ARRAY_LEN> depNormsExprs;

    for (auto i = 0; i != numTests; ++i) {
        auto indepNorms = indepExpr();
        auto depNorms   = depExpr();
        for (unsigned j = 0; j != indepNorms.size(); ++j) {
            indepNormsExprs[j].push_back(indepNorms[j]);
            depNormsExprs[j].push_back(depNorms[j]);
        }
    }

    std::array<double, ARRAY_LEN> indepMedians;
    std::array<double, ARRAY_LEN> indepMaxs;
    std::array<double, ARRAY_LEN> depMedians;
    std::array<double, ARRAY_LEN> depMaxs;

    // calculate the median and max
    for (unsigned i = 0; i != depth; ++i) {
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
    out_indep << "Independent expression norms: " << std::endl;
    for (unsigned i = 0; i != depth; ++i) {
        out_indep << "Median: " << indepMedians[i] << ", Max: " << indepMaxs[i] << std::endl;
    }
    out_dep << "Dependent expression norms: " << std::endl;
    for (unsigned i = 0; i != depth; ++i) {
        out_dep << "Median: " << depMedians[i] << ", Max: " << depMaxs[i] << std::endl;
    }
    return 0;
}

int main(int argc, char* argv[]) {
    // get depth,ringdim,muldepth,numtests from command line
    if (argc != 6) {
        std::cerr << "Usage: " << argv[0] << " <depth> <ringDim> <mulDepth> <numTests> <isKey>" << std::endl;
        return 1;
    }
    unsigned depth = std::stoi(argv[1]);
    int ringDim    = std::stoi(argv[2]);
    int mulDepth   = std::stoi(argv[3]);
    int numTests   = std::stoi(argv[4]);
    int isKey      = std::stoi(argv[5]);

    // typical values
    // gaussian: depth=32, ringDim=65536, mulDepth=15, numTests=1000

    gaussian_mult(/*depth*/ depth, /*ringDim*/ ringDim, /*mulDepth*/ mulDepth, /*numTests*/ numTests, /*isKey*/ isKey);
    return 0;
}