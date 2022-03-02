// @file pre-base.h -- Public key type for lattice crypto operations.
// @author TPOC: contact@palisade-crypto.org
//
// @copyright Copyright (c) 2019, New Jersey Institute of Technology (NJIT)
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution. THIS SOFTWARE IS
// PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
// IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
// EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
// INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#ifndef LBCRYPTO_CRYPTO_BGVRNS_PARAMETERGENERATION_H
#define LBCRYPTO_CRYPTO_BGVRNS_PARAMETERGENERATION_H

#include "schemerns/rns-parametergeneration.h"

/**
 * @namespace lbcrypto
 * The namespace of lbcrypto
 */
namespace lbcrypto {

class ParameterGenerationBGVRNS : public ParameterGenerationRNS {
public:
  virtual ~ParameterGenerationBGVRNS() {}

  virtual bool ParamsGenBGVRNS(shared_ptr<CryptoParametersBase<DCRTPoly>> cryptoParams,
                 usint cyclOrder, usint ptm, usint numPrimes, usint relinWindow,
                 MODE mode,
                 usint firstModSize = 0,
                 usint dcrtBits = 0,
                 uint32_t numPartQ = 4,
                 usint multihopQBound = 0,
                 enum KeySwitchTechnique ksTech = BV,
                 enum RescalingTechnique rsTech = FIXEDMANUAL,
                 enum EncryptionTechnique encTech = STANDARD,
                 enum MultiplicationTechnique multTech = HPS) const override;


  /////////////////////////////////////
  // SERIALIZATION
  /////////////////////////////////////


  template <class Archive>
  void save(Archive &ar, std::uint32_t const version) const {}

  template <class Archive>
  void load(Archive &ar, std::uint32_t const version) {}

  std::string SerializedObjectName() const {
    return "ParameterGenerationBGVRNS";
  }
};

}  // namespace lbcrypto

#endif