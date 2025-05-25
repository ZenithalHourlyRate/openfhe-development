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
#ifdef NOISE
    auto cv = ct->GetElements();

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

    // CAUTION: here we use the default Openfhe Norm, unlike other tests
    double noise = (log2(res.Norm()));

    std::cout << "noise: " << noise << std::endl;

    auto ringDim = cv[0].GetParams()->GetRingDimension();
    // expansion factor delta
    auto delta = [](uint32_t n) -> double {
        return (2. * std::sqrt(n));
    };

    auto Bkey = 1;

    auto bound = log2((1. + delta(ringDim) * Bkey) / 2.);
    std::cout << "noise bound: " << bound << "  gap: " << bound - noise << std::endl;

    if (bound < noise) {
        std::cout << "exceeded!" << std::endl;
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
    cryptoContext->Enable(LEVELEDSHE);

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
