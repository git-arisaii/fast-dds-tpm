#ifndef _SECURITY_TPM_HELPER_H_
#define _SECURITY_TPM_HELPER_H_

#include <string>
#include <openssl/evp.h>
#include <tss2/tss2_esys.h>

#include <fastdds/rtps/security/exceptions/SecurityException.h>

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

bool loadTpmKey(
        ESYS_CONTEXT* esys_ctx,
        std::string key_name,
        ESYS_TR* key,
        SecurityException& exception);

bool calculateTpmDigest(
        TPM2_ALG_ID hash_alg,
        const uint8_t* buffer,
        uint16_t length,
        TPM2B_DIGEST* digest,
        SecurityException& exception);

std::string getTpmHashAlgName(
        TPM2_ALG_ID hash_alg);

TPM2_ALG_ID getTpmHashAlgId(
        std::string hash_alg_name);

uint16_t getTpmHashAlgSize(
        TPM2_ALG_ID hash_alg);

const EVP_MD* tpmHashAlgToOssl(
        TPM2_ALG_ID hash_alg);

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima

#endif // _SECURITY_TPM_HELPER_H_