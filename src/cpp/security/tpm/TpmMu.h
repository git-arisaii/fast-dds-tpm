#ifndef _SECURITY_TPM_MU_H_
#define _SECURITY_TPM_MU_H_

#include <vector>
#include <tss2/tss2_tpm2_types.h>

#include <fastdds/rtps/security/exceptions/SecurityException.h>

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

bool unmarshalTpmsAttest(
        const TPM2B_ATTEST& quoted,
        TPMS_ATTEST* attest,
        SecurityException& exception);

bool marshalTpm2bAttest(
        const TPM2B_ATTEST* src,
        std::vector<uint8_t>& buffer,
        SecurityException& exception);

bool unmarshalTpm2bAttest(
        const std::vector<uint8_t>& buffer,
        TPM2B_ATTEST* dest,
        SecurityException& exception);

bool marshalTpmtSignature(
        const TPMT_SIGNATURE* src,
        std::vector<uint8_t>& buffer,
        SecurityException& exception);

bool unmarshalTpmtSignature(
        const std::vector<uint8_t>& buffer,
        TPMT_SIGNATURE* dest,
        SecurityException& exception);

bool marshalTpmlPcrSelection(
        const TPML_PCR_SELECTION* src,
        std::vector<uint8_t>& buffer,
        SecurityException& exception);

bool unmarshalTpmlPcrSelection(
        const std::vector<uint8_t>& buffer,
        TPML_PCR_SELECTION* dest,
        SecurityException& exception);

bool marshalTpmlDigest(
        const TPML_DIGEST* src,
        std::vector<uint8_t>& buffer,
        SecurityException& exception);

bool unmarshalTpmlDigest(
        const std::vector<uint8_t>& buffer,
        TPML_DIGEST* dest,
        SecurityException& exception);

bool marshalTpmlDigestVec(
        const std::vector<TPML_DIGEST>& src_vec,
        std::vector<uint8_t>& buffer,
        SecurityException& exception);

bool unmarshalTpmlDigestVec(
        const std::vector<uint8_t>& buffer,
        std::vector<TPML_DIGEST>& dest_vec,
        SecurityException& exception);

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima

#endif // _SECURITY_TPM_MU_H_