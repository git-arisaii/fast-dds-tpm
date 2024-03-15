#ifndef _SECURITY_TPM_QUOTE_H_
#define _SECURITY_TPM_QUOTE_H_

#include <openssl/evp.h>
#include <tss2/tss2_esys.h>

#include <fastdds/rtps/security/exceptions/SecurityException.h>

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

bool generateTpmQuote(
        ESYS_CONTEXT* esys_ctx,
        const ESYS_TR& quoting_key,
        const TPML_PCR_SELECTION& pcr_selections,
        const TPM2B_DATA& qualifying_data,
        TPM2B_ATTEST** quoted,
        TPMT_SIGNATURE** signature,
        SecurityException& exception);

bool verifyTpmQuote(
        EVP_PKEY* pkey,
        const TPM2B_DATA& qualifying_data,
        const TPM2B_ATTEST& quoted,
        const TPMT_SIGNATURE& signature,
        const TPM2B_DIGEST& cp_digest,
        SecurityException& exception);

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima

#endif // _SECURITY_TPM_QUOTE_H_