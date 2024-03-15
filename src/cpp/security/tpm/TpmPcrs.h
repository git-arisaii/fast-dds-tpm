#ifndef _SECURITY_TPM_PCRS_H_
#define _SECURITY_TPM_PCRS_H_

#include <string>
#include <vector>
#include <map>
#include <tss2/tss2_esys.h>

#include <fastdds/rtps/security/exceptions/SecurityException.h>

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

bool buildPcrSelectionList(
        const std::vector<TPM2_ALG_ID>& hash_algs,
        const std::vector<uint32_t>& pcrs,
        TPML_PCR_SELECTION& pcr_selections,
        SecurityException& exception);

bool checkPcrSelectionList(
        ESYS_CONTEXT* esys_ctx,
        const TPML_PCR_SELECTION& pcr_selections,
        SecurityException& exception);

std::string printPcrSelectionBitmap(
        const TPMS_PCR_SELECTION& pcr_selection);

bool readPcrs(
        ESYS_CONTEXT* esys_ctx,
        const TPML_PCR_SELECTION& pcr_selections,
        std::vector<TPML_DIGEST>& pcr_digests,
        SecurityException& exception);

bool decodePcrDigests(
        const TPML_PCR_SELECTION& pcr_selections,
        const std::vector<TPML_DIGEST>& pcr_digests,
        std::map<TPM2_ALG_ID, std::map<uint32_t, TPM2B_DIGEST> >& pcr_map,
        TPM2_ALG_ID cp_hash_alg,
        TPM2B_DIGEST& cp_digest,
        SecurityException& exception);

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima

#endif // _SECURITY_TPM_PCRS_H_