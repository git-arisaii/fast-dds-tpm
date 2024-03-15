#include <security/tpm/TpmMu.h>

#include <string>
#include <tss2/tss2_mu.h>

#define S1(x) #x
#define S2(x) S1(x)
#define LOCATION " (" __FILE__ ":" S2(__LINE__) ")"
#define _SecurityException_(str) SecurityException(std::string(str) + LOCATION)

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

bool unmarshalTpmsAttest(
        const TPM2B_ATTEST& quoted,
        TPMS_ATTEST* attest,
        SecurityException& exception)
{
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPMS_ATTEST_Unmarshal(quoted.attestationData, quoted.size, &offset, attest);
    if (rc != TSS2_RC_SUCCESS)
    {
        exception = _SecurityException_("Tss2_MU_TPM2B_ATTEST_Unmarshal failed: " + std::to_string(rc));
        return false;
    }

    return true;
}

bool marshalTpm2bAttest(
        const TPM2B_ATTEST* src,
        std::vector<uint8_t>& buffer,
        SecurityException& exception)
{
    size_t offset = 0;
    Tss2_MU_TPM2B_ATTEST_Marshal(src, nullptr, (size_t) - 1, &offset);
    buffer.resize(offset);

    offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_ATTEST_Marshal(src, buffer.data(), buffer.size(), &offset);
    if (rc != TSS2_RC_SUCCESS)
    {
        exception = _SecurityException_("Tss2_MU_TPM2B_ATTEST_Marshal failed: " + std::to_string(rc));
        return false;
    }

    return true;
}

bool unmarshalTpm2bAttest(
        const std::vector<uint8_t>& buffer,
        TPM2B_ATTEST* dest,
        SecurityException& exception)
{
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_ATTEST_Unmarshal(buffer.data(), buffer.size(), &offset, dest);
    if (rc != TSS2_RC_SUCCESS)
    {
        exception = _SecurityException_("Tss2_MU_TPM2B_ATTEST_Unmarshal failed: " + std::to_string(rc));
        return false;
    }

    return true;
}

bool marshalTpmtSignature(
        const TPMT_SIGNATURE* src,
        std::vector<uint8_t>& buffer,
        SecurityException& exception)
{
    size_t offset = 0;
    Tss2_MU_TPMT_SIGNATURE_Marshal(src, nullptr, (size_t) - 1, &offset);
    buffer.resize(offset);

    offset = 0;
    TSS2_RC rc = Tss2_MU_TPMT_SIGNATURE_Marshal(src, buffer.data(), buffer.size(), &offset);
    if (rc != TSS2_RC_SUCCESS)
    {
        exception = _SecurityException_("Tss2_MU_TPMT_SIGNATURE_Marshal failed: " + std::to_string(rc));
        return false;
    }

    return true;
}

bool unmarshalTpmtSignature(
        const std::vector<uint8_t>& buffer,
        TPMT_SIGNATURE* dest,
        SecurityException& exception)
{
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(buffer.data(), buffer.size(), &offset, dest);
    if (rc != TSS2_RC_SUCCESS)
    {
        exception = _SecurityException_("Tss2_MU_TPMT_SIGNATURE_Unmarshal failed: " + std::to_string(rc));
        return false;
    }

    return true;
}

bool marshalTpmlPcrSelection(
        const TPML_PCR_SELECTION* src,
        std::vector<uint8_t>& buffer,
        SecurityException& exception)
{
    size_t offset = 0;
    Tss2_MU_TPML_PCR_SELECTION_Marshal(src, nullptr, (size_t) - 1, &offset);
    buffer.resize(offset);

    offset = 0;
    TSS2_RC rc = Tss2_MU_TPML_PCR_SELECTION_Marshal(src, buffer.data(), buffer.size(), &offset);
    if (rc != TSS2_RC_SUCCESS)
    {
        exception = _SecurityException_("Tss2_MU_TPML_PCR_SELECTION_Marshal failed: " + std::to_string(rc));
        return false;
    }

    return true;
}

bool unmarshalTpmlPcrSelection(
        const std::vector<uint8_t>& buffer,
        TPML_PCR_SELECTION* dest,
        SecurityException& exception)
{
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPML_PCR_SELECTION_Unmarshal(buffer.data(), buffer.size(), &offset, dest);
    if (rc != TSS2_RC_SUCCESS)
    {
        exception = _SecurityException_("Tss2_MU_TPML_PCR_SELECTION_Unmarshal failed: " + std::to_string(rc));
        return false;
    }

    return true;
}

bool marshalTpmlDigest(
        const TPML_DIGEST* src,
        std::vector<uint8_t>& buffer,
        SecurityException& exception)
{
    size_t offset = 0;
    Tss2_MU_TPML_DIGEST_Marshal(src, nullptr, (size_t) - 1, &offset);
    buffer.resize(offset);

    offset = 0;
    TSS2_RC rc = Tss2_MU_TPML_DIGEST_Marshal(src, buffer.data(), buffer.size(), &offset);
    if (rc != TSS2_RC_SUCCESS)
    {
        exception = _SecurityException_("Tss2_MU_TPML_DIGEST_Marshal failed: " + std::to_string(rc));
        return false;
    }

    return true;
}

bool unmarshalTpmlDigest(
        const std::vector<uint8_t>& buffer,
        TPML_DIGEST* dest,
        SecurityException& exception)
{
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPML_DIGEST_Unmarshal(buffer.data(), buffer.size(), &offset, dest);
    if (rc != TSS2_RC_SUCCESS)
    {
        exception = _SecurityException_("Tss2_MU_TPML_DIGEST_Unmarshal failed: " + std::to_string(rc));
        return false;
    }

    return true;
}

bool marshalTpmlDigestVec(
        const std::vector<TPML_DIGEST>& src_vec,
        std::vector<uint8_t>& buffer,
        SecurityException& exception)
{
    size_t buffer_size = 0;
    for (const TPML_DIGEST& src : src_vec)
    {
        size_t offset = 0;
        Tss2_MU_TPML_DIGEST_Marshal(&src, nullptr, (size_t) - 1, &offset);
        buffer.resize(buffer_size + offset);

        offset = buffer_size;
        TSS2_RC rc = Tss2_MU_TPML_DIGEST_Marshal(&src, buffer.data(), buffer.size(), &offset);
        if (rc != TSS2_RC_SUCCESS)
        {
            exception = _SecurityException_("Tss2_MU_TPML_DIGEST_Marshal failed: " + std::to_string(rc));
            return false;
        }

        buffer_size = buffer.size();
    }

    return true;
}

bool unmarshalTpmlDigestVec(
        const std::vector<uint8_t>& buffer,
        std::vector<TPML_DIGEST>& dest_vec,
        SecurityException& exception)
{
    size_t offset = 0;
    dest_vec.clear();
    do
    {
        TPML_DIGEST dest;
        TSS2_RC rc = Tss2_MU_TPML_DIGEST_Unmarshal(buffer.data(), buffer.size(), &offset, &dest);
        if (rc != TSS2_RC_SUCCESS)
        {
            exception = _SecurityException_("Tss2_MU_TPML_DIGEST_Unmarshal failed: " + std::to_string(rc));
            return false;
        }
        dest_vec.push_back(dest);
    }
    while (offset < buffer.size());

    return true;
}

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima