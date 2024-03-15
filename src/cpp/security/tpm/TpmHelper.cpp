#include <security/tpm/TpmHelper.h>

#include <vector>
#include <fstream>
#include <openssl/err.h>

#define S1(x) #x
#define S2(x) S1(x)
#define LOCATION " (" __FILE__ ":" S2(__LINE__) ")"
#define _SecurityException_(str) SecurityException(std::string(str) + LOCATION)

#define OSSL_ERR() std::string(ERR_error_string(ERR_get_error(), nullptr))

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

bool loadTpmKey(
        ESYS_CONTEXT* esys_ctx,
        std::string key_name,
        ESYS_TR* key,
        SecurityException& exception)
{
    try
    {
        TPM2_HANDLE tpm_handle = std::stol(key_name, nullptr, 0);
        TSS2_RC rc = Esys_TR_FromTPMPublic(esys_ctx, tpm_handle, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, key);
        if (rc != TSS2_RC_SUCCESS)
        {
            exception = _SecurityException_("TPM Error! Esys_TR_FromTPMPublic failed: " + std::to_string(rc));
            return false;
        }
        return true;
    }
    catch (const std::exception&)
    {
        // Key name is not a handle
    }

    try
    {
        std::ifstream input(key_name, std::ios::binary);
        std::vector<uint8_t> buf(std::istreambuf_iterator<char>(input), {});

        TSS2_RC rc = Esys_TR_Deserialize(esys_ctx, buf.data(), buf.size(), key);
        if (rc != TSS2_RC_SUCCESS)
        { 
            exception = _SecurityException_("TPM Error! Esys_TR_Deserialize failed: " + std::to_string(rc));
            return false;
        }
        return true;
    }
    catch (const std::exception& e)
    {
        exception = _SecurityException_("Failed to load key file " + key_name + ". Reason: " + e.what());
        return false;
    }
}

bool calculateTpmDigest(
        TPM2_ALG_ID hash_alg,
        const uint8_t* buffer,
        uint16_t length,
        TPM2B_DIGEST* digest,
        SecurityException& exception)
{
    const EVP_MD *md = tpmHashAlgToOssl(hash_alg);
    if (!md)
    {
        exception = _SecurityException_("Hash algorithm " + getTpmHashAlgName(hash_alg) + " is not supported by OpenSSL.");
        return false;
    }

    EVP_MD_CTX *md_ctx = EVP_MD_CTX_create();
    if (!md_ctx)
    {
        exception = _SecurityException_("EVP_MD_CTX_create failed: " + OSSL_ERR());
        return false;
    }

    int rc = EVP_DigestInit_ex(md_ctx, md, nullptr);
    if (!rc)
    {
        exception = _SecurityException_("EVP_DigestInit_ex failed: " + OSSL_ERR());
        EVP_MD_CTX_destroy(md_ctx);
        return false;
    }

    rc = EVP_DigestUpdate(md_ctx, buffer, length);
    if (!rc)
    {
        exception = _SecurityException_("EVP_DigestUpdate failed: " + OSSL_ERR());
        EVP_MD_CTX_destroy(md_ctx);
        return false;
    }

    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(md_ctx, digest->buffer, &size);
    if (!rc)
    {
        exception = _SecurityException_("EVP_DigestFinal_ex failed: " + OSSL_ERR());
        EVP_MD_CTX_destroy(md_ctx);
        return false;
    }

    digest->size = size;
    return true;
}

std::string getTpmHashAlgName(
        TPM2_ALG_ID hash_alg)
{
    switch (hash_alg)
    {
    case TPM2_ALG_SHA1:
        return "sha1";
    case TPM2_ALG_SHA256:
        return "sha256";
    case TPM2_ALG_SHA384:
        return "sha384";
    case TPM2_ALG_SHA512:
        return "sha512";
    case TPM2_ALG_SM3_256:
        return "sm3_256";
    }
    return "";
}

TPM2_ALG_ID getTpmHashAlgId(
        std::string hash_alg_name)
{
    if (hash_alg_name == "sha1")
        return TPM2_ALG_SHA1;
    if (hash_alg_name == "sha256")
        return TPM2_ALG_SHA256;
    if (hash_alg_name == "sha384")
        return TPM2_ALG_SHA384;
    if (hash_alg_name == "sha512")
        return TPM2_ALG_SHA512;
    if (hash_alg_name == "sm3_256")
        return TPM2_ALG_SM3_256;
    return TPM2_ALG_NULL;
}

uint16_t getTpmHashAlgSize(
        TPM2_ALG_ID hash_alg)
{
    switch (hash_alg)
    {
    case TPM2_ALG_SHA1:
        return TPM2_SHA1_DIGEST_SIZE;
    case TPM2_ALG_SHA256:
        return TPM2_SHA256_DIGEST_SIZE;
    case TPM2_ALG_SHA384:
        return TPM2_SHA384_DIGEST_SIZE;
    case TPM2_ALG_SHA512:
        return TPM2_SHA512_DIGEST_SIZE;
    case TPM2_ALG_SM3_256:
        return TPM2_SM3_256_DIGEST_SIZE;
    }
    return 0;
}

const EVP_MD* tpmHashAlgToOssl(
        TPM2_ALG_ID hash_alg)
{
    switch (hash_alg)
    {
    case TPM2_ALG_SHA1:
        return EVP_sha1();
    case TPM2_ALG_SHA256:
        return EVP_sha256();
    case TPM2_ALG_SHA384:
        return EVP_sha384();
    case TPM2_ALG_SHA512:
        return EVP_sha512();
#if HAVE_EVP_SM3
    case TPM2_ALG_SM3_256:
      return EVP_sm3();
#endif
    }
    return nullptr;
}

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima