#include <security/tpm/TpmQuote.h>

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/rsa.h>

#include <security/tpm/TpmHelper.h>
#include <security/tpm/TpmPcrs.h>
#include <security/tpm/TpmMu.h>

#define S1(x) #x
#define S2(x) S1(x)
#define LOCATION " (" __FILE__ ":" S2(__LINE__) ")"
#define _SecurityException_(str) SecurityException(std::string(str) + LOCATION)

#define OSSL_ERR() std::string(ERR_error_string(ERR_get_error(), nullptr))

namespace eprosima {
namespace fastrtps {
namespace rtps {
namespace security {

/* TPM functions modified from tpm2-tools.
 * SPDX-License-Identifier: BSD-3-Clause */

static uint8_t* tpmEcdhSignatureToBuffer(
        const TPMS_SIGNATURE_ECDSA& ecdsa,
        uint16_t* size)
{
    /* the DER encoded ECDSA signature */
    uint8_t* buffer = nullptr;

    const TPM2B_ECC_PARAMETER *R = &ecdsa.signatureR;
    const TPM2B_ECC_PARAMETER *S = &ecdsa.signatureS;

    ECDSA_SIG *sig = ECDSA_SIG_new();
    if (sig == nullptr)
    {
        return nullptr;
    }

    BIGNUM *bn_r = BN_bin2bn(R->buffer, R->size, nullptr);
    if (!bn_r)
    {
        ECDSA_SIG_free(sig);
        return nullptr;
    }

    BIGNUM *bn_s = BN_bin2bn(S->buffer, S->size, nullptr);
    if (!bn_s)
    {
        BN_free(bn_r);
        ECDSA_SIG_free(sig);
        return nullptr;
    }

    int rc = ECDSA_SIG_set0(sig, bn_r, bn_s);
    if (rc != 1)
    {
        BN_free(bn_r);
        BN_free(bn_s);
        ECDSA_SIG_free(sig);
        return nullptr;
    }

    /*
     * r and s are now owned by the ecdsa signature no need
     * to free
     */

    int len = i2d_ECDSA_SIG(sig, nullptr);
    if (len <= 0)
    {
        ECDSA_SIG_free(sig);
        return nullptr;
    }

    buffer = (uint8_t*) malloc(len);
    if (!buffer)
    {
        ECDSA_SIG_free(sig);
        return nullptr;
    }

    unsigned char *pp = buffer;
    len = i2d_ECDSA_SIG(sig, &pp);
    if (len <= 0)
    {
        free(buffer);
        ECDSA_SIG_free(sig);
        return nullptr;
    }

    *size = len;
    return buffer;
}

static uint8_t* tpmSignatureToBuffer(
        const TPMT_SIGNATURE& signature,
        uint16_t* size)
{
    uint8_t* buffer = nullptr;
    *size = 0;

    switch (signature.sigAlg)
    {
    case TPM2_ALG_RSASSA:
        *size = signature.signature.rsassa.sig.size;
        buffer = (uint8_t*) malloc(*size);
        if (!buffer)
        {
            return nullptr;
        }
        memcpy(buffer, signature.signature.rsassa.sig.buffer, *size);
        break;
    case TPM2_ALG_RSAPSS:
        *size = signature.signature.rsapss.sig.size;
        buffer = (uint8_t*) malloc(*size);
        if (!buffer)
        {
            return nullptr;
        }
        memcpy(buffer, signature.signature.rsapss.sig.buffer, *size);
        break;
    case TPM2_ALG_HMAC:
    {
        const TPMU_HA* hmac_sig = &(signature.signature.hmac.digest);
        *size = getTpmHashAlgSize(signature.signature.hmac.hashAlg);
        if (*size == 0)
        {
            return nullptr;
        }
        buffer = (uint8_t*) malloc(*size);
        if (!buffer)
        {
            return nullptr;
        }
        memcpy(buffer, hmac_sig, *size);
        break;
    }
    case TPM2_ALG_ECDSA:
    case TPM2_ALG_SM2:
        return tpmEcdhSignatureToBuffer(signature.signature.ecdsa, size);
    }

    return buffer;
}

bool generateTpmQuote(
        ESYS_CONTEXT* esys_ctx,
        const ESYS_TR& quoting_key,
        const TPML_PCR_SELECTION& pcr_selections,
        const TPM2B_DATA& qualifying_data,
        TPM2B_ATTEST** quoted,
        TPMT_SIGNATURE** signature,
        SecurityException& exception)
{
    if (!checkPcrSelectionList(esys_ctx, pcr_selections, exception))
    {
        return false;
    }

    TPMT_SIG_SCHEME sig_scheme;
    sig_scheme.scheme = TPM2_ALG_NULL; // Only use signing scheme in signature key
    TSS2_RC rc = Esys_Quote(esys_ctx, quoting_key, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &qualifying_data, &sig_scheme, &pcr_selections, quoted, signature);
    if (rc != TSS2_RC_SUCCESS)
    {
        exception = _SecurityException_("TPM Error! Esys_Quote failed: " + std::to_string(rc));
        return false;
    }

    return true;
}

bool verifyTpmQuote(
        EVP_PKEY* pkey,
        const TPM2B_DATA& qualifying_data,
        const TPM2B_ATTEST& quoted,
        const TPMT_SIGNATURE& signature,
        const TPM2B_DIGEST& cp_digest,
        SecurityException& exception)
{
    TPM2_ALG_ID hash_alg = signature.signature.any.hashAlg;
    TPM2B_DIGEST quoted_digest;
    if (!calculateTpmDigest(hash_alg, quoted.attestationData, quoted.size, &quoted_digest, exception))
    {
        return false;
    }

#if OPENSSL_VERSION_NUMBER >= 0x10101003L
#if OPENSSL_VERSION_MAJOR < 3
    if (hash_alg == TPM2_ALG_SM3_256)
    {
        if (!EVP_PKEY_set_alias_type(pkey, EVP_PKEY_SM2))
        {
            exception = _SecurityException_("EVP_PKEY_set_alias_type failed: " + OSSL_ERR());
            return false;
        }
    }
#endif
#endif

    bool signature_verified = false;
    const int rsa_paddings[] = { -1 , /*<< no padding */
                                 RSA_PKCS1_PADDING, RSA_PKCS1_PSS_PADDING };
    for (int rsa_padding : rsa_paddings)
    {
        EVP_PKEY_CTX *pkey_ctx = EVP_PKEY_CTX_new(pkey, nullptr);
        if (!pkey_ctx)
        {
            exception = _SecurityException_("EVP_PKEY_CTX_new failed: " + OSSL_ERR());
            return false;
        }

        const EVP_MD *md = tpmHashAlgToOssl(hash_alg);
        if (!md)
        {
            exception = _SecurityException_("Hash algorithm " + getTpmHashAlgName(hash_alg) + " is not supported by OpenSSL.");
            EVP_PKEY_CTX_free(pkey_ctx);
            return false;
        }

        int rc = EVP_PKEY_verify_init(pkey_ctx);
        if (!rc)
        {
            exception = _SecurityException_("EVP_PKEY_verify_init failed: " + OSSL_ERR());
            EVP_PKEY_CTX_free(pkey_ctx);
            return false;
        }

        rc = EVP_PKEY_CTX_set_signature_md(pkey_ctx, md);
        if (!rc)
        {
            exception = _SecurityException_("EVP_PKEY_CTX_set_signature_md failed: " + OSSL_ERR());
            EVP_PKEY_CTX_free(pkey_ctx);
            return false;
        }

        if (rsa_padding != -1)
        {
            rc = EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, rsa_padding);
            if (rc < 0)
            {
                exception = _SecurityException_("EVP_PKEY_CTX_set_rsa_padding failed: " + OSSL_ERR());
                EVP_PKEY_CTX_free(pkey_ctx);
                return false;
            }
        }

        uint16_t signature_size;
        uint8_t* signature_buffer;
        signature_buffer = tpmSignatureToBuffer(signature, &signature_size);
        if (!signature_buffer)
        {
            exception = _SecurityException_("Failed to get signature data for verification");
            EVP_PKEY_CTX_free(pkey_ctx);
            return false;
        }

        rc = EVP_PKEY_verify(pkey_ctx, signature_buffer, signature_size,
                             quoted_digest.buffer, quoted_digest.size);
        EVP_PKEY_CTX_free(pkey_ctx);

        if (rc == 1)
        {
            signature_verified = true;
            break;
        }
    }

    if (!signature_verified)
    {
        exception = _SecurityException_("Failed to verify signature with provided public key");
        return false;
    }

    TPMS_ATTEST attest;
    if(!unmarshalTpmsAttest(quoted, &attest, exception))
    {
        return false;
    }

    if (attest.extraData.size != qualifying_data.size
        || memcmp(attest.extraData.buffer, qualifying_data.buffer, qualifying_data.size) != 0)
    {
        exception = _SecurityException_("Invalid qualifying data in provided quote");
        return false;
    }

    if (!tpmDigestsEqual(attest.attested.quote.pcrDigest, cp_digest))
    {
        exception = _SecurityException_("Invalid PCR composite digest in provided quote");
        return false;
    }

    return true;
}

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima