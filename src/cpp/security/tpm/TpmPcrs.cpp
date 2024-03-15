#include <security/tpm/TpmPcrs.h>

#include <cstring>
#include <bitset>
#include <openssl/evp.h>
#include <openssl/err.h>

#include <security/tpm/TpmHelper.h>

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

static bool buildPcrSelection(
        TPM2_ALG_ID hash_alg,
        const std::vector<uint32_t>& pcrs,
        TPMS_PCR_SELECTION& pcr_selection,
        SecurityException& exception)
{
    pcr_selection.hash = hash_alg;
    pcr_selection.sizeofSelect = 3; // Minimum selection size
    memset(pcr_selection.pcrSelect, 0, TPM2_PCR_SELECT_MAX);

    for (uint32_t pcr : pcrs)
    {
        if (pcr / 8 >= TPM2_PCR_SELECT_MAX)
        {
            exception = _SecurityException_("Unsupported PCR register: " + std::to_string(pcr) + " in bank " + getTpmHashAlgName(hash_alg));
            return false;
        }
        if ((pcr / 8) + 1 > pcr_selection.sizeofSelect)
        {
            pcr_selection.sizeofSelect = (pcr / 8) + 1;
        }
        pcr_selection.pcrSelect[pcr / 8] |= (1 << (pcr % 8));
    }

    return true;
}

bool buildPcrSelectionList(
        const std::vector<TPM2_ALG_ID>& hash_algs,
        const std::vector<uint32_t>& pcrs,
        TPML_PCR_SELECTION& pcr_selections,
        SecurityException& exception)
{
    if (hash_algs.size() > TPM2_NUM_PCR_BANKS)
    {
        exception = _SecurityException_("Too many PCR banks: " + std::to_string(hash_algs.size()));
        return false;
    }

    for (unsigned int i = 0; i < hash_algs.size(); i++)
    {
        if (!buildPcrSelection(hash_algs[i], pcrs, pcr_selections.pcrSelections[i], exception))
        {
            return false;
        }
    }

    pcr_selections.count = hash_algs.size();
    return true;
}

std::string printPcrSelectionBitmap(
        const TPMS_PCR_SELECTION& pcr_selection)
{
    std::string result = "|";
    for (uint32_t j = 0; j < pcr_selection.sizeofSelect; j++) {
        uint8_t v = pcr_selection.pcrSelect[j];
        std::string binary = std::bitset<8>(v).to_string();
        result.insert(0, binary);
        result.insert(0, "|");
    }
    return "PCR bank " + getTpmHashAlgName(pcr_selection.hash) + " => " + result;
}

static bool getSupportedPcrBanks(
        ESYS_CONTEXT* esys_ctx,
        TPMS_CAPABILITY_DATA** capability_data,
        SecurityException& exception)
{
    TPMI_YES_NO more_data;
    TSS2_RC rc = Esys_GetCapability(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, TPM2_CAP_PCRS, 0, 1, &more_data, capability_data);
    if (rc != TSS2_RC_SUCCESS)
    {
        exception = _SecurityException_("TPM Error! Esys_GetCapability failed: " + std::to_string(rc));
        return false;
    }

    return true;
}

bool checkPcrSelectionList(
        ESYS_CONTEXT* esys_ctx,
        const TPML_PCR_SELECTION& pcr_selections,
        SecurityException& exception)
{
    TPMS_CAPABILITY_DATA* capability_data;
    if (!getSupportedPcrBanks(esys_ctx, &capability_data, exception))
    {
        return false;
    }
  
    uint32_t i, j, k;
    for (i = 0; i < pcr_selections.count; i++)
    {
        for (j = 0; j < capability_data->data.assignedPCR.count; j++)
        {
            if (pcr_selections.pcrSelections[i].hash == capability_data->data.assignedPCR.pcrSelections[j].hash)
            {
                for (k = 0; k < pcr_selections.pcrSelections[i].sizeofSelect; k++)
                {
                    uint8_t a = pcr_selections.pcrSelections[i].pcrSelect[k];
                    uint8_t b = capability_data->data.assignedPCR.pcrSelections[j].pcrSelect[k];
                    if (a & ~b)
                    {
                        exception = _SecurityException_("Unsupported PCR register in bank: " + getTpmHashAlgName(pcr_selections.pcrSelections[i].hash));
                        free(capability_data);
                        return false;
                    }
                }
                break;
            }
        }

        if (j >= capability_data->data.assignedPCR.count)
        {
            exception = _SecurityException_("Unsupported PCR bank: " + getTpmHashAlgName(pcr_selections.pcrSelections[i].hash));
            free(capability_data);
            return false;
        }
    }

    free(capability_data);
    return true;
}

static void updatePcrSelectionList(
        TPML_PCR_SELECTION *s1,
        TPML_PCR_SELECTION *s2)
{
    uint32_t i1, i2, j;
    for (i2 = 0; i2 < s2->count; i2++)
    {
        for (i1 = 0; i1 < s1->count; i1++)
        {
            if (s2->pcrSelections[i2].hash != s1->pcrSelections[i1].hash)
                continue;

            for (j = 0; j < s1->pcrSelections[i1].sizeofSelect; j++)
            {
                uint8_t b1 = s1->pcrSelections[i1].pcrSelect[j];
                uint8_t b2 = s2->pcrSelections[i2].pcrSelect[j];
                *(s1->pcrSelections[i1].pcrSelect + j) = b1 & ~b2;
            }
        }
    }
}

static bool isPcrSelectionListUnset(
        TPML_PCR_SELECTION *s)
{
    uint32_t i, j;
    for (i = 0; i < s->count; i++)
    {
        for (j = 0; j < s->pcrSelections[i].sizeofSelect; j++)
        {
            if (s->pcrSelections[i].pcrSelect[j])
            {
                return false;
            }
        }
    }

    return true;
}

static inline bool isPcrSelectionBitSet(
        const TPMS_PCR_SELECTION* s,
        uint32_t pcr)
{
    return (s->pcrSelect[((pcr) / 8)] & (1 << ((pcr) % 8)));
}

bool readPcrs(
        ESYS_CONTEXT* esys_ctx,
        const TPML_PCR_SELECTION& pcr_selections,
        std::vector<TPML_DIGEST>& pcr_digests,
        SecurityException& exception)
{
    TPML_PCR_SELECTION pcr_selections_tmp;
    memcpy(&pcr_selections_tmp, &pcr_selections, sizeof(pcr_selections_tmp));

    if (!checkPcrSelectionList(esys_ctx, pcr_selections_tmp, exception))
    {
        return false;
    }

    pcr_digests.clear();
    uint32_t pcr_update_counter;
    do
    {
        TPML_PCR_SELECTION *pcr_selections_out;
        TPML_DIGEST* pcr_values;
        TSS2_RC rc = Esys_PCR_Read(esys_ctx, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &pcr_selections_tmp, &pcr_update_counter, &pcr_selections_out, &pcr_values);
        if (rc != TSS2_RC_SUCCESS)
        {
            exception = _SecurityException_("TPM Error! Esys_PCR_Read failed: " + std::to_string(rc));
            return false;
        }
        pcr_digests.push_back(*pcr_values);
        free(pcr_values);

        updatePcrSelectionList(&pcr_selections_tmp, pcr_selections_out);
        free(pcr_selections_out);
    }
    while (!isPcrSelectionListUnset(&pcr_selections_tmp));

    return true;
}

bool decodePcrDigests(
        const TPML_PCR_SELECTION& pcr_selections,
        const std::vector<TPML_DIGEST>& pcr_digests,
        std::map<TPM2_ALG_ID, std::map<uint32_t, TPM2B_DIGEST> >& pcr_map,
        TPM2_ALG_ID cp_hash_alg,
        TPM2B_DIGEST& cp_digest,
        SecurityException& exception)
{
    // Prepare composite digesting
    const EVP_MD* md = tpmHashAlgToOssl(cp_hash_alg);
    if (!md)
    {
        exception = _SecurityException_("Hash algorithm " + getTpmHashAlgName(cp_hash_alg) + " is not supported by OpenSSL.");
        return false;
    }

    EVP_MD_CTX* md_ctx = EVP_MD_CTX_create();
    if (!md_ctx)
    {
        exception = _SecurityException_("EVP_MD_CTX_create failed: " + OSSL_ERR());
        return false;
    }

    int rc = EVP_DigestInit_ex(md_ctx, md, NULL);
    if (!rc)
    {
        exception = _SecurityException_("EVP_DigestInit_ex failed: " + OSSL_ERR());
        EVP_MD_CTX_destroy(md_ctx);
        return false;
    }

    pcr_map.clear();
    size_t vi = 0;  /* value index */
    uint32_t di = 0;  /* digest index */

    // Loop through all PCR hash banks
    for (uint32_t i = 0; i < pcr_selections.count; i++)
    {
        const TPMS_PCR_SELECTION* pcr_selection = &pcr_selections.pcrSelections[i];
        TPM2_ALG_ID hash_alg = pcr_selection->hash;
        std::map<uint32_t, TPM2B_DIGEST> pcr_bank_map;

        // Loop through all PCRs in this bank
        for (uint32_t pcr_id = 0; pcr_id < pcr_selection->sizeofSelect * 8u; pcr_id++)
        {
            if (!isPcrSelectionBitSet(pcr_selection, pcr_id))
            {
                // skip non-selected banks
                continue;
            }
            const TPML_DIGEST* pcr_value = &pcr_digests[vi];
            if (vi >= pcr_digests.size() || di >= pcr_value->count)
            {
                exception = _SecurityException_("Invalid digest list for provided PCR selection in bank " + getTpmHashAlgName(hash_alg));
                EVP_MD_CTX_destroy(md_ctx);
                return false;
            }

            // Store current PCR digest in map
            const TPM2B_DIGEST* d = &pcr_value->digests[di];
            pcr_bank_map[pcr_id] = *d;

            // Update composite digest
            rc = EVP_DigestUpdate(md_ctx, d->buffer, d->size);
            if (!rc)
            {
                exception = _SecurityException_("EVP_DigestUpdate failed: " + OSSL_ERR());
                EVP_MD_CTX_destroy(md_ctx);
                return false;
            }

            if (++di >= pcr_value->count) {
                di = 0;
                ++vi;
            }
        } /* end looping through all PCRs in a bank */

        pcr_map[hash_alg] = pcr_bank_map;
    }  /* end looping through all PCR banks */

    // Finalize composite digest
    unsigned size = EVP_MD_size(md);
    rc = EVP_DigestFinal_ex(md_ctx, cp_digest.buffer, &size);
    if (!rc)
    {
        exception = _SecurityException_("EVP_DigestFinal_ex failed: " + OSSL_ERR());
        EVP_MD_CTX_destroy(md_ctx);
        return false;
    }
    cp_digest.size = size;

    return true;
}

} //namespace security
} //namespace rtps
} //namespace fastrtps
} //namespace eprosima