/* esp32_sha.c
 *
 * Copyright (C) 2006-2023 wolfSSL Inc.
 *
 * This file is part of wolfSSL.
 *
 * wolfSSL is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * wolfSSL is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 */
#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>
/*****************************************************************************/
/* this entire file content is excluded when NO_SHA, NO_SHA256
 * or when using WC_SHA384 or WC_SHA512
 */
#if !defined(NO_SHA) || !defined(NO_SHA256) || defined(WC_SHA384) || \
     defined(WC_SHA512)

#include "wolfssl/wolfcrypt/logging.h"


/* this entire file content is excluded if not using HW hash acceleration */
#if defined(WOLFSSL_ESP32_CRYPT) && \
   !defined(NO_WOLFSSL_ESP32_CRYPT_HASH)

#include <hal/sha_hal.h>
#if !defined(CONFIG_IDF_TARGET_ESP32)
#include <esp_crypto_lock.h>
#endif

#include <wolfssl/wolfcrypt/sha.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#include "wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h"
#include "wolfssl/wolfcrypt/error-crypt.h"

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

/*
 * Local types
 * */
struct CalculationContext
{
    /* Accelerator context. NULL if not doing a hardware calculation. */
    WC_ESP32SHA* Context;

    /* Next value to use for the WC_ESP32SHA calculation token. Never 0.*/
    uint32_t NextToken;
};


/* Locally 
 * undefine SOC_SHA_SUPPORT_RESUME : to test hashing without session resumption
 *                                   even on micros that support it.
 * define SINGLE_THREADED : for single threading support (useful for printing
 *                          diagnostic messages from within critical sections). 
 **/
//#undef  SOC_SHA_SUPPORT_RESUME
//#define  SINGLE_THREADED

/* So we never have to return magic numbers! */
#define SUCCESS (0)

#if !defined(CONFIG_IDF_TARGET_ESP32)
#define SHA_INVALID SHA_TYPE_MAX
#endif


/*
 * Local static variables.
 * */
static const char* TAG = "wolf_hw_sha";

/* Track the number of times we have enabled the hardware accelerator so
 * we can disable it when it isn't used any more. */
static int32_t EnableCount = 0;

/* Context for the Sha calculation the hardware is currently working on. */
static struct CalculationContext HardwareContext = { NULL, 1 };

/* Value used for WC_ESP32SHA when there is no partial result for a Sha in
 * the harware. */
const uint32_t CalculationToken_PartialNotInHardwre = 0;

/* If protect fields that could be accessed by multiple threads with a
 * critical section. This includes fields in WC_ESP32SHA. */
#if !defined(SINGLE_THREADED)
static portMUX_TYPE sha_crit_sect = portMUX_INITIALIZER_UNLOCKED;
#endif

/*
 * Private function prototypes
 * */
static void esp_sha_init_ctx(WC_ESP32SHA* ctx);
static void Enter__ShaCriticalSection();
static void Leave__ShaCriticalSection();
static WC_ESP_SHA_TYPE MapHashType(enum wc_HashType hash_type);
static bool CanAccelerate(WC_ESP_SHA_TYPE type);
static bool IsWorkingOn(WC_ESP32SHA* pContext);
static void ClearWorkingOn();
static void StashIntermediateResult();

static void FlipEndian(const word32* pSource, word32* pDestination, size_t szData);
static int HashBlock(const word32* pData, int nBlockSize, WC_ESP32SHA* ctx);
static int RetrieveDigest(WC_ESP32SHA* ctx, word32* pDigest, size_t szDigest);
static int HashAndFinishDigest(const word32* pData, size_t szData, word32* pDigest, size_t szDigest, WC_ESP32SHA* pContext);
static void PrintResult(const char* pchContext, int nReturnValue);
static void PrintHex(const char* pchContext, const byte* pData, size_t szData);

/*
 * Public functions. */

/* esp_sha_enable_hw_accelerator
 * Enables the sha hardware accelerator. Must call esp_sha_disable_hw_accelerator
 * exactly the same number of times.
 *
 * Returns:
 *  SUCCESS for succes.
 *  SHA_HW_FALLBACK : if hardware acceleration is not supported.
 * */
int esp_sha_enable_hw_accelerator()
{
    int ret = SUCCESS;
    bool bLock; 
    Enter__ShaCriticalSection();
    {
      bLock = 0 == EnableCount;
      ++EnableCount;
    }
    Leave__ShaCriticalSection();

    if (bLock)
    {
      // can't call inside critical section.
      periph_module_enable(PERIPH_SHA_MODULE);
#if !defined(CONFIG_IDF_TARGET_ESP32)
      esp_crypto_sha_aes_lock_acquire();
#endif
    }

    assert(SUCCESS == ret || SHA_HW_FALLBACK == ret);
    return ret;
}

/* esp_sha_enable_hw_accelerator
 * Disable the sha hardware accelerator. Must call esp_sha_enable_hw_accelerator
 * exactly the same number of times.
 *
 * Returns:
 *  0 for succes.
 *  -1 if hardware acceleration is not supported.
 * */
int esp_sha_disable_hw_accelerator()
{
    int ret = SUCCESS;
    bool bUnlock;
    Enter__ShaCriticalSection();
  
    // Too many disables? 
    assert(EnableCount > 0);
  
    --EnableCount;
    bUnlock  = 0 == EnableCount;
  
    Leave__ShaCriticalSection();
  
    if (bUnlock)
    {
      // can't call inside critical section.
#if !defined(CONFIG_IDF_TARGET_ESP32)
      esp_crypto_sha_aes_lock_release();
#endif
      periph_module_disable(PERIPH_SHA_MODULE);
    }

    assert(SUCCESS == ret || SHA_HW_FALLBACK == ret);
    return ret;
}

/* esp_sha_init
**
**   ctx: any wolfSSL ctx from any hash algo
**   hash_type: the specific wolfSSL enum for hash type
**   returns: 0 on success (never fails). 
**
** Initializes ctx based on chipset capabilities and current state.
** Active HW states, such as from during a copy operation, are demoted to SW.
** For hash_type not available in HW, set SW mode.
**
** See esp_sha_init_ctx(ctx)
*/
int esp_sha_init_2(WC_ESP32SHA* ctx, enum wc_HashType hash_type)
{
  int ret = 0;

  ctx->sha_type = MapHashType(hash_type);
  if (SHA_INVALID == ctx->sha_type)
  {
    ESP_LOGW(TAG, "Unexpected hash_type in esp_sha_init");
  }

  if (CanAccelerate(ctx->sha_type))
  {
    bool bAcceleratorEnabled;
    Enter__ShaCriticalSection();
    {
      bAcceleratorEnabled = EnableCount > 0;
      if (bAcceleratorEnabled)
      {
        ctx->can_accelerate = true; 
        esp_sha_init_ctx(ctx);
      }
      else
      {
        ctx->can_accelerate = false; 
      }
    }
    Leave__ShaCriticalSection();
    if (!bAcceleratorEnabled)
    {
      ESP_LOGW(TAG, "hardware acceleration disabled in esp_sha_init");
    }
  }
  else
  {
    ctx->can_accelerate = false;
  }

  return ret;
}

int esp_sha_free_2(WC_ESP32SHA* ctx)
{
    Enter__ShaCriticalSection();
    {
      if (IsWorkingOn(ctx))
      {
        ClearWorkingOn();
      }
      ctx->can_accelerate = false; 
    }
    Leave__ShaCriticalSection();

    return SUCCESS;
}


/*
** esp_sha_ctx_copy
** Copy hardware context information (other places take care of copy the wc_Sha data). 
*/
int esp_sha_ctx_copy_2(struct wc_Sha* src, struct wc_Sha* dst)
{
  int ret = SUCCESS;
#if SOC_SHA_SUPPORT_RESUME
  
  WC_ESP32SHA* pSource = &src->ctx;
  WC_ESP32SHA* pDestination = &dst->ctx;

  Enter__ShaCriticalSection();
  {
    if (IsWorkingOn(pSource))
    {
      sha_hal_wait_idle();
      sha_hal_read_digest(pDestination->sha_type, pDestination->partial_result);
    }
    else
    {
      assert(CalculationToken_PartialNotInHardwre == pSource->calculation_token);
      memcpy(pDestination->partial_result, pSource->partial_result, WC_SHA_DIGEST_SIZE);
    }
    pDestination->calculation_token = CalculationToken_PartialNotInHardwre;
    pDestination->can_accelerate = pSource->can_accelerate;
    pDestination->isfirstblock = pSource->isfirstblock;
  }
  Leave__ShaCriticalSection();

  assert(HardwareContext.Context == NULL || HardwareContext.Context->calculation_token != CalculationToken_PartialNotInHardwre);
#else

  WC_ESP32SHA* pSource = &src->ctx;
  WC_ESP32SHA* pDestination = &dst->ctx;

  Enter__ShaCriticalSection();
  {
    // Without resumption support we can only have one sha accelerated at a time
    // so even if src is being accelerated with an intermediate result in the
    // hardware, the destination is not in hardware because dst will have a
    // different memory location for the digest. 
    pDestination->calculation_token = CalculationToken_PartialNotInHardwre;
    pDestination->can_accelerate = pSource->can_accelerate;
    pDestination->isfirstblock = pSource->isfirstblock;
  }
  Leave__ShaCriticalSection();

  
#endif

  return ret;
} /* esp_sha_ctx_copy */

#ifndef NO_SHA
/*
** sha1 process
**
** sha: context for hash operation
** data: data to hash.
**
** returns:
**  SUCCESS : Hash operation completed.
**  SHA_HW_FALLBACK : Unable to do the hash operation. Fallback to software. 
*/
int esp_sha_process_2(struct wc_Sha* sha, const byte* data)
{
    int ret;

    ESP_LOGV(TAG, "enter esp_sha_process");
    static_assert(sizeof(HardwareContext.Context->partial_result) >= WC_SHA_DIGEST_SIZE, "partial result buffer too small");
  
    ret = HashBlock((const word32*)data, WC_SHA_BLOCK_SIZE, &sha->ctx);

    ESP_LOGV(TAG, "leave esp_sha_process");

    return ret;
} /* esp_sha_process */

/*
** retrieve sha1 digest
*/
int esp_sha_finish_digest_2(struct wc_Sha* sha, byte blockprocess)
{
    int ret = SUCCESS;

    ESP_LOGV(TAG, "enter esp_sha_digest_process");
    static_assert(sizeof(HardwareContext.Context->partial_result) >= WC_SHA_DIGEST_SIZE, "partial result buffer too small");

    ret = HashAndFinishDigest(blockprocess ? sha->buffer : NULL, WC_SHA_BLOCK_SIZE, sha->digest, WC_SHA_DIGEST_SIZE, &sha->ctx);

    ESP_LOGV(TAG, "leave esp_sha_digest_process");

    return ret;
} /* esp_sha_digest_process */
#endif /* NO_SHA */

/*
 * Private functions. */

void Enter__ShaCriticalSection()
{
#if !defined(SINGLE_THREADED)
    taskENTER_CRITICAL(&sha_crit_sect);
#endif
}

void Leave__ShaCriticalSection()
{
#if !defined(SINGLE_THREADED)
    taskEXIT_CRITICAL(&sha_crit_sect);
#endif
}

/* MapHashType
 * Translates WolfSSL hash type enumeration to Espressif hash type enumeration.
 * Returns SHA_TYPE_MAX for unsupported types. */
WC_ESP_SHA_TYPE MapHashType(enum wc_HashType hash_type)
{
    switch (hash_type) { /* check each wolfSSL hash type WC_[n] */
#if !defined(NO_SHA)
        case WC_HASH_TYPE_SHA:
            return SHA1;
#endif

#if !defined(NO_SHA256)
        case WC_HASH_TYPE_SHA256:
            return SHA2_256;
#endif

#if defined(WC_SHA384)
        case  WC_HASH_TYPE_SHA384:
            return SHA2_384;
#endif

#if defined(WC_SHA512)
        case WC_HASH_TYPE_SHA512:
            return SHA2_512;
#endif

#ifndef WOLFSSL_NOSHA512_224
        case WC_HASH_TYPE_SHA512_224:
            return SHA2_512;
#endif

#ifndef WOLFSSL_NOSHA512_256
        case WC_HASH_TYPE_SHA512_256:
            return SHA2_512;
#endif

        default:
             return SHA_INVALID;
    }
}

/* CanAccelerate
 * Returns true iff the target hardware can accelerate the hash type supplied. */
bool CanAccelerate(WC_ESP_SHA_TYPE type)
{
    switch (type) {
#if SOC_SHA_SUPPORT_SHA1 && !defined(NO_SHA)
        case SHA1:
          return true;
#endif

#if SOC_SHA_SUPPORT_SHA224
    case SHA2_224:
          return true;
#endif

#if SOC_SHA_SUPPORT_SHA256 && !defined(NO_SHA256)
        case SHA2_256:
            return true;
#endif

#if SOC_SHA_SUPPORT_SHA384 && defined(WC_SHA384)
        case SHA2_384:
            return true;
#endif

#if SOC_SHA_SUPPORT_SHA512 && defined(WC_SHA512)
        case SHA2_512:
            return true;
#endif

#if SOC_SHA_SUPPORT_SHA512_T && defined(WOLFSSL_NOSHA512_224)
        case SHA2_512224:
            return true;
#endif

#if SOC_SHA_SUPPORT_SHA512_T && defined(WOLFSSL_NOSHA512_256)
        case SHA2_512256:
        case SHA2_512T:
            return true;
#endif
        case SHA_INVALID:
        default:
            return false;
    }

    return false;
}

/* esp_sha_init_ctx
 * Initialize the context we use to keep track of sha hardware acceleration. */
static void esp_sha_init_ctx(WC_ESP32SHA* ctx)
{
  // Must have a valid sha type at this point.
  assert(ctx->sha_type != SHA_INVALID);
  assert(CanAccelerate(ctx->sha_type));

  memset(ctx->partial_result, 0, sizeof(ctx->partial_result));
  ctx->calculation_token = CalculationToken_PartialNotInHardwre;
  ctx->isfirstblock = true;

  // may not be needed?
  ctx->initializer = NULL;
  ctx->lockDepth = 0; 

} /* esp_sha_init_ctx */

/* GetNextCalculationToken
 *
 * Retrieves a new calculation token. Never 0 and unique until
 * uint32_t wraps.
 * */
uint32_t GetNextCalculationToken()
{
  ++HardwareContext.NextToken;
  if (0 == HardwareContext.NextToken)
  {
    // valid tokens are never 0.
    HardwareContext.NextToken = 1;
  }

  return HardwareContext.NextToken;
}

/* IsWorkingOn
 *
 * Returns true iff the hardware engine is currently computing or holding a partial
 * hash result for pContext. 
 **/
bool IsWorkingOn(WC_ESP32SHA* pContext)
{
  if (NULL == pContext)
  {
    assert(false);
    return false; 
  }

  if (NULL == HardwareContext.Context)
  {
    return false; 
  }

  // Calculation from context in hardware? 
  uint32_t uContextToken = pContext->calculation_token;
  uint32_t uInProcessToken = HardwareContext.Context->calculation_token;
  assert(uInProcessToken != CalculationToken_PartialNotInHardwre);
  return uContextToken == uInProcessToken && uContextToken != CalculationToken_PartialNotInHardwre;
}

/* ClearWorkingOn
 *
 * Clear record of which context the hardware accelerator is working on. Frees the
 * hardware for another calculation. 
 **/
void ClearWorkingOn()
{
  if (NULL != HardwareContext.Context)
  {
    HardwareContext.Context->calculation_token = CalculationToken_PartialNotInHardwre;
    HardwareContext.Context = NULL;
  }
}

/* ContinueOrAvailable
 *
 *  Returns true iff the hardware accelerator is working on nothing or pContext
 * */
bool ContinueOrAvailable(WC_ESP32SHA* pContext)
{
  assert(NULL != pContext);
  return  NULL == HardwareContext.Context || IsWorkingOn(pContext);
}

/* StashIntermediateResult
 *
 * Stash the partial result stored in the hardware accelerator in a temporary buffer so
 * the calculation can be resumed later. 
 **/
void StashIntermediateResult()
{
  assert(NULL != HardwareContext.Context);
  if (NULL != HardwareContext.Context)
  {
    sha_hal_read_digest(HardwareContext.Context->sha_type, HardwareContext.Context->partial_result);
    HardwareContext.Context->calculation_token = CalculationToken_PartialNotInHardwre;
    HardwareContext.Context = NULL;
  }
}

/* RestoreIntermediateResult
 *
 * Restore a partial result from a previously stashed calculation so the hash can be resumed. 
 **/
#if defined(SOC_SHA_SUPPORT_RESUME)
void RestoreIntermediateResult(WC_ESP32SHA* ctx)
{
  assert(NULL == HardwareContext.Context);
  assert(ctx->can_accelerate);
  assert(CalculationToken_PartialNotInHardwre == ctx->calculation_token);

  if (!ctx->isfirstblock)
  {
      // no history from first block, so only subsequent ones need to be loaded. 
      sha_hal_write_digest(ctx->sha_type, ctx->partial_result);
  }
  
  ctx->calculation_token = GetNextCalculationToken();
  assert(CalculationToken_PartialNotInHardwre != ctx->calculation_token);

  // we save the context and the digest store in case another sha
  // operation is required before this one is all done. 
  HardwareContext.Context = ctx;
}
#endif

/* SetAccelerationContext
 *
 * Set the context currently being accelerated by hardware, provided none is using the hardware. 
 **/
void SetAccelerationContext(WC_ESP32SHA* pContext)
{
  assert(NULL != pContext);
  assert(NULL == HardwareContext.Context || pContext->calculation_token == HardwareContext.Context->calculation_token);

  if (HardwareContext.Context == NULL)
  {
    assert(pContext->calculation_token == CalculationToken_PartialNotInHardwre);
    HardwareContext.Context = pContext;
    pContext->calculation_token = GetNextCalculationToken();
    assert(CalculationToken_PartialNotInHardwre != pContext->calculation_token);
  }
}

/* FlipEndian
 *
 * Swaps byte order for words in pSource, writing filped bytes into
 * pDestination. pSource and pDestination may point to the same memory
 * location.
 * pSource: data to be flipped
 * pDestination: output buffer (may be same as pSource)
 * szData: number of _bytes_ to reorder. 
 **/
void FlipEndian(const word32* pSource, word32* pDestination, size_t szData)
{
    ByteReverseWords(pDestination, pSource, szData);
}

/*
 * HashBlock
 *
 * Starts hashing data using the hardware accelerator, if possible.
 * This may stash the intermediate result from another hash in its digest store
 * while we use the hardware for this calculation. The hardware accelerator may
 * still be working on the hash, in parallel, when this function finishes. 
 *
 * IMPORTANT NOTE:
 *   The digest store and context are retained to support future operations. For
 *   example, if another hash is requested the results for the ctx hash may be
 *   stashed temporarily in the pDigestStore until the next operation for ctx. At
 *   that point, its partial result will be reloaded into the hardware before
 *   continuing with the hash operation. 
 *
 * pData: the data block to hash.
 * nBlockSize: size of the datablock in bytes (must be suitable for the hash being computed)
 * ctx: hardware acceleration context for the hash
 *
 * Returns:
 *   SUCCESS : the data was hashed.
 *   SHA_HW_FALLBACK : hardware wasn't available to do the hash. find another way.
 *   
 **/
int HashBlock(const word32* pData, int nBlockSize, WC_ESP32SHA* ctx)
{
    int ret = SHA_HW_FALLBACK;
    assert(NULL != pData);
    assert(NULL != ctx);
   
    if (NULL == pData || NULL == ctx)
    {
      return BAD_FUNC_ARG;
    }
   
    if (!ctx->can_accelerate)
    {
      return SHA_HW_FALLBACK;
    }

#if SOC_SHA_SUPPORT_RESUME
    Enter__ShaCriticalSection();
    {
        sha_hal_wait_idle();
        if (HardwareContext.Context == NULL)
        {
          RestoreIntermediateResult(ctx);
        }
        else if (!IsWorkingOn(ctx))
        {
          StashIntermediateResult();
          RestoreIntermediateResult(ctx);
        }

        word32 aTemp[nBlockSize / sizeof(word32)];
        FlipEndian(pData, aTemp, nBlockSize);

        sha_hal_hash_block(ctx->sha_type, aTemp, nBlockSize / sizeof(word32), ctx->isfirstblock);
        ctx->isfirstblock = false;
    }
    Leave__ShaCriticalSection();

    ret = SUCCESS;

    assert(HardwareContext.Context == NULL || HardwareContext.Context->calculation_token != CalculationToken_PartialNotInHardwre);
    return ret;
#else
    Enter__ShaCriticalSection();
    {
        bool bCanAccelerate = ContinueOrAvailable(ctx);
        if (bCanAccelerate && HardwareContext.Context != ctx)
        {
            assert(NULL == HardwareContext.Context);
            assert(ctx->isfirstblock);
            SetAccelerationContext(ctx);
        }

        if (bCanAccelerate)
        {
            word32 aTemp[nBlockSize / sizeof(word32)];
            FlipEndian(pData, aTemp, nBlockSize);
   
            sha_hal_hash_block(ctx->sha_type, aTemp, nBlockSize / sizeof(word32), ctx->isfirstblock);
            ctx->isfirstblock = false;
            ret = SUCCESS;
        }
        else
        {
            ret = SHA_HW_FALLBACK;
        }
    }
    Leave__ShaCriticalSection();
    return ret;
#endif
}

/* HashAndFinishDigest
 *
 * Optionally hash a block of data and retrieve the hash of this block and all
 * previous blocks. Completes digest by clearing hardware context. 
 * pData, szData: data & its length (in bytes) to hash before returning the digest 
 *                if not NULL,
 * pDigest, szDigest: destination for the digest.
 * pContext: accelerator context for the hash.
 *
 * Returns:
 *   SUCCESS : if the hash is completed successfully.
 *   SHA_HW_FALLBACK : if the hash could not be completed with the hardware and
 *          must be performed in software.
 *   BAD_FUNC_ARG : if pDigest or pContext are null or szDigest is 0. 
 **/
int HashAndFinishDigest(const word32* pData, size_t szData, word32* pDigest, size_t szDigest, WC_ESP32SHA* pContext)
{
  int ret = SUCCESS;

  if (NULL == pDigest || NULL == pContext || 0 == szDigest)
  {
    return BAD_FUNC_ARG;
  }

  if (NULL != pData)
  {
    ret = HashBlock(pData, szData, pContext);
  }

  if (SUCCESS == ret)
  {
    ret = RetrieveDigest(pContext, pDigest, szDigest);
  }

  // This is needed because callers reinitialize the sha context so we need to
  // make sure we aren't in the accelerator still. Removing this would allow
  // intermediate hash results to be retrieved, but that isn't needed.
  esp_sha_free_2(pContext);

  assert(SUCCESS == ret || SHA_HW_FALLBACK == ret || BAD_FUNC_ARG == ret);
  return ret;
}

/* RetrieveDigest
 *
 * Retrieves the hash digest for the context provided. The digets may come
 * from hardware registers or prior stashed result (if another sha calculation
 * required the hardware in between times).
 *
 * Returns:
 *   SUCCESS : if the digest is retrieved successfully.
 *   SHA_HW_FALLBACK : if the hash could not be retrieved with the hardware and
 *          must be performed in software.
 *   BAD_FUNC_ARG : if pDigest or pContext are null or szDigest is 0. 
 **/
int RetrieveDigest(WC_ESP32SHA* ctx, word32* pDigestStore, size_t szDigest)
{
  assert(NULL != ctx);
  assert(NULL != pDigestStore);

  if (NULL == ctx || NULL == pDigestStore)
  {
    return BAD_FUNC_ARG;
  }

  if (!ctx->can_accelerate)
  {
    return SHA_HW_FALLBACK;
  }

#if SOC_SHA_SUPPORT_RESUME

  Enter__ShaCriticalSection();
  {
    if (IsWorkingOn(ctx))
    {
        sha_hal_wait_idle();
        sha_hal_read_digest(ctx->sha_type, pDigestStore);
    }
    else
    {
        assert(CalculationToken_PartialNotInHardwre == ctx->calculation_token);
        memcpy(pDigestStore, ctx->partial_result, szDigest);
    }

    FlipEndian(pDigestStore, pDigestStore, szDigest);

  }
  Leave__ShaCriticalSection();

  assert(HardwareContext.Context == NULL || HardwareContext.Context->calculation_token != CalculationToken_PartialNotInHardwre);
  return SUCCESS;
#else

  int ret = SUCCESS;
  
  Enter__ShaCriticalSection();
  {
    assert(IsWorkingOn(ctx));
    if (IsWorkingOn(ctx))
    {
        sha_hal_wait_idle();
        sha_hal_read_digest(ctx->sha_type, pDigestStore);
        FlipEndian(pDigestStore, pDigestStore, szDigest);
    }
    else
    {
      ret = SHA_HW_INTERNAL_ERROR;
    }
  }
  Leave__ShaCriticalSection();

  return ret;

#endif
}

static void PrintResult(const char* pchContext, int ret)
{
  if (SUCCESS == ret)
  {
    printf("%s: hardware\n", pchContext);
  }
  else if (SHA_HW_FALLBACK == ret)
  {
    printf("%s: software hash\n", pchContext);
  }
  else
  {
    printf("%s: error %d\n", pchContext, ret);
  }
}

static void PrintHex(const char* pchContext, const byte* pData, size_t szData)
{
  printf("%s - ", pchContext);
  while (szData--)
  {
    printf("%02X-", *pData++);
  }
  printf("\n");
}


#endif /* WOLFSSL_ESP32_CRYPT */
#endif /* !defined(NO_SHA) ||... */


