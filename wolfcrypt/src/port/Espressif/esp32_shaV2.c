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
#include <esp_crypto_lock.h>

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

//#undef  SOC_SHA_SUPPORT_RESUME

#define SUCCESS (0)

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

/* If not single threaded, protect local fields with a critical section */
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

static int HashBlock(const word32* pData, int nBlockSize, WC_ESP32SHA* ctx);
static int RetrieveDigest(WC_ESP32SHA* ctx, word32* pDigest, size_t szDigest);
static void PrintResult(const char* pchContext, int nReturnValue);
static void PrintHex(const char* pchContext, const byte* pData, size_t szData);

/*
 * Public functions. */

/* esp_sha_enable_hw_accelerator
 * Enables the sha hardware accelerator. Must call esp_sha_disable_hw_accelerator
 * exactly the same number of times.
 *
 * Returns:
 *  0 for succes.
 *  -1 if hardware acceleration is not supported.
 * */
int esp_sha_enable_hw_accelerator()
{
  bool bLock; 
  Enter__ShaCriticalSection();
  {
    bLock = 0 == EnableCount;
    ++EnableCount;
  }
  Leave__ShaCriticalSection();

  if (bLock)
  {
    periph_module_enable(PERIPH_SHA_MODULE);
    esp_crypto_sha_aes_lock_acquire();
  }
  
  return 0;
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
  bool bUnlock;
  Enter__ShaCriticalSection();

  // Too many disables? 
  assert(EnableCount > 0);

  --EnableCount;
  bUnlock  = 0 == EnableCount;

  Leave__ShaCriticalSection();

  if (bUnlock)
  {
    esp_crypto_sha_aes_lock_release();
    periph_module_disable(PERIPH_SHA_MODULE);
  }

  return 0;
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
  if (SHA_TYPE_MAX == ctx->sha_type)
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
    PrintResult("Process block", ret);
  
    //wc_esp_process_block(&sha->ctx, (const word32*)data, WC_SHA_BLOCK_SIZE);

    ESP_LOGV(TAG, "leave esp_sha_process");

    return ret;
} /* esp_sha_process */

/*
** retrieve sha1 digest
*/
int esp_sha_digest_process_2(struct wc_Sha* sha, byte blockprocess)
{
    int ret = SUCCESS;

    ESP_LOGV(TAG, "enter esp_sha_digest_process");

    if (blockprocess) {
      printf("Process another block\n");
      ret = HashBlock(sha->buffer, WC_SHA_BLOCK_SIZE, &sha->ctx);
      PrintResult("Process last block", ret);
    }

    if (SUCCESS == ret)
    {
        ret = RetrieveDigest(&sha->ctx, sha->digest, WC_SHA_DIGEST_SIZE);
        PrintResult("Retrieve digest", ret);
    }

    ESP_LOGV(TAG, "leave esp_sha_digest_process");

    return ret;
} /* esp_sha_digest_process */
#endif /* NO_SHA */


/*
 * Private functions. */

void Enter__ShaCriticalSection()
{
#if !defined(SINGLE_THREADED)
    //taskENTER_CRITICAL(&sha_crit_sect);
#endif
}

void Leave__ShaCriticalSection()
{
#if !defined(SINGLE_THREADED)
    //taskEXIT_CRITICAL(&sha_crit_sect);
#endif
}

#if defined(DEBUG_WOLFSSL)
    /* Only when debugging, we'll keep tracking of block numbers. */
    static int this_block_num = 0;
#endif

/* MapHashType
 * Translates WolfSSL hash type enumeration to Espressif hash type enumeration.
 * Returns SHA_TYPE_MAX for unsupported types. */
WC_ESP_SHA_TYPE MapHashType(enum wc_HashType hash_type)
{
    switch (hash_type) { /* check each wolfSSL hash type WC_[n] */
        case WC_HASH_TYPE_SHA:
            return SHA1; /* assign Espressif SHA HW type */

        case WC_HASH_TYPE_SHA256:
            return SHA2_256; /* assign Espressif SHA HW type */

        case  WC_HASH_TYPE_SHA384:
            return SHA2_384; /* Espressif type, but we won't use HW */

        case WC_HASH_TYPE_SHA512:
            return SHA2_512; /* assign Espressif SHA HW type */

    #ifndef WOLFSSL_NOSHA512_224
        case WC_HASH_TYPE_SHA512_224:
            return SHA2_512; /* Espressif type, but we won't use HW */
    #endif

    #ifndef WOLFSSL_NOSHA512_256
        case WC_HASH_TYPE_SHA512_256:
            return SHA2_512; /* Espressif type, but we won't use HW */
    #endif

        default:
             return SHA_TYPE_MAX;
    }
}

/* CanAccelerate
 * Returns true iff the target hardware can accelerate the hash type supplied. */
bool CanAccelerate(WC_ESP_SHA_TYPE type)
{
    switch (type) {
    case SHA1:
      return SOC_SHA_SUPPORT_SHA1 ? true : false;
    case SHA2_224:
      return SOC_SHA_SUPPORT_SHA224 ? true : false; 
    case SHA2_256:
        return SOC_SHA_SUPPORT_SHA256 ? true : false;
    case SHA2_384:
        return SOC_SHA_SUPPORT_SHA384 ? true : false;
    case SHA2_512:
        return SOC_SHA_SUPPORT_SHA512 ? true : false;
    case SHA2_512224:
    case SHA2_512256:
    case SHA2_512T:
        return SOC_SHA_SUPPORT_SHA512_T ? true : false;
    case SHA_TYPE_MAX:
    default:
        return false;
    }
}

/* esp_sha_init_ctx
 * Initialize the context we use to keep track of sha hardware acceleration. */
static void esp_sha_init_ctx(WC_ESP32SHA* ctx)
{
  // Must have a valid sha type at this point.
  assert(ctx->sha_type < SHA_TYPE_MAX);
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
    PrintHex("Stashed", HardwareContext.Context->partial_result, sizeof(HardwareContext.Context->partial_result));
    HardwareContext.Context->calculation_token = CalculationToken_PartialNotInHardwre;
    HardwareContext.Context = NULL;
  }
}

/* RestoreIntermediateResult
 *
 * Restore a partial result from a previously stashed calculation so the hash can be resumed. 
 **/
void RestoreIntermediateResult(WC_ESP32SHA* ctx)
{
  assert(NULL == HardwareContext.Context);
  assert(ctx->can_accelerate);
  assert(CalculationToken_PartialNotInHardwre == ctx->calculation_token);

  if (!ctx->isfirstblock)
  {
    PrintHex("Restoring", ctx->partial_result, sizeof(ctx->partial_result));
    sha_hal_write_digest(ctx->sha_type, ctx->partial_result);
  }
  else
  {
    printf("First block, no need to restore\n");
  }
  
  ctx->calculation_token = GetNextCalculationToken();
  assert(CalculationToken_PartialNotInHardwre != ctx->calculation_token);

  // we save the context and the digest store in case another sha
  // operation is required before this one is all done. 
  HardwareContext.Context = ctx;
}

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
    sha_hal_wait_idle();
    if (HardwareContext.Context == NULL)
    {
      SetAccelerationContext(ctx);
    }
    else if (!IsWorkingOn(ctx))
    {
      StashIntermediateResult();
      RestoreIntermediateResult(ctx);
    }

  if (!ctx->isfirstblock)
  {
    byte abyPrevious[WC_SHA_DIGEST_SIZE];
    sha_hal_read_digest(ctx->sha_type, abyPrevious);
    PrintHex("Last digest", abyPrevious, sizeof(abyPrevious));
  }

  int nSwap = nBlockSize / sizeof(word32);
  word32 aTemp[nBlockSize / sizeof(word32)];
  const word32 *pSource = pData;
  word32 *pDestination = aTemp;
  while (nSwap--)
  {
    *pDestination++ = __builtin_bswap32(*pSource++);
  }
  
    sha_hal_hash_block(ctx->sha_type, aTemp, nBlockSize / sizeof(word32), ctx->isfirstblock);
    ctx->isfirstblock = false;
     Leave__ShaCriticalSection();
 
    ret = SUCCESS;
#else
    Enter__ShaCriticalSection();
    bool bCanAccelerate = ContinueOrAvailable(ctx);
    if (bCanAccelerate && HardwareContext.Context != ctx)
    {
      assert(NULL == HardwareContext.Context);
      assert(ctx->isfirstblock);
      SetAccelerationContext(ctx);
    }
    Leave__ShaCriticalSection();
    
    if (bCanAccelerate)
    {
      sha_hal_hash_block(ctx->sha_type, pData, nBlockSize / sizeof(word32), ctx->isfirstblock);
      ctx->isfirstblock = false;
      ret = SUCCESS;
    }
    else
    {
      ret = SHA_HW_FALLBACK;
    }
#endif

  return ret;
}

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
      printf("Working on\n");
      sha_hal_wait_idle();
      sha_hal_read_digest(ctx->sha_type, pDigestStore);
    }
    else
    {
      printf("From cache\n");

      assert(CalculationToken_PartialNotInHardwre == ctx->calculation_token);
      memcpy(pDigestStore, ctx->partial_result, szDigest);
    }

    int nSwap = szDigest / sizeof(word32);
    word32* pSwap = pDigestStore;
    while (nSwap--)
    {
      word32 Temp = __builtin_bswap32(*pSwap);
      *pSwap++ = Temp;
    }

  }
  Leave__ShaCriticalSection();

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
