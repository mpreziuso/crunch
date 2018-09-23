#ifndef _SHA2_H
#define _SHA2_H

#include "Common/Tcdefs.h"
#include "Common/Endian.h"

//#define SHA_64BIT

/* define the hash functions that you need  */
#define SHA_2   /* for dynamic hash length  */
#define SHA_224
#define SHA_256
#ifdef SHA_64BIT
#  define SHA_384
#  define SHA_512
#  define NEED_UINT_64T
#endif

#ifndef EXIT_SUCCESS
#define EXIT_SUCCESS    0
#define EXIT_FAILURE    1
#endif

#define li_64(h) 0x##h##ull

#define VOID_RETURN	void
#define INT_RETURN	int

#if defined(__cplusplus)
extern "C"
{
#endif

/* Note that the following function prototypes are the same */
/* for both the bit and byte oriented implementations.  But */
/* the length fields are in bytes or bits as is appropriate */
/* for the version used.  Bit sequences are arrays of bytes */
/* in which bit sequence indexes increase from the most to  */
/* the least significant end of each byte                   */

#define SHA224_DIGEST_SIZE  28
#define SHA224_BLOCK_SIZE   64
#define SHA256_DIGEST_SIZE  32
#define SCRYPT_SHA256_DIGEST_SIZE 1024
#define SHA256_BLOCK_SIZE   64

/* type to hold the SHA256 (and SHA224) context */

typedef struct
{   uint_32t count[2];
    uint_32t hash[8];
    uint_32t wbuf[16];
} sha256_ctx;

typedef sha256_ctx  sha224_ctx;

__device__ VOID_RETURN sha256_compile(sha256_ctx ctx[1]);
__device__ void sha256_getstate_c(sha256_ctx ctx[1], sha256_ctx octx[1]);
__device__ void sha256_setstate_c(sha256_ctx ctx[1], sha256_ctx ictx);
__device__ VOID_RETURN sha256_begin(sha256_ctx ctx[1]);
__device__ VOID_RETURN sha256_hash(const unsigned char data[], unsigned long len, sha256_ctx ctx[1]);
__device__ VOID_RETURN sha256_end(unsigned char hval[], sha256_ctx ctx[1]);
__device__ VOID_RETURN sha256(unsigned char hval[], const unsigned char data[], unsigned long len);

#if defined(__cplusplus)
}
#endif

#endif
