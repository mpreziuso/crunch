#ifndef _SHA2_H
#define _SHA2_H

//#include "Common/Tcdefs.h"
//#include "Common/Endian.h"

#define SHA_2   /* for dynamic hash length  */
#define SHA_224
#define SHA_256

#define li_64(h) 0x##h##ull

#define VOID_RETURN	void
#define INT_RETURN	int

#if defined(__cplusplus)
extern "C"
{
#endif


#include <inttypes.h>
#include <limits.h>

typedef int8_t int8;
typedef int16_t int16;
typedef int32_t int32;
typedef int64_t int64;
typedef uint8_t byte;
//typedef uint16_t uint16;
//typedef uint32_t uint32;
typedef uint64_t uint64;

#if UCHAR_MAX != 0xffU
#error UCHAR_MAX != 0xff
#endif
#define __int8 char

#if USHRT_MAX != 0xffffU
#error USHRT_MAX != 0xffff
#endif
#define __int16 short

#if UINT_MAX != 0xffffffffU
#error UINT_MAX != 0xffffffff
#endif
#define __int32 int

#define __int64 long long

//typedef uint64 TC_LARGEST_COMPILER_UINT;
#ifndef TC_LARGEST_COMPILER_UINT
#       ifdef TC_NO_COMPILER_INT64
                typedef unsigned __int32        TC_LARGEST_COMPILER_UINT;
#       else
                typedef unsigned __int64        TC_LARGEST_COMPILER_UINT;
#       endif
#endif

#define BOOL int
#define LONG long
#ifndef FALSE
#define FALSE 0
#define TRUE 1
#endif

// Integer types required by Cryptolib
typedef unsigned __int8 uint_8t;
typedef unsigned __int16 uint_16t;
typedef unsigned __int32 uint_32t;
#ifndef TC_NO_COMPILER_INT64
typedef uint64 uint_64t;
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
