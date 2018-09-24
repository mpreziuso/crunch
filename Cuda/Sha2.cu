#include "Common/Endian.h"
#ifndef PLATFORM_BYTE_ORDER
#define PLATFORM_BYTE_ORDER BYTE_ORDER
#endif
#ifndef IS_LITTLE_ENDIAN
#define IS_LITTLE_ENDIAN LITTLE_ENDIAN
#endif

#include <string.h>     /* for memcpy() etc.        */

#include "Sha2.cuh"

#if defined(__cplusplus)
extern "C"
{
#endif

#define rotl32(x,n)   (((x) << n) | ((x) >> (32 - n)))
// #define rotr32(x,n)   (((x) >> n) | ((x) << (32 - n)))
#define rotr32(x, n) __funnelshift_r( (x), (x), (n) )
//#define rotr32(x,n)  { unsigned int * y = __byte_perm(x, x, 0x3210+0x1111*(n/8)); printf("%x", y); return y; }

#if !defined(bswap_32)
#define bswap_32(x) __byte_perm(x, x, 0x0123);
#endif

#if (PLATFORM_BYTE_ORDER == IS_LITTLE_ENDIAN)
#define SWAP_BYTES
#else
#undef  SWAP_BYTES
#endif

#define ch(x,y,z)       ((z) ^ ((x) & ((y) ^ (z))))
#define maj(x,y,z)      (((x) & (y)) | ((z) & ((x) ^ (y))))

/* round transforms for SHA256 and SHA512 compression functions */

#define vf(n,i) v[(n - i) & 7]

#define hf(i) (p[i & 15] += \
    g_1(p[(i + 14) & 15]) + p[(i + 9) & 15] + g_0(p[(i + 1) & 15]))


#if defined(SHA_224) || defined(SHA_256)
#define SHA256_MASK (SHA256_BLOCK_SIZE - 1)

#if defined(SWAP_BYTES)
#define bsw_32(p,n) \
    { int _i = (n); while(_i--) ((uint_32t*)p)[_i] = bswap_32(((uint_32t*)p)[_i]); }
#else
#define bsw_32(p,n)
#endif
//__device__ void bsw_32(uint_32t *p, uint_32t i) {
//  
//  while(i--) {
//    p[i] = __byte_perm(p[i], p[i], 0x0123);
//  }
//}

#define s_0(x)  (rotr32((x),  2) ^ rotr32((x), 13) ^ rotr32((x), 22))
#define s_1(x)  (rotr32((x),  6) ^ rotr32((x), 11) ^ rotr32((x), 25))
#define g_0(x)  (rotr32((x),  7) ^ rotr32((x), 18) ^ ((x) >>  3))
#define g_1(x)  (rotr32((x), 17) ^ rotr32((x), 19) ^ ((x) >> 10))
#define k_0     k256

/* rotated SHA256 round definition. Rather than swapping variables as in    */
/* FIPS-180, different variables are 'rotated' on each round, returning     */
/* to their starting positions every eight rounds                           */

/* SHA256 mixing data   */

__constant__ const uint_32t k256[64] =
{   0x428a2f98ul, 0x71374491ul, 0xb5c0fbcful, 0xe9b5dba5ul,
    0x3956c25bul, 0x59f111f1ul, 0x923f82a4ul, 0xab1c5ed5ul,
    0xd807aa98ul, 0x12835b01ul, 0x243185beul, 0x550c7dc3ul,
    0x72be5d74ul, 0x80deb1feul, 0x9bdc06a7ul, 0xc19bf174ul,
    0xe49b69c1ul, 0xefbe4786ul, 0x0fc19dc6ul, 0x240ca1ccul,
    0x2de92c6ful, 0x4a7484aaul, 0x5cb0a9dcul, 0x76f988daul,
    0x983e5152ul, 0xa831c66dul, 0xb00327c8ul, 0xbf597fc7ul,
    0xc6e00bf3ul, 0xd5a79147ul, 0x06ca6351ul, 0x14292967ul,
    0x27b70a85ul, 0x2e1b2138ul, 0x4d2c6dfcul, 0x53380d13ul,
    0x650a7354ul, 0x766a0abbul, 0x81c2c92eul, 0x92722c85ul,
    0xa2bfe8a1ul, 0xa81a664bul, 0xc24b8b70ul, 0xc76c51a3ul,
    0xd192e819ul, 0xd6990624ul, 0xf40e3585ul, 0x106aa070ul,
    0x19a4c116ul, 0x1e376c08ul, 0x2748774cul, 0x34b0bcb5ul,
    0x391c0cb3ul, 0x4ed8aa4aul, 0x5b9cca4ful, 0x682e6ff3ul,
    0x748f82eeul, 0x78a5636ful, 0x84c87814ul, 0x8cc70208ul,
    0x90befffaul, 0xa4506cebul, 0xbef9a3f7ul, 0xc67178f2ul,
};

__device__ void m_cycle(uint_32t *p, uint_32t *v, int x, int y) {
  uint32_t v4 = vf(4,x);
  uint32_t v0 = vf(0,x);
  vf(7, x) += (y ? hf(x) : p[x]) + k_0[x+y] + s_1(v4) + ch(v4, vf(5,x), vf(6,x));
  vf(3, x) += vf(7,x);
  vf(7, x) += s_0(v0) + maj(v0, vf(1, x), vf(2, x));
}

/* Compile 64 bytes of hash data into SHA256 digest value   */
/* NOTE: this routine assumes that the byte order in the    */
/* ctx->wbuf[] at this point is such that low address bytes */
/* in the ORIGINAL byte stream will go into the high end of */
/* words on BOTH big and little endian systems              */

__device__ VOID_RETURN sha256_compile(sha256_ctx ctx[1])
{
    int j, mp;
    uint_32t *p = ctx->wbuf, v[8];
    memcpy(v, ctx->hash, 8 * sizeof(uint_32t));

    for(j = 0; j < 64; j+=16)
    {
	for(mp = 0; mp < 16; mp++) {
		m_cycle(p, v, mp, j);
        }
//	printf("%02d: [ %x %x %x ] [ %x %x %x ] [ %x %x %x ] [ %x %x %x ] [ %x %x %x ] [ %x ]\n", j, &p);
//        printf("%02d: [ ", j);
//        for(int i = 0; i < 16; i++) {
//          printf("%x ", p[i]);
//        }
//        printf(" ]\n");
    }
    for(j = 0; j < 8; j++) {
      ctx->hash[j] += v[j];
    }
}

/* SHA256 hash data in an array of bytes into hash buffer   */
/* and call the hash_compile function as required.          */

__device__ VOID_RETURN sha256_hash(const unsigned char data[], unsigned long len, sha256_ctx ctx[1])
{   uint_32t pos = (uint_32t)(ctx->count[0] & SHA256_MASK),
             space = SHA256_BLOCK_SIZE - pos;
    const unsigned char *sp = data;
//printf("L %d %d %d\n", ctx->count[0], len);
    if((ctx->count[0] += len) < len)
        ++(ctx->count[1]);

    while(len >= space) {
        memcpy(((unsigned char*)ctx->wbuf) + pos, sp, space);
        sp += space; len -= space; space = SHA256_BLOCK_SIZE; pos = 0;
        bsw_32(ctx->wbuf, SHA256_BLOCK_SIZE >> 2);
        sha256_compile(ctx);
    }
    memcpy(((unsigned char*)ctx->wbuf) + pos, sp, len);
/*    printf("SET count [");
    for(int i = 0; i < 2; i++) {
      printf("%x ", ctx->count[i]);
    }
    printf("]\nSET buf [");
    for(int i = 0; i < 16; i++) {
      printf("%x ", ctx->wbuf[i]);
    }
    printf("\nSET hash [");
    for(int i = 0; i < 8; i++) {
      printf("%x ", ctx->hash[i]);
    }
    printf("]\n");
*/
}

__device__ void sha256_setstate_c(sha256_ctx ctx[1], sha256_ctx ictx) {
  memcpy(ctx, &ictx, sizeof(sha256_ctx));
}


/* SHA256 Final padding and digest calculation  */

__device__ static void sha_end1(unsigned char hval[], sha256_ctx ctx[1], const unsigned int hlen)
{   uint_32t    i = (uint_32t)(ctx->count[0] & SHA256_MASK);

    /* put bytes in the buffer in an order in which references to   */
    /* 32-bit words will put bytes with lower addresses into the    */
    /* top of 32 bit words on BOTH big and little endian machines   */
    bsw_32(ctx->wbuf, (i + 3) >> 2);

    /* we now need to mask valid bytes and add the padding which is */
    /* a single 1 bit and as many zero bits as necessary. Note that */
    /* we can always add the first padding byte here because the    */
    /* buffer always has at least one empty slot                    */
    ctx->wbuf[i >> 2] &= 0xffffff80 << 8 * (~i & 3);
    ctx->wbuf[i >> 2] |= 0x00000080 << 8 * (~i & 3);

    /* we need 9 or more empty positions, one for the padding byte  */
    /* (above) and eight for the length count.  If there is not     */
    /* enough space pad and empty the buffer                        */
    if(i > SHA256_BLOCK_SIZE - 9)
    {
        if(i < 60) ctx->wbuf[15] = 0;
        sha256_compile(ctx);
        i = 0;
    }
    else    /* compute a word index for the empty buffer positions  */
        i = (i >> 2) + 1;

    memset(ctx->wbuf + i, 0, sizeof(ctx->wbuf) - 2 - i);
    /* the following 32-bit length fields are assembled in the      */
    /* wrong byte order on little endian machines but this is       */
    /* corrected later since they are only ever used as 32-bit      */
    /* word values.                                                 */
    ctx->wbuf[14] = (ctx->count[1] << 3) | (ctx->count[0] >> 29);
    ctx->wbuf[15] = ctx->count[0] << 3;
    sha256_compile(ctx);

    /* extract the hash value as bytes in case the hash buffer is   */
    /* mislaigned for 32-bit words                                  */
    // #pragma unroll
    for(i = 0; i < hlen; ++i)
        hval[i] = (unsigned char)(ctx->hash[i >> 2] >> (8 * (~i & 3)));
}

#endif

#if defined(SHA_256)

__constant__ const uint_32t i256[8] =
{
    0x6a09e667ul, 0xbb67ae85ul, 0x3c6ef372ul, 0xa54ff53aul,
    0x510e527ful, 0x9b05688cul, 0x1f83d9abul, 0x5be0cd19ul
};

__device__ VOID_RETURN sha256_begin(sha256_ctx ctx[1])
{
    ctx->count[0] = ctx->count[1] = 0;
    ctx->hash[0] = 0x6a09e667ul;
    ctx->hash[1] = 0xbb67ae85ul;
    ctx->hash[2] = 0x3c6ef372ul;
    ctx->hash[3] = 0xa54ff53aul;
    ctx->hash[4] = 0x510e527ful;
    ctx->hash[5] = 0x9b05688cul;
    ctx->hash[6] = 0x1f83d9abul;
    ctx->hash[7] = 0x5be0cd19ul;
//    memcpy(ctx->hash, i256, 8 * sizeof(uint_32t));
}

__device__ VOID_RETURN sha256_end(unsigned char hval[], sha256_ctx ctx[1])
{
    sha_end1(hval, ctx, SHA256_DIGEST_SIZE);
}

__device__ VOID_RETURN s_sha256_end(unsigned char hval[], sha256_ctx ctx[1])
{   
    sha_end1(hval, ctx, SHA256_DIGEST_SIZE);
}  

__device__ VOID_RETURN sha256(unsigned char hval[], const unsigned char data[], unsigned long len)
{   sha256_ctx  cx[1];

    sha256_begin(cx);
    sha256_hash(data, len, cx);
    sha_end1(hval, cx, SHA256_DIGEST_SIZE);
}

#endif

#define CTX_256(x)  ((x)->uu->ctx256)

#if defined(__cplusplus)
}
#endif
