#include "Sha2.cu"
#include "Sha2.cuh"

#define SHA256_DIGESTSIZE 32
#define SHA256_BLOCKSIZE 64
#define SALT_SIZE 16
__constant__ int ITERATIONS = 100000;
__constant__ unsigned char SHA256_IPAD_CONST = (unsigned char) 0x36;
__constant__ unsigned char SHA256_OPAD_CONST = (unsigned char) 0x5C;
__constant__ __device__ const unsigned char cuda_init_derive[32] = {
        230,  88,  20, 228,  56,  39,  89, 248,
         85,  80,   2, 158, 114,  61, 199, 231,
      1>>24,1>>16,1>>8, 0x01, 0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0
};

__device__ void hmac_sha256_c(sha256_ctx actx, sha256_ctx bctx, unsigned char *d, int ld, unsigned char *out, unsigned char* scratch) {
  sha256_ctx ictx, octx;
  memcpy(&ictx,&actx, sizeof(sha256_ctx));
  sha256_hash (d, ld, &ictx);
  sha256_end (scratch, &ictx);

  memcpy(&octx, &bctx, sizeof(sha256_ctx));
  sha256_hash (scratch, SHA256_DIGESTSIZE, &octx);
  sha256_end ((unsigned char *) out, &octx);
}

__device__ void cuda_derive_u_sha256 (unsigned char *pwd, int pwd_len, unsigned char *u){
  unsigned char j[SHA256_DIGESTSIZE];
  unsigned char ibuf[SHA256_BLOCKSIZE], obuf[SHA256_BLOCKSIZE];
  int i;

  sha256_ctx ictx, octx;
  unsigned char scratch[SHA256_DIGESTSIZE];
  memset(ibuf + pwd_len, SHA256_IPAD_CONST, SHA256_BLOCKSIZE - pwd_len);
  memset(obuf + pwd_len, SHA256_OPAD_CONST, SHA256_BLOCKSIZE - pwd_len);
  for(i = 0; i < pwd_len; ++i) {
    ibuf[i] = (unsigned char) (pwd[i] ^ SHA256_IPAD_CONST);
    obuf[i] = (unsigned char) (pwd[i] ^ SHA256_OPAD_CONST);
  }
  sha256_begin(&ictx);
  sha256_begin(&octx);
  sha256_hash((unsigned char*)ibuf, SHA256_BLOCKSIZE, &ictx);
  sha256_hash((unsigned char*)obuf, SHA256_BLOCKSIZE, &octx);

  hmac_sha256_c(ictx, octx, (unsigned char *)cuda_init_derive, SALT_SIZE+4, j, scratch);
  memcpy(u, j, SHA256_DIGESTSIZE);

  for(int c = 0; c < ITERATIONS; ++c) {
    hmac_sha256_c(ictx, octx, j, SHA256_DIGESTSIZE, j, scratch);
    #pragma unroll
    for(i = 0; i<SHA256_DIGESTSIZE;i++) {
      u[i] ^= j[i];
    }
  }
}
