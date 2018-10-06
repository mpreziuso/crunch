#include "Sha2.cu"
#include "Sha2.cuh"

#define SHA256_DIGESTSIZE 32
#define SHA256_BLOCKSIZE 64
#define SALT_SIZE 16

__constant__ int ITERATIONS = 100000;
__constant__ unsigned char SHA256_IPAD_CONST = (unsigned char) 0x36;
__constant__ unsigned char SHA256_OPAD_CONST = (unsigned char) 0x5C;
__constant__ __device__ unsigned char cuda_init_derive[32] = {
        230,  88,  20, 228,  56,  39,  89, 248,
         85,  80,   2, 158, 114,  61, 199, 231,
      1>>24,1>>16,1>>8, 0x01, 0,   0,   0,   0,
          0,   0,   0,   0,   0,   0,   0,   0
};

__device__ void hmac_sha256_c(sha256_ctx actx, sha256_ctx bctx, unsigned char *d, int ld, unsigned char *out) {
//  sha256_ctx octx;
  sha256_hash(d, ld, &actx);
  sha256_end(out, &actx);

  memcpy(&actx, &bctx, sizeof(sha256_ctx));
  sha256_hash(out, SHA256_DIGESTSIZE, &actx);
  sha256_end ((unsigned char *) out, &actx);
}

__device__ void cuda_derive_key_sha256 (unsigned char *pwd, int pwd_len, unsigned char *u){
  unsigned char j[SHA256_DIGESTSIZE];
  unsigned char ibuf[SHA256_BLOCKSIZE], obuf[SHA256_BLOCKSIZE];
  int i, c;

  sha256_ctx ictx, octx;
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

  hmac_sha256_c(ictx, octx, (unsigned char * )cuda_init_derive, SALT_SIZE+4, j);
  memcpy(u, j, SHA256_DIGESTSIZE);

  for(c = 1; c < ITERATIONS; c++) {
    hmac_sha256_c(ictx, octx, j, SHA256_DIGESTSIZE, j);
    for(i = 0; i<SHA256_DIGESTSIZE;i++) {
      u[i] ^= j[i];
    }
  }
}
