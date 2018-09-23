#include "Sha2.cu"
#include "Sha2.cuh"

#define SHA256_DIGESTSIZE 32
#define SHA256_BLOCKSIZE 64

__device__ void hmac_cstate(unsigned char *in, sha256_ctx *out) {
  sha256_ctx xctx;
  sha256_begin(&xctx);
  sha256_hash((unsigned char *) in, SHA256_BLOCKSIZE, &xctx);
  sha256_getstate_c(&xctx, out);
}

__device__ void hmac_sha256_c(sha256_ctx actx, sha256_ctx bctx, unsigned char *d, int ld, unsigned char *out) {
  sha256_ctx ictx, octx;
  unsigned char isha[SHA256_DIGESTSIZE];

  sha256_setstate_c(&ictx, actx);
  sha256_hash ((unsigned char *) d, ld, &ictx);
  sha256_end ((unsigned char *) isha, &ictx);

  sha256_setstate_c(&octx, bctx);
  sha256_hash ((unsigned char *) isha, SHA256_DIGESTSIZE, &octx);
  sha256_end ((unsigned char *) out, &octx);
}

__device__ void cuda_init_derive(unsigned char *salt, int salt_len, unsigned char * j, int block) {
  unsigned char counter[4] = { 0x00, 0x00, 0x00, 0x01 };
  counter[0] = block >> 24;
  counter[1] = block >> 16;
  counter[2] = block >>  8;
  counter[3] = block;

  memcpy(j, salt, salt_len);
  memcpy(&j[salt_len], counter, 4);
}

__device__ void cuda_derive_u_sha256 (unsigned char * init_pad, unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *u){
  unsigned char j[SHA256_DIGESTSIZE], k[SHA256_DIGESTSIZE];
  unsigned char ibuf[SHA256_BLOCKSIZE], obuf[SHA256_BLOCKSIZE];
  int c, i;

  sha256_ctx ictx, octx;

  memset(ibuf + pwd_len, (unsigned char) 0x36, SHA256_BLOCKSIZE - pwd_len);
  memset(obuf + pwd_len, (unsigned char) 0x5C, SHA256_BLOCKSIZE - pwd_len);
  for(i = 0; i < pwd_len; ++i) {
    ibuf[i] = (unsigned char) (pwd[i] ^ 0x36);
    obuf[i] = (unsigned char) (pwd[i] ^ 0x5C);
  }

  hmac_cstate(ibuf, &ictx);
  hmac_cstate(obuf, &octx);
  hmac_sha256_c(ictx, octx, init_pad, salt_len+4, j);
  memcpy(u, j, SHA256_DIGESTSIZE);

  for(c = 1; c < iterations; c++) {
    hmac_sha256_c(ictx, octx, j, SHA256_DIGESTSIZE, k);
    for(i = 0; i<SHA256_DIGESTSIZE;i++) {
      u[i] ^= k[i];
      j[i]  = k[i];
    }
  }
}

__device__ void cuda_derive_key_sha256(unsigned char * init_pad, unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *dk, int dklen) {
  cuda_derive_u_sha256(init_pad, pwd, pwd_len, salt, salt_len, iterations, dk);
}
