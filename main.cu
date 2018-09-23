#include <stdio.h>
#include <cmath>
#include "Cuda/PBKDF2.cu"

#define ERRCHECK(ans) { gpuAssert((ans), __FILE__, __LINE__); }
inline void gpuAssert(cudaError_t code, const char *file, int line, bool abort=true,bool wait=true)
{
   if (code != cudaSuccess) 
   {
      fprintf(stderr,"GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
      if (abort) exit(code);
   }
}

#define SHA256_DIGESTSIZE 32
#define SHA256_BLOCKSIZE 64

__global__ void PBKDF2Kernel(int n, int c, unsigned char *out) {
  unsigned char salt[17] = {
	230,  88,  20, 228,
	 56,  39,  89, 248,
	 85,  80,   2, 158,
	114,  61, 199, 231,
                         0
  }; 
  unsigned char passwd[22] = "governor washout beak";
  unsigned char init[SHA256_DIGESTSIZE];
  int salt_len = sizeof(salt) - 1;
  int pwd_len = sizeof(passwd) - 1;
  cuda_init_derive(salt, salt_len, init, 1);
  for (int i = blockIdx.x * blockDim.x + threadIdx.x; i<n; i += blockDim.x * gridDim.x) {
    cuda_derive_key_sha256((unsigned char *)init, passwd, pwd_len, salt, salt_len, c, out, SHA256_DIGESTSIZE);
  }
}

int main() {
  cudaError_t err;
  int device = 0;
  int numSMs;
  const int N = 10000;

  cudaDeviceProp props;
  err = cudaGetDeviceProperties(&props, device);

  if(err) { return -1; }

  printf("%s (%2d)\n", props.name, props.multiProcessorCount);
  cudaSetDevice(device);
  cudaDeviceGetAttribute(&numSMs, cudaDevAttrMultiProcessorCount, device);

  cudaError_t error;
  /* Stop eating CPU while waiting for results! */
  error = cudaSetDeviceFlags(cudaDeviceScheduleBlockingSync);
  if (error != cudaSuccess) { 
    fprintf(stderr, "Could not set blocking sync (error %d)\n", error);
  }


    int blockSize;      // The launch configurator returned block size 
    int minGridSize;    // The minimum grid size needed to achieve the maximum occupancy for a full device launch 
    int gridSize;       // The actual grid size needed, based on input size 

    float time;
    cudaEvent_t start, stop;
    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);

    cudaOccupancyMaxPotentialBlockSize(&minGridSize, &blockSize, PBKDF2Kernel, 0, N); 

    // Round up according to array size 
    gridSize = (N + blockSize - 1) / blockSize; 

    cudaEventRecord(stop, 0);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&time, start, stop);
    printf("Occupancy calculator elapsed time:  %3.3f ms \n", time);

  unsigned char *d_hash;
  unsigned char h_hash[SHA256_DIGESTSIZE];
  cudaMalloc(&d_hash, sizeof(unsigned char) * SHA256_DIGESTSIZE);
  ERRCHECK(cudaGetLastError());
  printf("SMs: %d, X: %d, Y: %d\n", numSMs, 32*numSMs, 512);
  printf("grid: %d, min grid: %d, block: %d\n", gridSize, minGridSize, blockSize);
  PBKDF2Kernel<<<gridSize,blockSize>>>(N, 100000, d_hash);
  ERRCHECK(cudaDeviceSynchronize());
  ERRCHECK(cudaGetLastError());
  cudaMemcpy(h_hash, d_hash, sizeof(unsigned char)*SHA256_DIGESTSIZE, cudaMemcpyDeviceToHost);
  ERRCHECK(cudaGetLastError());

  for(int i = 0; i < sizeof(h_hash); i++) {
    printf("%02x ",h_hash[i]);
  }
  printf("\n");
  cudaFree(d_hash);
  cudaDeviceReset();
  return 0;
}
