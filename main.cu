#include <stdio.h>
#include <cmath>
#include "Cuda/PBKDF2.cu"

#define SHA256_DIGESTSIZE 32
#define SHA256_BLOCKSIZE 64

#define BLOCK_SIZE 384
#define GRID_SIZE 26

#define ERRCHECK(ans) { gpuAssert((ans), __FILE__, __LINE__); }
inline void gpuAssert(cudaError_t code, const char *file, int line, bool abort=true,bool wait=true)
{
   if (code != cudaSuccess) 
   {
      fprintf(stderr,"GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
      if (abort) exit(code);
   }
}

__global__ void PBKDF2Kernel(int n, int c, unsigned char ** out) {
  unsigned char salt[17] = {
	230,  88,  20, 228,
	 56,  39,  89, 248,
	 85,  80,   2, 158,
	114,  61, 199, 231,
                         0
  }; 
  unsigned char passwd[22] = "governor washout beak";
  int pwd_len = sizeof(passwd) - 1;
  for (int i = blockIdx.x * blockDim.x + threadIdx.x; i<n; i += blockDim.x * gridDim.x) {
    cuda_derive_key_sha256(passwd, pwd_len, salt, c, (unsigned char *)&out[i], SHA256_DIGESTSIZE);
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
  cudaOccupancyMaxPotentialBlockSize(&minGridSize, &blockSize, PBKDF2Kernel, 0, N); 

  // Round up according to array size 
  gridSize = (N + blockSize - 1) / blockSize; 

  unsigned char **finalDest;
  unsigned char *cpuDest;
  cpuDest = (unsigned char *)malloc(BLOCK_SIZE*SHA256_DIGESTSIZE*sizeof(unsigned char*));
  cudaMalloc((void**)&finalDest, BLOCK_SIZE*SHA256_DIGESTSIZE*sizeof(unsigned char*));
  ERRCHECK(cudaGetLastError());
  printf("SMs: %d, X: %d, Y: %d\n", numSMs, 32*numSMs, 512);
  printf("grid: %d, min grid: %d, block: %d\n", gridSize, minGridSize, blockSize);
  PBKDF2Kernel<<<GRID_SIZE,BLOCK_SIZE>>>(N, 100000, finalDest);
  ERRCHECK(cudaDeviceSynchronize());
  ERRCHECK(cudaGetLastError());
  cudaMemcpy(cpuDest, finalDest, BLOCK_SIZE*SHA256_DIGESTSIZE*sizeof(unsigned char*), cudaMemcpyDeviceToHost);
  ERRCHECK(cudaGetLastError());

/*  for(size_t i = &cpuDest[0]; i < &cpuDest[BLOCK_SIZE-1]; i++) {
    if(i != null) {
//    for(size_t c = 0; c < sizeof(unsigned char)*SHA256_DIGESTSIZE; c++) {
      printf("%02x ", *i);
    }
    printf("\n");
  }*/
  for(int i = 0; i < BLOCK_SIZE; i++) {
    for(int j = 0; j < SHA256_DIGESTSIZE; j++) {
      printf("%02x ", cpuDest[i*SHA256_DIGESTSIZE + j]);
    }
    printf("\n");
  }
//  for(unsigned char *hash = &cpuDest[0][0]; hash <= &cpuDest[BLOCK_SIZE][SHA256_DIGESTSIZE]; hash++) {
//    for(int c = 0; c < SHA256_DIGESTSIZE; c++) {
//      printf("%02x ", (&hash));
//    }
//    printf("\n");
//  }
  printf("\n");
  cudaFree(finalDest);
  free(cpuDest);
  cudaDeviceReset();
  return 0;
}
