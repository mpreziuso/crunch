#include <stdio.h>
#include <cmath>
#include "Cuda/PBKDF2.cu"

#define SHA256_DIGESTSIZE 32
#define SHA256_BLOCKSIZE 64

// #define BLOCK_SIZE 640
// #define GRID_SIZE 157
#define N 1000

#define ERRCHECK(ans) { gpuAssert((ans), __FILE__, __LINE__); }
inline void gpuAssert(cudaError_t code, const char *file, int line, bool abort=true,bool wait=true)
{
   if (code != cudaSuccess) 
   {
      fprintf(stderr,"GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
      if (abort) exit(code);
   }
}

__global__ void PBKDF2Kernel(int n, unsigned char* out) {
  unsigned char passwd[22] = "governor washout beak";
  int pwd_len = sizeof(passwd) - 1;
  for (int i = blockIdx.x * blockDim.x + threadIdx.x; i<n; i += blockDim.x * gridDim.x) {
    cuda_derive_u_sha256(passwd, pwd_len, &out[SHA256_DIGESTSIZE*i]);
  }
}

int main() {
  cudaError_t err;
  int device = 0;
  int numSMs;
  //const int N = 100000;

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
  unsigned char *finalDest;
//  unsigned char *cpuDest;
//  cpuDest = (unsigned char *)malloc(N*SHA256_DIGESTSIZE);
  cudaMallocManaged((void**)&finalDest, N*SHA256_DIGESTSIZE);
  ERRCHECK(cudaGetLastError());
  printf("SMs: %d, X: %d, Y: %d\n", numSMs, 32*numSMs, 512);
  printf("grid: %d, min grid: %d, block: %d\n", gridSize, minGridSize, blockSize);
  PBKDF2Kernel<<<gridSize, blockSize>>>(N, finalDest);
  ERRCHECK(cudaDeviceSynchronize());
  ERRCHECK(cudaGetLastError());
  //cudaMemcpy(cpuDest, finalDest, N*SHA256_DIGESTSIZE, cudaMemcpyDeviceToHost);
  //ERRCHECK(cudaGetLastError());
  
  for(int i = 0; i < N; i++) {
    for(int j = 0; j < SHA256_DIGESTSIZE; j++) {
      printf("%02x ", finalDest[i*SHA256_DIGESTSIZE + j]);
    }
    printf("\n");
  }
  
  cudaFree(finalDest);
  //free(cpuDest);
  cudaDeviceReset();
  return 0;
}
