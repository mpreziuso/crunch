#include <stdio.h>
#include <cmath>
#include "Cuda/PBKDF2.cu"

#define ERRCHECK(ans) { gpuAssert((ans), __FILE__, __LINE__); }
inline void gpuAssert(cudaError_t code, const char *file, int line, bool abort=true,bool wait=true) {
   if (code != cudaSuccess) {
      fprintf(stderr,"GPUassert: %s %s %d\n", cudaGetErrorString(code), file, line);
      if (abort) exit(code);
   }
}

#define SHA256_DIGESTSIZE 32
#define SHA256_BLOCKSIZE 64

__global__ void PBKDF2Kernel(int n, unsigned char *out) {
  unsigned char passwd[22] = "governor washout beak";
  int pwd_len = sizeof(passwd) - 1;
  for (int i = blockIdx.x * blockDim.x + threadIdx.x; i<n; i += blockDim.x * gridDim.x) {
    cuda_derive_key_sha256(passwd, pwd_len, &out[SHA256_DIGESTSIZE*i]);
  }
}

int main() {
  cudaError_t err;
  int device = 0;
  int numSMs;
  const int N = 1;

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

  unsigned char *finalDestination;
  cudaMallocManaged((void **)&finalDestination, N*SHA256_DIGESTSIZE);
  ERRCHECK(cudaGetLastError());
  printf("SMs: %d, X: %d, Y: %d\n", numSMs, 32*numSMs, 512);
  printf("grid: %d, min grid: %d, block: %d\n", gridSize, minGridSize, blockSize);
  //PBKDF2Kernel<<<1,1>>>(N, 100000, d_hash);
  PBKDF2Kernel<<<gridSize,blockSize>>>(N, finalDestination);
  ERRCHECK(cudaDeviceSynchronize());
  ERRCHECK(cudaGetLastError());

  for(int i = 0; i < N; i++) {
    for(int j = 0; j < SHA256_DIGESTSIZE; j++) {
      printf("%02x ", finalDestination[i*SHA256_DIGESTSIZE+j]);
    }
    printf("\n");
  }
  cudaFree(finalDestination);
  cudaDeviceReset();
  return 0;
}
