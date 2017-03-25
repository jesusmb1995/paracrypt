namespace paracrypt {

    class CUDACipherDevice:public GPUCipherDevice<cudaStream_t> {
      private:
	int device;
	const cudaDeviceProp devProp;
	int maxCudaBlocksPerSM;
	int nWarpsPerBlock;
	int nThreadsPerThreadBlock;
	int nConcurrentKernels = 1;
#define HANDLE_ERROR( err ) (HandleError( err, __FILE__, __LINE__ ))
	static void HandleError(cudaError_t err,
				const char *file, int line);
      public:
	// 0 <= device < cudaGetDeviceCount()
	 CUDACipherDevice(int device);
	int getNWarpsPerBlock();
	int getThreadsPerThreadBlock();
	int getMaxBlocksPerSM();
	int getConcurrentKernels();
	int getGridSize(int n_blocks, int threadsPerCipherBlock);
	const cudaDeviceProp* getDeviceProperties();
	void set();
	void malloc(void** data, int size);
	void free(void* data);
	void memcpyTo(void* host, void* dev, int size, cudaStream_t stream);
	void memcpyFrom(void* dev, void* host, int size, cudaStream_t stream);
	cudaStream_t getNewStream();
	void freeStream(cudaStream_t s);
    };

}
