namespace paracrypt {

    class CUDACipherDevice:public GPUCipherDevice {
      private:
    int getGridSize();
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
	const cudaDeviceProp* getDeviceProperties();
	void set();
	void malloc(void** data, int size);
	void memcpyTo(void* host, void* dev, int size);
	void memcpyFrom(void* dev, void* host, int size);
	void launch(kernel, launchConfig);
	template < typename FN, typename... ARGS >
	void launch(launch_config_t* config, FN&& kernel, ARGS&&... args);
    };

}
