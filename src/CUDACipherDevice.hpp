namespace paracrypt {

    class CUDACipherDevice: public GPUCipherDevice {
      private:
	int device;
        const cudaDeviceProp devProp;
	int maxCudaBlocksPerSM;
	int nWarpsPerBlock;
	int nThreadsPerThreadBlock;
      public:
	// 0 <= device < cudaGetDeviceCount()
	CUDACipherDevice(int device);
	int getNWarpsPerBlock();
	int getThreadsPerThreadBlock();
	int getMaxBlocksPerSM();
	const cudaDeviceProp* getDeviceProperties();
    };

}
