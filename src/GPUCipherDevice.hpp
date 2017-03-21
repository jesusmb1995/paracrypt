namespace paracrypt {

    class GPUCipherDevice: {
      public:
	virtual int getThreadsPerThreadBlock() = 0;
	virtual int getNWarpsPerBlock() = 0;
	virtual int getMaxBlocksPerSM() = 0;
    };

}
