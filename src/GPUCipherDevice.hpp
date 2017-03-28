#pragma once

//#include <boost/unordered_map.hpp>
//#include <boost/thread/shared_mutex.hpp>

namespace paracrypt {

    template<typename S, typename F>
    class GPUCipherDevice {
      protected:
//boost::unordered_map<int,S> streams;
    //boost::shared_mutex streams_access;
    virtual S newStream();
    virtual void freeStream(S s);
    S acessStream(int stream_id);
      public:
    virtual ~GPUCipherDevice();
	virtual int getThreadsPerThreadBlock() = 0;
	virtual int getNWarpsPerBlock() = 0;
	virtual int getMaxBlocksPerSM() = 0;
	virtual int getConcurrentKernels() = 0;
	int getGridSize(int n_blocks, int threadsPerCipherBlock);
	virtual void set() = 0; // must be called to set operations to this device
	virtual void malloc(void** data, int size) = 0;
	virtual void free(void* data) = 0;
	virtual void memcpyTo(void* host, void* dev, int size, int stream_id) = 0; // Async
	virtual void memcpyFrom(void* dev, void* host, int size, int stream_id) = 0; // Async
	virtual void waitMemcpyFrom(int stream_id) = 0; ; //waits until mempcyFrom finishes
	virtual int checkMemcpyFrom(int stream_id) = 0; ; //checks if memcpyFrom has finished
	virtual void setMemCpyFromCallback(int stream_id, F func) = 0; ;
	int addStream(); // thread-safe
	void delStream(int stream_id); // thread-safe
   };

}

#include "GPUCipherDevice.tpp"
