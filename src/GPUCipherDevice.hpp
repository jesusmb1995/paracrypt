#include <functional>
#include "driver_types.h"

namespace paracrypt {

	struct launch_config {
		int grid_size;
		int kernel_number;
	} launch_config_t;

    class GPUCipherDevice {
      public:
    virtual ~GPUCipherDevice() {}
	virtual int getThreadsPerThreadBlock() = 0;
	virtual int getNWarpsPerBlock() = 0;
	virtual int getMaxBlocksPerSM() = 0;
	virtual int getConcurrentKernels() = 0;
	int getGridSize(int n_blocks, int threadsPerCipherBlock);

	virtual void set(); // must be called to set operations to this device
	virtual void malloc(void* data, int size);
	virtual void memcpyTo(void* host, void* dev, int size); // Async
	virtual void memcpyFrom(void* dev, void* host, int size); // Sync

	template < typename FN, typename... ARGS >
	virtual void launch(launch_config_t* config, FN&& kernel, ARGS&&... args); // Async
    };

}
