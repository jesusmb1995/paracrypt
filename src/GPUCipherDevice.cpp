#include "GPUCipherDevice.hpp"

template<typename S>
int paracrypt::GPUCipherDevice<S>::getGridSize(int n_blocks, int threadsPerCipherBlock) {
    int gridSize = n_blocks * threadsPerCipherBlock / this->getThreadsPerThreadBlock();
    return gridSize;
}
