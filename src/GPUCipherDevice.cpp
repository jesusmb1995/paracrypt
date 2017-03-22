#include "GPUCipherDevice.hpp"

int paracrypt::GPUCipherDevice::getGridSize(int n_blocks, int threadsPerCipherBlock) {
    int gridSize = n_blocks * threadsPerCipherBlock / this->getThreadsPerThreadBlock();
    return gridSize;
}
