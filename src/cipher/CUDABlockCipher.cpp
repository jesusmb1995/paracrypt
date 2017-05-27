#include "CUDABlockCipher.hpp"

paracrypt::CUDABlockCipher::CUDABlockCipher()
: paracrypt::BlockCipher::BlockCipher()
{}

paracrypt::CUDABlockCipher::CUDABlockCipher(CUDABlockCipher* cipher)
: paracrypt::BlockCipher::BlockCipher(cipher)
{}
