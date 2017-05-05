/*
 *  Copyright (C) 2017 Jesus Martin Berlanga. All Rights Reserved.
 *
 *  This file is part of Paracrypt.
 *
 *  Paracrypt is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Paracrypt is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Paracrypt.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "CudaPinned.hpp"
#include "../device/CUDACipherDevice.hpp"

namespace paracrypt {

bool paracrypt::CudaPinned::alloc(void** ptr, std::streampos size)
{
	cudaError_t e = cudaHostAlloc(ptr,size,0);
	HANDLE_PRINT_ERROR_NUMBER(e);
	return e == cudaSuccess;
}

void paracrypt::CudaPinned::free(void* ptr)
{
	HANDLE_ERROR(cudaFreeHost(ptr));
}

} /* namespace paracrypt */
