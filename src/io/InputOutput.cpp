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

#include "InputOutput.hpp"
#include <sys/resource.h>

namespace paracrypt {

InputOutput::InputOutput() {
	/*
	 *        http://man7.org/linux/man-pages/man2/setrlimit.2.html
	 *
	 *        int getrlimit(int resource, struct rlimit *rlim);
	 *
	 *        RLIMIT_MEMLOCK
	 *            This is the maximum number of bytes of memory that may be
	 *            locked into RAM.  This limit is in effect rounded down to the
	 *            nearest multiple of the system page size.  This limit affects
	 *            mlock(2), mlockall(2), and the mmap(2) MAP_LOCKED operation.
	 *
	 *            In Linux kernels before 2.6.9, this limit controlled the
	 *            amount of memory that could be locked by a privileged process.
	 *            Since Linux 2.6.9, no limits are placed on the amount of
	 *            memory that a privileged process may lock, and this limit
	 *            instead governs the amount of memory that an unprivileged
	 *            process may lock.
	 */
	struct rlimit limit;
	getrlimit(RLIMIT_MEMLOCK,&limit);
    this->rlimitMemLock = limit->rlim_cur;
    this->lockLimit = this->rlimitMemLock;
}

InputOutput::~InputOutput() {}

/*
 *     TODO If we do not want to use CUDA functions we could use ...
 *
 *     mlock(), mlock2(), and mlockall() lock part or all of the calling
 *     process's virtual address space into RAM, preventing that memory from
 *     being paged to the swap area.
 */
/*
 * https://devblogs.nvidia.com/parallelforall/how-optimize-data-transfers-cuda-cc/
 *
 * Allocate pinned host memory in CUDA C/C++ using cudaMallocHost() or
 * cudaHostAlloc(), and deallocate it with cudaFreeHost(). It is possible
 * for pinned memory allocation to fail, so you should always check for
 * errors. The following code excerpt demonstrates allocation of pinned
 * memory with error checking.
 */

void InputOutput::setLockLimit(int bytes) {
	if(bytes < this->rlimitMemLock) {
		this->lockLimit = bytes;
	} else {
		this->lockLimit = this->rlimitMemLock;
	}
}

int InputOutput::getLockLimit() {
	return this->lockLimit;
}

} /* namespace paracrypt */
