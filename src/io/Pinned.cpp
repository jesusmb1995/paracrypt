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

#include "Pinned.hpp"
#include <sys/sysinfo.h>
#include <algorithm>
#include "../logging.hpp"

const rlim_t paracrypt::Pinned::getAvaliablePinneableRAM()
{
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
	struct sysinfo info;
	getrlimit(RLIMIT_MEMLOCK,&limit);
	sysinfo(&info);
	rlim_t lock_limit = limit.rlim_cur;
	rlim_t ram_limit = info.freeram;
	rlim_t pinneable_limit = std::min(lock_limit, ram_limit);
	return pinneable_limit;
}

const rlim_t paracrypt::Pinned::getReasonablyBigChunkOfRam(rlim_t lim)
{
    rlim_t avaliableRam = getAvaliablePinneableRAM();
    rlim_t usableRAM = BUFFERS_RAM_USAGE_FACTOR*avaliableRam;
    rlim_t reasonableRam = lim == 0 ?
    		usableRAM :
    		std::min(usableRAM, lim);

    LOG_INF(boost::format(
    		" Available RAM: %llu bytes."
    		" Limit set by user: %llu bytes."
    		" Suggested pinned alloc: %llu bytes."
    		"\n")
    % avaliableRam
    % lim
    % reasonableRam
    );

    return reasonableRam;
}

//const rlim_t paracrypt::Pinned::allocReasonablyBigChunkOfRam(
//		void** ptr,
//		rlim_t lim,
//		rlim_t chunkSize,
//){
//
//}

